#include <netinet/tcp.h>
#include "fbc_common.h"
#include "fbc_packet.h"
#include "fbc_address.h"
#include "fbc_tcp.h"

void fbc_tcp_set_next_protocol(fbc_Packet *packet)
{
	fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_NULL);
}

fbc_Packet *fbc_tcp_init_packet(Byte *buf)
{
	struct tcphdr *tcph = NULL;
	fbc_Packet *packet = fbc_alloc_packet();
	if (! packet)	return NULL;

	packet->next_packet = NULL;
	fbc_set_protocol(packet->protocol, FBC_PROTOCOL_TCP);

	packet->header = buf;
	tcph = (struct tcphdr *)buf;
	packet->playload = buf + ((tcph->doff & 0x0f) << 2);
	packet->tail = NULL;

	packet->fbc_analyze_playload	= fbc_tcp_analyze_playload;
	packet->fbc_init_packet 	= fbc_tcp_init_packet;
	packet->fbc_destroy_packet 	= fbc_tcp_destroy_packet;
	packet->fbc_print_packet 	= fbc_tcp_print_packet;

	fbc_tcp_set_next_protocol(packet);

	packet->next_packet = packet->fbc_analyze_playload(packet);

	return packet;
}

void fbc_tcp_destroy_packet(fbc_Packet *packet)
{
	if (packet) {
		if (packet->next_packet) {
			packet->next_packet->fbc_destroy_packet(packet->next_packet);
		}
		packet->next_packet = NULL;
		free(packet);
	}
}

fbc_Packet *fbc_tcp_analyze_playload(fbc_Packet *packet)
{
	return fbc_init_packet_by_protocol(packet->playload, packet->next_protocol);
}

void fbc_tcp_print_packet(FILE *out, char *pre, fbc_Packet *packet)
{
	struct tcphdr *tcph;
	if (!packet || !packet->header)		return;
	tcph = (struct tcphdr *)packet->header;

	fprintf(out, "%sTCP Header:\n", pre);
	fprintf(out, "%sSrc Port: %d\n", pre, ntohs(tcph->source));
	fprintf(out, "%sDst Port: %d\n", pre, ntohs(tcph->dest));
	fprintf(out, "%sSeq Num : %d\n", pre, ntohl(tcph->seq));
	fprintf(out, "%sAck Num : %d\n", pre, ntohl(tcph->ack_seq));
	fprintf(out, "%sData Off: %d\n", pre, (tcph->doff & 0x0f));
	fprintf(out, "%sReserve : \n", pre ); /* TODO */
	fprintf(out, "%sURG: %d, ACK: %d, PSH: %d, RST: %d, SYN: %d, FIN: %d\n", pre,
			tcph->urg & 0x01, tcph->ack & 0x01, tcph->psh & 0x01,
			tcph->rst & 0x01, tcph->syn & 0x01, tcph->fin &0x01
		);
	fprintf(out, "%sWindow  : %d\n", pre, ntohs(tcph->window));
	fprintf(out, "%sCheckSum: 0x%04x\n", pre, ntohs(tcph->check));
	fprintf(out, "%sUrgPoint: 0x%04x\n", pre, ntohs(tcph->urg_ptr));
	
	/* TODO: print options and padding */
	if (packet->next_packet && packet->next_packet->fbc_print_packet) {
		(packet->next_packet->fbc_print_packet)(out, pre, packet->next_packet);
	}

}
