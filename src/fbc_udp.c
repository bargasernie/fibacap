#include <netinet/udp.h>
#include "fbc_common.h"
#include "fbc_packet.h"
#include "fbc_address.h"
#include "fbc_udp.h"

void fbc_udp_set_next_protocol(fbc_Packet *packet)
{
	fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_NULL);
}

fbc_Packet *fbc_udp_init_packet(Byte *buf)
{
	fbc_Packet *packet = fbc_alloc_packet();
	if (! packet)	return NULL;

	packet->next_packet = NULL;
	fbc_set_protocol(packet->protocol, FBC_PROTOCOL_UDP);

	packet->header = buf;
	packet->playload = buf + sizeof(struct udphdr);
	packet->tail = NULL;

	packet->fbc_analyze_playload	= fbc_udp_analyze_playload;
	packet->fbc_init_packet 	= fbc_udp_init_packet;
	packet->fbc_destroy_packet 	= fbc_udp_destroy_packet;
	packet->fbc_print_packet 	= fbc_udp_print_packet;

	fbc_udp_set_next_protocol(packet);

	packet->next_packet = packet->fbc_analyze_playload(packet);

	return packet;
}

void fbc_udp_destroy_packet(fbc_Packet *packet)
{
	if (packet) {
		if (packet->next_packet) {
			packet->next_packet->fbc_destroy_packet(packet->next_packet);
		}
		packet->next_packet = NULL;
		free(packet);
	}
}

fbc_Packet *fbc_udp_analyze_playload(fbc_Packet *packet)
{
	return fbc_init_packet_by_protocol(packet->playload, packet->next_protocol);
}

void fbc_udp_print_packet(FILE *out, char *pre, fbc_Packet *packet)
{
	struct udphdr *udph;
	if (!packet || !packet->header)		return;
	udph = (struct udphdr *)packet->header;

	fprintf(out, "%sUDP Header:\n", pre);
	fprintf(out, "%sSrc Port: %d\n", pre, ntohs(udph->source));
	fprintf(out, "%sDst Port: %d\n", pre, ntohs(udph->dest));
	fprintf(out, "%sLength  : %d\n", pre, ntohs(udph->len));
	fprintf(out, "%sCheckSum: 0x%04x\n", pre, ntohs(udph->check));
	
	/* TODO: print options and padding */
	if (packet->next_packet && packet->next_packet->fbc_print_packet) {
		(packet->next_packet->fbc_print_packet)(out, pre, packet->next_packet);
	}

}
