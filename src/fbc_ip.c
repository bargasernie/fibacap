#include <netinet/ip.h>
#include <arpa/inet.h>
#include "fbc_common.h"
#include "fbc_packet.h"
#include "fbc_address.h"
#include "fbc_ip.h"

void fbc_ip_set_next_protocol(fbc_Packet *packet)
{
	int p = ((struct ip *)(packet->header))->ip_p & 0xff;
	switch (p) {
		case IPPROTO_TCP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_TCP);
			break;
		case IPPROTO_UDP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_UDP);
			break;
		case IPPROTO_ICMP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_ICMP);
			break;
		default:
			fbc_set_protocol(packet->next_protocol, "Other");
	}
}

fbc_Packet *fbc_ip_init_packet(Byte *buf)
{
	struct ip *iph = NULL;
	fbc_Packet *packet = fbc_alloc_packet();
	if (! packet)	return NULL;

	packet->next_packet = NULL;
	fbc_set_protocol(packet->protocol, FBC_PROTOCOL_IP);

	packet->header = buf;
	iph = (struct ip *)buf;
	packet->playload = (buf + iph->ip_hl * 4);
	packet->tail = NULL;

	packet->fbc_analyze_playload	= fbc_ip_analyze_playload;
	packet->fbc_init_packet 	= fbc_ip_init_packet;
	packet->fbc_destroy_packet 	= fbc_ip_destroy_packet;
	packet->fbc_print_packet 	= fbc_ip_print_packet;

	fbc_ip_set_next_protocol(packet);

	packet->next_packet = packet->fbc_analyze_playload(packet);

	return packet;
}

void fbc_ip_destroy_packet(fbc_Packet *packet)
{
	if (packet) {
		if (packet->next_packet) {
			packet->next_packet->fbc_destroy_packet(packet->next_packet);
		}
		packet->next_packet = NULL;
		free(packet);
	}
}

fbc_Packet *fbc_ip_analyze_playload(fbc_Packet *packet)
{
	return fbc_init_packet_by_protocol(packet->playload, packet->next_protocol);
}

void fbc_ip_print_packet(FILE *out, char *pre, fbc_Packet *packet)
{
	char ipstring[16];
	if ( ! (packet && packet->header) )	return;
	struct ip *iph = (struct ip *)(packet->header);
	fprintf(out, "%sIP Header:\n", pre);
	fprintf(out, "%sVersion: %d\n", pre, iph->ip_v & 0x0f);
	fprintf(out, "%sHeaderLen: %d\n", pre, iph->ip_hl & 0x0f);
	fprintf(out, "%sTypeOfService: %d\n", pre, iph->ip_tos & 0xff);
	fprintf(out, "%sIP Length: %d\n", pre, ntohs(iph->ip_len) & 0xffff);
	fprintf(out, "%sIdentification: %d\n", pre, ntohs(iph->ip_id) & 0xffff);
	fprintf(out, "%sFlags: RF=%d, DF=%d, MF=%d\n", pre,
			(ntohs(iph->ip_off) & IP_RF ? 1 : 0), 
			(ntohs(iph->ip_off) & IP_DF ? 1 : 0), 
			(ntohs(iph->ip_off) & IP_MF ? 1 : 0)
		);
	fprintf(out, "%sFragment Offset Field: 0x%04x\n", pre, ntohs(iph->ip_off) & 0xffff);
	fprintf(out, "%sTime Of Live: %d\n", pre, iph->ip_ttl & 0xff);
	fprintf(out, "%sNext Protocol: %s(0x%02x)\n", pre, packet->next_protocol, iph->ip_p & 0xff);
	fprintf(out, "%sChecksum: 0x%04x\n", pre, iph->ip_sum);

	fbc_ip_addr_to_string(&(iph->ip_src), ipstring, sizeof(ipstring));
	fprintf(out, "%sSrc Address: %s\n", pre, ipstring);
	fbc_ip_addr_to_string(&(iph->ip_dst), ipstring, sizeof(ipstring));
	fprintf(out, "%sDst Address: %s\n", pre, ipstring);

	/* TODO: print option data and padding in header.
	 */

	if (packet->next_packet) {
		packet->next_packet->fbc_print_packet(out, pre, packet->next_packet);
	}
}
