
#include <netinet/in.h>
#include <netinet/ether.h>
#include <malloc.h>

#include "fbc_common.h"
#include "fbc_packet.h"
#include "fbc_address.h"
#include "fbc_ether.h"
#include "fbc_ip.h"


/**
 * Define ether packet
 *
 */

void fbc_ether_set_next_protocol(fbc_Packet *packet)
{
	struct ether_header *eh = (struct ether_header *)packet->header;

	switch (ntohs(eh->ether_type)) {
		case ETHERTYPE_IP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_IP);
			break;
		case ETHERTYPE_ARP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_ARP);
			break;
		case ETHERTYPE_IPV6:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_IPV6);
			break;
		case ETHERTYPE_PUP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_PUP);
			break;
		case ETHERTYPE_SPRITE:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_SPRITE);
			break;
		case ETHERTYPE_REVARP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_REVARP);
			break;
		case ETHERTYPE_AT:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_AT);
			break;
		case ETHERTYPE_AARP:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_AARP);
			break;
		case ETHERTYPE_VLAN:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_VLAN);
			break;
		case ETHERTYPE_IPX:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_IPX);
			break;
		case ETHERTYPE_LOOPBACK:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_LOOPBACK);
			break;
		default:
			fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_UNKNOWN);
			break;
	}
}

fbc_Packet *fbc_ether_init_packet(Byte *buf) 
{
	fbc_Packet *packet = fbc_alloc_packet();
	if (! packet)	return NULL;

	packet->next_packet = NULL;

	fbc_set_protocol(packet->protocol, FBC_PROTOCOL_ETHER);
	packet->header = buf;
	packet->playload = buf + sizeof(struct ether_header);
	packet->tail = NULL;
	
	packet->fbc_analyze_playload 	= fbc_ether_analyze_playload;
	packet->fbc_init_packet 	= fbc_ether_init_packet;
	packet->fbc_destroy_packet 	= fbc_ether_destroy_packet;
	packet->fbc_print_packet 	= fbc_ether_print_packet;

	fbc_ether_set_next_protocol(packet);

	packet->next_packet = packet->fbc_analyze_playload(packet);
	return packet;
}

struct fbc_Packet *fbc_ether_analyze_playload(struct fbc_Packet *packet)
{
	return fbc_init_packet_by_protocol(packet->playload, packet->next_protocol);
}

void fbc_ether_print_packet(FILE *out, char *pre, struct fbc_Packet *packet)
{
	struct ether_header *eh = 0;
	char buf[ETH_ALEN + ETH_ALEN + ETH_ALEN];
	if (! packet)	return;

	eh = (struct ether_header *)(packet->header);

	fprintf(out, "%sEther Header:\n", pre);
	fprintf(out, "%sDst Addr: %s\n", pre, fbc_ether_addr_to_string((struct ether_addr *)&(eh->ether_dhost), buf, sizeof(buf)));
	
	fprintf(out, "%sSrc Addr: %s\n", pre, fbc_ether_addr_to_string((struct ether_addr *)&(eh->ether_shost), buf, sizeof(buf)));
	fprintf(out, "%sPL Type : %s(0x%04x)\n", pre, packet->next_protocol, ntohs(eh->ether_type));

	if (packet->next_packet) {
		(packet->next_packet->fbc_print_packet)(out, pre, packet->next_packet);
	}
	
}

void fbc_ether_destroy_packet(struct fbc_Packet *packet)
{
	if (packet) {
		if (packet->next_packet) {
			packet->next_packet->fbc_destroy_packet(packet->next_packet);
		}
		packet->next_packet = NULL;
		free(packet);
	}
}
