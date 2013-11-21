#include <net/if_arp.h>
#include <netinet/in.h>

#include "fbc_common.h"
#include "fbc_packet.h"
#include "fbc_address.h"
#include "fbc_arp.h"


fbc_Packet *fbc_arp_init_packet(Byte *buf)
{
	/* struct arphdr *arph = NULL; */
	fbc_Packet *packet = fbc_alloc_packet();
	if (!buf || !packet)	return NULL;


	fbc_set_protocol(packet->protocol, FBC_PROTOCOL_ARP);
	fbc_set_protocol(packet->next_protocol, FBC_PROTOCOL_NULL);
	packet->next_packet = NULL;

	packet->header = buf;
	/* arph = (struct arphdr *)buf; */
	packet->playload = buf + sizeof(struct arphdr);
	packet->tail = NULL;

	packet->fbc_init_packet = fbc_arp_init_packet;
	packet->fbc_destroy_packet = fbc_arp_destroy_packet;
	packet->fbc_print_packet = fbc_arp_print_packet;
	packet->fbc_analyze_playload = fbc_arp_analyze_playload;

	return packet;
}

fbc_Packet *fbc_arp_analyze_playload(fbc_Packet *packet)
{
	return NULL;
}

void fbc_arp_destroy_packet(fbc_Packet *packet)
{
	if (packet) {
		if (packet->next_packet) {
			packet->next_packet->fbc_destroy_packet(packet->next_packet);
		}
		packet->next_packet = NULL;
		free(packet);
	}
}

void fbc_arp_hardware_protocol_to_fbc_protocol(unsigned short hp, protocol_t fp)
{
	switch (hp) {
		case ARPHRD_ETHER:
			fbc_set_protocol(fp, FBC_PROTOCOL_ETHER);
			break;
		default:
			fbc_set_protocol(fp, FBC_PROTOCOL_NULL);
			break;
	}
}

void fbc_arp_opcode_to_string(unsigned short op, char *opstring)
{
	if (! opstring) 	return;
	switch (op) {
		case ARPOP_REQUEST:
			strcpy(opstring, "REQUEST");
			break;
		case ARPOP_REPLY:
			strcpy(opstring, "REPLY");
			break;
		case ARPOP_RREQUEST:
			strcpy(opstring, "RREQUEST");
			break;
		case ARPOP_RREPLY:
			strcpy(opstring, "RREPLY");
			break;
		case ARPOP_InREQUEST:
			strcpy(opstring, "InREQUEST");
			break;
		case ARPOP_InREPLY:
			strcpy(opstring, "InREPLY");
			break;
		case ARPOP_NAK:
			strcpy(opstring, "NAK");
			break;
		default:
			strcpy(opstring, "UNKNOWN");
			break;
	}
}

void fbc_arp_print_packet(FILE *out, char *pre, fbc_Packet *packet)
{
	struct arphdr *arph = (struct arphdr *)packet->header;
	protocol_t hrd;
	protocol_t pro;
	char opstring[16];
	char hard_addr[64];
	char prot_addr[64];
	char hex[64];
	Byte *sender_hard_addr;
	Byte *sender_prot_addr;
	Byte *target_hard_addr;
	Byte *target_prot_addr;
	int hlen;
	int plen;

	fprintf(out, "%sARP Header:\n", pre);

	fbc_arp_hardware_protocol_to_fbc_protocol(ntohs(arph->ar_hrd), hrd);
	fprintf(out, "%sHardware Type: %s(%d)\n", pre, hrd, ntohs(arph->ar_hrd));

	fbc_network_protocol_to_fbc_protocol(ntohs(arph->ar_pro), pro);
	fprintf(out, "%sProtocol Type: %s(0x%04x)\n", pre, pro, ntohs(arph->ar_pro));

	hlen = arph->ar_hln & 0xff;
	plen = arph->ar_pln & 0xff;
	fprintf(out, "%sHardware Addr Len: %d\n", pre, hlen);
	fprintf(out, "%sProtocol Addr Len: %d\n", pre, plen);

	fbc_arp_opcode_to_string(ntohs(arph->ar_op), opstring);
	fprintf(out, "%sARP Opcode: %s(%d)\n", pre, opstring, ntohs(arph->ar_op));
	
	sender_hard_addr = packet->playload;
	sender_prot_addr = sender_hard_addr + hlen;
	target_hard_addr = sender_prot_addr + plen;
	target_prot_addr = sender_hard_addr + hlen;

	fprintf(out, "%sSender Hardware Addr: %s(0x%s)\n", pre, 
			fbc_get_addr_string(hrd, sender_hard_addr, 64, hard_addr),
			fbc_get_hex_string(sender_hard_addr, hlen, hex));
	fprintf(out, "%sSender Protocol Addr: %s(0x%s)\n", pre, 
			fbc_get_addr_string(pro, sender_prot_addr, 64, prot_addr),
			fbc_get_hex_string(sender_prot_addr, plen, hex));
	fprintf(out, "%sTarget Hardware Addr: %s(0x%s)\n", pre, 
			fbc_get_addr_string(hrd, target_hard_addr, 64, hard_addr),
			fbc_get_hex_string(target_hard_addr, hlen, hex));
	fprintf(out, "%sSender Protocol Addr: %s(0x%s)\n", pre, 
			fbc_get_addr_string(pro, target_prot_addr, 64, prot_addr),
			fbc_get_hex_string(target_prot_addr, plen, hex));

}
