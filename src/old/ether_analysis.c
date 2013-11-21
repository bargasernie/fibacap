#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include "analysis.h"
#include "ether_analysis.h"

struct Frame *ether_analyzer(Byte *buf, int len)
{
	struct Frame *frame;
	if (!(frame = (struct Frame *)malloc(sizeof(struct Frame)))) {
		fprintf(stderr, "In %s line %d, can not allocate memory for struct Frame!\n", __FILE__, __LINE__);
		return NULL;
	}
	frame->header = (struct ether_header *)buf;

	frame->playload = (Byte *)(buf + sizeof(struct ether_header));
	frame->tail = NULL;

	return frame;
}

char *ether_addr_to_string(const struct ether_addr *enaddr, char *addr_string)
{
	sprintf(addr_string, "%02x:%02x:%02x:%02x:%02x:%02x", 
			enaddr->ether_addr_octet[0], enaddr->ether_addr_octet[1],
			enaddr->ether_addr_octet[2], enaddr->ether_addr_octet[3],
			enaddr->ether_addr_octet[4], enaddr->ether_addr_octet[5]);
	return addr_string;
}


char *ether_type_to_string(u_int16_t etype, char *type_string)
{
	switch (etype) {
		case ETHERTYPE_IP:
			strcpy(type_string, "IP");
			break;
		case ETHERTYPE_ARP:
			strcpy(type_string, "ARP");
			break;
		case ETHERTYPE_IPV6:
			strcpy(type_string, "IPV6");
			break;
		case ETHERTYPE_PUP:
			strcpy(type_string, "PUP");
			break;
		case ETHERTYPE_SPRITE:
			strcpy(type_string, "SPRITE");
			break;
		case ETHERTYPE_REVARP:
			strcpy(type_string, "REVARP");
			break;
		case ETHERTYPE_AT:
			strcpy(type_string, "AT");
			break;
		case ETHERTYPE_AARP:
			strcpy(type_string, "AARP");
			break;
		case ETHERTYPE_VLAN:
			strcpy(type_string, "VLAN");
			break;
		case ETHERTYPE_IPX:
			strcpy(type_string, "IPX");
			break;
		case ETHERTYPE_LOOPBACK:
			strcpy(type_string, "LOOPBACK");
			break;
		default:
			strcpy(type_string, "Other");
			break;
	}

	return type_string;

}

void ether_header_print(FILE *out, const char *pre, struct ether_header *header) 
{
	char buf[ETH_ALEN + ETH_ALEN];
	fprintf(out, "%sDst Addr: %s\n", pre, ether_addr_to_string((struct ether_addr *)&(header->ether_dhost), buf));
	fprintf(out, "%sSrc Addr: %s\n", pre, ether_addr_to_string((struct ether_addr *)&(header->ether_shost), buf));
	fprintf(out, "%sPL Type : %s(0x%04x)\n", pre, ether_type_to_string(ntohs(header->ether_type), buf), ntohs(header->ether_type));

}

