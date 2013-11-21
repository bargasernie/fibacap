#include <netinet/in.h>
#include <net/ethernet.h>
#include "fbc_packet.h"


/* If a protocol is defined, 
 * 	1. the header file must be included below
 *	2. an entry must be added to protocal_table
 */
#include "fbc_ether.h"
#include "fbc_ip.h"
#include "fbc_arp.h"
#include "fbc_tcp.h"
#include "fbc_udp.h"


static struct Protocol_Table {
	protocol_t	p;
	fbc_init_packet_t fbc_init_packet_method;
} protocol_table[MAX_PROTOCOL_TYPE] = {
	{ FBC_PROTOCOL_ETHER, fbc_ether_init_packet },
	{ FBC_PROTOCOL_IP   , fbc_ip_init_packet    },
	{ FBC_PROTOCOL_ARP  , fbc_arp_init_packet   },
	{ FBC_PROTOCOL_TCP  , fbc_tcp_init_packet   },
	{ FBC_PROTOCOL_UDP  , fbc_udp_init_packet   },
	{ FBC_PROTOCOL_NULL , 0                     }
};

fbc_Packet *fbc_init_packet_by_protocol(Byte *buf, protocol_t p)
{
	fbc_Packet *packet = NULL;
	int i = 0;

	if (!buf || !p)	return packet;

	while (1) {
		if (fbc_protocol_equal(protocol_table[i].p, FBC_PROTOCOL_NULL))	break;
		if (fbc_protocol_equal(protocol_table[i].p, p)) {
			if (protocol_table[i].fbc_init_packet_method) {
				packet = (protocol_table[i].fbc_init_packet_method)(buf);
			}
			break;
		}
		i++;
	}
	return packet;
}

fbc_Packet *fbc_alloc_packet()
{
	struct fbc_Packet *packet = (fbc_Packet *)malloc(sizeof(fbc_Packet));
	if (! packet) {
		fprintf(stderr, "Can not allocate memory to init packet\n");
		return NULL;
	}
	return packet;
}

void fbc_dealloc_packet(fbc_Packet *packet)
{
	free(packet);
}

void fbc_network_protocol_to_fbc_protocol(unsigned short np, protocol_t fp)
{
	switch (np) {
		case ETHERTYPE_IP:
			fbc_set_protocol(fp, FBC_PROTOCOL_IP);
			break;
		case ETHERTYPE_IPV6:
			fbc_set_protocol(fp, FBC_PROTOCOL_IPV6);
			break;
		case ETHERTYPE_VLAN:
			fbc_set_protocol(fp, FBC_PROTOCOL_VLAN);
			break;
		default:
			fbc_set_protocol(fp, FBC_PROTOCOL_UNKNOWN);
			break;
	}
}
