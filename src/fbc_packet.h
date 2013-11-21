#ifndef	_FBC_PACKET_H_
#define	_FBC_PACKET_H_

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "fbc_common.h"


#define fbc_set_protocol(packet_protocol, protocol)   strcpy((packet_protocol), (protocol))
#define fbc_protocol_equal(p1, p2)	(strcmp((p1), (p2)) == 0)

typedef struct fbc_Packet *(*fbc_analyze_playload_t)(struct fbc_Packet *packet);
typedef struct fbc_Packet *(*fbc_init_packet_t)(Byte *buf);
typedef void (*fbc_destroy_packet_t)(struct fbc_Packet *packet);
typedef void (*fbc_print_packet_t)(FILE *out, char *pre, struct fbc_Packet *packet);

/**
 * struct fbc_Packet, the abstract of structure packet, including datalink frames,
 * network packets.
 */
struct fbc_Packet {
	Byte *header;
	Byte *playload;
	Byte *tail;

	struct fbc_Packet *next_packet;

	protocol_t protocol;
	protocol_t next_protocol;

	fbc_analyze_playload_t fbc_analyze_playload;
	/**
	 * this function is used to init the fbc packet
	 */
	fbc_init_packet_t fbc_init_packet;
	fbc_destroy_packet_t fbc_destroy_packet;
	fbc_print_packet_t fbc_print_packet;
};
typedef struct fbc_Packet fbc_Packet;

/* defined protocol */

#define MAX_PROTOCOL_TYPE	128

fbc_Packet *fbc_init_packet_by_protocol(Byte *buf, protocol_t p);
fbc_Packet *fbc_alloc_packet();
void fbc_dealloc_packet(fbc_Packet *packet);
void fbc_network_protocol_to_fbc_protocol(unsigned short np, protocol_t fp);

#endif
