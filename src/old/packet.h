#ifndef	_PACKET_H_
#define	_PACKET_H_

#include <stdio.h>
#include "common.h"


typedef Packet *(analyze_playload_t)(protocal_t protocal, protocal_t next_protocal, Byte *playload);
typedef void (init_packet_t)(struct Packet *packet);
typedef void (print_packet_t)(FILE *out, char *pre, struct Packet *packet);

/**
 * struct Packet, the abstract of structure packet, including datalink frames,
 * network packets.
 */
struct Packet {
	Byte *header;
	Byte *playload;
	Byte *tail;

	protocal_t protocal;
	protocal_t next_protocal;

	analyze_playload_t analyze_playload;
	init_packet_t init_packet;
	print_packet_t print_packet;
};
typedef struct Packet Packet;

#endif
