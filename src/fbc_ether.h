#ifndef _FBC_ETHER_H_
#define _FBC_ETHER_H_

#include "fbc_packet.h"

/*
fbc_init_packet_t 	fbc_ether_init_packet;
fbc_destroy_packet_t 	fbc_ether_destroy_packet;
fbc_analyze_playload_t 	fbc_ether_analyze_playload;
fbc_print_packet_t 	fbc_ether_print_packet;
*/

fbc_Packet *fbc_ether_init_packet(Byte *buf);
struct fbc_Packet *fbc_ether_analyze_playload(struct fbc_Packet *packet);
void fbc_ether_print_packet(FILE *out, char *pre, struct fbc_Packet *packet);
void fbc_ether_destroy_packet(struct fbc_Packet *packet);

#endif
