#ifndef	_FBC_UDP_H_
#define	_FBC_UDP_H_

#include "fbc_packet.h"

fbc_Packet *fbc_udp_init_packet(Byte *buf);
struct fbc_Packet *fbc_udp_analyze_playload(struct fbc_Packet *packet);
void fbc_udp_print_packet(FILE *out, char *pre, struct fbc_Packet *packet);
void fbc_udp_destroy_packet(struct fbc_Packet *packet);

#endif
