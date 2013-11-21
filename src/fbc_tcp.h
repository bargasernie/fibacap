#ifndef	_FBC_TCP_H_
#define	_FBC_TCP_H_

#include "fbc_packet.h"

fbc_Packet *fbc_tcp_init_packet(Byte *buf);
struct fbc_Packet *fbc_tcp_analyze_playload(struct fbc_Packet *packet);
void fbc_tcp_print_packet(FILE *out, char *pre, struct fbc_Packet *packet);
void fbc_tcp_destroy_packet(struct fbc_Packet *packet);

#endif
