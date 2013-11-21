#ifndef	_FBC_IP_H_
#define	_FBC_IP_H_

#include "fbc_packet.h"

fbc_Packet *fbc_ip_init_packet(Byte *buf);
struct fbc_Packet *fbc_ip_analyze_playload(struct fbc_Packet *packet);
void fbc_ip_print_packet(FILE *out, char *pre, struct fbc_Packet *packet);
void fbc_ip_destroy_packet(struct fbc_Packet *packet);

#endif
