#ifndef	_FBC_ARP_H_
#define	_FBC_ARP_H_

#include "fbc_packet.h"

fbc_Packet *fbc_arp_init_packet(Byte *buf);
struct fbc_Packet *fbc_arp_analyze_playload(struct fbc_Packet *packet);
void fbc_arp_print_packet(FILE *out, char *pre, struct fbc_Packet *packet);
void fbc_arp_destroy_packet(struct fbc_Packet *packet);

#endif
