#include <netinet/ether.h>
#include "fbc_filter_ether.h"

int fbc_filter_ether_srcaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *srcaddr = (Byte *)(((struct ether_header *)packet->header)->ether_shost);
	return (memcpy(srcaddr, arg, arg_size) == 0);
}

int fbc_filter_ether_dstaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *srcaddr = (Byte *)(((struct ether_header *)packet->header)->ether_dhost);
	return (memcpy(srcaddr, arg, arg_size) == 0);
}
