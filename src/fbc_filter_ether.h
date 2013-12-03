#ifndef	_FBC_FILTER_ETHER_H_
#define	_FBC_FILTER_ETHER_H_

#include "fbc_packet.h"
#include "fbc_filter.h"
#include "fbc_pf.h"

/* Filter attribute */
fbc_add_func_into_filter_t fbc_ether_attribute_map(char *attr);

/* Filter function
 *
 */
/* int fbc_filter_ether_srcaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size); */
/* int fbc_filter_ether_dstaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size); */


#endif
