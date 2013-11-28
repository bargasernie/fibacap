#include <netinet/ether.h>
#include "fbc_filter_ether.h"
#include "fbc_pf.h"
#include "fbc_address.h"
#include "fbc_lib.h"

/* If you want to add an protocol be filtered, there are several parts:
 *
 * 	1. attribute of the protocol
 * 	2. filter function
 * 	3. function that adds filter function into filter
 * 	4. attribute map
 * 	5. attribute map function
 */


/* 
 * 4. attribute map
 */
/* ether attribute map */
int fbc_filter_ether_add_src_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ether_add_dst_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ether_add_addr_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ether_add_next_protocol_filter_func(fbc_Filter *filter, char *attr, char *value);

static struct fbc_attribute_map_list fbc_ether_attribute[32] = {
	{ "src", fbc_filter_ether_add_src_filter_func },
	{ "dst", fbc_filter_ether_add_dst_filter_func },
	{ "addr", fbc_filter_ether_add_addr_filter_func },
	{ "next_protocol", fbc_filter_ether_add_next_protocol_filter_func },
	{ FBC_ATTRIBUTE_NULL, 0, }
};

/**
 * 2. filter function
 *
 */

/* fbc_filter_func_t */
int fbc_filter_ether_srcaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *srcaddr = (Byte *)(((struct ether_header *)packet->header)->ether_shost);
	DPRINTF("-DEBUG- fbc_filter_ether_srcaddr:\tmatching ether srcaddr\n");
	return (memcmp(srcaddr, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ether_dstaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *dstaddr = (Byte *)(((struct ether_header *)packet->header)->ether_dhost);
	DPRINTF("-DEBUG- fbc_filter_ether_dstaddr:\tmatching ether dstaddr\n");
	return (memcmp(dstaddr, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ether_addr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *srcaddr = (Byte *)(((struct ether_header *)(packet->header))->ether_shost);
	void *dstaddr = (Byte *)(((struct ether_header *)(packet->header))->ether_dhost);
	DPRINTF("-DEBUG- fbc_filter_ether_addr:\tmatching ether addr\n");
	return (memcmp(srcaddr, arg, arg_size) == 0) || (memcmp(dstaddr, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ether_next_protocol(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *next_protocol = (Byte *)&(((struct ether_header *)(packet->header))->ether_type);
	DPRINTF("-DEBUG- fbc_filter_ether_next_protocol:\tmatching ether type (next protocol)\n");
	return (memcmp(next_protocol, arg, arg_size) == 0);
}

/*
 * 5. attribute map function
 */
fbc_add_func_into_filter_t fbc_ether_attribute_map(char *attr)
{
	int i = 0;
	while (1) {
		if (fbc_attribute_equal(fbc_ether_attribute[i].attribute, attr)) {
			return (fbc_ether_attribute[i].add_func_into_filter);
		}
		if (fbc_attribute_equal(fbc_ether_attribute[i].attribute, FBC_ATTRIBUTE_NULL)) {
			fprintf(stderr, "No attribute %s in protocol %s\n", attr, FBC_PROTOCOL_ETHER);
			return 0;
		}
		i++;
	}
	return 0;
	
}

/*
 * 3. function that adds filter function into filter
 */
int fbc_filter_ether_add_src_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[ETH_ALEN];
	DPRINTF2("-DEBUG- fbc_filter_ether_add_src_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ether_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ether_srcaddr, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ether_add_src_filter_func: add fbc_ether_srcaddr into filter\n");
	return 1;
}

int fbc_filter_ether_add_dst_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[ETH_ALEN];
	DPRINTF2("-DEBUG- fbc_filter_ether_add_dst_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ether_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ether_dstaddr, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ether_add_dst_filter_func: add fbc_filter_ether_dstaddr into filter\n");
	return 1;
}

int fbc_filter_ether_add_addr_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[ETH_ALEN];
	DPRINTF2("-DEBUG- fbc_filter_ether_add_addr_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ether_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ether_addr, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ether_add_addr_filter_func: add fbc_filcter_ether_addr into filter\n");
	return 1;
}

int fbc_filter_ether_add_next_protocol_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t np;
	DPRINTF2("-DEBUG- fbc_filter_ether_add_next_protocol_filter_func: <%s>=<%s>\n", attr, value);
	np = htons((u_int16_t)(string_to_uint(value) & 0xffff));
	fbc_filter_add_func(filter, fbc_filter_ether_next_protocol, &np, sizeof(np));
	DPRINTF("-DEBUG- fbc_filter_ether_add_next_protocol_filter_func: add fbc_filter_ether_next_protocol into filter\n");
	return 1;
}

