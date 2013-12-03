#include <netinet/ip.h>
#include "fbc_filter_ip.h"
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
/* ip attribute map */
int fbc_filter_ip_add_src_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_dst_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_addr_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_version_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_hl_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_tos_filter_func(fbc_Filter *filter, char *attr, char *value);

static struct fbc_attribute_map_list fbc_ip_attribute[32] = {
	{ "src", fbc_filter_ip_add_src_filter_func },
	{ "dst", fbc_filter_ip_add_dst_filter_func },
	{ "addr", fbc_filter_ip_add_addr_filter_func },
	{ "version", fbc_filter_ip_add_version_filter_func },
	{ "hl", fbc_filter_ip_add_hl_filter_func },
	{ "tos", fbc_filter_ip_add_tos_filter_func },
	{ FBC_ATTRIBUTE_NULL, 0, }
};

/**
 * 2. filter function
 *
 */

/* fbc_filter_func_t */
int fbc_filter_ip_src(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *src = (void *)&(((struct ip *)packet->header)->ip_src);
	DPRINTF("-DEBUG- fbc_filter_ip_src:\tmatching ip src\n");
	return (memcmp(src, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ip_dst(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *dst = (void *)&(((struct ip *)packet->header)->ip_dst);
	DPRINTF("-DEBUG- fbc_filter_ip_dst:\tmatching ip dst\n");
	return (memcmp(dst, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ip_addr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *src = (void *)&(((struct ip *)(packet->header))->ip_src);
	void *dst = (void *)&(((struct ip *)(packet->header))->ip_dst);
	DPRINTF("-DEBUG- fbc_filter_ip_addr:\tmatching ip addr\n");
	return (memcmp(src, arg, arg_size) == 0) || (memcmp(dst, arg, arg_size) == 0);
}

/* fbc_filter_func_t */
int fbc_filter_ip_version(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	Byte ver = (((struct ip *)packet->header)->ip_v) & 0x0f;
	DPRINTF("-DEBUG- fbc_filter_ip_version:\tmatching ip protocol version\n");
	return (ver == *(Byte *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_hl(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	Byte hl = (((struct ip *)packet->header)->ip_hl) & 0x0f;
	DPRINTF("-DEBUG- fbc_filter_ip_hl:\tmatching ip header length\n");
	return (hl == *(Byte *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_tos(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	Byte tos = (((struct ip *)packet->header)->ip_tos) & 0xff;
	DPRINTF("-DEBUG- fbc_filter_ip_tos:\tmatching type of service\n");
	return (tos == *(Byte *)arg);
}

/*
 * 3. function that adds filter function into filter
 */
int fbc_filter_ip_add_src_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[sizeof(struct in_addr)];
	DPRINTF2("-DEBUG- fbc_filter_ip_add_src_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ip_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ip_src, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ip_add_src_filter_func: add fbc_filter_ip_src into filter\n");
	return 1;
}

int fbc_filter_ip_add_dst_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[sizeof(struct in_addr)];
	DPRINTF2("-DEBUG- fbc_filter_ip_add_dst_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ip_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ip_dst, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ip_add_dst_filter_func: add fbc_filter_filter_ip_dst into filter\n");
	return 1;
}

int fbc_filter_ip_add_addr_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte addr[sizeof(struct in_addr)];
	DPRINTF2("-DEBUG- fbc_filter_ip_add_addr_filter_func: <%s>=<%s>\n", attr, value);
	fbc_ip_addr_pton(value, addr, sizeof(addr));
	fbc_filter_add_func(filter, fbc_filter_ip_addr, addr, sizeof(addr));
	DPRINTF("-DEBUG- fbc_filter_ip_add_addr_filter_func: add fbc_filcter_ip_addr into filter\n");
	return 1;
}

int fbc_filter_ip_add_version_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte version;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_version_filter_func: <%s>=<%s>\n", attr, value);
	version = (Byte)(string_to_uint(value) & 0x0f);
	fbc_filter_add_func(filter, fbc_filter_ip_version, &version, sizeof(version));
	DPRINTF("-DEBUG- fbc_filter_ip_add_version_filter_func: add fbc_filter_filter_ip_version into filter\n");
	return 1;
}

int fbc_filter_ip_add_hl_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte hl;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_hl_filter_func: <%s>=<%s>\n", attr, value);
	hl = (Byte)(string_to_uint(value) & 0x0f);
	fbc_filter_add_func(filter, fbc_filter_ip_hl, &hl, sizeof(hl));
	DPRINTF("-DEBUG- fbc_filter_ip_add_hl_filter_func: add fbc_filter_filter_ip_hl into filter\n");
	return 1;
}

int fbc_filter_ip_add_tos_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	Byte tos;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_hl_filter_func: <%s>=<%s>\n", attr, value);
	tos = (Byte)(string_to_uint(value) & 0xff);
	fbc_filter_add_func(filter, fbc_filter_ip_tos, &tos, sizeof(tos));
	DPRINTF("-DEBUG- fbc_filter_ip_add_tos_filter_func: add fbc_filter_filter_ip_tos into filter\n");
	return 1;
}

/*
 * 5. attribute map function
 */
fbc_add_func_into_filter_t fbc_ip_attribute_map(char *attr)
{
	int i = 0;
	while (1) {
		if (fbc_attribute_equal(fbc_ip_attribute[i].attribute, attr)) {
			return (fbc_ip_attribute[i].add_func_into_filter);
		}
		if (fbc_attribute_equal(fbc_ip_attribute[i].attribute, FBC_ATTRIBUTE_NULL)) {
			fprintf(stderr, "No attribute %s in protocol %s\n", attr, FBC_PROTOCOL_ETHER);
			return 0;
		}
		i++;
	}
	return 0;
	
}

