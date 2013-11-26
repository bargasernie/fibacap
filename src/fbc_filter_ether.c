#include <netinet/ether.h>
#include "fbc_filter_ether.h"
#include "fbc_pf.h"

int fbc_filter_ether_add_src_filter_func(fbc_Filter *filter, char *attr, char *value);

static struct fbc_attribute_map_list fbc_ether_attribute[32] = {
	{ "src", fbc_filter_ether_add_src_filter_func },
	{ "dst", 0 },
	{ FBC_ATTRIBUTE_NULL, 0, }
};

int fbc_filter_ether_srcaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *srcaddr = (Byte *)(((struct ether_header *)packet->header)->ether_shost);
	DPRINTF("-DEBUG- fbc_filter_ether_srcaddr:\tmatching ether srcaddr\n");
	return (memcmp(srcaddr, arg, arg_size) == 0);
}

int fbc_filter_ether_dstaddr(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	void *dstaddr = (Byte *)(((struct ether_header *)packet->header)->ether_dhost);
	DPRINTF("-DEBUG- fbc_filter_ether_dstaddr:\tmatching ether dstaddr\n");
	return (memcmp(dstaddr, arg, arg_size) == 0);
}

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

int fbc_filter_ether_add_src_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	DPRINTF2("-DEBUG- fbc_filter_ether_add_src_filter_func: <%s>=<%s>\n", attr, value);
	return 1;
}
