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
int fbc_filter_ip_add_tlen_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_id_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_rf_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_df_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_mf_filter_func(fbc_Filter *filter, char *attr, char *value);
int fbc_filter_ip_add_fragoff_filter_func(fbc_Filter *filter, char *attr, char *value);

static struct fbc_attribute_map_list fbc_ip_attribute[32] = {
	{ "src", fbc_filter_ip_add_src_filter_func },
	{ "dst", fbc_filter_ip_add_dst_filter_func },
	{ "addr", fbc_filter_ip_add_addr_filter_func },
	{ "version", fbc_filter_ip_add_version_filter_func },
	{ "hl", fbc_filter_ip_add_hl_filter_func },
	{ "tos", fbc_filter_ip_add_tos_filter_func },
	{ "tlen", fbc_filter_ip_add_tlen_filter_func },
	{ "id", fbc_filter_ip_add_id_filter_func },
	{ "RF", fbc_filter_ip_add_rf_filter_func },
	{ "DF", fbc_filter_ip_add_df_filter_func },
	{ "fragoff", fbc_filter_ip_add_fragoff_filter_func },
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

/* fbc_filter_func_t */
int fbc_filter_ip_tlen(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t tlen = ((struct ip *)packet->header)->ip_len;
	DPRINTF("-DEBUG- fbc_filter_ip_tlen:\tmatching total length\n");
	return (tlen == *(u_int16_t *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_id(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t id = ((struct ip *)packet->header)->ip_id;
	DPRINTF("-DEBUG- fbc_filter_ip_id:\tmatching ip id\n");
	return (id == *(u_int16_t *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_rf(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t flags = ntohs(((struct ip *)packet->header)->ip_off);
	DPRINTF("-DEBUG- fbc_filter_ip_rf:\tmatching ip flags RF\n");
	return ((flags & IP_RF) == *(u_int16_t *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_df(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t flags = ntohs(((struct ip *)packet->header)->ip_off);
	DPRINTF("-DEBUG- fbc_filter_ip_df:\tmatching ip flags DF\n");
	DPRINTF2("-DEBUG- fbc_filter_ip_df:\tPacket DF: %d, Arg DF: %d\n", (flags & IP_DF), *(u_int16_t *)arg);

	return ((flags & IP_DF) == *(u_int16_t *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_mf(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t flags = ntohs(((struct ip *)packet->header)->ip_off);
	DPRINTF("-DEBUG- fbc_filter_ip_mf:\tmatching ip flags MF\n");
	return ((flags & IP_MF) == *(u_int16_t *)arg);
}

/* fbc_filter_func_t */
int fbc_filter_ip_fragoff(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	u_int16_t fragoff = ntohs(((struct ip *)packet->header)->ip_off);
	DPRINTF("-DEBUG- fbc_filter_ip_mf:\tmatching ip fragment offset\n");
	return ((fragoff & IP_OFFMASK) == *(u_int16_t *)arg);
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
	DPRINTF2("-DEBUG- fbc_filter_ip_add_tos_filter_func: <%s>=<%s>\n", attr, value);
	tos = (Byte)(string_to_uint(value) & 0xff);
	fbc_filter_add_func(filter, fbc_filter_ip_tos, &tos, sizeof(tos));
	DPRINTF("-DEBUG- fbc_filter_ip_add_tos_filter_func: add fbc_filter_filter_ip_tos into filter\n");
	return 1;
}

int fbc_filter_ip_add_tlen_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t tlen;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_tlen_filter_func: <%s>=<%s>\n", attr, value);
	tlen = htons((u_int16_t)string_to_uint(value));
	fbc_filter_add_func(filter, fbc_filter_ip_tlen, &tlen, sizeof(tlen));
	DPRINTF("-DEBUG- fbc_filter_ip_add_tlen_filter_func: add fbc_filter_filter_ip_tlen into filter\n");
	return 1;
}

int fbc_filter_ip_add_id_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t id;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_id_filter_func: <%s>=<%s>\n", attr, value);
	id = htons((u_int16_t)string_to_uint(value));
	fbc_filter_add_func(filter, fbc_filter_ip_id, &id, sizeof(id));
	DPRINTF("-DEBUG- fbc_filter_ip_add_id_filter_func: add fbc_filter_filter_ip_id into filter\n");
	return 1;
}

int fbc_filter_ip_add_rf_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t rf;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_rf_filter_func: <%s>=<%s>\n", attr, value);
	rf = (u_int16_t)(string_to_uint(value) & 0xffff);

	if (rf == 1) {
		rf = IP_RF;
	} else if (rf == 0) {
		rf = 0;
	} else {
		DPRINTF("-DEBUG- fbc_filter_ip_add_rf_func: ip RF is not 1 or 0, set to default 0\n");
		rf = 0;
	}

	fbc_filter_add_func(filter, fbc_filter_ip_rf, &rf, sizeof(rf));
	DPRINTF("-DEBUG- fbc_filter_ip_add_rf_filter_func: add fbc_filter_filter_ip_rf into filter\n");
	return 1;
}

int fbc_filter_ip_add_df_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t df;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_df_filter_func: <%s>=<%s>\n", attr, value);
	df = (u_int16_t)(string_to_uint(value) & 0xffff);

	if (df == 1) {
		df = IP_DF;
	} else if (df == 0) {
		df = 0;
	} else {
		DPRINTF("-DEBUG- fbc_filter_ip_add_df_func: ip DF is not 1 or 0, set to default 0\n");
		df = 0;
	}

	fbc_filter_add_func(filter, fbc_filter_ip_df, &df, sizeof(df));
	DPRINTF("-DEBUG- fbc_filter_ip_add_df_filter_func: add fbc_filter_filter_ip_df into filter\n");
	return 1;
}

int fbc_filter_ip_add_mf_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t mf;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_mf_filter_func: <%s>=<%s>\n", attr, value);
	mf = (u_int16_t)(string_to_uint(value) & 0xffff);

	if (mf == 1) {
		mf = IP_MF;
	} else if (mf == 0) {
		mf = 0;
	} else {
		DPRINTF("-DEBUG- fbc_filter_ip_add_mf_func: ip MF is not 1 or 0, set to default 0\n");
		mf = 0;
	}

	fbc_filter_add_func(filter, fbc_filter_ip_mf, &mf, sizeof(mf));
	DPRINTF("-DEBUG- fbc_filter_ip_add_mf_filter_func: add fbc_filter_filter_ip_mf into filter\n");
	return 1;
}

int fbc_filter_ip_add_fragoff_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	u_int16_t fragoff;
	DPRINTF2("-DEBUG- fbc_filter_ip_add_id_filter_func: <%s>=<%s>\n", attr, value);
	fragoff = (u_int16_t)string_to_uint(value) & 0xffff;
	fbc_filter_add_func(filter, fbc_filter_ip_fragoff, &fragoff, sizeof(fragoff));
	DPRINTF("-DEBUG- fbc_filter_ip_add_fragoff_filter_func: add fbc_filter_filter_ip_fragoff into filter\n");
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

