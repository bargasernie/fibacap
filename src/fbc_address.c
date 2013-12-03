#include <stdio.h>
#include "fbc_address.h"
#include "fbc_packet.h"

const char *fbc_ether_addr_to_string(const struct ether_addr *enaddr, char *addr_string, int max_size)
{
	sprintf(addr_string, "%02x:%02x:%02x:%02x:%02x:%02x", 
			enaddr->ether_addr_octet[0], enaddr->ether_addr_octet[1],
			enaddr->ether_addr_octet[2], enaddr->ether_addr_octet[3],
			enaddr->ether_addr_octet[4], enaddr->ether_addr_octet[5]);
	return addr_string;
}

const char *fbc_ip_addr_to_string(const void *src, char *addr_string, int max_size)
{
	return inet_ntop(AF_INET, src, addr_string, max_size);
}

const char *fbc_get_addr_string(protocol_t p, Byte *addr, int len, char *addrstring) {
	if (!p || !addr || !addrstring)		return NULL;

	if (fbc_protocol_equal(p, FBC_PROTOCOL_ETHER)) {
		return fbc_ether_addr_to_string((const struct ether_addr *)addr, addrstring, len);
	}

	if (fbc_protocol_equal(p, FBC_PROTOCOL_IP)) {
		return fbc_ip_addr_to_string((const void *)addr, addrstring, len);
	}

	return "";
}

const char *fbc_get_hex_string(Byte *buf, int len, char *hexstring)
{
	char *t = hexstring;
	while (len--) {
		sprintf(t, "%02x", (*buf++ & 0xff));
		t += 2;
	}
	return hexstring;
}

void fbc_ether_addr_pton(const char *addr, Byte *dst, int size)
{
#define char_to_hex(c)							\
	(((c) >= '0' && (c) <= '9')	? ((c) - '0') 		: 	\
	 ((c) >= 'A' && (c) <= 'Z') 	? ((c) - 'A' + 10) 	: 	\
					  ((c) - 'a' + 10) )
	
	dst[0] = (Byte)((char_to_hex(addr[0]) * 16 + char_to_hex(addr[1])) & 0xff);
	dst[1] = (Byte)((char_to_hex(addr[3]) * 16 + char_to_hex(addr[4])) & 0xff);
	dst[2] = (Byte)((char_to_hex(addr[6]) * 16 + char_to_hex(addr[7])) & 0xff);
	dst[3] = (Byte)((char_to_hex(addr[9]) * 16 + char_to_hex(addr[10])) & 0xff);
	dst[4] = (Byte)((char_to_hex(addr[12]) * 16 + char_to_hex(addr[13])) & 0xff);
	dst[5] = (Byte)((char_to_hex(addr[15]) * 16 + char_to_hex(addr[16])) & 0xff);
}

void fbc_ip_addr_pton(const char *addr, Byte *dst, int size)
{
	inet_pton(AF_INET, addr, dst);
}
