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
