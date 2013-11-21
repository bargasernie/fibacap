#ifndef	_FBC_ADDRESS_H_
#define	_FBC_ADDRESS_H_

#include <net/ethernet.h>
#include <arpa/inet.h>

#include "fbc_common.h"

const char *fbc_ether_addr_to_string(const struct ether_addr *enaddr, char *addr_string, int max_size);

const char *fbc_ip_addr_to_string(const void *src, char *addr_string, int max_size);

const char *fbc_get_addr_string(protocol_t p, Byte *addr, int len, char *addrstring);

const char *fbc_get_hex_string(Byte *addr, int len, char *addrstring);

#endif
