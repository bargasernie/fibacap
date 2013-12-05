#include "fbc_checksum.h"
#include "fbc_lib.h"

unsigned short get_ip_checksum(Byte *header, int hlen)
{
	return checksum((unsigned short *)header, hlen >> 1);
}
