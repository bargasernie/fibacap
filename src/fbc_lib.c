#include "fbc_lib.h"

unsigned int string_to_uint(char *s)
{
	unsigned int uint = 0;
	unsigned int next = 0;

	/* heximal */
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		s += 2;
		do {
			if (*s >= '0' && *s <= '9') {
				next = *s - '0';
			} else if (*s >= 'a' && *s <= 'f') {
				next = *s - 'a' + 10;
			} else if (*s >= 'A' && *s <= 'F') {
				next = *s - 'A' + 10;
			} else {
				break;
			}
			uint *= 16;
			uint += next;
			++s;
		} while (1);
	} else {	/* decimal */
		do {
			if (*s >= '0' && *s <= '9') {
				next = *s - '0';
			} else {
				break;
			}
			uint *= 10;
			uint += next;
			++s;
		} while (1);
	}

	return uint;
}

unsigned short checksum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--) {
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return (unsigned short)(~sum);
}
