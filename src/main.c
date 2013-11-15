#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "analysis.h"

void print_byte(Byte byte) {
	int c = 8;
	while (c--) {
		printf("%c", (byte >> c & 0x01) ? '1' : '0');
	}
	printf(" ");
}

void print_hex(Byte byte) {
	int n = ((byte >> 4) & 0x0f);
	if (n < 10) {
		printf("%c", n + '0');
	} else {
		printf("%c", n - 10 + 'A');
	}
	n = (byte & 0x0f);
	if (n < 10) {
		printf("%c", n + '0');
	} else {
		printf("%c", n - 10 + 'A');
	}
	printf(" ");
}

void print_char(Byte byte) {
	if ('a' <= byte && byte <= 'z') {
		printf("%c", byte);
	} else {
		printf(".");
	}
}


void print_raw(Byte const *buf, int length)
{
	int i = 0;

	/*
	i = 0;
	while (i < length) {
		print_byte(buf[i++]);
		if (! (i % 4)) {
			printf("\n");
		}
	}
	printf("\n\n");
	*/

	i = 0;
	while (i < length) {
		print_hex(buf[i++]);
		if (! (i % 4)) {
			printf("\n");
		}
	}
	printf("\n\n");

	i = 0;
	while (i < length) {
		print_char(buf[i++]);
		if (! (i % 4)) {
			printf("\n");
		}
	}
	printf("\n\n");
}

int main()
{
	int s;
	Byte buf[1600];
	int nbytes;
	struct Frame *frame = 0;


	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s <= 0) {
		fprintf(stderr, "Can not create socket!\n");
		return -1;
	}

	while (1) {

		nbytes = recv(s, buf, sizeof(buf), 0);

		if (nbytes) {
			printf("Get packet, %dbytes\n", nbytes);

			frame = analyzer(buf, nbytes);

			frame_print(stdout, "", frame);

			frame_free(frame);
		} else {
			printf("Get no packet\n");
		}
	}

	return 0;
}

