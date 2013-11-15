#ifndef _COMMON_H_
#define _COMMON_H_

typedef unsigned int FBC_DEF_PROTOCAL

#define FBC_DEF_ETHER	0x0101
#define FBC_DEF_IP	0x0201
#define FBC_DEF_IPV6	0x0202
#define

struct Frame {
	struct ether_header *header;
	Byte *playload; 
	Byte *tail; 
};

#endif

