#ifndef _FBC_COMMON_H_
#define _FBC_COMMON_H_

#define	FBC_DEBUG
#ifdef	FBC_DEBUG
	#define	DPRINTF(fmt)			printf(fmt)
	#define	DPRINTF1(fmt, a)		printf(fmt, (a))
	#define	DPRINTF2(fmt, a, b)		printf(fmt, (a), (b))
	#define	DPRINTF3(fmt, a, b, c)		printf(fmt, (a), (b), (c))
	#define	DPRINTF4(fmt, a, b, c, d)	printf(fmt, (a), (b), (c), (d))
#else
	#define	DPRINTF(fmt)
	#define	DPRINTF1(fmt, a)
	#define	DPRINTF2(fmt, a, b)
	#define	DPRINTF3(fmt, a, b, c)
	#define	DPRINTF4(fmt, a, b, c, d)
#endif

typedef unsigned char Byte;
typedef char (protocol_t)[16];
typedef char (attribute_t)[16];

#define FBC_ATTRIBUTE_NULL	""
#include <string.h>
#define fbc_attribute_equal(a, b)	(strcmp((a), (b)) == 0)

typedef unsigned int FBC_DEF_PROTOCOL;

#define FBC_PROTOCOL_ETHER	"ETHER"

#define FBC_PROTOCOL_IP		"IP"
#define FBC_PROTOCOL_ARP	"ARP"
#define FBC_PROTOCOL_PUP	"PUP"
#define FBC_PROTOCOL_SPRITE	"SPRITE"
#define FBC_PROTOCOL_REVARP	"REVARP"
#define FBC_PROTOCOL_AT		"AT"
#define FBC_PROTOCOL_AARP	"AARP"
#define FBC_PROTOCOL_VLAN	"VLAN"
#define FBC_PROTOCOL_IPX	"IPX"
#define FBC_PROTOCOL_LOOPBACK	"LOOPBACK"
#define FBC_PROTOCOL_UNKNOWN	"UNKNOWN"
#define FBC_PROTOCOL_IPV6	"IPV6"

#define FBC_PROTOCOL_TCP	"TCP"
#define FBC_PROTOCOL_UDP	"UDP"
#define FBC_PROTOCOL_ICMP	"ICMP"

#define FBC_PROTOCOL_NULL	""
#define FBC_PROTOCOL_UNKNOWN	"UNKNOWN"

#endif

