#ifndef	_FBC_FILTER_H_
#define	_FBC_FILTER_H_

#include "fbc_packet.h"

typedef void * fbc_filter_arg_t;

typedef int (*fbc_filter_func_t)(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size);

#define MAX_FILTER_FUNC_PER_PROTOCOL 16

#define FBC_FAILED 	0
#define FBC_SUCCESS 	1

typedef struct fbc_Filter {
	protocol_t protocol;
	fbc_filter_func_t 	fbc_filter_func[MAX_FILTER_FUNC_PER_PROTOCOL];
	fbc_filter_arg_t 	fbc_filter_arg[MAX_FILTER_FUNC_PER_PROTOCOL];
	int 			fbc_filter_arg_size[MAX_FILTER_FUNC_PER_PROTOCOL];
	int 			filter_count;
	struct fbc_Filter *	next_filter;
} fbc_Filter;

fbc_Filter *fbc_alloc_filter();
int fbc_filter_add_func(fbc_Filter *fiter, fbc_filter_func_t func, fbc_filter_arg_t arg, int arg_size);
void fbc_filter_set_protocol(fbc_Filter *fiter, protocol_t p);
int fbc_filter_packet(fbc_Packet *packet, fbc_Filter *filter);

#endif
