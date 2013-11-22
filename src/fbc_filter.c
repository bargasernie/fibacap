#include "fbc_filter.h"

int fbc_filter_add_func(fbc_Filter *filter, fbc_filter_func_t func, fbc_filter_arg_t arg, int arg_size)
{
	if (filter->filter_count >= MAX_FILTER_FUNC_PER_PROTOCOL) {
		fprintf(stderr, "fbc_Filter is full, can not add more filter function\n");
		return FBC_FAILED;
	}

	filter->fbc_filter_func[filter->filter_count] = func;
	filter->fbc_filter_arg[filter->filter_count] = arg;
	filter->fbc_filter_arg_size[filter->filter_count] = arg_size;
	filter->filter_count++;
	DPRINTF("-DEBUG- fbc_filter_add_func:\tadd func into filter\n");
	return FBC_SUCCESS;
}

int fbc_filter_packet(fbc_Packet *packet, fbc_Filter *filter)
{
	int i, result;
	while (packet && filter) {
		if (fbc_protocol_equal(packet->protocol, filter->protocol)) {
			for (i = 0; i < filter->filter_count; i++) {
				result = (filter->fbc_filter_func[i])(
						packet, 
						filter->fbc_filter_arg[i], 
						filter->fbc_filter_arg_size[i]
					);
				DPRINTF1("-DEBUG- fbc_filter_packet: function return %d\n", result);
				if (result == FBC_FAILED) {
					DPRINTF("-DEBUG- fbc_filter_packet:\tfunc matched failed\n");
					return FBC_FAILED;
				}
			}
		} else {
			DPRINTF("-DEBUG- fbc_filter_packet:\tprotocols mismatched\n");
			return FBC_FAILED;
		}
		packet = packet->next_packet;
		filter = filter->next_filter;
	}

	/* all matched */
	if (! filter) {
		DPRINTF("-DEBUG- fbc_filter_packet:\tmatched\n");
		return FBC_SUCCESS;
	}

	DPRINTF("-DEBUG- fbc_filter_packet:\tunmatched filter left, failed\n");
	return FBC_FAILED;
}

fbc_Filter *fbc_alloc_filter()
{
	fbc_Filter *filter = (fbc_Filter *)malloc(sizeof(fbc_Filter));
	if (! filter) {
		fprintf(stderr, "Can not allocate memory to create fbc_Filter\n");
		return NULL;
	}
	filter->next_filter = NULL;
	filter->filter_count = 0;
	DPRINTF("-DEBUG- fbc_alloc_filter:\tallocate memory for filter\n");
	return filter;
}

void fbc_dealloc_filter(fbc_Filter *filter)
{
	DPRINTF("-DEBUG- fbc_dealloc_filter:\tfree filter\n");
	free(filter);
}

void fbc_filter_set_protocol(fbc_Filter *filter, protocol_t p)
{
	DPRINTF("-DEBUG- fbc_filter_set_protocol:\tset protocol to filter\n");
	fbc_set_protocol(filter->protocol, p);
}

void fbc_destroy_filter(fbc_Filter *filter)
{
	DPRINTF("-DEBUG- fbc_destroy_filter:\tdestroy filter\n");
	if (filter) {
		fbc_destroy_filter(filter->next_filter);
		fbc_dealloc_filter(filter);
	}
}
