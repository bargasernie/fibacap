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
	return FBC_SUCCESS;
}

int fbc_filter_packet(fbc_Packet *packet, fbc_Filter *filter)
{
	int i, result;
	while (packet || filter) {
		if (fbc_protocol_equal(packet->protocol, filter->protocol)) {
			for (i = 0; i < filter->filter_count; i++) {
				result = (filter->fbc_filter_func[i])(
						packet, 
						filter->fbc_filter_arg[i], 
						filter->fbc_filter_arg_size[i]
					);
				if (result == FBC_FAILED)	return FBC_FAILED;
			}
		} else {
			return FBC_FAILED;
		}
		packet = packet->next_packet;
		filter = filter->next_filter;
	}

	/* all matched */
	if (! filter)	return FBC_SUCCESS;

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
	return filter;
}

void fbc_filter_set_protocol(fbc_Filter *filter, protocol_t p)
{
	fbc_set_protocol(filter->protocol, p);
}
