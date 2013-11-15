#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include "analysis.h"
#include "ether_analysis.h"


struct Frame *analyzer(Byte *buf, int len) 
{
	return ether_analyzer(buf, len);
}

void frame_free(struct Frame *frame)
{
	free(frame);
}


void frame_print(FILE *out, const char *pre, const struct Frame *frame)
{
	ether_header_print(out, pre, frame->header);
	/* network_layer_print(frame->playload); */
}
