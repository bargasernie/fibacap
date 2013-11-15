#ifndef	_ANALYSIS_H_
#define	_ANALYSIS_H_

#include <net/ethernet.h>

typedef unsigned char Byte;


struct Frame *analyzer(Byte *buf, int len);
void	      frame_free(struct Frame *frame);

void frame_print(FILE *out, const char *pre, const struct Frame *frame); 

#endif
