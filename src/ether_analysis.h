#ifndef _ETHER_ANALYSIS_
#define _ETHER_ANALYSIS_

#include "analysis.h"

struct Frame *ether_analyzer(Byte *buf, int len);
void ether_header_print(FILE *out, const char *pre, struct ether_header *header);

#endif
