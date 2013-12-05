#ifndef	_FBC_PF_H_
#define	_FBC_PF_H_

#include "fbc_common.h"
#include "fbc_filter.h"

#define MAX_SIZE_IN_LINE 1024

#define FBC_LANG_FLAG_FILE 	'@'
#define FBC_LANG_FLAG_PROTOCOL 	'$'
#define FBC_LANG_FLAG_ATTRIBUTE '%'
#define FBC_LANG_FLAG_DESCRIPT 	'&'
#define FBC_LANG_FLAG_COMMENT 	'#'

#define string_arg_size(s)	(strlen(s) + 1)

typedef int (*fbc_add_func_into_filter_t)(fbc_Filter *filter, char *attr, char *value);
typedef fbc_add_func_into_filter_t (*fbc_attribute_map_t)(char *attr); 

struct fbc_protocol_map_list {
	protocol_t protocol;
	fbc_attribute_map_t attribute_map;
};

struct fbc_attribute_map_list {
	attribute_t attribute;
	fbc_add_func_into_filter_t add_func_into_filter;
};

fbc_Filter *fbc_read_pf_init_filter(const char *fileName);

#endif
