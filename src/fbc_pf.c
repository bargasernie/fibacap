
#include <stdio.h>
#include "fbc_common.h"
#include "fbc_pf.h"

#define is_blank(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')
#define attribute_equal(a, b)	(strcmp((a), (b)) == 0)
#define value_equal(a, b)	(strcmp((a), (b)) == 0)
#define ATTRIBUTE_NULL	""
#define VALUE_NULL	""


/* include protocol filter header for protocol map */
#include "fbc_filter_ether.h"

static struct fbc_protocol_map_list protocol_map[128] = {
	{ FBC_PROTOCOL_ETHER, fbc_ether_attribute_map }, /* implement ether_attribute_map */
	{ FBC_PROTOCOL_IP, 0 },
	{ FBC_PROTOCOL_TCP, 0 },
	{ FBC_PROTOCOL_NULL, 0 }
};

char *fbc_first_not_blank(char *s) {
	while (is_blank(*s)) 
		s++;
	return s;
}

void fbc_cut_tail_blank(char *s) {
	int len = strlen(s);
	char *t = s + len;
	if (len == 0)	return;
	do {
		--t;
		if (is_blank(*t)) {
			*t = '\0';
		} else {
			break;
		}
	} while (t != s);
}

void fbc_fetch_attr_value(char *cond, char **attr, char **value)
{
	*attr = cond;
	while (!is_blank(*cond) && !(*cond == '=')) {
		++cond;
	}
	while (is_blank(*cond) || *cond == '=') {
		*cond = '\0';
		++cond;
	}
	*value = cond;
}

fbc_attribute_map_t get_protocol_attribute_map(protocol_t protocol)
{
	int i = 0;
	while (1) {
		if (fbc_protocol_equal(protocol_map[i].protocol, protocol)) {
			return protocol_map[i].attribute_map;
		}
		if (fbc_protocol_equal(protocol_map[i].protocol, FBC_PROTOCOL_NULL)) {
			fprintf(stderr, "No protocol attribute map for protocol %s\n", protocol);
			return 0;
		}
		i++;
	}
	return 0;
}

int fbc_pf_add_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	fbc_attribute_map_t protocol_attr_map = get_protocol_attribute_map(filter->protocol);
	if (! protocol_attr_map) {
		fprintf(stderr, "Can not get protocol map for protocol %s\n", filter->protocol);
		return 1;
	}
	fbc_add_func_into_filter_t add_func_p = (protocol_attr_map)(attr);
	if (! add_func_p) {
		fprintf(stderr, "Can not get protocol attribute filter function for protocol %s, attribute %s\n", filter->protocol, attr);
		return 1;
	}
	return (add_func_p)(filter, attr, value);
}

fbc_Filter *fbc_read_pf_init_filter(const char *filename)
{
	FILE *pf = NULL;
	size_t len;
	ssize_t read = 0;
	char *line = 0;
	char *s;
	char *attr, *value;
	fbc_Filter *filter = 0;
	fbc_Filter *extra_filter = 0;

	DPRINTF1("-DEBUG- fbc_read_pf_init_filter: try open %s\n", filename);
	pf = fopen(filename, "r");
	if (! pf) {
		fprintf(stderr, "Can not open packet filter file %s\n", filename);
		return NULL;
	}

	line = (char *)malloc(MAX_SIZE_IN_LINE);
	if (! line) {
		fprintf(stderr, "Can not allocate buffer in fbc_read_pf_init_filter");
		return NULL;
	}

	extra_filter = fbc_alloc_filter();
	if (! extra_filter) 	return NULL;
	filter = extra_filter;

	DPRINTF1("-DEBUG- fbc_read_pf_init_filter: open %s successfully\n", filename);
	while ((read = getline(&line, &len, pf)) != -1) {
		DPRINTF1("-DEBUG- fbc_read_pf_init_filter: read %s\n", line);
		s = fbc_first_not_blank(line);
		fbc_cut_tail_blank(s);
		switch (*s) {
			case '$':
				DPRINTF1("-DEBUG- fbc_read_pf_init_filter: read protocol %s\n", s);
				filter->next_filter = fbc_alloc_filter();
				if (! filter->next_filter)	fbc_destroy_filter(extra_filter);
				filter = filter->next_filter;
				fbc_set_protocol(filter->protocol, s+1);
				DPRINTF1("-DEBUG- fbc_read_pf_init_filter: analyze protocol <%s>\n", s + 1);
				break;
			case '%':
				DPRINTF1("-DEBUG- fbc_read_pf_init_filter: read attribute %s\n", s);
				fbc_fetch_attr_value(s + 1, &attr, &value);
				if (attribute_equal(attr, ATTRIBUTE_NULL)) {
					fprintf(stderr, "No attribute in protocol %s\n", filter->protocol);
					break;
				}

				if (value_equal(value, VALUE_NULL)) {
					fprintf(stderr, "No value in protocol %s, attribute %s\n", filter->protocol, attr);
					break;
				}
				DPRINTF2("-DEBUG- fbc_read_pf_init_filter: analyze <%s>=<%s>\n", attr, value);

				fbc_pf_add_filter_func(filter, attr, value);
				break;
			case '\0':
				break;
			case '#':
				break;
			case '@':
				break;
			default:
				DPRINTF1("-DEBUG- fbc_read_pf_init_filter: read unknown line: %s\n", s);
				break;
		}
		
	}

	DPRINTF1("-DEBUG- fbc_read_pf_init_filter: close %s\n", filename);

	free(line);
	fclose(pf);

	return filter;
}
