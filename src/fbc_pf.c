
#include <stdio.h>
#include "fbc_common.h"
#include "fbc_pf.h"

#define is_blank(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')

char *fbc_first_not_blank(char *s) {
	while (*s == ' ' || *s == '\t' || '\n') 
		s++;
	return s;
}

void fbc_cut_tail_blank(char *s) {
	int len = strlen(s);
	char *t = s + len;
	do {
		--t;
		if (is_blank(*t)) {
			*t = '\0';
		}
	} while (t != s);
}

fbc_Filter *fbc_read_pf_init_filter(const char *filename)
{
	FILE *pf = NULL;
	size_t len;
	ssize_t read = 0;
	char *line = 0;
	char *s;
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
		printf("%s", line);
		s = fbc_first_not_blank(line);
		fbc_cut_tail_blank(s);
		switch (*s) {
			case '\0':
				break;
			case '#':
				break;
			case '@':
				break;
			case '$':
				filter->next_filter = fbc_alloc_filter();
				if (! filter->next_filter)	fbc_destroy_filter(extra_filter);
				filter = filter->next_filter;
				fbc_set_protocol(filter->protocol, s);
				break;
			case '%':
				break;
			default:
				break;
		}
		
	}

	DPRINTF1("-DEBUG- fbc_read_pf_init_filter: close %s\n", filename);

	free(line);
	fclose(pf);

	return filter;
}
