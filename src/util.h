#ifndef _UTILH_
#define _UTILH_
#include <stdlib.h>

typedef struct Opts {
	const char *basedir_primary;
	const char *basedir_working;
} OPTS;
OPTS *getopts(int argc, char **argv);
void cleanopts(OPTS *o);

int strip_non_b64(const char * str, int len, char *out);

int mkpath(char *dir, mode_t mode);

char *generate_filename_from_uri(const char *uri, const char *base_path);

#endif

