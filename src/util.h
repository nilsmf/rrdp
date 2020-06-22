#ifndef _UTILH_
#define _UTILH_

#define BASE10 10

typedef struct Opts {
	const char *basedir_primary;
	const char *basedir_working;
} OPTS;
OPTS *getopts(int argc, char **argv);
void cleanopts(OPTS *o);

int strip_non_b64(const char * str, int len, char *out);

int b64_decode(char *src, unsigned int src_len, unsigned char **b64);

char *generate_basepath_from_uri(const char *uri, const char *base_path, const char *proto);
char *generate_filename_from_uri(const char *uri, const char *base_path, const char *proto);

#endif

