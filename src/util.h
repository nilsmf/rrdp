#include <stdlib.h>

int strip_non_b64(const char * str, int len, char *out);

int mkpath(char *dir, mode_t mode);

//TODO stolen from rpki atm
enum rtype {
	RTYPE_EOF = 0,
	RTYPE_TAL,
	RTYPE_MFT,
	RTYPE_ROA,
	RTYPE_CER,
	RTYPE_CRL
};

//TODO stolen from rpki atm
int rsync_uri_parse(const char **hostp, size_t *hostsz,
    const char **modulep, size_t *modulesz,
    const char **pathp, size_t *pathsz,
    enum rtype *rtypep, const char *uri);

