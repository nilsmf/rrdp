#include <stdlib.h>

int strip_non_b64(const char * str, int len, char *out);

int mkpath(char *dir, mode_t mode);

char *generate_filename_from_uri(const char *uri, const char *base_path);

