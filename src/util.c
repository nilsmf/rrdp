#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <err.h>
#include <errno.h>

#include <sys/stat.h>
#include <libgen.h>

#include <src/util.h>

OPTS *newOpt(const char *basedir_primary,
	     const char *basedir_working) {
	OPTS *o = malloc(sizeof(OPTS));
	o->basedir_primary = basedir_primary;
	o->basedir_working = basedir_working;
	return o;
}

OPTS *getopts(int argc, char **argv) {
	return newOpt("/tmp/rrdp", "/tmp/rrdp_working");
}

void cleanopts(OPTS *o) {
	free(o);
}


// Truncate non base64 chars
int strip_non_b64(const char * str, int len, char *out) {
	char c;
	int i;
	int offset = 0;
	if (!out || !str) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		c = str[i];
		if (c == '+' || c == '/' || c == '=' || c == '\0' ||
		    (c >= '0' && c <= '9') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z')) {
			out[i - offset] = c;
			if (c == '\0') {
				break;
			}
		} else {
			offset++;
		}
	}
	return i - offset;
}

int mkpath(char *dir, mode_t mode)
{
	struct stat sb;

	if (!dir) {
		errno = EINVAL;
		return 1;
	}
	if (!stat(dir, &sb))
		return 0;

	char *newdir;
	mkpath(dirname(newdir = strdup(dir)), mode);
	int ret = mkdir(newdir, mode);
	free(newdir);
	return ret;
}

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
    enum rtype *rtypep, const char *uri)
{
	const char	*host, *module, *path;
	size_t		 sz;

	/* Initialise all output values to NULL or 0. */

	if (hostsz != NULL)
		*hostsz = 0;
	if (modulesz != NULL)
		*modulesz = 0;
	if (pathsz != NULL)
		*pathsz = 0;
	if (hostp != NULL)
		*hostp = 0;
	if (modulep != NULL)
		*modulep = 0;
	if (pathp != NULL)
		*pathp = 0;
	if (rtypep != NULL)
		*rtypep = RTYPE_EOF;

	/* Case-insensitive rsync URI. */

	if (strncasecmp(uri, "rsync://", 8)) {
		warnx("%s: not using rsync schema", uri);
		return 0;
	}

	/* Parse the non-zero-length hostname. */

	host = uri + 8;

	if ((module = strchr(host, '/')) == NULL) {
		warnx("%s: missing rsync module", uri);
		return 0;
	} else if (module == host) {
		warnx("%s: zero-length rsync host", uri);
		return 0;
	}

	if (hostp != NULL)
		*hostp = host;
	if (hostsz != NULL)
		*hostsz = module - host;

	/* The non-zero-length module follows the hostname. */

	if (module[1] == '\0') {
		warnx("%s: zero-length rsync module", uri);
		return 0;
	}

	module++;

	/* The path component is optional. */

	if ((path = strchr(module, '/')) == NULL) {
		assert(*module != '\0');
		if (modulep != NULL)
			*modulep = module;
		if (modulesz != NULL)
			*modulesz = strlen(module);
		return 1;
	} else if (path == module) {
		warnx("%s: zero-length module", uri);
		return 0;
	}

	if (modulep != NULL)
		*modulep = module;
	if (modulesz != NULL)
		*modulesz = path - module;

	path++;
	sz = strlen(path);

	if (pathp != NULL)
		*pathp = path;
	if (pathsz != NULL)
		*pathsz = sz;

	if (rtypep != NULL && sz > 4) {
		if (strcasecmp(path + sz - 4, ".roa") == 0)
			*rtypep = RTYPE_ROA;
		else if (strcasecmp(path + sz - 4, ".mft") == 0)
			*rtypep = RTYPE_MFT;
		else if (strcasecmp(path + sz - 4, ".cer") == 0)
			*rtypep = RTYPE_CER;
		else if (strcasecmp(path + sz - 4, ".crl") == 0)
			*rtypep = RTYPE_CRL;
	}

	return 1;
}
char *generate_filename_from_uri(const char *uri, const char *base_path) {
	if (!uri || !base_path) {
		err(1, "tried to write to defunct publish uri");
	}
	int BUFF_SIZE=4096;
	const char *path;
	size_t pathsz;
	const char *host;
	size_t hostsz;
	char *filename = malloc(sizeof(char)*(BUFF_SIZE*2 + strlen(base_path)));

	if (rsync_uri_parse(&host, &hostsz,
			    NULL, NULL,
			    &path, &pathsz,
			    NULL, uri) == 0) {
		err(1, "parse uri elem fail");
	}

	sprintf(filename, "%s/%.*s/%.*s", base_path, (int)hostsz, host, (int)pathsz, path);

	return filename;
}
