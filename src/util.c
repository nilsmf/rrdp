/*
 * Copyright (c) 2020 Nils Fisher <nils_fisher@hotmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <resolv.h>

#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include "util.h"

static struct opts *
newOpt(const char *basedir_primary, const char *basedir_working)
{
	if (!(basedir_primary || basedir_working)) {
		printf("basedir not set\n");
		return NULL;
	}
	if (!strcmp(basedir_primary, basedir_working)) {
		printf("working and primary directories are the same\n");
		return NULL;
	}
	struct opts *o = malloc(sizeof(struct opts));
	o->basedir_primary = basedir_primary;
	o->basedir_working = basedir_working;
	return o;
}

struct opts *
buildopts(int argc, char **argv)
{
	int opt;
	char *primary = NULL;
	char *working = NULL;
	while ((opt = getopt(argc, argv, ":p:w:")) != -1) {
		switch(opt) {
		case 'p':
			primary = optarg;
			break;
		case 'w':
			working = optarg;
			break;
		case ':':
			printf("missing argument\n");
			return NULL;
		case '?':
			printf("unknown option: %c\n", optopt);
		}
	}
	return newOpt(primary, working);
}

void
cleanopts(struct opts *o)
{
	free(o);
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

int b64_decode(char *src, unsigned char **b64) {
	size_t sz;
	int b64sz;

	if (!src || !b64)
		return -1;

	sz = ((strlen(src) + 3) / 4) * 3 + 1;
	if ((*b64 = malloc(sz)) == NULL)
		err(1, NULL);
	if ((b64sz = b64_pton(src, *b64, sz)) < 0) {
		free(*b64);
		*b64 = NULL;
		printf("failed to b64 decode");
		return -1;
	}
	return b64sz;
}

//TODO stolen from rpki atm
static int
rsync_uri_parse(const char **hostp, size_t *hostsz,
    const char **modulep, size_t *modulesz,
    const char **pathp, size_t *pathsz,
    enum rtype *rtypep, const char *uri, const char *proto)
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
	if (proto == NULL)
		proto = "rsync://";

	/* Case-insensitive rsync URI. */

	if (strncasecmp(uri, proto, strlen(proto))) {
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

char *
generate_basepath_from_uri(const char *uri, const char *base_path,
    const char *proto)
{
	const char *host;
	size_t hostsz;
	char *filename;

	if (!uri || !base_path) {
		err(1, "tried to write to defunct publish uri");
	}
	if (rsync_uri_parse(&host, &hostsz,
			    NULL, NULL,
			    NULL, NULL,
			    NULL, uri, proto) == 0) {
		err(1, "parse uri elem fail");
	}

	if (asprintf(&filename, "%s/%.*s/", base_path,
	    (int)hostsz, host) == -1)
		err(1, "asprintf");

	return filename;
}

char *
generate_filename_from_uri(const char *uri, const char *base_path,
    const char *proto)
{
	const char *path;
	size_t pathsz;
	const char *host;
	size_t hostsz;
	char *filename;

	if (!uri || !base_path) {
		err(1, "tried to write to defunct publish uri");
	}
	if (rsync_uri_parse(&host, &hostsz,
			    NULL, NULL,
			    &path, &pathsz,
			    NULL, uri, proto) == 0) {
		err(1, "parse uri elem fail");
	}

	if (asprintf(&filename, "%s/%.*s/%.*s", base_path,
	    (int)hostsz, host, (int)pathsz, path) == -1)
		err(1, "asprintf");

	return filename;
}

