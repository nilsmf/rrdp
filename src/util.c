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
#include <fcntl.h>

#include "util.h"
#include "file_util.h"

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
		printf("failed to b64 decode\n");
		printf("%s\n", src);
		return -1;
	}
	return b64sz;
}

/* TODO stolen from rpki atm */
enum rtype {
	RTYPE_EOF = 0,
	RTYPE_TAL,
	RTYPE_MFT,
	RTYPE_ROA,
	RTYPE_CER,
	RTYPE_CRL
};

/* TODO stolen from rpki atm */
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
		warnx("%s: not using %s schema", uri, proto);
		return 0;
	}

	/* Parse the non-zero-length hostname. */

	host = uri + strlen(proto);

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

	if (!uri || !base_path)
		err(1, "tried to write to defunct publish uri");
	if (rsync_uri_parse(&host, &hostsz,
			    NULL, NULL,
			    NULL, NULL,
			    NULL, uri, proto) == 0)
		err(1, "parse uri elem fail");

	if (asprintf(&filename, "%s/%.*s", base_path,
	    (int)hostsz, host) == -1)
		err(1, "asprintf");

	return filename;
}

static const char *
fetch_filename_from_uri(const char *uri, const char *proto)
{
	const char *module;
	size_t modulesz;

	if (!uri)
		err(1, "tried to write to defunct publish uri");
	if (rsync_uri_parse(NULL, NULL,
			    &module, &modulesz,
			    NULL, NULL,
			    NULL, uri, proto) == 0)
		err(1, "parse uri elem fail");

	return module;
}

static FILE *
open_uri(char *uri, char *dir_name, int dir, int write) {
	const char *filename;
	char *path_delim;
	int fd;
	int fd_flags = O_RDONLY;
	char * open_flags = "r";
	FILE *f;

	filename = fetch_filename_from_uri(uri, NULL);
	if (write) {
		if ((path_delim = strrchr(filename, '/'))) {
			/* XXX NF better way to do this directory sep? */
			path_delim[0] = '\0';
			if (mkpath_at(dir, filename, USR_RWX_MODE) != 0) {
				return NULL;
			}
			path_delim[0] = '/';
		}
		fd_flags = O_WRONLY|O_CREAT|O_TRUNC;
		open_flags = "w";
	}
	fd = openat(dir, filename, fd_flags, USR_RW_MODE);
	if (fd < 0 || !(f = fdopen(fd, open_flags)))
		return NULL;
	return f;
}

FILE *
open_primary_uri_read(char *uri, struct opts *opts) {
	return open_uri(uri, opts->basedir_primary, opts->primary_dir, 0);
}

FILE *
open_working_uri_read(char *uri, struct opts *opts) {
	return open_uri(uri, opts->basedir_working, opts->working_dir, 0);
}

FILE *
open_working_uri_write(char *uri, struct opts *opts) {
	return open_uri(uri, opts->basedir_working, opts->working_dir, 1);
}

void
free_workdir(struct opts *opts) {
	free(opts->basedir_working);
	close(opts->working_dir);
}
void
make_workdir(const char *basedir, struct opts *opts)
{
	char *tmpl;

	if (asprintf(&tmpl, "%s.XXXXXXXX", basedir) == -1)
		err(1, "%s", __func__);
	if (mkdtemp(tmpl) == NULL)
		err(1, "mkdtemp");
	opts->basedir_working = tmpl;
	opts->working_dir = open(opts->basedir_working, O_RDONLY|O_DIRECTORY);
	if (opts->working_dir < 0)
		err(1, "open");
}
