#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include <src/util.h>

OPTS *newOpt(const char *basedir_primary,
	     const char *basedir_working) {
	if (!(basedir_primary || basedir_working)) {
		printf("basedir not set\n");
		return NULL;
	}
	if (!strcmp(basedir_primary, basedir_working)) {
		printf("working and primary directories are the same\n");
		return NULL;
	}
	OPTS *o = malloc(sizeof(OPTS));
	o->basedir_primary = basedir_primary;
	o->basedir_working = basedir_working;
	return o;
}

OPTS *buildopts(int argc, char **argv) {
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

void cleanopts(OPTS *o) {
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

//TODO stolen from openbsd libc/net
#define u_char unsigned char
static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';
int b64_pton(char const *src, unsigned char *target, size_t targsize) {
	int tarindex, state, ch;
	u_char nextbyte;
	char *pos;

	state = 0;
	tarindex = 0;

	while ((ch = (unsigned char)*src++) != '\0') {
		if (isspace(ch))	/* Skip whitespace anywhere. */
			continue;

		if (ch == Pad64)
			break;

		pos = strchr(Base64, ch);
		if (pos == 0) 		/* A non-base64 character. */
			return (-1);

		switch (state) {
		case 0:
			if (target) {
				if (tarindex >= targsize)
					return (-1);
				target[tarindex] = (pos - Base64) << 2;
			}
			state = 1;
			break;
		case 1:
			if (target) {
				if (tarindex >= targsize)
					return (-1);
				target[tarindex]   |=  (pos - Base64) >> 4;
				nextbyte = ((pos - Base64) & 0x0f) << 4;
				if (tarindex + 1 < targsize)
					target[tarindex+1] = nextbyte;
				else if (nextbyte)
					return (-1);
			}
			tarindex++;
			state = 2;
			break;
		case 2:
			if (target) {
				if (tarindex >= targsize)
					return (-1);
				target[tarindex]   |=  (pos - Base64) >> 2;
				nextbyte = ((pos - Base64) & 0x03) << 6;
				if (tarindex + 1 < targsize)
					target[tarindex+1] = nextbyte;
				else if (nextbyte)
					return (-1);
			}
			tarindex++;
			state = 3;
			break;
		case 3:
			if (target) {
				if (tarindex >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base64);
			}
			tarindex++;
			state = 0;
			break;
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) {			/* We got a pad char. */
		ch = (unsigned char)*src++;	/* Skip it, get next. */
		switch (state) {
		case 0:		/* Invalid = in first position */
		case 1:		/* Invalid = in second position */
			return (-1);

		case 2:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for (; ch != '\0'; ch = (unsigned char)*src++)
				if (!isspace(ch))
					break;
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64)
				return (-1);
			ch = (unsigned char)*src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for (; ch != '\0'; ch = (unsigned char)*src++)
				if (!isspace(ch))
					return (-1);

			/*
			 * Now make sure for cases 2 and 3 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (target && tarindex < targsize &&
			    target[tarindex] != 0)
				return (-1);
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}

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
int rsync_uri_parse(const char **hostp, size_t *hostsz,
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

char *generate_basepath_from_uri(const char *uri, const char *base_path, const char *proto) {
	if (!uri || !base_path) {
		err(1, "tried to write to defunct publish uri");
	}
	int BUFF_SIZE=4096;
	const char *host;
	size_t hostsz;
	char *filename = malloc(sizeof(char)*(BUFF_SIZE*2 + strlen(base_path)));

	if (rsync_uri_parse(&host, &hostsz,
			    NULL, NULL,
			    NULL, NULL,
			    NULL, uri, proto) == 0) {
		err(1, "parse uri elem fail");
	}

	sprintf(filename, "%s/%.*s/", base_path, (int)hostsz, host);

	return filename;
}
char *generate_filename_from_uri(const char *uri, const char *base_path, const char *proto) {
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
			    NULL, uri, proto) == 0) {
		err(1, "parse uri elem fail");
	}

	sprintf(filename, "%s/%.*s/%.*s", base_path, (int)hostsz, host, (int)pathsz, path);

	return filename;
}
