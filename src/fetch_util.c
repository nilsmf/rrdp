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
/*      $OpenBSD: fetch.c,v 1.197 2020/07/04 11:23:35 kn Exp $  */
/*      $NetBSD: fetch.c,v 1.14 1997/08/18 10:20:20 lukem Exp $ */

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason Thorpe and Luke Mewburn.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <err.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <tls.h>
#include <limits.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <resolv.h>
#include <errno.h>
#include <poll.h>
#include <util.h>
#include <vis.h>
#include <setjmp.h>

#include "rrdp.h"
#include "log.h"

#define USER_AGENT "rrdp-client v0.1"
#define HTTP_USER_AGENT "rrdp-client v0.1"
#define IF_MODIFIED_SINCE "If-Modified-Since"
#define DATE "Date:"
#define DATE_LEN 5
#define LAST_MODIFIED "Last-Modified:"
#define LAST_MODIFIED_LEN 14

#define	HTTP_URL	"http://"	/* http URL prefix */
#define	HTTPS_URL	"https://"	/* https URL prefix */
#define HTTPS_PORT	443
#define HTTP_PORT	80

#define EMPTYSTRING(x)	((x) == NULL || (*(x) == '\0'))

static jmp_buf  httpabort;
int connect_timeout = 10;
int redirect_loop;
static int retried;

struct header_data {
	char date[TIME_LEN];
	char last_modified[TIME_LEN];
};

static void
get_value_from_header(char *buff, size_t buff_len, char *value, size_t val_len)
{
	size_t i, to_copy;
	char *val = NULL;

	for(i = 0; i < buff_len; i++) {
		if (!isspace((unsigned char)buff[i])) {
			val = buff + i;
			break;
		}
	}
	to_copy = buff_len - i;
	if (to_copy > val_len) {
		to_copy = val_len;
	}
	if (val[to_copy - 1] == '\r' || val[to_copy - 1] == '\n')
		to_copy--;
	strncpy(value, val, to_copy);
	value[to_copy] = '\0';
}

static size_t
header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
	struct header_data *header_data = userdata;
	if (nitems >= DATE_LEN && strncasecmp(DATE, buffer, DATE_LEN) == 0) {
		get_value_from_header(buffer + DATE_LEN, nitems - DATE_LEN,
		    header_data->date, TIME_LEN);
	} else if (nitems >= LAST_MODIFIED_LEN &&
	    strncasecmp(LAST_MODIFIED, buffer, LAST_MODIFIED_LEN) == 0) {
		get_value_from_header(buffer + LAST_MODIFIED_LEN,
		    nitems - LAST_MODIFIED_LEN,
		    header_data->last_modified, TIME_LEN);
	}
	return nitems;
}

static size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct xmldata *xml_data = userdata;
	XML_Parser p = xml_data->parser;
	if (xml_data->hash)
		SHA256_Update(&xml_data->ctx, (const u_int8_t *)ptr, nmemb);
	if (!p)
		return 0;
	if (!XML_Parse(p, ptr, nmemb, 0)) {
		fprintf(stderr, "Parse error at line %lu:\n%s\n",
			XML_GetCurrentLineNumber(p),
			XML_ErrorString(XML_GetErrorCode(p)));
		return 0;
	}
	return nmemb;
}

static int
hash_check(unsigned char *obuff, const char *hash) {
	int n;
	char obuff_hex[SHA256_DIGEST_LENGTH*2 + 1];

	for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
		sprintf(obuff_hex + 2*n, "%02x",
		    (unsigned int)obuff[n]);
	}
	if (strncasecmp(hash, obuff_hex,
	    SHA256_DIGEST_LENGTH*2)) {
		log_warnx("hash mismatch \n   '%.*s'\nvs '%.*s'",
		    SHA256_DIGEST_LENGTH*2, hash,
		    SHA256_DIGEST_LENGTH*2, obuff_hex);
		return -1;
	}
	return 0;
}

/*
 * Set the SIGALRM interval timer for wait seconds, 0 to disable.
 */
static void
alarmtimer(int wait)
{
	int save_errno = errno;
	struct itimerval itv;

	itv.it_value.tv_sec = wait;
	itv.it_value.tv_usec = 0;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
	errno = save_errno;
}

/*
 * Abort a http retrieval
 */
/* ARGSUSED */
static void
aborthttp(int signo)
{
	alarmtimer(0);
	log_warnx("\nfetch aborted.\n");
	longjmp(httpabort, 1);
}

static char *
ftp_readline(FILE *fp, size_t *lenp)
{
	return fparseln(fp, lenp, NULL, "\0\0\0", 0);
}

static void
ftp_close(FILE **fin, struct tls **tls, int *fd)
{
	int	ret;

	if (*tls != NULL) {
		do {
			ret = tls_close(*tls);
		} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);
		tls_free(*tls);
		*tls = NULL;
	}
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
	if (*fin != NULL) {
		fclose(*fin);
		*fin = NULL;
	}
}

static const char *
sockerror(struct tls *tls)
{
	int	save_errno = errno;
	if (tls != NULL) {
		const char *tlserr = tls_error(tls);
		if (tlserr != NULL)
			return tlserr;
	}
	return strerror(save_errno);
}

/* ARGSUSED */
static void
tooslow(int signo)
{
	dprintf(STDERR_FILENO, "%s: connect taking too long\n", "rrdp");
	_exit(2);
}

/*
 * Wait for an asynchronous connect(2) attempt to finish.
 */
static int
connect_wait(int s)
{
	struct pollfd pfd[1];
	int error = 0;
	socklen_t len = sizeof(error);

	pfd[0].fd = s;
	pfd[0].events = POLLOUT;

	if (poll(pfd, 1, -1) == -1)
		return -1;
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) == -1)
		return -1;
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

static char
hextochar(const char *str)
{
	unsigned char c, ret;

	c = str[0];
	ret = c;
	if (isalpha(c))
		ret -= isupper(c) ? 'A' - 10 : 'a' - 10;
	else
		ret -= '0';
	ret *= 16;

	c = str[1];
	ret += c;
	if (isalpha(c))
		ret -= isupper(c) ? 'A' - 10 : 'a' - 10;
	else
		ret -= '0';
	return ret;
}

/*
 * Determine whether the character needs encoding, per RFC1738:
 *	- No corresponding graphic US-ASCII.
 *	- Unsafe characters.
 */
static int
unsafe_char(const char *c0)
{
	const char *unsafe_chars = " <>\"#{}|\\^~[]`";
	const unsigned char *c = (const unsigned char *)c0;

	/*
	 * No corresponding graphic US-ASCII.
	 * Control characters and octets not used in US-ASCII.
	 */
	return (iscntrl(*c) || !isascii(*c) ||

	    /*
	     * Unsafe characters.
	     * '%' is also unsafe, if is not followed by two
	     * hexadecimal digits.
	     */
	    strchr(unsafe_chars, *c) != NULL ||
	    (*c == '%' && (!isxdigit(*++c) || !isxdigit(*++c))));
}

static char *
urldecode(const char *str)
{
	char *ret, c;
	int i, reallen;

	if (str == NULL)
		return NULL;
	if ((ret = malloc(strlen(str)+1)) == NULL)
		fatal("Can't allocate memory for URL decoding");
	for (i = 0, reallen = 0; str[i] != '\0'; i++, reallen++, ret++) {
		c = str[i];
		if (c == '+') {
			*ret = ' ';
			continue;
		}

		/* Cannot use strtol here because next char
		 * after %xx may be a digit.
		 */
		if (c == '%' && isxdigit((unsigned char)str[i+1]) &&
		    isxdigit((unsigned char)str[i+2])) {
			*ret = hextochar(&str[i+1]);
			i+=2;
			continue;
		}
		*ret = c;
	}
	*ret = '\0';

	return ret-reallen;
}

/*
 * Encode given URL, per RFC1738.
 * Allocate and return string to the caller.
 */
static char *
url_encode(const char *path)
{
	size_t i, length, new_length;
	char *epath, *epathp;

	length = new_length = strlen(path);

	/*
	 * First pass:
	 * Count unsafe characters, and determine length of the
	 * final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i))
			new_length += 2;

	epath = epathp = malloc(new_length + 1);	/* One more for '\0'. */
	if (epath == NULL)
		fatal("Can't allocate memory for URL encoding");

	/*
	 * Second pass:
	 * Encode, and copy final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i)) {
			snprintf(epathp, 4, "%%" "%02x",
			    (unsigned char)path[i]);
			epathp += 3;
		} else
			*(epathp++) = path[i];

	*epathp = '\0';
	return (epath);
}

static char *
recode_credentials(const char *userinfo)
{
	char *ui, *creds;
	size_t ulen, credsize;

	/* url-decode the user and pass */
	ui = urldecode(userinfo);

	ulen = strlen(ui);
	credsize = (ulen + 2) / 3 * 4 + 1;
	creds = malloc(credsize);
	if (creds == NULL)
		fatal("out of memory");
	if (b64_ntop(ui, ulen, creds, credsize) == -1)
		fatal("error in base64 encoding");
	free(ui);
	return (creds);
}

static int
stdio_tls_write_wrapper(void *arg, const char *buf, int len)
{
	struct tls *tls = arg;
	ssize_t ret;

	do {
		ret = tls_write(tls, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	return ret;
}

static int
stdio_tls_read_wrapper(void *arg, char *buf, int len)
{
	struct tls *tls = arg;
	ssize_t ret;

	do {
		ret = tls_read(tls, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	return ret;
}

static int
proxy_connect(int socket, char *host, char *cookie)
{
	int l;
	char buf[1024];
	char *connstr, *hosttail, *port;

	if (*host == '[' && (hosttail = strrchr(host, ']')) != NULL &&
		(hosttail[1] == '\0' || hosttail[1] == ':')) {
		host++;
		*hosttail++ = '\0';
	} else
		hosttail = host;

	port = strrchr(hosttail, ':');		/* find portnum */
	if (port != NULL)
		*port++ = '\0';
	if (!port)
		port = "443";

	if (cookie) {
		l = asprintf(&connstr, "CONNECT %s:%s HTTP/1.1\r\n"
			"Proxy-Authorization: Basic %s\r\n%s\r\n\r\n",
			host, port, cookie, HTTP_USER_AGENT);
	} else {
		l = asprintf(&connstr, "CONNECT %s:%s HTTP/1.1\r\n%s\r\n\r\n",
			host, port, HTTP_USER_AGENT);
	}

	if (l == -1)
		fatal("Could not allocate memory to assemble connect string!");
	log_debug("%s", connstr);
	if (write(socket, connstr, l) != l)
		fatal("Could not send connect string");
	read(socket, &buf, sizeof(buf)); /* only proxy header XXX: error
	    handling? */
	free(connstr);
	return(200);
}

static int
save_chunked(FILE *fin, struct tls *tls, int out, char *buf, size_t buflen,
    off_t *bytes, struct xmldata *data)
{
	char			*header, *end, *cp;
	unsigned long		chunksize;
	size_t			hlen, rlen, wlen;
	ssize_t			written;
	char			cr, lf;

	for (;;) {
		header = ftp_readline(fin, &hlen);
		if (header == NULL)
			break;
		/* strip CRLF and any optional chunk extension */
		header[strcspn(header, ";\r\n")] = '\0';
		errno = 0;
		chunksize = strtoul(header, &end, 16);
		if (errno || header[0] == '\0' || *end != '\0' ||
		    chunksize > INT_MAX) {
			warnx("Invalid chunk size '%s'", header);
			free(header);
			return -1;
		}
		free(header);

		if (chunksize == 0) {
			/* We're done.  Ignore optional trailer. */
			return 0;
		}

		for (written = 0; chunksize != 0; chunksize -= rlen) {
			rlen = (chunksize < buflen) ? chunksize : buflen;
			rlen = fread(buf, 1, rlen, fin);
			if (rlen == 0)
				break;
			*bytes += rlen;
			for (cp = buf, wlen = rlen; wlen > 0;
			    wlen -= written, cp += written) {
				if ((written = write_callback(cp, 1, wlen,
				    data)) == 0) {
					warnx("parse error");
					return -1;
				}
			}
		}

		if (rlen == 0 ||
		    fread(&cr, 1, 1, fin) != 1 ||
		    fread(&lf, 1, 1, fin) != 1)
			break;

		if (cr != '\r' || lf != '\n') {
			warnx("Invalid chunked encoding");
			return -1;
		}
	}

	if (ferror(fin))
		warnx("Error while reading from socket: %s", sockerror(tls));
	else
		warnx("Invalid chunked encoding: short read");

	return -1;
}

static int
url_get(const char *origline, const char *proxyenv, struct xmldata *data,
    struct header_data *header_data, char *modified_since)
{
	char pbuf[NI_MAXSERV], hbuf[NI_MAXHOST], *cp, *portnum, *path, ststr[4];
	char *hosttail, *cause = "unknown", *newline, *host, *port, *buf = NULL;
	char *epath, *redirurl, *loctail, *h, *p, gerror[200];
	int error, isredirect = 0, rval = -1;
	int isunavail = 0, retryafter = -1;
	struct addrinfo hints, *res0, *res;
	char *proxyurl = NULL;
	char *credentials = NULL, *proxy_credentials = NULL;
	int fd = -1, out = -1;
	volatile sig_t oldintr, oldinti;
	FILE *fin = NULL;
	const char *errstr;
	ssize_t len;
	char *proxyhost = NULL;
	char *sslpath = NULL, *sslhost = NULL;
	int ishttpsurl = 0;
	char *full_host = NULL;
	const char *scheme;
	char *locbase;
	struct tls *tls = NULL;
	int status;
	int save_errno;
	const size_t buflen = 128 * 1024;
	int chunked = 0;

	char *httpsport = "443";
	char *httpport = "80";
	off_t filesize;
	int family = PF_UNSPEC;
	char *httpuseragent = "User-Agent: " USER_AGENT;
	off_t bytes;
	struct tls_config *tls_config = NULL;

	newline = xstrdup(origline);
	if (strncasecmp(newline, HTTPS_URL, sizeof(HTTPS_URL) - 1) != 0) {
		warnx("%s: URL not permitted", newline);
		goto cleanup_url_get;
	}
	host = newline + sizeof(HTTPS_URL) - 1;
	scheme = HTTPS_URL;

	path = strchr(host, '/');

	if (EMPTYSTRING(path))
		path = strchr(host,'\0');
	else
		*path++ = '\0';

	if (proxyenv != NULL) {		/* use proxy */
		sslpath = strdup(path);
		sslhost = strdup(host);
		if (! sslpath || ! sslhost)
			fatal("Can't allocate memory for https path/host.");
		proxyhost = strdup(host);
		if (proxyhost == NULL)
			fatal("Can't allocate memory for proxy host.");
		proxyurl = strdup(proxyenv);
		if (proxyurl == NULL)
			fatal("Can't allocate memory for proxy URL.");
		if (strncasecmp(proxyurl, HTTP_URL, sizeof(HTTP_URL) - 1) == 0)
			host = proxyurl + sizeof(HTTP_URL) - 1;
		else {
			warnx("Malformed proxy URL: %s", proxyenv);
			goto cleanup_url_get;
		}
		if (EMPTYSTRING(host)) {
			warnx("Malformed proxy URL: %s", proxyenv);
			goto cleanup_url_get;
		}
		if (*--path == '\0')
			*path = '/';		/* add / back to real path */
		path = strchr(host, '/');	/* remove trailing / on host */
		if (!EMPTYSTRING(path))
			*path++ = '\0';		/* i guess this ++ is useless */

		path = strchr(host, '@');	/* look for proxy credentials */
		if (!EMPTYSTRING(path)) {
			*path = '\0';
			if (strchr(host, ':') == NULL) {
				warnx("Malformed proxy URL: %s", proxyenv);
				goto cleanup_url_get;
			}
			proxy_credentials = recode_credentials(host);
			*path = '@'; /* restore @ in proxyurl */

			/*
			 * This removes the password from proxyurl,
			 * filling with stars
			 */
			for (host = 1 + strchr(proxyurl + 5, ':');  *host != '@';
			    host++)
				*host = '*';

			host = path + 1;
		}

		path = newline;
	}

	if (*host == '[' && (hosttail = strrchr(host, ']')) != NULL &&
	    (hosttail[1] == '\0' || hosttail[1] == ':')) {
		host++;
		*hosttail++ = '\0';
		if (asprintf(&full_host, "[%s]", host) == -1)
			fatal("Cannot allocate memory for hostname");
	} else
		hosttail = host;

	portnum = strrchr(hosttail, ':');		/* find portnum */
	if (portnum != NULL)
		*portnum++ = '\0';
	port = portnum ? portnum : httpsport;

	if (full_host == NULL)
		full_host = xstrdup(host);
	log_debug("host %s, port %s, path %s, "
	    "auth %s.\n", host, port, path,
	    credentials ? credentials : "none");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	/*
	 * If the services file is corrupt/missing, fall back
	 * on our hard-coded defines.
	 */
	if (error == EAI_SERVICE && port == httpport) {
		snprintf(pbuf, sizeof(pbuf), "%d", HTTP_PORT);
		error = getaddrinfo(host, pbuf, &hints, &res0);
	} else if (error == EAI_SERVICE && port == httpsport) {
		snprintf(pbuf, sizeof(pbuf), "%d", HTTPS_PORT);
		error = getaddrinfo(host, pbuf, &hints, &res0);
	}
	if (error) {
		warnx("%s: %s", host, gai_strerror(error));
		goto cleanup_url_get;
	}

	fd = -1;
	for (res = res0; res; res = res->ai_next) {
		if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
		    sizeof(hbuf), NULL, 0, NI_NUMERICHOST) != 0)
			strlcpy(hbuf, "(unknown)", sizeof(hbuf));
		log_info("Trying %s...\n", hbuf);

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd == -1) {
			cause = "socket";
			continue;
		}

		if (connect_timeout) {
			(void)signal(SIGALRM, tooslow);
			alarmtimer(connect_timeout);
		}

		for (error = connect(fd, res->ai_addr, res->ai_addrlen);
		    error != 0 && errno == EINTR; error = connect_wait(fd))
			continue;
		if (error != 0) {
			save_errno = errno;
			close(fd);
			errno = save_errno;
			fd = -1;
			cause = "connect";
			continue;
		}

		/* get port in numeric */
		if (getnameinfo(res->ai_addr, res->ai_addrlen, NULL, 0,
		    pbuf, sizeof(pbuf), NI_NUMERICSERV) == 0)
			port = pbuf;
		else
			port = NULL;

		if (proxyenv && sslhost)
			proxy_connect(fd, sslhost, proxy_credentials);
		break;
	}
	freeaddrinfo(res0);
	if (fd < 0) {
		warn("%s", cause);
		goto cleanup_url_get;
	}

	ssize_t ret;
	if (proxyenv && sslpath) {
		ishttpsurl = 0;
		proxyurl = NULL;
		path = sslpath;
	}
	if (sslhost == NULL) {
		sslhost = xstrdup(host);
	}
	if ((tls = tls_client()) == NULL) {
		log_warnx("failed to create SSL client\n");
		goto cleanup_url_get;
	}
	if (tls_configure(tls, tls_config) != 0) {
		log_warnx("TLS configuration failure: %s\n",
		    tls_error(tls));
		goto cleanup_url_get;
	}
	if (tls_connect_socket(tls, fd, sslhost) != 0) {
		log_warnx("TLS connect failure: %s\n", tls_error(tls));
		goto cleanup_url_get;
	}
	do {
		ret = tls_handshake(tls);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);
	if (ret != 0) {
		log_warnx("TLS handshake failure: %s\n", tls_error(tls));
		goto cleanup_url_get;
	}
	fin = funopen(tls, stdio_tls_read_wrapper,
	    stdio_tls_write_wrapper, NULL, NULL);

	if (connect_timeout) {
		signal(SIGALRM, SIG_DFL);
		alarmtimer(0);
	}

	/*
	 * Construct and send the request. Proxy requests don't want leading /.
	 */
	epath = url_encode(path);
	if (proxyurl) {
		log_info("Requesting %s (via %s)\n", origline, proxyurl);
		/*
		 * Host: directive must use the destination host address for
		 * the original URI (path).
		 */
		fprintf(fin, "GET %s HTTP/1.1\r\n"
		    "Connection: close\r\n"
		    "Host: %s\r\n%s\r\n",
		    epath, proxyhost, httpuseragent);
		if (credentials)
			fprintf(fin, "Authorization: Basic %s\r\n",
			    credentials);
		if (modified_since)
			fprintf(fin, "%s\r\n", modified_since);
		if (proxy_credentials)
			fprintf(fin, "Proxy-Authorization: Basic %s\r\n",
			    proxy_credentials);
		fprintf(fin, "\r\n");
	} else {
		log_info("Requesting %s\n", origline);
		fprintf(fin,
		    "GET /%s HTTP/1.1\r\n"
		    "Connection: close\r\n"
		    "Host: ", epath);
		if (proxyhost) {
			fprintf(fin, "%s", proxyhost);
			port = NULL;
		} else if (strchr(host, ':')) {
			/*
			 * strip off scoped address portion, since it's
			 * local to node
			 */
			h = xstrdup(host);
			if ((p = strchr(h, '%')) != NULL)
				*p = '\0';
			fprintf(fin, "[%s]", h);
			free(h);
		} else
			fprintf(fin, "%s", host);

		/*
		 * Send port number only if it's specified and does not equal
		 * 80. Some broken HTTP servers get confused if you explicitly
		 * send them the port number.
		 */
		if (port && strcmp(port, "443") != 0)
			fprintf(fin, ":%s", port);
		fprintf(fin, "\r\n%s\r\n", httpuseragent);
		if (credentials)
			fprintf(fin, "Authorization: Basic %s\r\n",
			    credentials);
		if (modified_since)
			fprintf(fin, "%s\r\n", modified_since);
		fprintf(fin, "\r\n");
	}
	free(epath);

	if (fflush(fin) == EOF) {
		warnx("Writing HTTP request: %s", sockerror(tls));
		goto cleanup_url_get;
	}
	if ((buf = ftp_readline(fin, &len)) == NULL) {
		warnx("Receiving HTTP reply: %s", sockerror(tls));
		goto cleanup_url_get;
	}

	while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
		buf[--len] = '\0';
	log_debug("received '%s'\n", buf);

	cp = strchr(buf, ' ');
	if (cp == NULL)
		goto improper;
	else
		cp++;

	strlcpy(ststr, cp, sizeof(ststr));
	status = strtonum(ststr, 200, 503, &errstr);
	if (errstr) {
		strnvis(gerror, cp, sizeof gerror, VIS_SAFE);
		warnx("Error retrieving %s: %s", origline, gerror);
		goto cleanup_url_get;
	}

	switch (status) {
	case 200:	/* OK */
		/* FALLTHROUGH */
	case 206:	/* Partial Content */
		break;
	case 304:	/* See upstream can handle empty 304s */
		break;
	case 301:	/* Moved Permanently */
	case 302:	/* Found */
	case 303:	/* See Other */
	case 307:	/* Temporary Redirect */
		isredirect++;
		if (redirect_loop++ > 10) {
			warnx("Too many redirections requested");
			goto cleanup_url_get;
		}
		break;
	case 416:	/* Requested Range Not Satisfiable */
		warnx("File is already fully retrieved.");
		goto cleanup_url_get;
	case 503:
		isunavail = 1;
		break;
	default:
		strnvis(gerror, cp, sizeof gerror, VIS_SAFE);
		warnx("Error retrieving %s: %s", origline, gerror);
		goto cleanup_url_get;
	}

	/*
	 * Read the rest of the header.
	 */
	free(buf);
	filesize = -1;

	for (;;) {
		if ((buf = ftp_readline(fin, &len)) == NULL) {
			warnx("Receiving HTTP reply: %s", sockerror(tls));
			goto cleanup_url_get;
		}

		while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
			buf[--len] = '\0';
		if (len == 0)
			break;
		log_debug("received '%s'\n", buf);

		/* Look for some headers */
		cp = buf;
#define CONTENTLEN "Content-Length: "
		if (strncasecmp(cp, CONTENTLEN, sizeof(CONTENTLEN) - 1) == 0) {
			size_t s;
			cp += sizeof(CONTENTLEN) - 1;
			if ((s = strcspn(cp, " \t")))
				*(cp+s) = 0;
			filesize = strtonum(cp, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				goto improper;
#define LOCATION "Location: "
		} else if (isredirect &&
		    strncasecmp(cp, LOCATION, sizeof(LOCATION) - 1) == 0) {
			cp += sizeof(LOCATION) - 1;
			/*
			 * If there is a colon before the first slash, this URI
			 * is not relative. RFC 3986 4.2
			 */
			if (cp[strcspn(cp, ":/")] != ':') {
				fatalx("Relative redirect not supported");
				/* XXX doesn't handle protocol-relative URIs */
				if (*cp == '/') {
					locbase = NULL;
					cp++;
				} else {
					locbase = strdup(path);
					if (locbase == NULL)
						fatalx("Can't allocate memory"
						    " for location base");
					loctail = strchr(locbase, '#');
					if (loctail != NULL)
						*loctail = '\0';
					loctail = strchr(locbase, '?');
					if (loctail != NULL)
						*loctail = '\0';
					loctail = strrchr(locbase, '/');
					if (loctail == NULL) {
						free(locbase);
						locbase = NULL;
					} else
						loctail[1] = '\0';
				}
				/* Contruct URL from relative redirect */
				if (asprintf(&redirurl, "%s%s%s%s/%s%s",
				    scheme, full_host,
				    portnum ? ":" : "",
				    portnum ? portnum : "",
				    locbase ? locbase : "",
				    cp) == -1)
					fatalx("Cannot build "
					    "redirect URL");
				free(locbase);
			} else
				redirurl = xstrdup(cp);
			loctail = strchr(redirurl, '#');
			if (loctail != NULL)
				*loctail = '\0';
			log_info("Redirected to %s\n", redirurl);
			ftp_close(&fin, &tls, &fd);
			rval = url_get(redirurl, proxyenv, data, header_data,
			    modified_since);
			free(redirurl);
			goto cleanup_url_get;
#define RETRYAFTER "Retry-After: "
		} else if (isunavail &&
		    strncasecmp(cp, RETRYAFTER, sizeof(RETRYAFTER) - 1) == 0) {
			size_t s;
			cp += sizeof(RETRYAFTER) - 1;
			if ((s = strcspn(cp, " \t")))
				cp[s] = '\0';
			retryafter = strtonum(cp, 0, 0, &errstr);
			if (errstr != NULL)
				retryafter = -1;
#define TRANSFER_ENCODING "Transfer-Encoding: "
		} else if (strncasecmp(cp, TRANSFER_ENCODING,
			    sizeof(TRANSFER_ENCODING) - 1) == 0) {
			cp += sizeof(TRANSFER_ENCODING) - 1;
			cp[strcspn(cp, " \t")] = '\0';
			if (strcasecmp(cp, "chunked") == 0)
				chunked = 1;
		}
		header_callback(buf, 1, len, header_data);
		free(buf);
	}

	/* Content-Length should be ignored for Transfer-Encoding: chunked */
	if (chunked)
		filesize = -1;

	if (isunavail) {
		if (retried || retryafter != 0)
			warnx("Error retrieving %s: 503 Service Unavailable",
			    origline);
		else {
			log_info("Retrying %s\n", origline);
			retried = 1;
			ftp_close(&fin, &tls, &fd);
			rval = url_get(origline, proxyenv, data, header_data,
			    modified_since);
		}
		goto cleanup_url_get;
	}

	/* Open the output file.  */
	out = fileno(stdout);

	free(buf);
	if ((buf = malloc(buflen)) == NULL)
		fatal("Can't allocate memory for transfer buffer");

	/* Trap signals */
	oldintr = NULL;
	oldinti = NULL;
	if (setjmp(httpabort)) {
		if (oldintr)
			(void)signal(SIGINT, oldintr);
		if (oldinti)
			(void)signal(SIGINFO, oldinti);
		goto cleanup_url_get;
	}
	oldintr = signal(SIGINT, aborthttp);

	bytes = 0;

	/* Finally, suck down the file. */
	if (chunked) {
		error = save_chunked(fin, tls, out, buf, buflen, &bytes, data);
		signal(SIGINT, oldintr);
		signal(SIGINFO, oldinti);
		if (error == -1)
			goto cleanup_url_get;
	} else {
		while ((len = fread(buf, 1, buflen, fin)) > 0) {
			bytes += len;
			if (write_callback(buf, 1, len, data) == 0) {
				warnx("parse error");
				goto cleanup_url_get;
			}
		}
		save_errno = errno;
		signal(SIGINT, oldintr);
		signal(SIGINFO, oldinti);
		if (len == 0 && ferror(fin)) {
			errno = save_errno;
			warnx("Reading from socket: %s", sockerror(tls));
			goto cleanup_url_get;
		}
	}
	if (filesize != -1 && len == 0 && bytes != filesize) {
		log_info("Read short file.\n");
		goto cleanup_url_get;
	}

	rval = status;
	goto cleanup_url_get;

improper:
	warnx("Improper response from %s", host);

cleanup_url_get:
	free(full_host);
	free(sslhost);
	ftp_close(&fin, &tls, &fd);
	if (out >= 0 && out != fileno(stdout))
		close(out);
	free(buf);
	free(proxyhost);
	free(proxyurl);
	free(newline);
	free(credentials);
	free(proxy_credentials);
	return (rval);
}

long
fetch_xml_uri(struct xmldata *data) {
	char *modified_since = NULL;
	time_t current_time;
	struct tm *gmt_time;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	struct header_data header_data;
	long ret = 200;

	redirect_loop = 0;
	retried = 0;
	if (data->hash)
		SHA256_Init(&data->ctx);
	/* abuse that we never use modified since if we have a hash */
	else {
		if (strlen(data->modified_since) != 0) {
			if ((asprintf(&modified_since, "%s: %s",
			    IF_MODIFIED_SINCE, data->modified_since)) == -1)
				fatal("%s - asprintf", __func__);
		}
		/* get current gmt time to save for next time */
		if ((current_time = time(NULL)) == (time_t)-1)
			fatal("%s - time", __func__);
		if ((gmt_time = gmtime(&current_time)) == NULL)
			fatal("%s - gmtime", __func__);
		/* XXXNF what to do about localisation */
		if (strftime(data->modified_since, TIME_LEN, TIME_FORMAT,
		    gmt_time) != TIME_LEN - 1)
			fatal("%s - strftime", __func__);
	}
	if ((ret = url_get(data->uri, data->opts->httpproxy, data,
	    &header_data, modified_since)) == -1) {
		free(modified_since);
		warnx("url_get failed");
	}
	free(modified_since);
	if (data->hash) {
		SHA256_Final(obuff, &data->ctx);
		if (ret == 200 && hash_check(obuff, data->hash) == -1)
			ret = -1;
	}
	if (strlen(header_data.last_modified) > 0)
		strcpy(data->modified_since, header_data.last_modified);
	else if (strlen(header_data.date) > 0)
		strcpy(data->modified_since, header_data.date);
	return ret;
}

