/*      $OpenBSD$ */
/*
 * Copyright (c) 2020 Nils Fisher <nils_fisher@hotmail.com>
 * Copyright (c) 2021 Claudio Jeker <claudio@openbsd.com>
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
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <imsg.h>

#include <expat.h>

#include <openssl/sha.h>

#include "extern.h"
#include "rrdp.h"

#define MAX_SESSIONS	12
#define	READ_BUF_SIZE	(32 * 1024)

#define STATE_FILENAME	".state"

static struct msgbuf	msgq;

enum rrdp_state {
	REQ,
	WAITING,
	PARSING,
	PARSED,
	DONE,
};
enum rrdp_task {
	NOTIFICATION,
	SNAPSHOT,
	DELTA,
};

struct rrdp {
	TAILQ_ENTRY(rrdp)	 entry;
	size_t			 id;
	char			*notifyuri;
	char			*repouri;
	char			*localdir;

	struct pollfd		*pfd;
	int			 infd;
	int			 localfd;
	enum rrdp_state		 state;
	enum rrdp_task		 task;

	char			 hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX		 ctx;

	struct rrdp_session	 session;
	XML_Parser		 parser;
	struct notification_xml	*nxml;
	struct snapshot_xml	*sxml;
};

TAILQ_HEAD(,rrdp)	states = TAILQ_HEAD_INITIALIZER(states);

char *
xstrdup(const char *s)
{
	char *r;
	if ((r = strdup(s)) == NULL)
		err(1, "strdup");
	return r;
}

int
hex_to_bin(const char *hexstr, char *buf, size_t len)
{
	unsigned char ch, r;
	size_t pos = 0;
	int i;

	while (*hexstr) {
		r = 0;
		for (i = 0; i < 2; i++) {
			ch = hexstr[i];
			if (isdigit(ch))
				ch -= '0';
			else if (islower(ch))
				ch -= ('a' - 10);
			else if (isupper(ch))
				ch -= ('A' - 10);
			else
				return -1;
			if (ch > 0xf)
				return -1;
			r = r << 4 | ch;
		}
		if (pos < len)
			buf[pos++] = r;
		else
			return -1;

		hexstr += 2;
	}
	return 0;
}

/*
 * Report back that a RRDP request finished.
 * ok should only be set to 1 if the cache is now up-to-date.
 */
static void
rrdp_done(size_t id, int ok)
{
	enum rrdp_msg type = RRDP_END;
	struct ibuf *b;

	if ((b = ibuf_open(sizeof(type) + sizeof(id) + sizeof(ok))) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &type, sizeof(type));
	io_simple_buffer(b, &id, sizeof(id));
	io_simple_buffer(b, &ok, sizeof(ok));
	ibuf_close(&msgq, b);
}

/*
 * Request an URI to be fetched via HTTPS.
 * The main process will respond with a RRDP_HTTP_INI which includes
 * the file descriptor to read from. RRDP_HTTP_FIN is sent at the
 * end of the request with the HTTP status code and last modified timestamp.
 * If the request should not set the If-Modified-Since: header then last_mod
 * should be set to NULL, else it should point to a proper date string.
 */
static void
rrdp_fetch(size_t id, const char *uri, const char *last_mod)
{
	enum rrdp_msg type = RRDP_HTTP_REQ;
	struct ibuf *b;

	if ((b = ibuf_dynamic(256, UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &type, sizeof(type));
	io_simple_buffer(b, &id, sizeof(id));
	io_str_buffer(b, uri);
	io_str_buffer(b, last_mod);
	ibuf_close(&msgq, b);
}

/*
 * Parse the RRDP state file if it exists and set the session struct
 * based on that information.
 */
static void
rrdp_state_get(struct rrdp *s)
{
	FILE *f;
	int fd, ln = 0;
	const char *errstr;
	char *line = NULL;
	size_t len = 0;
	ssize_t n;

	if ((fd = openat(s->localfd, STATE_FILENAME, O_RDONLY)) == -1) {
//		if (errno != ENOENT)
			warn("%s: open state file", s->localdir);
		return;
	}
	f = fdopen(fd, "r");
	if (f == NULL)
		err(1, "fdopen");

	while ((n = getline(&line, &len, f)) != -1) {
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		switch (ln) {
		case 0:
			s->session.session_id = xstrdup(line);
			break;
		case 1:
			s->session.serial = strtonum(line, 1, LLONG_MAX,
			    &errstr);
			if (errstr)
				goto fail;
			break;
		case 2:
			s->session.last_mod = xstrdup(line);
			break;
		default:
			goto fail;
		}
		ln++;
	}

warnx("%s: GOT session_id: %s serial: %lld last_mod: %s", s->localdir,
s->session.session_id, s->session.serial, s->session.last_mod);

	free(line);
	if (ferror(f))
		goto fail;
	fclose(f);
	return;

fail:
	warnx("%s: troubles reading state file", s->localdir);
	fclose(f);
	free(s->session.session_id);
	free(s->session.last_mod);
	memset(&s->session, 0, sizeof(s->session));
}

/*
 * Carefully write the RRDP session state file back.
 */
static void
rrdp_state_save(struct rrdp *s)
{
	char *temp;
	FILE *f;
	int fd;

warnx("%s: SAVE session_id: %s serial: %lld last_mod: %s", s->localdir,
s->session.session_id, s->session.serial, s->session.last_mod);

	if (asprintf(&temp, "%s.XXXXXXXX", STATE_FILENAME) == -1)
		err(1, NULL);

	if ((fd = mkostempat(s->localfd, temp, O_CLOEXEC)) == -1)
		err(1, "%s: mkostempat: %s", s->localdir, temp);
	(void) fchmod(fd, 0644);
	f = fdopen(fd, "w");
	if (f == NULL)
		err(1, "fdopen");

	/* write session state file out */
	if (fprintf(f, "%s\n%lld\n%s\n", s->session.session_id,
	    s->session.serial, s->session.last_mod) < 0) {
		fclose(f);
		goto fail;
	}
	if (fclose(f) != 0)
		goto fail;

	if (renameat(s->localfd, temp, s->localfd, STATE_FILENAME) == -1)
		warn("%s: rename state file", s->localdir);
	free(temp);
	return;

fail:
	warnx("%s: failed to save state", s->localdir);
	unlinkat(s->localfd, temp, 0);
	free(temp);
}

static struct rrdp *
rrdp_new(size_t id, char *local, char *notify, char *repo)
{
	struct rrdp *s;
	int lfd;

	if ((lfd = open(local, O_RDONLY, 0)) == -1)
		err(1, "base directory %s", local);

	if ((s = calloc(1, sizeof(*s))) == NULL)
		err(1, NULL);

	s->infd = -1;
	s->id = id;
	s->localdir = local;
	s->localfd = lfd;
	s->notifyuri = notify;
	s->repouri = repo;

	rrdp_state_get(s);

	s->state = REQ;
	if ((s->parser = XML_ParserCreate(NULL)) == NULL)
		err(1, "XML_ParserCreate");

	s->nxml = new_notification_xml(s->parser, &s->session);

	TAILQ_INSERT_TAIL(&states, s, entry);

	return s;
}

static void
rrdp_free(struct rrdp *s)
{
	if (s == NULL)
		return;

	TAILQ_REMOVE(&states, s, entry);

	free_notification_xml(s->nxml);
	free_snapshot_xml(s->sxml);
	/* XXX free_delta_xml(s->dxml); */

	if (s->infd != -1)
		close(s->infd);
	if (s->parser)
		XML_ParserFree(s->parser);
	free(s->notifyuri);
	free(s->repouri);
	free(s->localdir);
	free(s->session.last_mod);
	free(s->session.session_id);

	free(s);
}

static struct rrdp *
rrdp_get(size_t id)
{
	struct rrdp *s;

	TAILQ_FOREACH(s, &states, entry)
		if (s->id == id)
			break;
	return s;
}

static void
rrdp_failed(struct rrdp *s)
{
	size_t id = s->id;

	/* may need to do some cleanup in the repo here */
	if (s->task == DELTA) {
		/* fallback to a snapshot */
		/* XXX free_delta_xml(s->dxml); */
		s->sxml = new_snapshot_xml(s->parser, &s->session);
		s->task = SNAPSHOT;
		s->state = REQ;
	} else {
		/*
		 * TODO: update state to track recurring failures
		 * and fall back to rsync after a while.
		 */
		rrdp_free(s);
		rrdp_done(id, 0);
	}
}

static void
rrdp_input(int fd)
{
	char *local, *notifyuri, *repouri, *last_mod;
	struct rrdp *s;
	enum rrdp_msg type;
	size_t id;
	int infd, status;

	infd = io_recvfd(fd, &type, sizeof(type));
	io_simple_read(fd, &id, sizeof(id));

	switch (type) {
	case RRDP_START:
		io_str_read(fd, &local);
		io_str_read(fd, &notifyuri);
		io_str_read(fd, &repouri);
		if (infd != -1)
			errx(1, "received unexpected fd");

		s = rrdp_new(id, local, notifyuri, repouri);

warnx("GOT:\nlocal\t%s\nnotify\t%s\nrepo\t%s\n",
    local, notifyuri, repouri);
		break;
	case RRDP_HTTP_INI:
		if (infd == -1)
			errx(1, "expected fd not received");
		s = rrdp_get(id);
		if (s == NULL)
			errx(1, "rrdp session %zu does not exist", id);
		if (s->state != WAITING)
			errx(1, "bad internal state");

		s->infd = infd;
		s->state = PARSING;
warnx("%s: INI: off we go", s->localdir);
		break;
	case RRDP_HTTP_FIN:
		io_simple_read(fd, &status, sizeof(status));
		io_str_read(fd, &last_mod);
		if (infd != -1)
			errx(1, "received unexpected fd");

		s = rrdp_get(id);
		if (s == NULL)
			errx(1, "rrdp session %zu does not exist", id);
		if (s->state == PARSING)
			warnx("%s: parser not finished", s->localdir);
		if (s->state != PARSED)
			errx(1, "bad internal state");


		s->state = DONE;
		if (status == 200) {
			/* Finalize the parser */
			if (XML_Parse(s->parser, NULL, 0, 1) != XML_STATUS_OK) {
				warnx("%s: parse error at line %lu: %s",
				    s->localdir,
				    XML_GetCurrentLineNumber(s->parser),
				    XML_ErrorString(XML_GetErrorCode(s->parser))
				    );
				rrdp_failed(s);
				break;
			}

			/* XXX process next */
warnx("%s: FIN: status: %d last_mod: %s", s->localdir,
    status, last_mod);
if (s->task == NOTIFICATION) {
log_notification_xml(s->nxml);
free(s->session.last_mod);
s->session.last_mod = last_mod;
rrdp_state_save(s);
s->sxml = new_snapshot_xml(s->parser, &s->session);
s->task = SNAPSHOT;
s->state = REQ;
} else {
rrdp_free(s);
rrdp_done(id, 0);
}
		} else if (status == 304 && s->task == NOTIFICATION) {
			rrdp_state_save(s);
			rrdp_free(s);
			rrdp_done(id, 1);
		} else {
			warnx("%s: failed with HTTP status %d", s->localdir,
			    status);
			rrdp_failed(s);
		}
		break;
	default:
		errx(1, "unexpected message %d", type);
	}
}

void
proc_rrdp(int fd)
{
	struct pollfd pfds[MAX_SESSIONS + 1];
	char buf[READ_BUF_SIZE];
	struct rrdp *s, *ns;
	size_t i;

	if (pledge("stdio rpath wpath cpath fattr recvfd", NULL) == -1)
		err(1, "pledge");

	memset(&pfds, 0, sizeof(pfds));

	msgbuf_init(&msgq);
	msgq.fd = fd;

	for (;;) {
		i = 1;
		TAILQ_FOREACH(s, &states, entry) {
			if (i >= MAX_SESSIONS + 1) {
				/* not enough sessions, wait for better times */
				s->pfd = NULL;
				continue;
			}
			/* request new assets when there are free sessions */
			if (s->state == REQ) {
				const char *uri;
				switch (s->task) {
				case NOTIFICATION:
					rrdp_fetch(s->id, s->notifyuri,
					    s->session.last_mod);
					break;
				case SNAPSHOT:
				case DELTA:
					uri = notification_get_next(s->nxml,
					    s->hash, sizeof(s->hash),
					    s->task == DELTA);
					SHA256_Init(&s->ctx);
					rrdp_fetch(s->id, uri, NULL);
					break;
				}
				s->state = WAITING;
			}
			s->pfd = pfds + i++;
			s->pfd->fd = s->infd;
			s->pfd->events = POLLIN;
		}

		/*
		 * Update main fd last.
		 * The previous loop may have enqueue messages.
		 */
		pfds[0].fd = fd;
		pfds[0].events = POLLIN;
		if (msgq.queued)
			pfds[0].events |= POLLOUT;

		if (poll(pfds, i, INFTIM) == -1)
			err(1, "poll");

		if (pfds[0].revents & POLLHUP)
			break;
		if (pfds[0].revents & POLLOUT) {
			switch (msgbuf_write(&msgq)) {
			case 0:
				errx(1, "write: connection closed");
			case -1:
				err(1, "write");
			}
		}
		if (pfds[0].revents & POLLIN)
			rrdp_input(fd);

		TAILQ_FOREACH_SAFE(s, &states, entry, ns) {
			if (s->pfd == NULL)
				continue;
			if (s->pfd->revents & POLLIN) {
				XML_Parser p = s->parser;
				ssize_t len;

				if (s->state != PARSING)
					errx(1, "bad parser state");

				len = read(s->infd, buf, sizeof(buf));
				if (len == -1) {
					warn("%s: read failure", s->localdir);
					rrdp_failed(s);
					continue;
				}
warnx("%s: GOT %zu bytes", s->localdir, len);
				if (len == 0) {
					/* parser stage finished */
					close(s->infd);
					s->infd = -1;

					if (s->task != NOTIFICATION) {
						char h[SHA256_DIGEST_LENGTH];

						SHA256_Final(h, &s->ctx);
						if (memcmp(s->hash, h,
						    sizeof(s->hash)) != 0) {
							warnx("%s: bad message "
							   "digest",
							   s->localdir);

							rrdp_failed(s);
							continue;
						}
warnx("%s: XML hash valid", s->localdir);
					}
warnx("%s: XML file parsed", s->localdir);

					s->state = PARSED;
					continue;
				}
				/* parse and maybe hash the bytes just read */
				if (s->task != NOTIFICATION)
					SHA256_Update(&s->ctx, buf, len);
				if (XML_Parse(p, buf, len, 0) !=
				    XML_STATUS_OK) {
					warnx("%s: parse error at line %lu: %s",
					    s->localdir,
					    XML_GetCurrentLineNumber(p),
					    XML_ErrorString(XML_GetErrorCode(p))
					    );
					rrdp_failed(s);
					continue;
				}
			}
		}
	}

	exit(0);
}

FILE *
open_primary_uri_read(char *uri, struct opts *opts)
{
	return NULL;
}

FILE *
open_working_uri_read(char *uri, struct opts *opts)
{
	return NULL;
}

FILE *
open_working_uri_write(char *uri, struct opts *opts)
{
	return NULL;
}

const char *
fetch_filename_from_uri(const char *uri, const char *proto)
{
	return NULL;
}

void
add_to_file_list(struct file_list *file_list, const char *filename,
    int withdraw, int check_duplicates)
{
}

int
fetch_uri_data(char *uri, char *hash, char *modified_since, struct opts *opts,
    XML_Parser p)
{
	return -1;
}
