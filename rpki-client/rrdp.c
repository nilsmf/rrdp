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

#include <err.h>
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
	char			*last_mod;
	char			*notifyuri;
	char			*repouri;
	char			*localdir;

	struct pollfd		*pfd;
	int			 infd;
	enum rrdp_state		 state;
	enum rrdp_task		 task;

	char			 hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX		 ctx;

	XML_Parser		 parser;
	struct notification_xml	*nxml;
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

static struct rrdp *
rrdp_new(size_t id, char *local, char *notify, char *repo)
{
	struct rrdp *s;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		err(1, NULL);

	s->infd = -1;
	s->id = id;
	s->localdir = local;
	s->notifyuri = notify;
	s->repouri = repo;

	s->state = REQ;
	if ((s->parser = XML_ParserCreate(NULL)) == NULL)
		err(1, "XML_ParserCreate");

	s->nxml = new_notification_xml(s->parser);

	TAILQ_INSERT_TAIL(&states, s, entry);

	return s;
}

static void
rrdp_free(struct rrdp *s)
{
	if (s == NULL)
		return;

	TAILQ_REMOVE(&states, s, entry);

	if (s->infd != -1)
		close(s->infd);
	if (s->parser)
		XML_ParserFree(s->parser);
	free(s->last_mod);
	free(s->notifyuri);
	free(s->repouri);
	free(s->localdir);

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
		/* fallback to SNAPSHOT */ ;
	} else {
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
		if (s->hash[0] != '\0')
			SHA256_Init(&s->ctx);
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
			/* XXX process next */
warnx("%s: FIN: status: %d last_mod: %s", s->localdir,
    status, last_mod);
log_notification_xml(s->nxml);
rrdp_free(s);
rrdp_done(id, 0);
		} else if (status == 304 && s->task == NOTIFICATION) {
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

#ifdef NOTYET
static void
rrdp_save_state(struct rrdp *s)
{
	/* session-id, serial, last_mod */
}
#endif

void
proc_rrdp(int fd)
{
	struct pollfd pfds[MAX_SESSIONS + 1];
	char buf[READ_BUF_SIZE];
	struct rrdp *s, *ns;
	size_t i;

	if (pledge("stdio recvfd", NULL) == -1)
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
				switch (s->task) {
				case NOTIFICATION:
					rrdp_fetch(s->id, s->notifyuri,
					    s->last_mod);
					break;
				case SNAPSHOT:
				case DELTA:
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
warnx("%s: GOT %zd bytes", s->localdir, len);
				if (s->hash[0] != '\0')
					SHA256_Update(&s->ctx, buf, len);
				if (XML_Parse(p, buf, len, len == 0) !=
				    XML_STATUS_OK) {
					warn("%s: parse error at line %lu: %s",
					    s->localdir,
					    XML_GetCurrentLineNumber(p),
					    XML_ErrorString(XML_GetErrorCode(p))
					    );
					rrdp_failed(s);
					continue;
				}
				/* parser stage finished */
				if (len == 0) {
					close(s->infd);
					s->infd = -1;

					if (s->hash[0] != '\0') {
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
					}
					s->state = PARSED;
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
