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
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <imsg.h>

#include <expat.h>

#include "extern.h"
#include "rrdp.h"

#define	READ_BUF_SIZE	(32 * 1024)
#define MAX_SESSIONS	12

static struct msgbuf	msgq;

struct rrdp_state {
	struct pollfd	*pfd;
	XML_Parser	 parser;
};

char *
xstrdup(const char *s)
{
	char *r;
	if ((r = strdup(s)) == NULL)
		err(1, "strdup");
	return r;
}

void
proc_rrdp(int fd)
{
	struct rrdp_state state[MAX_SESSIONS];
	struct pollfd pfds[MAX_SESSIONS + 1];
	char buf[READ_BUF_SIZE];
	size_t i;

	if (pledge("stdio recvfd", NULL) == -1)
		err(1, "pledge");

	memset(&state, 0, sizeof(state));
	memset(&pfds, 0, sizeof(pfds));

	for (i = 0; i < MAX_SESSIONS; i++) {
		pfds[1 + i].fd = -1;
		state[i].pfd = &pfds[1 + i];
	}

	msgbuf_init(&msgq);
	msgq.fd = fd;

	pfds[0].fd = fd;

	for (;;) {
		pfds[0].events = POLLIN;
		if (msgq.queued)
			pfds[0].events |= POLLOUT;

		for (i = 0; i < MAX_SESSIONS; i++) {
			pfds[1 + i].events = 0;
			if (pfds[1 + i].fd != -1)
				pfds[1 + i].events = POLLIN;
		}

		if (poll(pfds, sizeof(pfds) / sizeof(pfds[0]), INFTIM) == -1)
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

		if (pfds[0].revents & POLLIN) {
		}

		for (i = 0; i < MAX_SESSIONS; i++) {
			if (state[i].pfd->revents & POLLHUP) {
				/* XXX TODO */
				continue;
			}
			if (state[i].pfd->revents & POLLIN) {
				ssize_t s;
				XML_Parser p = state[i].parser;

				s = read(state[i].pfd->fd, buf, sizeof(buf));
				if (s == -1) {
					/* XXX */
					warn("read");
					continue;
				}
				if (!XML_Parse(p, buf, s, 0)) {
					warn("Parse error at line %lu:\n%s\n",
					    XML_GetCurrentLineNumber(p),
					    XML_ErrorString(XML_GetErrorCode(p))
					    );
					/* XXX */
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
