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

#include "extern.h"
#include "rrdp.h"

#define MAX_SESSIONS	12

static struct msgbuf	msgq;

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
	struct pollfd pfds[MAX_SESSIONS + 1];

	if (pledge("stdio recvfd", NULL) == -1)
		err(1, "pledge");

	memset(&pfds, 0, sizeof(pfds));

	msgbuf_init(&msgq);
	msgq.fd = fd;

	pfds[0].fd = fd;

	for (;;) {
		pfds[0].events |= POLLIN;
		if (msgq.queued)
			pfds[0].events |= POLLOUT;

		if (poll(pfds, sizeof(pfds) / sizeof(pfds[0]), INFTIM) == -1)
			err(1, "poll");

		if (pfds[0].revents & POLLHUP)
			break;

		if (pfds[0].revents & POLLIN) {
		}

		if (pfds[0].revents & POLLOUT) {
			switch (msgbuf_write(&msgq)) {
			case 0:
				errx(1, "write: connection closed");
			case -1:
				err(1, "write");
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
