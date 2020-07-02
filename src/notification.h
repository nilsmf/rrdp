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

#ifndef _NOTIFICATIONH_
#define _NOTIFICATIONH_

#include <stdio.h>
#include <sys/queue.h>

#include "util.h"
#include "fetch_util.h"

#define STATE_FILENAME ".state"

enum notification_scope {
	NOTIFICATION_SCOPE_START,
	NOTIFICATION_SCOPE_NOTIFICATION,
	NOTIFICATION_SCOPE_SNAPSHOT,
	NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT,
	NOTIFICATION_SCOPE_DELTA,
	NOTIFICATION_SCOPE_END
};

enum notification_state {
	NOTIFICATION_STATE_SNAPSHOT,
	NOTIFICATION_STATE_DELTAS,
	NOTIFICATION_STATE_NONE,
	NOTIFICATION_STATE_ERROR
};

struct delta_item {
	char *uri;
	char *hash;
	int serial;
	TAILQ_ENTRY(delta_item) q;
};

TAILQ_HEAD(delta_q, delta_item);

struct delta_item	*new_delta(const char *, const char *, int);
void			free_delta(struct delta_item *);

struct notification_xml {
	enum notification_scope	scope;
	char			*xmlns;
	int			version;
	char			*session_id;
	int			serial;
	char			*current_session_id;
	int			current_serial;
	char			*snapshot_uri;
	char			*snapshot_hash;
	struct delta_q		delta_q;
	enum notification_state	state;
};

struct notification_xml	*new_notification_xml(void);
void			free_notification_xml(struct notification_xml *);
void			print_notification_xml(struct notification_xml *);

struct xmldata	*new_notification_xml_data(char *, struct opts *);
void		save_notification_data(struct xmldata *);

#endif

