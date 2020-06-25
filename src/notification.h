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

#include <stdio.h>
#include <sys/queue.h>

#include "util.h"
#include "fetch_util.h"

typedef enum notification_scope {
	NOTIFICATION_SCOPE_START,
	NOTIFICATION_SCOPE_NOTIFICATION,
	NOTIFICATION_SCOPE_SNAPSHOT,
	NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT,
	NOTIFICATION_SCOPE_DELTA,
	NOTIFICATION_SCOPE_END
} NOTIFICATION_SCOPE;

typedef enum notification_state {
	NOTIFICATION_STATE_SNAPSHOT,
	NOTIFICATION_STATE_DELTAS,
	NOTIFICATION_STATE_NONE,
	NOTIFICATION_STATE_ERROR
} NOTIFICATION_STATE;

typedef struct delta_item {
	char *uri;
	char *hash;
	int serial;
	STAILQ_ENTRY(delta_item) q;
} DELTA_ITEM;

DELTA_ITEM *new_delta_item(const char *uri, const char *hash, int serial);
DELTA_ITEM *free_delta(DELTA_ITEM *d);

STAILQ_HEAD(DELTA_Q, delta_item);

typedef struct notificationXML {
	NOTIFICATION_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	int serial;
	char *current_session_id;
	int current_serial;
	char *snapshot_uri;
	char *snapshot_hash;
	struct DELTA_Q delta_q;
	NOTIFICATION_STATE state;
} NOTIFICATION_XML;
NOTIFICATION_XML *free_notification_xml(NOTIFICATION_XML *nxml);
NOTIFICATION_XML *new_notification_xml();
void print_notification_xml(NOTIFICATION_XML *notification_xml);

XML_DATA *new_notification_xml_data(char *uri, OPTS *opts);
void save_notification_data(XML_DATA *xml_data);
