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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include <expat.h>

#include "notification.h"
#include "file_util.h"

static void
add_delta(struct notification_xml *nxml, const char *uri, const char *hash,
    int serial)
{
	struct delta_item *d, *n;

	d = calloc(1, sizeof(struct delta_item));
	if (!d)
		err(1, NULL);

	d->serial = serial;
	d->uri = strdup(uri);
	d->hash = strdup(hash);
	if (d->uri == NULL || d->hash == NULL)
		err(1, NULL);

	n = TAILQ_LAST(&nxml->delta_q, delta_q);
	if (!n || serial < n->serial) {
		TAILQ_FOREACH(n, &nxml->delta_q, q) {
			if (n->serial == serial)
				err(1, "duplicate delta serial %d in "
				    "notification.xml", serial);
			if (n->serial < serial)
				break;
		}
	}

	if (n)
		TAILQ_INSERT_AFTER(&nxml->delta_q, n, d, q);
	else
		TAILQ_INSERT_HEAD(&nxml->delta_q, d, q);
}

void
free_delta(struct delta_item *d) {
	free(d->uri);
	free(d->hash);
	free(d);
}

struct notification_xml *
new_notification_xml(void)
{
	struct notification_xml *nxml;

	if ((nxml = calloc(1, sizeof(struct notification_xml))) == NULL)
		err(1, NULL);
	TAILQ_INIT(&(nxml->delta_q));

	return nxml;
}

void
free_notification_xml(struct notification_xml *nxml)
{
	if (nxml) {
		free(nxml->xmlns);
		free(nxml->session_id);
		free(nxml->snapshot_uri);
		free(nxml->snapshot_hash);
		while (!TAILQ_EMPTY(&nxml->delta_q)) {
			struct delta_item *d = TAILQ_FIRST(&nxml->delta_q);
			TAILQ_REMOVE(&nxml->delta_q, d, q);
			free_delta(d);
		}
	}
	free(nxml);
}

static void
check_state(struct notification_xml *nxml)
{
	struct delta_item *d;
	int serial_counter = 0;
	int serial_diff;

	/* Already have an error or already up to date keep it persistent */
	if (nxml->state == NOTIFICATION_STATE_ERROR ||
	    nxml->state == NOTIFICATION_STATE_NONE)
		return;

	/* No current data have to go from the snapshot */
	if (nxml->current_session_id == NULL || nxml->current_serial == 0) {
		nxml->state = NOTIFICATION_STATE_SNAPSHOT;
		return;
	}

	/* No data and yet check_state was called */
	if (nxml->session_id == NULL || nxml->serial == 0) {
		nxml->state = NOTIFICATION_STATE_ERROR;
		return;
	}

	/* New session available should go from snapshot */
	if(strcmp(nxml->current_session_id, nxml->session_id) != 0) {
		nxml->state = NOTIFICATION_STATE_SNAPSHOT;
		return;
	}

	serial_diff = nxml->serial - nxml->current_serial;

	if (serial_diff == 0) {
		/* Up to date, no further action needed */
		nxml->state = NOTIFICATION_STATE_NONE;
		return;
	}

	if (serial_diff < 0) {
		/* current serial is larger! can't even go from snapshot */
		printf("serial_diff is negative %d vs %d\n",
		    nxml->serial, nxml->current_serial);
		nxml->state = NOTIFICATION_STATE_ERROR;
		return;
	}

	/* current serial is greater lets try deltas */
	TAILQ_FOREACH(d, &(nxml->delta_q), q) {
		serial_counter++;
		if (nxml->current_serial + serial_counter != d->serial) {
			/* missing delta fall back to snapshot */
			nxml->state = NOTIFICATION_STATE_SNAPSHOT;
			return;
		}
	}
	/* all deltas present? */
	if (serial_counter != serial_diff) {
		printf("Mismatch for serial diff vs. "
		       "actual in order serials\n");
		nxml->state = NOTIFICATION_STATE_SNAPSHOT;
		return;
	}
	printf("Happy to apply %d deltas\n", serial_counter);
	/* All serials matched */
	nxml->state = NOTIFICATION_STATE_DELTAS;
}

void
print_notification_xml(struct notification_xml *notification_xml)
{
	printf("scope: %d\n", notification_xml->scope);
	printf("state: %d\n", notification_xml->state);
	printf("xmlns: %s\n", notification_xml->xmlns ?: "NULL");
	printf("version: %d\n", notification_xml->version);
	printf("current_session_id: %s\n",
	    notification_xml->current_session_id ?: "NULL");
	printf("current_serial: %d\n", notification_xml->current_serial);
	printf("session_id: %s\n", notification_xml->session_id ?: "NULL");
	printf("serial: %d\n", notification_xml->serial);
	printf("snapshot_uri: %s\n", notification_xml->snapshot_uri ?: "NULL");
	printf("snapshot_hash: %s\n",
	    notification_xml->snapshot_hash ?: "NULL");
}

static void
notification_elem_start(void *data, const char *el, const char **attr)
{
	struct xmldata *xml_data = data;
	struct notification_xml *notification_xml = xml_data->xml_data;
	int i;

	/*
	 * Can only enter here once as we should have no ways to get back to
	 * START scope
	 */
	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_START)
			err(1, "parse failed - entered notification "
			    "elem unexpectedely");
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0)
				notification_xml->xmlns = strdup(attr[i+1]);
			else if (strcmp("version", attr[i]) == 0)
				notification_xml->version =
				    (int)strtol(attr[i+1], NULL, BASE10);
			else if (strcmp("session_id", attr[i]) == 0)
				notification_xml->session_id =
				    strdup(attr[i+1]);
			else if (strcmp("serial", attr[i]) == 0)
				notification_xml->serial =
				    (int)strtol(attr[i+1], NULL, BASE10);
			else
				err(1, "parse failed - non conforming "
				    "attribute found in notification elem");
		}
		if (!(notification_xml->xmlns &&
		      notification_xml->version &&
		      notification_xml->session_id &&
		      notification_xml->serial))
			err(1, "parse failed - incomplete "
			    "notification attributes");

		if (notification_xml->version <= 0 ||
		    notification_xml->version > MAX_VERSION)
			err(1, "parse failed - invalid version");
		check_state(notification_xml);

		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION;
	/*
	 * Will enter here multiple times, BUT never nested. will start
	 * collecting character data in that handler
	 * mem is cleared in end block, (TODO or on parse failure)
	 */
	} else if (strcmp("snapshot", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NOTIFICATION)
			err(1, "parse failed - entered snapshot "
			    "elem unexpectedely");
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0)
				notification_xml->snapshot_uri =
				    strdup(attr[i+1]);
			else if (strcmp("hash", attr[i]) == 0)
				notification_xml->snapshot_hash =
				    strdup(attr[i+1]);
			else
				err(1, "parse failed - non conforming "
				    "attribute found in snapshot elem");
		}
		if (!notification_xml->snapshot_uri ||
		    !notification_xml->snapshot_hash)
			err(1, "parse failed - incomplete snapshot attributes");
		notification_xml->scope = NOTIFICATION_SCOPE_SNAPSHOT;
	} else if (strcmp("delta", el) == 0) {
		const char *delta_uri = NULL;
		const char *delta_hash = NULL;
		int delta_serial = 0;

		if (notification_xml->scope !=
		    NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT)
			err(1, "parse failed - entered delta "
			    "elem unexpectedely");
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0)
				delta_uri = attr[i+1];
			else if (strcmp("hash", attr[i]) == 0)
				delta_hash = attr[i+1];
			else if (strcmp("serial", attr[i]) == 0)
				delta_serial =
				    (int)strtol(attr[i+1], NULL, BASE10);
			else
				err(1, "parse failed - non conforming "
				    "attribute found in snapshot elem");
		}
		/* Only add to the list if we are relevant */
		if (!delta_uri || !delta_hash || !delta_serial)
			err(1, "parse failed - incomplete delta attributes");

		if (notification_xml->current_serial &&
		    notification_xml->current_serial < delta_serial) {
			add_delta(notification_xml,
			    delta_uri, delta_hash, delta_serial);
			printf("adding delta %d %s \n",
			    delta_serial, delta_uri);
		}
		notification_xml->scope = NOTIFICATION_SCOPE_DELTA;
	} else
		err(1, "parse failed - unexpected elem exit found");
}

static void
notification_elem_end(void *data, const char *el)
{
	struct xmldata *xml_data = data;
	struct notification_xml *notification_xml = xml_data->xml_data;

	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope !=
		    NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT)
			err(1, "parse failed - exited notification "
			    "elem unexpectedely");
		notification_xml->scope = NOTIFICATION_SCOPE_END;
		/* check the state to see if we have enough delta info */
		check_state(notification_xml);
	} else if (strcmp("snapshot", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_SNAPSHOT)
			err(1, "parse failed - exited snapshot "
			    "elem unexpectedely");
		notification_xml->scope =
		    NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else if (strcmp("delta", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_DELTA)
			err(1, "parse failed - exited delta "
			    "elem unexpectedely");
		notification_xml->scope =
		    NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else
		err(1, "parse failed - unexpected elem exit found");
}

/* XXXCJ this needs more cleanup and error checking */
void
save_notification_data(struct xmldata *xml_data)
{
	int fd;
	FILE *f;
	struct notification_xml *nxml = xml_data->xml_data;

	printf("saving %s/%s\n", xml_data->opts->basedir_primary,
	    STATE_FILENAME);

	fd = openat(xml_data->opts->primary_dir, STATE_FILENAME,
	    O_WRONLY|O_CREAT|O_TRUNC, ALL_RW_MODE);
	if (fd < 0 || !(f = fdopen(fd, "w")))
		err(1, "%s", __func__);
	/*
	 * TODO maybe this should actually come from the snapshot/deltas that
	 * get written might not matter if we have verified consistency already
	 */
	fprintf(f, "%s\n%d\n", nxml->session_id, nxml->serial);
	fclose(f);
}

/* XXXCJ this needs more cleanup and error checking */
static void
fetch_existing_notification_data(struct xmldata *xml_data)
{
	int fd;
	FILE *f;
	struct notification_xml *nxml = xml_data->xml_data;
	char *line = NULL;
	size_t len = 0;
	ssize_t s;
	int l = 0;

	printf("investigating %s/%s\n", xml_data->opts->basedir_primary,
	    STATE_FILENAME);

	fd = openat(xml_data->opts->primary_dir, STATE_FILENAME, O_RDONLY);
	if (fd < 0 || !(f = fdopen(fd, "r"))) {
		printf("no state file found %d\n", fd);
		return;
	}

	while (l < 2 && (s = getline(&line, &len, f)) != -1) {
		/* must have at least 1 char serial / session */
		if (s <= 1) {
			fclose(f);
			printf("bad notification file\n");
			return;
		}
		line[s - 1] = '\0';
		if (l == 0)
			nxml->current_session_id = strdup(line);
		else if (l == 1) {
			/*
			 * XXXCJ use strtonum here and maybe 64bit int
			 */
			nxml->current_serial = (int)strtol(line, NULL, BASE10);
		}
		l++;
	}
	printf("current session %s\ncurrent serial %d\n",
	    nxml->current_session_id ?: "NULL", nxml->current_serial);
	fclose(f);
}

struct xmldata *
new_notification_xml_data(char *uri, struct opts *opts)
{
	struct xmldata *xml_data;

	if ((xml_data = calloc(1, sizeof(struct xmldata))) == NULL)
		err(1, NULL);
	xml_data->xml_data = new_notification_xml();

	xml_data->uri = uri;
	xml_data->opts = opts;
	/* no hash verification for notification file */
	xml_data->hash = NULL;

	fetch_existing_notification_data(xml_data);

	xml_data->parser = XML_ParserCreate(NULL);
	if (xml_data->parser == NULL)
		err(1, "XML_ParserCreate");

	XML_SetElementHandler(xml_data->parser, notification_elem_start,
	    notification_elem_end);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

