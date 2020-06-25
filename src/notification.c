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

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include "notification.h"

DELTA_ITEM *new_delta_item(const char *uri, const char *hash, int serial) {
	DELTA_ITEM *d = calloc(1, sizeof(DELTA_ITEM));
	if (d) {
		d->uri = strdup(uri);
		d->hash = strdup(hash);
		d->serial = serial;
	}
	return d;
}

DELTA_ITEM *free_delta(DELTA_ITEM *d) {
	free(d->uri);
	free(d->hash);
	free(d);

	return NULL;
}

NOTIFICATION_XML *new_notification_xml() {
	NOTIFICATION_XML *nxml = calloc(1, sizeof(NOTIFICATION_XML));
//	nxml->delta_q = STAILQ_HEAD_INITIALIZER(nxml->delta_q);
	STAILQ_INIT(&(nxml->delta_q));
	return nxml;
}

NOTIFICATION_XML *free_notification_xml(NOTIFICATION_XML *nxml) {
	if (nxml) {
		free(nxml->xmlns);
		free(nxml->version);
		free(nxml->session_id);
		free(nxml->snapshot_uri);
		free(nxml->snapshot_hash);
		while (!STAILQ_EMPTY(&(nxml->delta_q))) {
			DELTA_ITEM *d = STAILQ_FIRST(&(nxml->delta_q));
			STAILQ_REMOVE_HEAD(&(nxml->delta_q), q);
			free_delta(d);
		}
	}
	free(nxml);
	return NULL;
}

void check_state(NOTIFICATION_XML *nxml) {
	// Already have an error or already up to date keep it persistent
	if (nxml->state == NOTIFICATION_STATE_ERROR || nxml->state == NOTIFICATION_STATE_NONE)
		return;

	// No current data have to go from the snapshot
	if (!nxml->current_session_id ||
	    !nxml->current_serial) {
		nxml->state = NOTIFICATION_STATE_SNAPSHOT;
		return;
	}

	if (nxml->session_id && nxml->serial) {
		// New session available should go from snapshot
		if(strcmp(nxml->current_session_id, nxml->session_id) != 0) {
			nxml->state = NOTIFICATION_STATE_SNAPSHOT;
			return;
		}
		int serial_diff = nxml->serial - nxml->current_serial;
		// We are up to date take no further action
		if (serial_diff == 0) {
			nxml->state = NOTIFICATION_STATE_NONE;
			return;
		//current serial is larger! oh oh should probably go from snapshot
		//TODO check this assumption
		} else if (serial_diff < 0) {
			nxml->state = NOTIFICATION_STATE_SNAPSHOT;
			return;
		// current serial is greater lets try deltas
		} else {
			if (!STAILQ_EMPTY(&(nxml->delta_q))) {
				DELTA_ITEM *d;
				int serial_counter = 0;
				STAILQ_FOREACH(d, &(nxml->delta_q), q) {
					//TODO should we allow for out of order serial deltas
					serial_counter++;
					if (nxml->current_serial + serial_counter != d->serial) {
						nxml->state = NOTIFICATION_STATE_SNAPSHOT;
						return;
					}
				}
				if (serial_counter != serial_diff) {
					printf("Mismatch for serial diff vs. actual in order serials");
					nxml->state = NOTIFICATION_STATE_SNAPSHOT;
					return;
				}
				printf("Happy to apply %d deltas", serial_counter);
				//All serials matched
				nxml->state = NOTIFICATION_STATE_DELTAS;
				return;
			}
			// TODO should we have a default here
		}
		// TODO should we have a default here
	}
	// TODO should we have a default here
	return;
}

void print_notification_xml(NOTIFICATION_XML *notification_xml) {
	printf("scope: %d\n", notification_xml->scope);
	printf("state: %d\n", notification_xml->state);
	printf("xmlns: %s\n", notification_xml->xmlns ?: "NULL");
	printf("version: %s\n", notification_xml->version ?: "NULL");
	printf("current_session_id: %s\n", notification_xml->current_session_id ?: "NULL");
	printf("current_serial: %d\n", notification_xml->current_serial);
	printf("session_id: %s\n", notification_xml->session_id ?: "NULL");
	printf("serial: %d\n", notification_xml->serial);
	printf("snapshot_uri: %s\n", notification_xml->snapshot_uri ?: "NULL");
	printf("snapshot_hash: %s\n", notification_xml->snapshot_hash ?: "NULL");
}

void notification_elem_start(void *data, const char *el, const char **attr) {
	XML_DATA *xml_data = (XML_DATA*)data;
	NOTIFICATION_XML *notification_xml = (NOTIFICATION_XML*)xml_data->xml_data;
	// Can only enter here once as we should have no ways to get back to START scope
	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_START) {
			err(1, "parse failed - entered notification elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0) {
				notification_xml->xmlns = strdup(attr[i+1]);
			} else if (strcmp("version", attr[i]) == 0) {
				notification_xml->version = strdup(attr[i+1]);
			} else if (strcmp("session_id", attr[i]) == 0) {
				notification_xml->session_id = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				notification_xml->serial = (int)strtol(attr[i+1],NULL,BASE10);
			} else {
				err(1, "parse failed - non conforming attribute found in notification elem");
			}
		}
		if (!(notification_xml->xmlns &&
		      notification_xml->version &&
		      notification_xml->session_id &&
		      notification_xml->serial)) {
			err(1, "parse failed - incomplete notification attributes");
		}

		check_state(notification_xml);

		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION;
		//print_notification_xml(notification_xml);
	// Will enter here multiple times, BUT never nested. will start collecting character data in that handler
	// mem is cleared in end block, (TODO or on parse failure)
	} else if (strcmp("snapshot", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NOTIFICATION) {
			err(1, "parse failed - entered snapshot elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				notification_xml->snapshot_uri = strdup(attr[i+1]);
			} else if (strcmp("hash", attr[i]) == 0) {
				notification_xml->snapshot_hash = strdup(attr[i+1]);
			} else {
				err(1, "parse failed - non conforming attribute found in snapshot elem");
			}
		}
		if (!notification_xml->snapshot_uri ||
		    !notification_xml->snapshot_hash) {
			err(1, "parse failed - incomplete snapshot attributes");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_SNAPSHOT;
	} else if (strcmp("delta", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT) {
			err(1, "parse failed - entered delta elem unexpectedely");
		}
		const char *delta_uri = NULL;
		const char *delta_hash = NULL;
		int delta_serial = 0;
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				delta_uri = attr[i+1];
			} else if (strcmp("hash", attr[i]) == 0) {
				delta_hash = attr[i+1];
			} else if (strcmp("serial", attr[i]) == 0) {
				delta_serial = (int)strtol(attr[i+1],NULL,BASE10);
			} else {
				err(1, "parse failed - non conforming attribute found in snapshot elem");
			}
		}
		//Only add to the list if we are relevant
		if (delta_uri && delta_hash && delta_serial) {
			//TODO current use delta check expects current delta in list as well...
			if (notification_xml->current_serial &&
			    notification_xml->current_serial < delta_serial) {
				DELTA_ITEM *d = new_delta_item(delta_uri, delta_hash, delta_serial);
				if (d) {
					STAILQ_INSERT_TAIL(&(notification_xml->delta_q), d, q);
				} else {
					err(1, "alloc failed - creating delta");
				}
			} else {
				printf("excluding delta %d %s \n", delta_serial, delta_uri);
			}
		} else {
			err(1, "parse failed - incomplete delta attributes");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_DELTA;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void notification_elem_end(void *data, const char *el) {
	XML_DATA *xml_data = (XML_DATA*)data;
	NOTIFICATION_XML *notification_xml = (NOTIFICATION_XML*)xml_data->xml_data;
	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT) {
			err(1, "parse failed - exited notification elem unexpectedely");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_END;
		//check the state to see if we have enough delta info
		check_state(notification_xml);
		//print_notification_xml(notification_xml);
		//printf("end %s\n", el);
	} else if (strcmp("snapshot", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_SNAPSHOT) {
			err(1, "parse failed - exited snapshot elem unexpectedely");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else if (strcmp("delta", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_DELTA) {
			err(1, "parse failed - exited delta elem unexpectedely");
		}
		//print_notification_xml(notification_xml);
		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void save_notification_data(XML_DATA *xml_data) {
	char *notification_filename = generate_filename_from_uri(xml_data->uri, xml_data->opts->basedir_primary, "https://");
	printf("saving %s\n", notification_filename);
	FILE *f = fopen(notification_filename, "w");
	if (f) {
		NOTIFICATION_XML *nxml = (NOTIFICATION_XML*)xml_data->xml_data;
		//TODO maybe this should actually come from the snapshot/deltas that get written
		// might not matter if we have verified consistency already
		fprintf(f, "%s\n%d\n", nxml->session_id, nxml->serial);
		fclose(f);
	}
}

void fetch_existing_notification_data(XML_DATA *xml_data) {
	char *notification_filename = generate_filename_from_uri(xml_data->uri, xml_data->opts->basedir_primary, "https://");
	printf("investigating %s\n", notification_filename);
	fflush(stdout);
	char *line = NULL;
	size_t len = 0;
	FILE *f = fopen(notification_filename, "r");
	if (f) {
		NOTIFICATION_XML *nxml = (NOTIFICATION_XML*)xml_data->xml_data;
		ssize_t s = getline(&line, &len, f);
		line[strlen(line)-1] = '\0';
		nxml->current_session_id = strdup(line);
		s = getline(&line, &len, f);
		line[strlen(line)-1] = '\0';
		nxml->current_serial = (int)strtol(line,NULL,BASE10);
		fclose(f);
	} else {
		printf("no file %s found", notification_filename);
	}
	free(notification_filename);
}

XML_DATA *new_notification_xml_data(char *uri, OPTS *opts) {
	XML_DATA *xml_data = calloc(1, sizeof(XML_DATA));

	xml_data->xml_data = (void*)new_notification_xml();
	xml_data->uri = uri;
	xml_data->opts = opts;
	//no hash verification for notification file
	xml_data->hash = NULL;
	fetch_existing_notification_data(xml_data);
	xml_data->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(xml_data->parser, notification_elem_start, notification_elem_end);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

