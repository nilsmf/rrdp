#include <string.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include <src/notification.h>
#include <src/util.h>

DELTA_ITEM *new_delta_item(const char *uri, const char *hash, const char *serial) {
	DELTA_ITEM *d = calloc(1, sizeof(DELTA_ITEM));
	if (d) {
		d->uri = strdup(uri);
		d->hash = strdup(hash);
		d->serial = strdup(serial);
	}
	return d;
}

DELTA_ITEM *free_delta(DELTA_ITEM *d) {
	free(d->uri);
	free(d->hash);
	free(d->serial);
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
		free(nxml->serial);
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

void print_notification_xml(NOTIFICATION_XML *notification_xml) {
	printf("scope: %d\n", notification_xml->scope);
	printf("xmlns: %s\n", notification_xml->xmlns ?: "NULL");
	printf("version: %s\n", notification_xml->version ?: "NULL");
	printf("session_id: %s\n", notification_xml->session_id ?: "NULL");
	printf("serial: %s\n", notification_xml->serial ?: "NULL");
	printf("snapshot_uri: %s\n", notification_xml->snapshot_uri ?: "NULL");
	printf("snapshot_hash: %s\n", notification_xml->snapshot_hash ?: "NULL");
}

void notification_elem_start(void *data, const char *el, const char **attr) {
	NOTIFICATION_XML *notification_xml = (NOTIFICATION_XML*)data;
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
				notification_xml->serial = strdup(attr[i+1]);
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
		const char *delta_serial = NULL;
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				delta_uri = attr[i+1];
			} else if (strcmp("hash", attr[i]) == 0) {
				delta_hash = attr[i+1];
			} else if (strcmp("serial", attr[i]) == 0) {
				delta_serial = attr[i+1];
			} else {
				err(1, "parse failed - non conforming attribute found in snapshot elem");
			}
		}
		if (delta_uri && delta_hash && delta_serial) {
			DELTA_ITEM *d = new_delta_item(delta_uri, delta_hash, delta_serial);
			if (d) {
				STAILQ_INSERT_TAIL(&(notification_xml->delta_q), d, q);
			} else {
				err(1, "alloc failed - creating delta");
			}
		} else {
			err(1, "parse failed - incomplete snapshot attributes");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_DELTA;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void notification_elem_end(void *data, const char *el) {
	NOTIFICATION_XML *notification_xml = (NOTIFICATION_XML*)data;
	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT) {
			err(1, "parse failed - exited notification elem unexpectedely");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_END;
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

XML_DATA *new_notify_xml_data() {
	XML_DATA *xml_data = calloc(1, sizeof(XML_DATA));

	xml_data->xml_data = (void*)new_notification_xml();
	xml_data->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(xml_data->parser, notification_elem_start, notification_elem_end);
	XML_SetUserData(xml_data->parser, xml_data->xml_data);

	return xml_data;
}

