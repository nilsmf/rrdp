#include <string.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include <src/notification.h>

typedef enum notification_scope {
	NOTIFICATION_SCOPE_NONE,
	NOTIFICATION_SCOPE_NOTIFICATION,
	NOTIFICATION_SCOPE_SNAPSHOT,
	NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT,
	NOTIFICATION_SCOPE_DELTA,
	NOTIFICATION_SCOPE_END
} NOTIFICATION_SCOPE;

typedef struct notificationXML {
	NOTIFICATION_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	char *serial;
	char *snapshot_uri;
	char *snapshot_hash;
	char *delta_uri;
	char *delta_hash;
	char *delta_serial;

} NOTIFICATION_XML;

void print_notification_xml(NOTIFICATION_XML *notification_xml) {
	printf("scope: %d\n", notification_xml->scope);
	printf("xmlns: %s\n", notification_xml->xmlns ?: "NULL");
	printf("version: %s\n", notification_xml->version ?: "NULL");
	printf("session_id: %s\n", notification_xml->session_id ?: "NULL");
	printf("serial: %s\n", notification_xml->serial ?: "NULL");
	printf("snapshot_uri: %s\n", notification_xml->snapshot_uri ?: "NULL");
	printf("snapshot_hash: %s\n", notification_xml->snapshot_hash ?: "NULL");
	printf("delta_uri: %s\n", notification_xml->delta_uri ?: "NULL");
	printf("delta_hash: %s\n", notification_xml->delta_hash ?: "NULL");
	printf("delta_serial: %s\n", notification_xml->delta_serial ?: "NULL");
}

void notification_elem_start(void *data, const char *el, const char **attr) {
	NOTIFICATION_XML *notification_xml = (NOTIFICATION_XML*)data;
	// Can only enter here once as we should have no ways to get back to NONE scope
	if (strcmp("notification", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_NONE) {
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
		print_notification_xml(notification_xml);
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
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				notification_xml->delta_uri = strdup(attr[i+1]);
			} else if (strcmp("hash", attr[i]) == 0) {
				notification_xml->delta_hash = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				notification_xml->delta_serial = strdup(attr[i+1]);
			} else {
				err(1, "parse failed - non conforming attribute found in snapshot elem");
			}
		}
		if (!notification_xml->delta_uri ||
		    !notification_xml->delta_hash ||
		    !notification_xml->delta_serial) {
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
		print_notification_xml(notification_xml);
		printf("end %s\n", el);
	} else if (strcmp("snapshot", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_SNAPSHOT) {
			err(1, "parse failed - exited snapshot elem unexpectedely");
		}
		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else if (strcmp("delta", el) == 0) {
		if (notification_xml->scope != NOTIFICATION_SCOPE_DELTA) {
			err(1, "parse failed - exited delta elem unexpectedely");
		}
		print_notification_xml(notification_xml);
		notification_xml->scope = NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void process_notification(FILE* notification_file_out) {
	int BUFF_SIZE = 200;
	char read_buffer[BUFF_SIZE];
	NOTIFICATION_XML *notification_xml = calloc(1, sizeof(NOTIFICATION_XML));
	XML_Parser p = XML_ParserCreate(NULL);

	XML_SetElementHandler(p, notification_elem_start, notification_elem_end);
	XML_SetUserData(p, (void*)notification_xml);
	//printf("reading\n");
	while (fgets(read_buffer, BUFF_SIZE, notification_file_out)) {
		//printf("%ld chars read:\n", strlen(read_buffer));
		//printf("%.200s\n", read_buffer);
		fflush(stdout);
		if (!XML_Parse(p, read_buffer, strlen(read_buffer), 0)) {
			fprintf(stderr, "Parse error at line %lu:\n%s\n",
				XML_GetCurrentLineNumber(p),
				XML_ErrorString(XML_GetErrorCode(p)));
			err(1, "parse failed - basic xml error");
		}
	}
	XML_Parse(p, "", 0, 1);
}

