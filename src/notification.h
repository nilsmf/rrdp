#include <stdio.h>
#include <sys/queue.h>

#include <src/util.h>
#include <src/fetch_util.h>

typedef enum notification_scope {
	NOTIFICATION_SCOPE_START,
	NOTIFICATION_SCOPE_NOTIFICATION,
	NOTIFICATION_SCOPE_SNAPSHOT,
	NOTIFICATION_SCOPE_NOTIFICATION_POST_SNAPSHOT,
	NOTIFICATION_SCOPE_DELTA,
	NOTIFICATION_SCOPE_END
} NOTIFICATION_SCOPE;

typedef enum xml_parse_status {
	XML_PARSE_STATUS_NONE,
	XML_PARSE_STATUS_PARSING,
	XML_PARSE_STATUS_VALID_SNAPSHOT,
	XML_PARSE_STATUS_VALID_DELTAS,
	XML_PARSE_STATUS_ERROR
} XML_PARSE_STATUS;

typedef struct delta_item {
	char *uri;
	char *hash;
	char *serial;
	STAILQ_ENTRY(delta_item) q;
} DELTA_ITEM;

DELTA_ITEM *new_delta_item(const char *uri, const char *hash, const char *serial);
DELTA_ITEM *free_delta(DELTA_ITEM *d);

STAILQ_HEAD(DELTA_Q, delta_item);

typedef struct notificationXML {
	NOTIFICATION_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	char *serial;
	char *snapshot_uri;
	char *snapshot_hash;
	struct DELTA_Q delta_q;
	XML_PARSE_STATUS status;
} NOTIFICATION_XML;
NOTIFICATION_XML *free_notification_xml(NOTIFICATION_XML *nxml);
NOTIFICATION_XML *new_notification_xml(OPTS *opts);
void print_notification_xml(NOTIFICATION_XML *notification_xml);

XML_DATA *new_notify_xml_data();
