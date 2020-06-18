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

typedef enum notify_state {
	NOTIFY_STATE_SNAPSHOT,
	NOTIFY_STATE_DELTAS,
	NOTIFY_STATE_NONE,
	NOTIFY_STATE_ERROR
} NOTIFY_STATE;

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
	NOTIFY_STATE state;
} NOTIFICATION_XML;
NOTIFICATION_XML *free_notification_xml(NOTIFICATION_XML *nxml);
NOTIFICATION_XML *new_notification_xml();
int apply_basedir_working_snapshot(XML_DATA *xml_data);
void print_notification_xml(NOTIFICATION_XML *notification_xml);

XML_DATA *new_notify_xml_data(char *uri, OPTS *opts);
void save_notify_data(XML_DATA *xml_data);
