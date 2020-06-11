#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include <src/notification.h>
#include <src/snapshot.h>
#include <src/delta.h>

// libxm (l?)
// ftp/curl
//
// xml has urls to download the files
//
// rrdp servers
// step 0. fetch notification files
// 	step 0.1 process notification files
// step 1. fetch snapshot
// 	step 1.1 process snapshot files
// step 2. fetch delta
// 	step 2.1 process deltas
//
// ? Should I stage changes in some directory and only change them if whole xml passes
// ? If 1 snapshot fails should we try other snapshots
//  if parsing a delta fails whole snapshot must fail since we wont be able to update all the bits and pieces... hmmm tends to imply an intermediate dir...
//
// nice to have optimise with keep alives etc.
//
// - start to check which things need to be updated (serial #)
// - start to validate file existance and hash
// - add 2nd layer of files in case of error
// - exit early from xml parsing if we know we are ok already?
// - start to handle errors better

void fetch_delta_xml(char *uri, OPTS *opts) {
	XML_DATA *delta_xml_data = new_delta_xml_data(uri, opts);
	if (fetch_xml_uri(delta_xml_data) != 0) {
		err(1, "failed to curl");
	}
}

void fetch_snapshot_xml(char *uri ,OPTS *opts) {
	XML_DATA *snapshot_xml_data = new_snapshot_xml_data(uri, opts);
	if (fetch_xml_uri(snapshot_xml_data) != 0) {
		err(1, "failed to curl");
	}
}

void fetch_notification_xml(char* uri, OPTS *opts) {
	XML_DATA *notify_xml_data = new_notify_xml_data(uri, opts);
	if (fetch_xml_uri(notify_xml_data) != 0) {
		err(1, "failed to curl");
	}
	NOTIFICATION_XML *nxml = (NOTIFICATION_XML*)notify_xml_data->xml_data;

	if (nxml) {
		print_notification_xml(nxml);
		switch (nxml->state) {
		case NOTIFY_STATE_ERROR:
			err(1, "NOTIFY_STATE_ERROR");
		case NOTIFY_STATE_NONE:
			printf("up to date\n");
			return;
		case NOTIFY_STATE_DELTAS:
			printf("fetching deltas\n");
			while (!STAILQ_EMPTY(&(nxml->delta_q))) {
				DELTA_ITEM *d = STAILQ_FIRST(&(nxml->delta_q));
				STAILQ_REMOVE_HEAD(&(nxml->delta_q), q);
				fetch_delta_xml(d->uri, opts);
				free_delta(d);
			}
			//TODO if failed to fetch/apply deltas then fallthrough to snapshot
			break;
		case NOTIFY_STATE_SNAPSHOT:
			printf("fetching snapshot\n");
			fetch_snapshot_xml(nxml->snapshot_uri, opts);
		}
		save_notify_data(notify_xml_data);
	} else {
		err(1, "no notification_xml available");
	}
}

int main(int argc, char **argv) {
	OPTS *opts;

	opts = getopts(argc, argv);

	fetch_notification_xml("https://ca.rg.net/rrdp/notify.xml", opts);

	cleanopts(opts);
}

