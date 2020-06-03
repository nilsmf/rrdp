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

typedef struct Opts {
	int something;
} opts;

opts* newOpt(int sthing) {
	opts *o = malloc(sizeof(opts));
	o->something = sthing;
	return o;
}

opts* getopts(int argc, char** argv) {
	return newOpt(4);
}

void cleanopts(opts *o) {
	free(o);
}

int main(int argc, char** argv) {
	pid_t	pid;
	opts *options;
	int snapshot_file_pipe[2];
	FILE *snapshot_file_in;
	FILE *snapshot_file_out;
	int delta_file_pipe[2];
	FILE *delta_file_in;
	FILE *delta_file_out;
	
	options = getopts(argc, argv);

    	if (pipe(snapshot_file_pipe) != 0)
		err(1, "pipe");
	/* split off the snapshot processor/fetcher */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(snapshot_file_pipe[1]);
		snapshot_file_out = fdopen(snapshot_file_pipe[0], "r");
		process_snapshot(snapshot_file_out);
		close(snapshot_file_pipe[0]);
		exit(0);
	}
	close(snapshot_file_pipe[0]);

    	if (pipe(delta_file_pipe) != 0)
		err(1, "pipe");
	/* split off the delta processor/fetcher */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(delta_file_pipe[1]);
		delta_file_out = fdopen(delta_file_pipe[0], "r");
		process_delta(delta_file_out);
		close(delta_file_pipe[0]);
		exit(0);
	}
	close(delta_file_pipe[0]);

	XML_DATA *notify_xml_data = new_notify_xml_data();
	if (fetch_xml_url("https://ca.rg.net/rrdp/notify.xml", notify_xml_data) != 0) {
		err(1, "failed to curl");
	}
	NOTIFICATION_XML *nxml = (NOTIFICATION_XML*)notify_xml_data->xml_data;

	snapshot_file_in = fdopen(snapshot_file_pipe[1], "w");
	delta_file_in = fdopen(delta_file_pipe[1], "w");
	if (nxml) {
		print_notification_xml(nxml);
		//fetch_url_old(nxml->snapshot_uri, snapshot_file_in);
	/*	while (!STAILQ_EMPTY(&(nxml->delta_q))) {
			DELTA_ITEM *d = STAILQ_FIRST(&(nxml->delta_q));
			STAILQ_REMOVE_HEAD(&(nxml->delta_q), delta);
			fetch_url_old(d->uri, delta_file_in);
			free_delta(d);
		}*/
	}
	fclose(snapshot_file_in);
	fclose(delta_file_in);
	close(snapshot_file_pipe[1]);
	close(delta_file_pipe[1]);

	cleanopts(options);
}

