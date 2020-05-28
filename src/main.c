#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include <src/fetch_util.h>
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
	
	options = getopts(argc, argv);
	if( pipe(snapshot_file_pipe) != 0)
		err(1, "pipe");
	if ((pid = fork()) == -1)
		err(1, "fork");

	/* snapshot fetcher */
	if (pid == 0) {
		close(snapshot_file_pipe[0]);
		snapshot_file_in = fdopen(snapshot_file_pipe[1], "w");
		//fetch_url("https://ca.rg.net/rrdp/eaf7cb9c-717a-4c02-b683-4ee3820ab3d0/snapshot/5753.xml", snapshot_file_in);
		//fetch_file("regress/snapshot.xml", snapshot_file_in);
		//fetch_file("regress/notify.xml", snapshot_file_in);
		fetch_file("regress/5738.xml", snapshot_file_in);
		//close(snapshot_file_pipe[1]);
		exit(0);
	}
	close(snapshot_file_pipe[1]);

	//if ((pid = fork()) == -1)
	//	err(1, "fork");
	/* snapshot processor */
	//if (pid == 0) {
		snapshot_file_out = fdopen(snapshot_file_pipe[0], "r");
		process_delta(snapshot_file_out);
		//process_snapshot(snapshot_file_out);
		//process_notification(snapshot_file_out);
		close(snapshot_file_pipe[0]);
	//}

	cleanopts(options);
}

