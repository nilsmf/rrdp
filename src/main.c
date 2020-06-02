#include <stdlib.h>
#include <string.h>
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

void handle_snapshot_filenames(FILE *snapshot_filename_out, FILE *snapshot_file_in) {
	size_t buff_size = sizeof(char)*200;
	char *buff = malloc(buff_size);
	while(getline(&buff, &buff_size, snapshot_filename_out)) {
		strrchr(buff, '\n')[0] = '\0';
		fetch_url(buff, snapshot_file_in);
	}
}

void handle_delta_filenames(FILE *delta_filename_out, FILE *delta_file_in) {
	size_t buff_size = sizeof(char)*200;
	char *buff = malloc(buff_size);
	while(getline(&buff, &buff_size, delta_filename_out)) {
		strrchr(buff, '\n')[0] = '\0';
		fetch_url(buff, delta_file_in);
	}
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
	int snapshot_filename_pipe[2];
	FILE *snapshot_filename_in;
	FILE *snapshot_filename_out;
	int delta_filename_pipe[2];
	FILE *delta_filename_in;
	FILE *delta_filename_out;
	int notification_file_pipe[2];
	FILE *notification_file_in;
	FILE *notification_file_out;
	
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

    	if (pipe(snapshot_filename_pipe) != 0)
		err(1, "pipe");
	/* split off the snapshot filename processor/file reader */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(snapshot_filename_pipe[1]);
		snapshot_filename_out = fdopen(snapshot_file_pipe[0], "r");
		snapshot_file_in = fdopen(snapshot_file_pipe[1], "w");
		handle_snapshot_filenames(snapshot_filename_out, snapshot_file_in);
		close(snapshot_filename_pipe[0]);
		exit(0);
	}
	close(snapshot_filename_pipe[0]);

    	if (pipe(delta_filename_pipe) != 0)
		err(1, "pipe");
	/* split off the delta filename processor/fetcher */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(delta_filename_pipe[1]);
		delta_filename_out = fdopen(delta_file_pipe[0], "r");
		delta_file_in = fdopen(delta_file_pipe[1], "w");
		handle_delta_filenames(delta_filename_out, delta_file_in);
		close(delta_filename_pipe[0]);
		exit(0);
	}
	close(delta_filename_pipe[0]);

	if (pipe(notification_file_pipe) != 0)
		err(1, "pipe");
	/* split off notification processor */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(notification_file_pipe[1]);
		notification_file_out = fdopen(notification_file_pipe[0], "r");
		delta_filename_in = fdopen(delta_filename_pipe[1], "w");
		snapshot_filename_in = fdopen(snapshot_filename_pipe[1], "w");
		process_notification(notification_file_out, snapshot_filename_in, delta_filename_in);
		close(notification_file_pipe[0]);
		close(snapshot_filename_pipe[1]);
		close(delta_filename_pipe[1]);
		exit(0);
	}
	close(notification_file_pipe[0]);

	/* split off notification reader */
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		notification_file_in = fdopen(notification_file_pipe[1], "w");
		//fetch_file("regress/notify.xml", notification_file_in);
		fetch_url("https://ca.rg.net/rrdp/notify.xml", notification_file_in);
		//close(notification_file_pipe[1]);
		exit(0);
	}
	
	cleanopts(options);
}

