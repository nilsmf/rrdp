#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

// libxm (l?)
// ftp/curl
// 
// xml has urls to download the files
//
// rrpd servers 
// step 1. fetch snapshot
// step 2. fetch delta
// step 3. fetch individual non deltas
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

void fetch_snapshots(int snapshot_file_input) {
	char str[] = "hello world\n";
	for (int i=0; i<5; i++) {
		write(snapshot_file_input, str, strlen(str) + 1);
	}
}

void process_snapshots(int snapshot_file_output) {
	char read_buffer[200];
	char *buffer_ptr;
	int chars_read;
	int chunk_size;
	while ((chars_read = read(snapshot_file_output, read_buffer, sizeof(read_buffer))) != 0) {
		printf("read\n");
		buffer_ptr = read_buffer;
		//TODO handle extra bits in case read_buffer couldnt fit whole message
		for(chunk_size = strlen(buffer_ptr) + 1; chunk_size > 1 && chars_read >= chunk_size;) {
			printf("%.200s", buffer_ptr);
			chars_read -= chunk_size;
			buffer_ptr += chunk_size;
			chunk_size = strlen(buffer_ptr) + 1;
		}
	}
}

int main(int argc, char** argv) {
	pid_t	pid;
	opts *options;
	int snapshot_file_pipe[2];
	
	options = getopts(argc, argv);
	if( pipe(snapshot_file_pipe) != 0)
		err(1, "pipe");
	if ((pid = fork()) == -1)
		err(1, "fork");

	/* snapshot fetcher */
	if (pid == 0) {
		close(snapshot_file_pipe[0]);
		fetch_snapshots(snapshot_file_pipe[1]);
		close(snapshot_file_pipe[1]);
		exit(0);
	}
	close(snapshot_file_pipe[1]);

	if ((pid = fork()) == -1)
		err(1, "fork");
	/* snapshot processor */
	if (pid == 0) {
		process_snapshots(snapshot_file_pipe[0]);
	}

	cleanopts(options);
}

