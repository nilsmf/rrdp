#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <curl/curl.h>

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

void fetch_snapshots(FILE* snapshot_file_input) {
/*	CURL *curl = curl_easy_init();
	int res = -1;
	if(curl) {
		fprintf(snapshot_file_input, "hello world\n");
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, "http://www.shouldistartdrinking.com/");
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, snapshot_file_input);
		res = curl_easy_perform(curl);
		fprintf(snapshot_file_input, "curl response: %d\n", res);
		curl_easy_cleanup(curl);
	}
	fprintf(snapshot_file_input, "bye world %d\n", res);
*/
	//printf("writing to pipe\n");
	char str[] = "hello world 1234 1234 1234\n";
	for (int i=0; i<5; i++) {
		//write(snapshot_file_input, str, strlen(str) + 1);
		fprintf(snapshot_file_input, "%d - %s", i, str);
		fflush(snapshot_file_input);
	}

}

void process_snapshots(FILE* snapshot_file_output) {
	char read_buffer[200];
	//printf("reading\n");
	while (fgets(read_buffer, 200, snapshot_file_output)) {
		//printf("%ld chars read:\n", strlen(read_buffer));
		printf("%.200s", read_buffer);
	}
		
/*	char *buffer_ptr;
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
*/
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
		fetch_snapshots(snapshot_file_in);
		close(snapshot_file_pipe[1]);
		exit(0);
	}
	close(snapshot_file_pipe[1]);

	if ((pid = fork()) == -1)
		err(1, "fork");
	/* snapshot processor */
	if (pid == 0) {
		snapshot_file_out = fdopen(snapshot_file_pipe[0], "r");
		process_snapshots(snapshot_file_out);
	}

	cleanopts(options);
}

