#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <err.h>

#include <curl/curl.h>
#include <expat.h>

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
	//CURL feetch
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
	

	//STATIC
	/*
	char str[] = "hello world 1234 1234 1234\n";
	for (int i=0; i<5; i++) {
		//write(snapshot_file_input, str, strlen(str) + 1);
		fprintf(snapshot_file_input, "%d - %s", i, str);
		fflush(snapshot_file_input);
	}*/

	FILE *snapshot_file_disk = fopen("regress/snapshot.xml", "r");
	if (snapshot_file_disk) {
		char read_buffer[200];
		//printf("reading\n");
		while (fgets(read_buffer, 200, snapshot_file_disk)) {
			//printf("%ld chars read:\n", strlen(read_buffer));
			fprintf(snapshot_file_input, "%.200s", read_buffer);
			fflush(snapshot_file_input);
		}
	}
}

typedef enum snapshot_scope {
	SNAPSHOT_SCOPE_NONE,
	SNAPSHOT_SCOPE_SNAPSHOT,
	SNAPSHOT_SCOPE_PUBLISH
} SNAPSHOT_SCOPE;

typedef struct snapshotXML {
	SNAPSHOT_SCOPE scope;

} SNAPSHOT_XML;

void snapshot_elem_start(void *data, const char *el, const char **attr) {
	SNAPSHOT_XML *snapshot_xml = (SNAPSHOT_XML*)data;
	if (!strcmp("snapshot", el)) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_NONE) {
			err(1, "parse failed");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
		printf("start %s\n", el);
	}
	else if (!strcmp("publish", el)) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
			err(1, "parse failed");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_PUBLISH;
		printf("start %s\n", el);
	} else {
		err(1, "parse failed");
	}
}

void snapshot_elem_end(void *data, const char *el) {
	SNAPSHOT_XML *snapshot_xml = (SNAPSHOT_XML*)data;
	if (!strcmp("snapshot", el)) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
			err(1, "parse failed");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_NONE;
		printf("end %s\n", el);
	}
	else if (!strcmp("publish", el)) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_PUBLISH) {
			err(1, "parse failed");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
		printf("end %s\n", el);
	} else {
		err(1, "parse failed");
	}
}

void process_snapshots(FILE* snapshot_file_out) {
	int BUFF_SIZE = 200;
	char read_buffer[BUFF_SIZE];
	SNAPSHOT_XML *snapshot_xml = malloc(sizeof(SNAPSHOT_XML));
	XML_Parser p = XML_ParserCreate(NULL);
	XML_SetElementHandler(p, snapshot_elem_start, snapshot_elem_end);
	XML_SetUserData(p, (void*)snapshot_xml);
	//printf("reading\n");
	while (fgets(read_buffer, BUFF_SIZE, snapshot_file_out)) {
		//printf("%ld chars read:\n", strlen(read_buffer));
		//printf("%.200s", read_buffer);
		if (!XML_Parse(p, read_buffer, strlen(read_buffer), 0)) {
			fprintf(stderr, "Parse error at line %lu:\n%s\n",
				XML_GetCurrentLineNumber(p),
				XML_ErrorString(XML_GetErrorCode(p)));
		}
	}
	XML_Parse(p, "", 0, 1);
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
		close(snapshot_file_pipe[0]);
	}

	cleanopts(options);
}

