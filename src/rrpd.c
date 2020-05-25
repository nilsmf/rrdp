#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <err.h>

#include <curl/curl.h>
#include <expat.h>

#include <src/util.h>
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

void fetch_snapshots(FILE* snapshot_file_input) {
	//CURL fetch
	CURL *curl = curl_easy_init();
	int res = -1;
	if(curl) {
		printf("starting curl\n");
		fflush(stdout);
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, "https://ca.rg.net/rrdp/eaf7cb9c-717a-4c02-b683-4ee3820ab3d0/snapshot/5740.xml");
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, snapshot_file_input);
		res = curl_easy_perform(curl);
		printf("curl response: %d\n", res);
		fflush(stdout);
		curl_easy_cleanup(curl);
	} else {
		err(1, "curl init failure");
	}
	printf("bye world %d\n", res);
	fflush(stdout);

	//printf("writing to pipe\n");
	

	//STATIC
	/*
	char str[] = "hello world 1234 1234 1234\n";
	for (int i=0; i<5; i++) {
		//write(snapshot_file_input, str, strlen(str) + 1);
		fprintf(snapshot_file_input, "%d - %s", i, str);
		fflush(snapshot_file_input);
	}*/
}

void fetch_snapshots_static(FILE* snapshot_file_input) {
	FILE *snapshot_file_disk = fopen("regress/5740.xml", "r");
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
	SNAPSHOT_SCOPE_PUBLISH,
	SNAPSHOT_SCOPE_END
} SNAPSHOT_SCOPE;

typedef struct snapshotXML {
	SNAPSHOT_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	char *serial;
	char *publish_uri;
	char *publish_data;
	unsigned int publish_data_length;

} SNAPSHOT_XML;

void print_snapshot_xml(SNAPSHOT_XML* snapshot_xml) {
	printf("scope: %d\n", snapshot_xml->scope);
	printf("xmlns: %s\n", snapshot_xml->xmlns ?: "NULL");
	printf("version: %s\n", snapshot_xml->version ?: "NULL");
	printf("session_id: %s\n", snapshot_xml->session_id ?: "NULL");
	printf("serial: %s\n", snapshot_xml->serial ?: "NULL");
}

void snapshot_elem_start(void *data, const char *el, const char **attr) {
	SNAPSHOT_XML *snapshot_xml = (SNAPSHOT_XML*)data;
	// Can only enter here once as we should have no ways to get back to NONE scope
	if (strcmp("snapshot", el) == 0) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_NONE) {
			err(1, "parse failed - entered snapshot elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0) {
				snapshot_xml->xmlns = strdup(attr[i+1]);
			} else if (strcmp("version", attr[i]) == 0) {
				snapshot_xml->version = strdup(attr[i+1]);
			} else if (strcmp("session_id", attr[i]) == 0) {
				snapshot_xml->session_id = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				snapshot_xml->serial = strdup(attr[i+1]);
			} else {
				err(1, "parse failed - non conforming attribute found in publish elem");
			}
		}
		if (!(snapshot_xml->xmlns &&
		      snapshot_xml->version &&
		      snapshot_xml->session_id &&
		      snapshot_xml->serial)) {
			err(1, "parse failed - incomplete snapshot attributes");
		}

		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
		printf("start %s\n", el);
		fflush(stdout);
		print_snapshot_xml(snapshot_xml);
	// Will enter here multiple times, BUT never nested. will start collecting character data in that handler
	// mem is cleared in end block, (TODO or on parse failure)
	} else if (strcmp("publish", el) == 0) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
			err(1, "parse failed - entered publish elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				snapshot_xml->publish_uri = strdup(attr[i+1]);
			} else if (strcmp("xmlns", attr[i]) == 0) {
			} else {
				err(1, "parse failed - non conforming attribute found in publish elem");
			}
		}
		if (!snapshot_xml->publish_uri) {
			err(1, "parse failed - incomplete publish attributes");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_PUBLISH;
		printf("start %s\n", el);
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void snapshot_elem_end(void *data, const char *el) {
	SNAPSHOT_XML *snapshot_xml = (SNAPSHOT_XML*)data;
	if (strcmp("snapshot", el) == 0) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
			err(1, "parse failed - exited snapshot elem unexpectedely");
		}
		snapshot_xml->scope = SNAPSHOT_SCOPE_END;
		print_snapshot_xml(snapshot_xml);
		printf("end %s\n", el);
	}
	else if (strcmp("publish", el) == 0) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_PUBLISH) {
			err(1, "parse failed - exited publish elem unexpectedely");
		}
		if (!snapshot_xml->publish_uri) {
			err(1, "parse failed - no data recovered from publish elem");
		}
		//TODO write this data somewhere (and/or never keep this much and stream it straight to staging file?)
		//printf("publish: '%.*s'\n", snapshot_xml->publish_data ? snapshot_xml->publish_data_length : 4, snapshot_xml->publish_data ?: "NULL");
		free(snapshot_xml->publish_uri);
		snapshot_xml->publish_uri = NULL;
		free(snapshot_xml->publish_data);
		snapshot_xml->publish_data = NULL;
		snapshot_xml->publish_data_length = 0;
		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
		printf("end %s\n", el);
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void snapshot_content_handler(void *data, const char *content, int length)
{
	int new_length;
	SNAPSHOT_XML *snapshot_xml = (SNAPSHOT_XML*)data;
	if (snapshot_xml->scope == SNAPSHOT_SCOPE_PUBLISH) {
		//optmisiation atm this often gets called with '\n' as the only data... seems wasteful
		if (length == 1 && content[0] == '\n') {
			return;
		}
		//printf("parse chunk %d\n", length);
		//append content to publish_data
		if (snapshot_xml->publish_data) {
			snapshot_xml->publish_data = realloc(snapshot_xml->publish_data, sizeof(char)*(snapshot_xml->publish_data_length + length));
			strncpy(snapshot_xml->publish_data + snapshot_xml->publish_data_length, content, length);
		} else {
			snapshot_xml->publish_data = strndup(content, length);
		}
		new_length = strip_non_b64(snapshot_xml->publish_data, snapshot_xml->publish_data_length + length, snapshot_xml->publish_data);
		if (new_length == -1) {
			err(1, "parse failed - b64 parse error");
		}
		snapshot_xml->publish_data_length = new_length;
		//printf("publish_data running total (%d) '%.*s'\n", snapshot_xml->publish_data_length, snapshot_xml->publish_data_length, snapshot_xml->publish_data);
	}
	else {
		//printf("chars found '%.*s'\n", length, content);
	}
}

void process_snapshots(FILE* snapshot_file_out) {
	int BUFF_SIZE = 200;
	char read_buffer[BUFF_SIZE];
	SNAPSHOT_XML *snapshot_xml = calloc(1, sizeof(SNAPSHOT_XML));
	XML_Parser p = XML_ParserCreate(NULL);

	XML_SetElementHandler(p, snapshot_elem_start, snapshot_elem_end);
	XML_SetCharacterDataHandler(p, snapshot_content_handler);
	XML_SetUserData(p, (void*)snapshot_xml);
	//printf("reading\n");
	while (fgets(read_buffer, BUFF_SIZE, snapshot_file_out)) {
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
		//fetch_snapshots_static(snapshot_file_in);
		close(snapshot_file_pipe[1]);
		exit(0);
	}
	close(snapshot_file_pipe[1]);

	//if ((pid = fork()) == -1)
	//	err(1, "fork");
	/* snapshot processor */
	//if (pid == 0) {
		snapshot_file_out = fdopen(snapshot_file_pipe[0], "r");
		process_snapshots(snapshot_file_out);
		close(snapshot_file_pipe[0]);
	//}

	cleanopts(options);
}

