#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <err.h>

#include <curl/curl.h>
#include <libxml/xmlreader.h>
#include <libxml/parser.h>

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

static void print_element_names(xmlNode * a_node)
{
	xmlNode *cur_node = NULL;

	for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			printf("node type: Element, name: %s\n", cur_node->name);
		}

		print_element_names(cur_node->children);
	}
}

void publish_node(xmlDoc *doc, xmlNode *publish_node) {
	xmlElemDump(stdout, doc, publish_node);
}

void process_snapshots(int snapshot_fd) {
	xmlValidCtxtPtr ctxt = NULL;
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;

	ctxt = xmlNewParserCtxt();
	if (!ctxt) {
		fprintf(stderr, "xml ctxt allocation failed");
		return;
	}

	ctxt->userData = stdout; 
	ctxt->error    = (xmlValidityErrorFunc) fprintf;   /* register error function */ 
	ctxt->warning  = (xmlValidityWarningFunc) fprintf; /* register warning function */ 

	doc = xmlCtxtReadFd(ctxt, snapshot_fd, "", NULL, 0);
	if (!doc) {
		fprintf(stderr, "parse failed");
		xmlFreeParserCtxt(ctxt);
		return;
	}
	if (ctxt->valid != 0) {
		fprintf(stderr, "not valid");
		xmlFreeDoc(doc);
		xmlFreeParserCtxt(ctxt);
		return;
	}


	root_element = xmlDocGetRootElement(doc);
	for (xmlNode *cur_node = root_element; cur_node; cur_node = cur_node->next) {
		printf("reading node");
		if (cur_node->type == XML_ELEMENT_NODE && !strcmp(cur_node->name, "publish")) {
			publish_node(doc, cur_node);
		}
	}

	xmlFreeDoc(doc);
	xmlFreeParserCtxt(ctxt);
}

int main(int argc, char** argv) {
	pid_t	pid;
	opts *options;
	int snapshot_file_pipe[2];
	FILE *snapshot_file_in;
	
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
		process_snapshots(snapshot_file_pipe[0]);
	}

	cleanopts(options);
}

