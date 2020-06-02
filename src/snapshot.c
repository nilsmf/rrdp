#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include <src/util.h>

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

void print_snapshot_xml(SNAPSHOT_XML *snapshot_xml) {
	printf("scope: %d\n", snapshot_xml->scope);
	printf("xmlns: %s\n", snapshot_xml->xmlns ?: "NULL");
	printf("version: %s\n", snapshot_xml->version ?: "NULL");
	printf("session_id: %s\n", snapshot_xml->session_id ?: "NULL");
	printf("serial: %s\n", snapshot_xml->serial ?: "NULL");
}

FILE *open_snapshot_file(const char *publish_uri) {
	if (!publish_uri) {
		err(1, "tried to write to defunct publish uri");
	}
	//TODO what are our max lengths? 4096 seems to be safe catchall according to RFC-8181
	char *base_local = "/tmp/rrdp/";
	char *filename = generate_filename_from_uri(publish_uri, base_local);

	//create dir if necessary
	char *path_delim = strrchr(filename, '/');
	path_delim[0] = '\0';
	mkpath(filename, 0777);
	path_delim[0] = '/';
	FILE * ret = fopen(filename, "w");
	free(filename);
	return ret;
}

int write_snapshot_publish(SNAPSHOT_XML *snapshot_xml) {
	FILE *f;
	if (!(f = open_snapshot_file(snapshot_xml->publish_uri))) {
		err(1, "file open error");
	}
	//TODO decode b64 message
	fprintf(f, "%.*s", snapshot_xml->publish_data_length,
		snapshot_xml->publish_data);
	return snapshot_xml->publish_data_length;
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
				err(1, "parse failed - non conforming attribute found in snapshot elem");
			}
		}
		if (!(snapshot_xml->xmlns &&
		      snapshot_xml->version &&
		      snapshot_xml->session_id &&
		      snapshot_xml->serial)) {
			err(1, "parse failed - incomplete snapshot attributes");
		}

		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
		//print_snapshot_xml(snapshot_xml);
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
		//print_snapshot_xml(snapshot_xml);
		//printf("end %s\n", el);
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
		write_snapshot_publish(snapshot_xml);
		free(snapshot_xml->publish_uri);
		snapshot_xml->publish_uri = NULL;
		free(snapshot_xml->publish_data);
		snapshot_xml->publish_data = NULL;
		snapshot_xml->publish_data_length = 0;
		snapshot_xml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
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

void process_snapshot(FILE* snapshot_file_out) {
	int ret;
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
			if ((ret = XML_GetErrorCode(p)) == XML_ERROR_JUNK_AFTER_DOC_ELEMENT) {
				int junk_index = XML_GetCurrentByteIndex(p);
				fprintf(stderr, "-------------------------------\nJunk error might mean a new XML %d\n\t%.*s\n", junk_index, BUFF_SIZE, read_buffer);
			}
			fprintf(stderr, "snapshot Parse error (%d) at line %lu:\n%s\n",
				ret,
				XML_GetCurrentLineNumber(p),
				XML_ErrorString(XML_GetErrorCode(p)));
			err(1, "parse failed - basic xml error");
		}
	}
}


