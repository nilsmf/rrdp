#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include <src/util.h>

typedef enum delta_scope {
	DELTA_SCOPE_NONE,
	DELTA_SCOPE_DELTA,
	DELTA_SCOPE_PUBLISH,
	DELTA_SCOPE_END
} DELTA_SCOPE;

typedef struct deltaXML {
	DELTA_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	char *serial;
	char *publish_uri;
	char *publish_hash;
	char *publish_data;
	unsigned int publish_data_length;

} DELTA_XML;

void print_delta_xml(DELTA_XML *delta_xml) {
	printf("scope: %d\n", delta_xml->scope);
	printf("xmlns: %s\n", delta_xml->xmlns ?: "NULL");
	printf("version: %s\n", delta_xml->version ?: "NULL");
	printf("session_id: %s\n", delta_xml->session_id ?: "NULL");
	printf("serial: %s\n", delta_xml->serial ?: "NULL");
}

FILE *open_delta_file(const char *publish_uri) {
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

int write_delta_publish(DELTA_XML *delta_xml) {
	FILE *f;
	if (!(f = open_delta_file(delta_xml->publish_uri))) {
		err(1, "file open error");
	}
	//TODO decode b64 message
	fprintf(f, "%.*s", delta_xml->publish_data_length,
		delta_xml->publish_data);
	return delta_xml->publish_data_length;
}

int write_delta_withdraw(DELTA_XML *delta_xml) {
	char *base_local = "/tmp/rrdp/";
	char *filename = generate_filename_from_uri(delta_xml->publish_uri, base_local);
	int ret = unlink(filename);
	free(filename);
	return ret;
}

void delta_elem_start(void *data, const char *el, const char **attr) {
	DELTA_XML *delta_xml = (DELTA_XML*)data;
	// Can only enter here once as we should have no ways to get back to NONE scope
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_NONE) {
			err(1, "parse failed - entered delta elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0) {
				delta_xml->xmlns = strdup(attr[i+1]);
			} else if (strcmp("version", attr[i]) == 0) {
				delta_xml->version = strdup(attr[i+1]);
			} else if (strcmp("session_id", attr[i]) == 0) {
				delta_xml->session_id = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				delta_xml->serial = strdup(attr[i+1]);
			} else {
				err(1, "parse failed - non conforming attribute found in delta elem");
			}
		}
		if (!(delta_xml->xmlns &&
		      delta_xml->version &&
		      delta_xml->session_id &&
		      delta_xml->serial)) {
			err(1, "parse failed - incomplete delta attributes");
		}

		delta_xml->scope = DELTA_SCOPE_DELTA;
		//print_delta_xml(delta_xml);
	// Will enter here multiple times, BUT never nested. will start collecting character data in that handler
	// mem is cleared in end block, (TODO or on parse failure)
	} else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA) {
			err(1, "parse failed - entered publish elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				delta_xml->publish_uri = strdup(attr[i+1]);
			} else if (strcmp("hash", attr[i]) == 0) {
				delta_xml->publish_hash = strdup(attr[i+1]);
			} else if (strcmp("xmlns", attr[i]) == 0) {
			} else {
				err(1, "parse failed - non conforming attribute found in publish elem");
			}
		}
		if (!delta_xml->publish_uri) {
			err(1, "parse failed - incomplete publish attributes");
		}
		delta_xml->scope = DELTA_SCOPE_PUBLISH;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void delta_elem_end(void *data, const char *el) {
	DELTA_XML *delta_xml = (DELTA_XML*)data;
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA) {
			err(1, "parse failed - exited delta elem unexpectedely");
		}
		delta_xml->scope = DELTA_SCOPE_END;
		//print_delta_xml(delta_xml);
		//printf("end %s\n", el);
	}
	//TODO does this allow <publish></withdraw> or is that caught by basic xml parsing
	else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_PUBLISH) {
			err(1, "parse failed - exited publish elem unexpectedely");
		}
		if (!delta_xml->publish_uri) {
			err(1, "parse failed - no data recovered from publish elem");
		}
		//TODO write this data somewhere (and/or never keep this much and stream it straight to staging file?)
		//printf("publish: '%.*s'\n", delta_xml->publish_data ? delta_xml->publish_data_length : 4, delta_xml->publish_data ?: "NULL");
		if (strcmp("publish", el) == 0) {
			write_delta_publish(delta_xml);
		} else {
			write_delta_withdraw(delta_xml);
		}
		free(delta_xml->publish_uri);
		delta_xml->publish_uri = NULL;
		free(delta_xml->publish_hash);
		delta_xml->publish_hash = NULL;
		free(delta_xml->publish_data);
		delta_xml->publish_data = NULL;
		delta_xml->publish_data_length = 0;
		delta_xml->scope = DELTA_SCOPE_DELTA;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void delta_content_handler(void *data, const char *content, int length)
{
	int new_length;
	DELTA_XML *delta_xml = (DELTA_XML*)data;
	if (delta_xml->scope == DELTA_SCOPE_PUBLISH) {
		//optmisiation atm this often gets called with '\n' as the only data... seems wasteful
		if (length == 1 && content[0] == '\n') {
			return;
		}
		//printf("parse chunk %d\n", length);
		//append content to publish_data
		if (delta_xml->publish_data) {
			delta_xml->publish_data = realloc(delta_xml->publish_data, sizeof(char)*(delta_xml->publish_data_length + length));
			strncpy(delta_xml->publish_data + delta_xml->publish_data_length, content, length);
		} else {
			delta_xml->publish_data = strndup(content, length);
		}
		new_length = strip_non_b64(delta_xml->publish_data, delta_xml->publish_data_length + length, delta_xml->publish_data);
		if (new_length == -1) {
			err(1, "parse failed - b64 parse error");
		}
		delta_xml->publish_data_length = new_length;
		//printf("publish_data running total (%d) '%.*s'\n", delta_xml->publish_data_length, delta_xml->publish_data_length, delta_xml->publish_data);
	}
	else {
		//printf("chars found '%.*s'\n", length, content);
	}
}

XML_Parser create_delta_parser(DELTA_XML **delta_xml) {
	if (delta_xml) {
		free(*delta_xml);
	}
	*delta_xml = calloc(1, sizeof(DELTA_XML));
	XML_Parser p = XML_ParserCreate(NULL);

	XML_SetElementHandler(p, delta_elem_start, delta_elem_end);
	XML_SetCharacterDataHandler(p, delta_content_handler);
	XML_SetUserData(p, (void*)delta_xml);
	return p;
}

void process_delta(FILE* delta_file_out) {
	int ret;
	int BUFF_SIZE = 200;
	char read_buffer[BUFF_SIZE];
	DELTA_XML *delta_xml = NULL;
	XML_Parser p = create_delta_parser(&delta_xml);
	//printf("reading\n");
	while (fgets(read_buffer, BUFF_SIZE, delta_file_out)) {
		//printf("%ld chars read:\n", strlen(read_buffer));
		//printf("%.200s\n", read_buffer);
		fflush(stdout);
		if (!XML_Parse(p, read_buffer, strlen(read_buffer), 0)) {
			if ((ret = XML_GetErrorCode(p)) == XML_ERROR_JUNK_AFTER_DOC_ELEMENT) {
				int junk_index = XML_GetCurrentByteIndex(p);
				fprintf(stderr, "-------------------------------\nJunk error might mean a new XML %d\n\t%.*s\n", junk_index, BUFF_SIZE, read_buffer);
				XML_ParserFree(p);
				p = create_delta_parser(&delta_xml);
				if (XML_Parse(p, read_buffer, strlen(read_buffer), 0)) {
					continue;
				}
			}
			fprintf(stderr, "delta Parse error (%d) at line %lu:\n%s\n",
				ret,
				XML_GetCurrentLineNumber(p),
				XML_ErrorString(XML_GetErrorCode(p)));
			err(1, "parse failed - basic xml error");
		}
	}
}

