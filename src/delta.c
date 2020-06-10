#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include <src/delta.h>

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
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
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
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
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
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
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

XML_DATA *new_delta_xml_data(OPTS *opts) {
	XML_DATA *xml_data = calloc(1, sizeof(XML_DATA));

	xml_data->xml_data = calloc(1, sizeof(DELTA_XML));
	xml_data->opts = opts;
	xml_data->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(xml_data->parser, delta_elem_start, delta_elem_end);
	XML_SetCharacterDataHandler(xml_data->parser, delta_content_handler);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

