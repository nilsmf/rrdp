/*
 * Copyright (c) 2020 Nils Fisher <nils_fisher@hotmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>

#include "snapshot.h"
#include "file_util.h"

enum snapshot_scope {
	SNAPSHOT_SCOPE_NONE,
	SNAPSHOT_SCOPE_SNAPSHOT,
	SNAPSHOT_SCOPE_PUBLISH,
	SNAPSHOT_SCOPE_END
};

struct snapshot_xml {
	enum snapshot_scope	scope;
	char			*xmlns;
	char			*version;
	char			*session_id;
	int			serial;
	char			*publish_uri;
	char			*publish_data;
	unsigned int		publish_data_length;
};

static void
print_snapshot_xml(struct snapshot_xml *snapshot_xml)
{
	printf("scope: %d\n", snapshot_xml->scope);
	printf("xmlns: %s\n", snapshot_xml->xmlns ?: "NULL");
	printf("version: %s\n", snapshot_xml->version ?: "NULL");
	printf("session_id: %s\n", snapshot_xml->session_id ?: "NULL");
	printf("serial: %d\n", snapshot_xml->serial);
}

static FILE *
open_snapshot_file(const char *publish_uri, const char *base_dir)
{
	if (!publish_uri) {
		err(1, "tried to write to defunct publish uri");
	}
	//TODO what are our max lengths? 4096 seems to be safe catchall according to RFC-8181
	char *filename = generate_filename_from_uri(publish_uri, base_dir, NULL);

	// TODO quick and dirty getting path
	//create dir if necessary
	char *path_delim = strrchr(filename, '/');
	path_delim[0] = '\0';
	mkpath(filename, 0777);
	path_delim[0] = '/';
	FILE * ret = fopen(filename, "w");
	free(filename);
	return ret;
}

static int
write_snapshot_publish(struct xmldata *xml_data)
{
	struct snapshot_xml *snapshot_xml = xml_data->xml_data;
	unsigned char *data_decoded;
	int decoded_len = 0;
	FILE *f;
	if (!(f = open_snapshot_file(snapshot_xml->publish_uri, xml_data->opts->basedir_working))) {
		err(1, "file open error");
	}
	//decode b64 message
	decoded_len = b64_decode(snapshot_xml->publish_data, &data_decoded);
	if (decoded_len > 0) {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);
	return snapshot_xml->publish_data_length;
}

static void
snapshot_elem_start(void *data, const char *el, const char **attr)
{
	struct xmldata *xml_data = data;
	struct snapshot_xml *snapshot_xml = xml_data->xml_data;
	int i;

	// Can only enter here once as we should have no ways to get back to NONE scope
	if (strcmp("snapshot", el) == 0) {
		if (snapshot_xml->scope != SNAPSHOT_SCOPE_NONE) {
			err(1, "parse failed - entered snapshot elem unexpectedely");
		}
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0) {
				snapshot_xml->xmlns = strdup(attr[i+1]);
			} else if (strcmp("version", attr[i]) == 0) {
				snapshot_xml->version = strdup(attr[i+1]);
			} else if (strcmp("session_id", attr[i]) == 0) {
				snapshot_xml->session_id = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				snapshot_xml->serial = (int)strtol(attr[i+1],NULL,BASE10);
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
		for (i = 0; attr[i]; i += 2) {
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

static void
snapshot_elem_end(void *data, const char *el)
{
	struct xmldata *xml_data = data;
	struct snapshot_xml *snapshot_xml = xml_data->xml_data;
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
		write_snapshot_publish(xml_data);
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

static void
snapshot_content_handler(void *data, const char *content, int length)
{
	int new_length;
	struct xmldata *xml_data = data;
	struct snapshot_xml *snapshot_xml = xml_data->xml_data;
	if (snapshot_xml->scope == SNAPSHOT_SCOPE_PUBLISH) {
		//optmisiation atm this often gets called with '\n' as the only data... seems wasteful
		if (length == 1 && content[0] == '\n') {
			return;
		}
		//printf("parse chunk %d\n", length);
		//append content to publish_data
		if (snapshot_xml->publish_data) {
			new_length = snapshot_xml->publish_data_length + length;
			snapshot_xml->publish_data = realloc(snapshot_xml->publish_data, sizeof(char)*(new_length + 1));
			strncpy(snapshot_xml->publish_data + snapshot_xml->publish_data_length, content, length);
			snapshot_xml->publish_data[new_length] = '\0';
		} else {
			snapshot_xml->publish_data = strndup(content, length);
			new_length = length;
		}
		snapshot_xml->publish_data_length = new_length;
	} else {
		//printf("chars found '%.*s'\n", length, content);
	}
}

struct xmldata *
new_snapshot_xml_data(char *uri, char *hash, struct opts *opts)
{
	struct xmldata *xml_data = calloc(1, sizeof(struct xmldata));

	xml_data->xml_data = calloc(1, sizeof(struct snapshot_xml));
	xml_data->uri = uri;
	xml_data->opts = opts;
	xml_data->hash = hash;
	xml_data->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(xml_data->parser, snapshot_elem_start, snapshot_elem_end);
	XML_SetCharacterDataHandler(xml_data->parser, snapshot_content_handler);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

