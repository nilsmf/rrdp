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

#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <expat.h>

#include "extern.h"
#include "rrdp.h"

enum snapshot_scope {
	SNAPSHOT_SCOPE_NONE,
	SNAPSHOT_SCOPE_SNAPSHOT,
	SNAPSHOT_SCOPE_PUBLISH,
	SNAPSHOT_SCOPE_END
};

struct snapshot_xml {
	struct file_list	*file_list;
	XML_Parser		 parser;
	struct rrdp_session	*current;
	char			*session_id;
	long long		 serial;
	char			*publish_uri;
	char			*publish_data;
	unsigned int		 publish_data_length;
	int			 version;
	enum snapshot_scope	 scope;
};

static void
write_snapshot_publish(struct snapshot_xml *sxml)
{
#ifdef NOTYET
	FILE *f;
	unsigned char *data_decoded;
	size_t decoded_len;
	const char *filename;

	f = open_working_uri_write(sxml->publish_uri, NULL);
	if (f == NULL)
		err(1, "%s - file open fail", __func__);
	/* decode b64 message */
	if (base64_decode(snapshot_xml->publish_data, &data_decoded,
	    &decoded_len) == -1) {
		warnx("base64 decode failed in snapshot");
	} else {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);

	filename = fetch_filename_from_uri(sxml->publish_uri,
	    "rsync://");
	add_to_file_list(sxml->file_list, filename, 0, 0);
#endif

warnx("%s", sxml->publish_uri);

	free(sxml->publish_uri);
	free(sxml->publish_data);
	sxml->publish_uri = NULL;
	sxml->publish_data = NULL;
}

static void
start_snapshot_elem(struct snapshot_xml *sxml, const char **attr)
{
	XML_Parser p = sxml->parser;
	int has_xmlns = 0;
	int i;

	if (sxml->scope != SNAPSHOT_SCOPE_NONE) {
		PARSE_FAIL(p,
		    "parse failed - entered snapshot elem unexpectedely");
	}
	for (i = 0; attr[i]; i += 2) {
		const char *errstr;
		if (strcmp("xmlns", attr[i]) == 0) {
			has_xmlns = 1;
			continue;
		}
		if (strcmp("version", attr[i]) == 0) {
			sxml->version = strtonum(attr[i + 1],
			    1, MAX_VERSION, &errstr);
			if (errstr == NULL)
				continue;
		}
		if (strcmp("session_id", attr[i]) == 0) {
			sxml->session_id = xstrdup(attr[i+1]);
			continue;
		}
		if (strcmp("serial", attr[i]) == 0) {
			sxml->serial = strtonum(attr[i + 1],
			    1, LLONG_MAX, &errstr);
			if (errstr == NULL)
				continue;
		}
		PARSE_FAIL(p,
		    "parse failed - non conforming "
		    "attribute found in snapshot elem");
	}
	if (!(has_xmlns && sxml->version && sxml->session_id && sxml->serial)) {
		PARSE_FAIL(p,
		    "parse failed - incomplete snapshot attributes");
	}
	if (strcmp(sxml->current->session_id, sxml->session_id) != 0)
		PARSE_FAIL(p, "parse failed - session_id mismatch");
	if (sxml->current->serial != sxml->serial)
		PARSE_FAIL(p, "parse failed - serial mismatch");

	sxml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
}

static void
end_snapshot_elem(struct snapshot_xml *sxml)
{
	XML_Parser p = sxml->parser;

	if (sxml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
		PARSE_FAIL(p, "parse failed - exited snapshot "
		    "elem unexpectedely");
	}
	sxml->scope = SNAPSHOT_SCOPE_END;
}

static void
start_publish_elem(struct snapshot_xml *sxml, const char **attr)
{
	XML_Parser p = sxml->parser;
	int i;

	if (sxml->scope != SNAPSHOT_SCOPE_SNAPSHOT) {
		PARSE_FAIL(p, "parse failed - entered publish "
		    "elem unexpectedely");
	}
	for (i = 0; attr[i]; i += 2) {
		if (strcmp("uri", attr[i]) == 0) {
			sxml->publish_uri = xstrdup(attr[i+1]);
			continue;
		}
		PARSE_FAIL(p, "parse failed - non conforming"
		    " attribute found in publish elem");
	}
	if (!sxml->publish_uri)
		PARSE_FAIL(p, "parse failed - incomplete publish attributes");
	sxml->scope = SNAPSHOT_SCOPE_PUBLISH;
}

static void
end_publish_elem(struct snapshot_xml *sxml)
{
	XML_Parser p = sxml->parser;

	if (sxml->scope != SNAPSHOT_SCOPE_PUBLISH) {
		PARSE_FAIL(p, "parse failed - exited publish "
		    "elem unexpectedely");
	}
	if (!sxml->publish_uri) {
		PARSE_FAIL(p, "parse failed - no data recovered "
		    "from publish elem");
	}

	write_snapshot_publish(sxml);

	sxml->scope = SNAPSHOT_SCOPE_SNAPSHOT;
}

static void
snapshot_xml_elem_start(void *data, const char *el, const char **attr)
{
	struct snapshot_xml *sxml = data;
	XML_Parser p = sxml->parser;

	/*
	 * Can only enter here once as we should have no ways to get back to
	 * NONE scope
	 */
	if (strcmp("snapshot", el) == 0)
		start_snapshot_elem(data, attr);
	/*
	 * Will enter here multiple times, BUT never nested. will start
	 * collecting character data in that handler mem is cleared in end
	 * block, (TODO or on parse failure)
	 */
	else if (strcmp("publish", el) == 0)
		start_publish_elem(data, attr);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
snapshot_xml_elem_end(void *data, const char *el)
{
	struct snapshot_xml *sxml = data;
	XML_Parser p = sxml->parser;

	if (strcmp("snapshot", el) == 0)
		end_snapshot_elem(data);
	else if (strcmp("publish", el) == 0)
		end_publish_elem(data);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
snapshot_content_handler(void *data, const char *content, int length)
{
	struct snapshot_xml *sxml = data;
	int new_length;

	if (sxml->scope == SNAPSHOT_SCOPE_PUBLISH) {
		/*
		 * optmisiation, this often gets called with '\n' as the
		 * only data... seems wasteful
		 */
		if (length == 1 && content[0] == '\n')
			return;

		/* append content to publish_data */
		new_length = sxml->publish_data_length + length;
		sxml->publish_data = realloc(sxml->publish_data,
		    new_length + 1);
		if (sxml->publish_data == NULL)
			err(1, "%s - realloc", __func__);

		memcpy(sxml->publish_data +
		    sxml->publish_data_length, content, length);
		sxml->publish_data[new_length] = '\0';
		sxml->publish_data_length = new_length;
	}
}

void
log_snapshot_xml(struct snapshot_xml *sxml)
{
	logx("scope: %d", sxml->scope);
	logx("version: %d", sxml->version);
	logx("session_id: %s serial: %lld", sxml->session_id, sxml->serial);
}

struct snapshot_xml *
new_snapshot_xml(XML_Parser p, struct rrdp_session *rs)
{
	struct snapshot_xml *sxml;

	if ((sxml = calloc(1, sizeof(*sxml))) == NULL)
		err(1, "%s", __func__);
	sxml->parser = p;
	sxml->current = rs;

	if (XML_ParserReset(sxml->parser, NULL) != XML_TRUE)
		errx(1, "%s: XML_ParserReset failed", __func__);

	XML_SetElementHandler(sxml->parser, snapshot_xml_elem_start,
	    snapshot_xml_elem_end);
	XML_SetCharacterDataHandler(sxml->parser, snapshot_content_handler);
	XML_SetUserData(sxml->parser, sxml);

	return sxml;
}

void
free_snapshot_xml(struct snapshot_xml *sxml)
{
	free(sxml->publish_uri);
	free(sxml->publish_data);
	free(sxml->session_id);

	/* XXX TODO NUKE file_list */
	free(sxml);
}
