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
#include <openssl/sha.h>

#include "extern.h"
#include "rrdp.h"

enum delta_scope {
	DELTA_SCOPE_NONE,
	DELTA_SCOPE_DELTA,
	DELTA_SCOPE_PUBLISH,
	DELTA_SCOPE_END
};

struct delta_xml {
	struct file_list	*file_list;
	XML_Parser		 parser;
	struct rrdp_session	*current;
	char			*session_id;
	long long		 serial;
	char			*publish_uri;
	char			*publish_data;
	char			 publish_hash[SHA256_DIGEST_LENGTH];
	unsigned int		 publish_data_length;
	int			 published_already;
	int			 version;
	enum delta_scope	 scope;
};

enum validate_return {
	VALIDATE_RETURN_NO_FILE,
	VALIDATE_RETURN_FILE_DEL,
	VALIDATE_RETURN_HASH_MISMATCH,
	VALIDATE_RETURN_HASH_MATCH
};


#ifdef NOTYET
static enum validate_return
validate_publish_hash(struct delta_xml *delta_xml, struct opts *opts,
    int primary)
{
	FILE *f;
	int BUFF_SIZE = 200;
	char read_buff[BUFF_SIZE];
	size_t buff_len;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	char *hash = delta_xml->publish_hash;
	int first_read = 1;
	SHA256_CTX ctx;

	if (primary)
		f = open_primary_uri_read(delta_xml->publish_uri, opts);
	else
		f = open_working_uri_read(delta_xml->publish_uri, opts);
	if (!f)
		return VALIDATE_RETURN_NO_FILE;
	while ((buff_len = fread(read_buff, 1, BUFF_SIZE, f))) {
		/* empty file = withdrawn */
		if (first_read) {
			if (buff_len == 0) {
				fclose(f);
				return VALIDATE_RETURN_FILE_DEL;
			} else {
				SHA256_Init(&ctx);
				first_read = 0;
			}
		}
		SHA256_Update(&ctx, (const u_int8_t *)read_buff, buff_len);
	}
	fclose(f);
	if (!SHA256_Final(obuff, &ctx))
		return VALIDATE_RETURN_HASH_MISMATCH;
	if (!memcmp(hash, obuff, sizeof(obuff)))
		return VALIDATE_RETURN_HASH_MATCH;
	return VALIDATE_RETURN_HASH_MISMATCH;
}
#endif

static int
verify_publish(struct delta_xml *dxml)
{
#ifdef NOTYET
	enum validate_return v_return;

	/* Check working dir first */
	v_return = validate_publish_hash(dxml, NULL, 0);
	/* Check the primary dir if we haven't seen the file this delta run */
	if (v_return == VALIDATE_RETURN_NO_FILE) {
		v_return = validate_publish_hash(dxml, NULL, 1);
	} else {
		dxml->published_already = 1;
	}
	/* delta expects file to exist and match */
	/* XXX WRONG !!! */
	if (dxml->publish_hash[0]) {
		if (v_return == VALIDATE_RETURN_HASH_MATCH)
			return 1;
		warnx("hash validation mismatch");
		return 0;
	/* delta expects file to not exist (or have been deleted) */
	} else if (v_return <= VALIDATE_RETURN_FILE_DEL)
		return 1;
	warnx("found file but without hash");
	return 0;
#endif
	return 1;
}

static void
write_delta(struct delta_xml *dxml, int withdraw)
{
#ifdef NOTYET
	FILE *f;
	unsigned char *data_decoded;
	size_t decoded_len;
	const char *filename;

	f = open_working_uri_write(dxml->publish_uri, NULL);
	if (f == NULL)
		err(1, "%s - file open fail", __func__);
	if (withdraw == 0) {
		/* decode b64 message */
		if (base64_decode(dxml->publish_data, &data_decoded,
		    &decoded_len) == -1) {
			warnx("base64 of delta element failed");
		} else {
			fwrite(data_decoded, 1, decoded_len, f);
			free(data_decoded);
		}
	}
	fclose(f);

	filename = fetch_filename_from_uri(dxml->publish_uri, "rsync://");
	add_to_file_list(dxml->file_list, filename, withdraw,
	    dxml->published_already);
#endif

warnx("%s", dxml->publish_uri);

	free(dxml->publish_uri);
	free(dxml->publish_data);
	dxml->publish_uri = NULL;
	dxml->publish_data = NULL;
}

static void
start_delta_elem(struct delta_xml *dxml, const char **attr)
{
	XML_Parser p = dxml->parser;
	int has_xmlns = 0;
	int i;

	if (dxml->scope != DELTA_SCOPE_NONE)
		PARSE_FAIL(p,
		    "parse failed - entered delta elem unexpectedely");
	for (i = 0; attr[i]; i += 2) {
		const char *errstr;
		if (strcmp("xmlns", attr[i]) == 0) {
			has_xmlns = 1;
			continue;
		}
		if (strcmp("version", attr[i]) == 0) {
			dxml->version = strtonum(attr[i + 1],
			    1, MAX_VERSION, &errstr);
			if (errstr == NULL)
				continue;
		}
		if (strcmp("session_id", attr[i]) == 0) {
			dxml->session_id = xstrdup(attr[i+1]);
			continue;
		}
		if (strcmp("serial", attr[i]) == 0) {
			dxml->serial = strtonum(attr[i + 1],
			    1, LLONG_MAX, &errstr);
			if (errstr == NULL)
				continue;
		}
		PARSE_FAIL(p, "parse failed - non conforming "
		    "attribute found in delta elem");
	}
	if (!(has_xmlns && dxml->version && dxml->session_id && dxml->serial))
		PARSE_FAIL(p, "parse failed - incomplete delta attributes");
	if (strcmp(dxml->current->session_id, dxml->session_id) != 0)
		PARSE_FAIL(p, "parse failed - session_id mismatch");

	dxml->scope = DELTA_SCOPE_DELTA;
}

static void
end_delta_elem(struct delta_xml *dxml)
{
	XML_Parser p = dxml->parser;

	if (dxml->scope != DELTA_SCOPE_DELTA)
		PARSE_FAIL(p, "parse failed - exited delta "
		    "elem unexpectedely");
	dxml->scope = DELTA_SCOPE_END;

}

static void
start_publish_withdraw_elem(struct delta_xml *dxml, const char **attr,
    int withdraw)
{
	XML_Parser p = dxml->parser;
	int i, hasUri = 0, hasHash = 0;

	if (dxml->scope != DELTA_SCOPE_DELTA)
		PARSE_FAIL(p, "parse failed - entered publish/withdraw "
		    "elem unexpectedely");
	for (i = 0; attr[i]; i += 2) {
		if (strcmp("uri", attr[i]) == 0 && hasUri++ == 0) {
			dxml->publish_uri = xstrdup(attr[i+1]);
			continue;
		}
		if (strcmp("hash", attr[i]) == 0 && hasHash++ == 0) {
			if (hex_to_bin(attr[i + 1], dxml->publish_hash,
			    sizeof(dxml->publish_hash)) == 0)
				continue;
		}
		PARSE_FAIL(p, "parse failed - non conforming "
		    "attribute found in publish/withdraw elem");
	}
	if (hasUri != 1)
		PARSE_FAIL(p,
		    "parse failed - incomplete publish/withdraw attributes");
	if (withdraw && hasHash != 1)
		PARSE_FAIL(p, "parse failed - incomplete withdraw attributes");

	dxml->scope = DELTA_SCOPE_PUBLISH;
}

static void
end_publish_withdraw_elem(struct delta_xml *dxml, int withdraw)
{
	XML_Parser p = dxml->parser;

	if (dxml->scope != DELTA_SCOPE_PUBLISH)
		PARSE_FAIL(p, "parse failed - exited publish/withdraw "
		    "elem unexpectedely");
	/* XXXNF this check looks dodgy */
	if (!dxml->publish_uri)
		PARSE_FAIL(p, "parse failed - no data recovered from "
		    "publish/withdraw elem");
	/*
	 * TODO should we never keep this much and stream it straight to
	 * staging file?
	 */
	if (verify_publish(dxml) == 0)
		PARSE_FAIL(p, "failed to verify delta hash for %s",
		    dxml->publish_uri);
	write_delta(dxml, withdraw);

	dxml->scope = DELTA_SCOPE_DELTA;
}

static void
delta_xml_elem_start(void *data, const char *el, const char **attr)
{
	struct delta_xml *dxml = data;
	XML_Parser p = dxml->parser;

	/*
	 * Can only enter here once as we should have no ways to get back to
	 * NONE scope
	 */
	if (strcmp("delta", el) == 0)
		start_delta_elem(dxml, attr);
	/*
	 * Will enter here multiple times, BUT never nested. will start
	 * collecting character data in that handler
	 * mem is cleared in end block, (TODO or on parse failure)
	 */
	else if (strcmp("publish", el) == 0)
		start_publish_withdraw_elem(dxml, attr, 0);
	else if (strcmp("withdraw", el) == 0)
		start_publish_withdraw_elem(dxml, attr, 1);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
delta_xml_elem_end(void *data, const char *el)
{
	struct delta_xml *dxml = data;
	XML_Parser p = dxml->parser;

	if (strcmp("delta", el) == 0)
		end_delta_elem(dxml);
	/*
	 * TODO does this allow <publish></withdraw> or is that caught by basic
	 * xml parsing
	 */
	else if (strcmp("publish", el) == 0)
		end_publish_withdraw_elem(dxml, 0);
	else if (strcmp("withdraw", el) == 0)
		end_publish_withdraw_elem(dxml, 1);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
delta_content_handler(void *data, const char *content, int length)
{
	int new_length;
	struct delta_xml *dxml = data;

	if (dxml->scope == DELTA_SCOPE_PUBLISH) {
		/*
		 * optmisiation, this often gets called with '\n' as the
		 * only data... seems wasteful
		 */
		if (length == 1 && content[0] == '\n')
			return;

		/* append content to publish_data */
		new_length = dxml->publish_data_length + length;
		dxml->publish_data = realloc(dxml->publish_data,
		    sizeof(char)*(new_length + 1));
		if (dxml->publish_data == NULL)
			err(1, "%s - realloc", __func__);

		memcpy(dxml->publish_data +
		    dxml->publish_data_length, content, length);
		dxml->publish_data[new_length] = '\0';
		dxml->publish_data_length = new_length;
	}
}

void
log_delta_xml(struct delta_xml *dxml)
{
	logx("version: %d", dxml->version);
	logx("session_id: %s serial: %lld", dxml->session_id, dxml->serial);
}

struct delta_xml *
new_delta_xml(XML_Parser p, struct rrdp_session *rs)
{
	struct delta_xml *dxml;

	if ((dxml = calloc(1, sizeof(*dxml))) == NULL)
		err(1, "%s", __func__);
	dxml->parser = p;
	dxml->current = rs;

	if (XML_ParserReset(dxml->parser, NULL) != XML_TRUE)
		errx(1, "%s: XML_ParserReset failed", __func__);

	XML_SetElementHandler(dxml->parser, delta_xml_elem_start,
	    delta_xml_elem_end);
	XML_SetCharacterDataHandler(dxml->parser, delta_content_handler);
	XML_SetUserData(dxml->parser, dxml);

	return dxml;
}

void
free_delta_xml(struct delta_xml *dxml)
{
	if (dxml == NULL)
		return;

	free(dxml->session_id);
	free(dxml->publish_uri);
	free(dxml->publish_data);

	/* XXX TODO NUKE file_list */
	free(dxml);
}
