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
#include <openssl/sha.h>

#include "log.h"
#include "rrdp.h"

enum delta_scope {
	DELTA_SCOPE_NONE,
	DELTA_SCOPE_DELTA,
	DELTA_SCOPE_PUBLISH,
	DELTA_SCOPE_END
};

struct delta_xml {
	enum delta_scope	scope;
	char			*xmlns;
	int			version;
	char			*session_id;
	int			serial;
	char			*publish_uri;
	char			*publish_hash;
	char			*publish_data;
	unsigned int		publish_data_length;
	struct notification_xml	*nxml;
};

static void
log_delta_xml(struct delta_xml *delta_xml)
{
	log_debug("scope: %d", delta_xml->scope);
	log_debug("xmlns: %s", delta_xml->xmlns ?: "NULL");
	log_debug("version: %d", delta_xml->version);
	log_debug("session_id: %s", delta_xml->session_id ?: "NULL");
	log_debug("serial: %d", delta_xml->serial);
}

static void
zero_delta_global_data(struct delta_xml *delta_xml)
{
	delta_xml->scope = DELTA_SCOPE_NONE;
	delta_xml->xmlns = NULL;
	delta_xml->version = 0;
	delta_xml->session_id = NULL;
	delta_xml->serial = 0;
}

static void
zero_delta_publish_data(struct delta_xml *delta_xml)
{
	delta_xml->publish_uri = NULL;
	delta_xml->publish_hash = NULL;
	delta_xml->publish_data = NULL;
	delta_xml->publish_data_length = 0;
}

static void
free_delta_publish_data(struct delta_xml *delta_xml)
{
	free(delta_xml->publish_uri);
	free(delta_xml->publish_hash);
	free(delta_xml->publish_data);
	zero_delta_publish_data(delta_xml);
}

static void
free_delta_xml_data(struct xmldata *xml_data)
{
	struct delta_xml *delta_xml = xml_data->xml_data;
	XML_ParserFree(xml_data->parser);
	free(delta_xml->xmlns);
	free(delta_xml->session_id);
	zero_delta_global_data(delta_xml);
	free_delta_publish_data(xml_data->xml_data);
}

enum validate_return {
	VALIDATE_RETURN_NO_FILE,
	VALIDATE_RETURN_FILE_DEL,
	VALIDATE_RETURN_HASH_MISMATCH,
	VALIDATE_RETURN_HASH_MATCH
};


static enum validate_return
validate_publish_hash(struct delta_xml *delta_xml, struct opts *opts,
    int primary)
{
	FILE *f;
	int BUFF_SIZE = 200;
	char read_buff[BUFF_SIZE];
	size_t buff_len;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	unsigned char bin_hash[SHA256_DIGEST_LENGTH];
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
	if (!SHA256_Final(obuff, &ctx) || !hash ||
	    strlen(hash) < 2*SHA256_DIGEST_LENGTH)
		return VALIDATE_RETURN_HASH_MISMATCH;
	for (int n = 0; n < SHA256_DIGEST_LENGTH; n++) {
		if (sscanf(&hash[2*n], "%2hhx", &bin_hash[n]) != 1)
			return VALIDATE_RETURN_HASH_MISMATCH;
	}
	if (!memcmp(bin_hash, obuff, SHA256_DIGEST_LENGTH))
		return VALIDATE_RETURN_HASH_MATCH;
	return VALIDATE_RETURN_HASH_MISMATCH;
}

static int
verify_publish(struct xmldata *xml_data)
{
	struct delta_xml *delta_xml = xml_data->xml_data;
	enum validate_return v_return;

	/* Check working dir first */
	v_return = validate_publish_hash(delta_xml, xml_data->opts, 0);
	/* Check the primary dir if we haven't seen the file this delta run */
	if (v_return == VALIDATE_RETURN_NO_FILE) {
		v_return = validate_publish_hash(delta_xml, xml_data->opts, 1);
	}
	/* delta expects file to exist and match */
	if (delta_xml->publish_hash) {
		if (v_return == VALIDATE_RETURN_HASH_MATCH)
			return 1;
		log_warnx("hash validation mismatch");
		return 0;
	/* delta expects file to not exist (or have been deleted) */
	} else if (v_return <= VALIDATE_RETURN_FILE_DEL)
		return 1;
	log_warnx("found file but without hash");
	return 0;
}

static void
write_delta(struct xmldata *xml_data, int withdraw)
{
	struct delta_xml *delta_xml = xml_data->xml_data;
	FILE *f;
	unsigned char *data_decoded;
	int decoded_len;

	if (withdraw && xml_data->opts->ignore_withdraw)
		return;
	f = open_working_uri_write(delta_xml->publish_uri, xml_data->opts);
	if (f == NULL)
		fatal("%s - file open fail", __func__);
	if (withdraw) {
		fclose(f);
		return;
	}
	/* decode b64 message */
	decoded_len = b64_decode(delta_xml->publish_data, &data_decoded);
	if (decoded_len > 0) {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);
}

static void
start_delta_elem(struct xmldata *xml_data, const char **attr)
{
	XML_Parser p = xml_data->parser;
	struct delta_xml *delta_xml = xml_data->xml_data;
	int i;

	if (delta_xml->scope != DELTA_SCOPE_NONE)
		PARSE_FAIL(p, "parse failed - entered delta elem"
		    " unexpectedely");
	for (i = 0; attr[i]; i += 2) {
		if (strcmp("xmlns", attr[i]) == 0)
			delta_xml->xmlns = xstrdup(attr[i+1]);
		else if (strcmp("version", attr[i]) == 0)
			delta_xml->version =
			    (int)strtol(attr[i+1], NULL, BASE10);
		else if (strcmp("session_id", attr[i]) == 0)
			delta_xml->session_id = xstrdup(attr[i+1]);
		else if (strcmp("serial", attr[i]) == 0)
			delta_xml->serial =
			    (int)strtol(attr[i+1], NULL, BASE10);
		else
			PARSE_FAIL(p, "parse failed - non conforming "
			    "attribute found in delta elem");
	}
	if (!(delta_xml->xmlns &&
	      delta_xml->version &&
	      delta_xml->session_id &&
	      delta_xml->serial))
		PARSE_FAIL(p, "parse failed - incomplete delta attributes");
	if (delta_xml->version <= 0 || delta_xml->version > MAX_VERSION)
		PARSE_FAIL(p, "parse failed - invalid version");
	if (strcmp(delta_xml->nxml->session_id, delta_xml->session_id) != 0)
		PARSE_FAIL(p, "parse failed - session_id mismatch");

	delta_xml->scope = DELTA_SCOPE_DELTA;
}

static void
end_delta_elem(struct xmldata *xml_data)
{
	XML_Parser p = xml_data->parser;
	struct delta_xml *delta_xml = xml_data->xml_data;

	if (delta_xml->scope != DELTA_SCOPE_DELTA) {
		PARSE_FAIL(p, "parse failed - exited delta "
		    "elem unexpectedely");
	}
	delta_xml->scope = DELTA_SCOPE_END;

}

static void
start_publish_withdraw_elem(struct xmldata *xml_data, const char **attr,
    int withdraw)
{
	XML_Parser p = xml_data->parser;
	struct delta_xml *delta_xml = xml_data->xml_data;
	int i;

	if (delta_xml->scope != DELTA_SCOPE_DELTA)
		PARSE_FAIL(p, "parse failed - entered publish/withdraw "
		    "elem unexpectedely");
	for (i = 0; attr[i]; i += 2) {
		if (strcmp("uri", attr[i]) == 0)
			delta_xml->publish_uri = xstrdup(attr[i+1]);
		else if (strcmp("hash", attr[i]) == 0)
			delta_xml->publish_hash = xstrdup(attr[i+1]);
		else if (strcmp("xmlns", attr[i]) == 0);
			/* XXX should we do nothing? */
		else
			PARSE_FAIL(p, "parse failed - non conforming "
			    "attribute found in publish/withdraw elem");
	}
	if (!delta_xml->publish_uri)
		PARSE_FAIL(p, "parse failed - incomplete publish/withdraw attributes");
	if (withdraw && !delta_xml->publish_hash) {
		PARSE_FAIL(p, "parse failed - incomplete withdraw attributes");
	}
	delta_xml->scope = DELTA_SCOPE_PUBLISH;

}

static void
end_publish_withdraw_elem(struct xmldata *xml_data, int withdraw)
{
	XML_Parser p = xml_data->parser;
	struct delta_xml *delta_xml = xml_data->xml_data;

	if (delta_xml->scope != DELTA_SCOPE_PUBLISH) {
		PARSE_FAIL(p, "parse failed - exited publish/withdraw "
		    "elem unexpectedely");
	}
	/* XXXNF this check looks dodgy */
	if (!delta_xml->publish_uri) {
		PARSE_FAIL(p, "parse failed - no data recovered from "
		    "publish/withdraw elem");
	}
	/*
	 * TODO should we never keep this much and stream it straight to
	 * staging file?
	 */
	if (verify_publish(xml_data) == 0) {
		PARSE_FAIL(p, "failed to verify delta hash:\n%s\n%s\n%s",
		    delta_xml->publish_hash, delta_xml->publish_uri,
		    xml_data->opts->basedir_working);
	}

	write_delta(xml_data, withdraw);
	free_delta_publish_data(delta_xml);
	delta_xml->scope = DELTA_SCOPE_DELTA;
}

static void
delta_xml_elem_start(void *data, const char *el, const char **attr)
{
	struct xmldata *xml_data = data;
	XML_Parser p = xml_data->parser;

	/*
	 * Can only enter here once as we should have no ways to get back to
	 * NONE scope
	 */
	if (strcmp("delta", el) == 0)
		start_delta_elem(data, attr);
	/*
	 * Will enter here multiple times, BUT never nested. will start
	 * collecting character data in that handler
	 * mem is cleared in end block, (TODO or on parse failure)
	 */
	else if (strcmp("publish", el) == 0)
		start_publish_withdraw_elem(data, attr, 0);
	else if (strcmp("withdraw", el) == 0)
		start_publish_withdraw_elem(data, attr, 1);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
delta_xml_elem_end(void *data, const char *el)
{
	struct xmldata *xml_data = data;
	XML_Parser p = xml_data->parser;

	if (strcmp("delta", el) == 0)
		end_delta_elem(data);
	/*
	 * TODO does this allow <publish></withdraw> or is that caught by basic
	 * xml parsing
	 */
	else if (strcmp("publish", el) == 0)
		end_publish_withdraw_elem(data, 0);
	else if (strcmp("withdraw", el) == 0)
		end_publish_withdraw_elem(data, 1);
	else
		PARSE_FAIL(p, "parse failed - unexpected elem exit found");
}

static void
delta_content_handler(void *data, const char *content, int length)
{
	int new_length;
	struct xmldata *xml_data = data;
	struct delta_xml *delta_xml = xml_data->xml_data;

	if (delta_xml->scope == DELTA_SCOPE_PUBLISH) {
		/*
		 * optmisiation, this often gets called with '\n' as the
		 * only data... seems wasteful
		 */
		if (length == 1 && content[0] == '\n')
			return;

		/* append content to publish_data */
		new_length = delta_xml->publish_data_length + length;
		delta_xml->publish_data = realloc(delta_xml->publish_data,
		    sizeof(char)*(new_length + 1));
		if (delta_xml->publish_data == NULL)
			fatal("%s - realloc", __func__);

		memcpy(delta_xml->publish_data +
		    delta_xml->publish_data_length, content, length);
		delta_xml->publish_data[new_length] = '\0';
		delta_xml->publish_data_length = new_length;
	}
}

static void
setup_xml_data(struct xmldata *xml_data, struct delta_xml *delta_xml,
    char *uri, char *hash, struct opts *opts, struct notification_xml *nxml)
{
	xml_data->uri = uri;
	xml_data->opts = opts;
	xml_data->hash = hash;
	/* delta doesn't use modified since */
	xml_data->modified_since[0] = '\0';

	xml_data->parser = XML_ParserCreate(NULL);
	if (xml_data->parser == NULL)
		fatalx("%s - XML_ParserCreate", __func__);
	XML_SetElementHandler(xml_data->parser, delta_xml_elem_start,
	    delta_xml_elem_end);
	XML_SetCharacterDataHandler(xml_data->parser, delta_content_handler);
	XML_SetUserData(xml_data->parser, xml_data);

	xml_data->xml_data = delta_xml;
	zero_delta_global_data(delta_xml);
	zero_delta_publish_data(delta_xml);
	delta_xml->nxml = nxml;
}

int
fetch_delta_xml(char *uri, char *hash, struct opts *opts,
    struct notification_xml* nxml)
{
	struct xmldata xml_data;
	struct delta_xml delta_xml;
	int ret = 0;
	setup_xml_data(&xml_data, &delta_xml, uri, hash, opts, nxml);
	if (fetch_xml_uri(&xml_data) != 200)
		ret = 1;
	free_delta_xml_data(&xml_data);
	return ret;
}

