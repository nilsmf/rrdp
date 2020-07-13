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

#include "delta.h"
#include "log.h"
#include "file_util.h"

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
	log_info("scope: %d", delta_xml->scope);
	log_info("xmlns: %s", delta_xml->xmlns ?: "NULL");
	log_info("version: %d", delta_xml->version);
	log_info("session_id: %s", delta_xml->session_id ?: "NULL");
	log_info("serial: %d", delta_xml->serial);
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
	struct delta_xml *delta_xml;
	XML_ParserFree(xml_data->parser);
	delta_xml = xml_data->xml_data;
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

	if (primary)
		f = open_primary_uri_read(delta_xml->publish_uri, opts);
	else
		f = open_working_uri_read(delta_xml->publish_uri, opts);
	if (!f)
		return VALIDATE_RETURN_NO_FILE;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	while ((buff_len = fread(read_buff, 1, BUFF_SIZE, f))) {
		/* empty file = withdrawn */
		if (first_read && buff_len == 0) {
			fclose(f);
			return VALIDATE_RETURN_FILE_DEL;
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

	v_return = validate_publish_hash(delta_xml, xml_data->opts, 1);
	/* Check the primary dir if we haven't seen the file this delta run */
	if (v_return == VALIDATE_RETURN_NO_FILE) {
		v_return = validate_publish_hash(delta_xml, xml_data->opts, 0);
	}
	/* delta expects file to exist and match */
	if (delta_xml->publish_hash) {
		return v_return == VALIDATE_RETURN_HASH_MATCH;
	/* delta expects file to not exist (or have been deleted) */
	} else {
		return v_return <= VALIDATE_RETURN_FILE_DEL;
	}
}

static int
write_delta(struct xmldata *xml_data, int withdraw)
{
	struct delta_xml *delta_xml = xml_data->xml_data;
	FILE *f;
	unsigned char *data_decoded;
	int decoded_len;

	f = open_working_uri_write(delta_xml->publish_uri, xml_data->opts);
	if (f == NULL)
		err(1, "%s", __func__);
	if (withdraw) {
		fclose(f);
		return 0;
	}
	/* decode b64 message */
	decoded_len = b64_decode(delta_xml->publish_data, &data_decoded);
	if (decoded_len > 0) {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);
	return delta_xml->publish_data_length;
}

static void
delta_elem_start(void *data, const char *el, const char **attr)
{
	struct xmldata *xml_data = data;
	struct delta_xml *delta_xml = xml_data->xml_data;
	int i;

	/*
	 * Can only enter here once as we should have no ways to get back to
	 * NONE scope
	 */
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_NONE)
			err(1, "parse failed - entered delta elem "
			    "unexpectedely");
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0)
				delta_xml->xmlns = strdup(attr[i+1]);
			else if (strcmp("version", attr[i]) == 0)
				delta_xml->version =
				    (int)strtol(attr[i+1], NULL, BASE10);
			else if (strcmp("session_id", attr[i]) == 0)
				delta_xml->session_id = strdup(attr[i+1]);
			else if (strcmp("serial", attr[i]) == 0)
				delta_xml->serial =
				    (int)strtol(attr[i+1], NULL, BASE10);
			else
				err(1, "parse failed - non conforming "
				    "attribute found in delta elem");
		}
		if (!(delta_xml->xmlns &&
		      delta_xml->version &&
		      delta_xml->session_id &&
		      delta_xml->serial))
			err(1, "parse failed - incomplete delta attributes");
		if (delta_xml->version <= 0 ||
		    delta_xml->version > MAX_VERSION)
			err(1, "parse failed - invalid version");
		if (strcmp(delta_xml->nxml->session_id, delta_xml->session_id)
		    != 0)
			err(1, "parse failed - session_id mismatch");

		delta_xml->scope = DELTA_SCOPE_DELTA;
	/*
	 * Will enter here multiple times, BUT never nested. will start
	 * collecting character data in that handler
	 * mem is cleared in end block, (TODO or on parse failure)
	 */
	} else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA)
			err(1, "parse failed - entered publish "
			    "elem unexpectedely");
		for (i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0)
				delta_xml->publish_uri = strdup(attr[i+1]);
			else if (strcmp("hash", attr[i]) == 0)
				delta_xml->publish_hash = strdup(attr[i+1]);
			else if (strcmp("xmlns", attr[i]) == 0);
				/* XXX should we do nothing? */
			else
				err(1, "parse failed - non conforming "
				    "attribute found in publish elem");
		}
		if (!delta_xml->publish_uri)
			err(1, "parse failed - incomplete publish attributes");
		if (strcmp("withdraw", el) == 0 && !delta_xml->publish_hash) {
			err(1, "parse failed - incomplete withdraw attributes");
		}
		delta_xml->scope = DELTA_SCOPE_PUBLISH;
	} else
		err(1, "parse failed - unexpected elem exit found");
}

static void
delta_elem_end(void *data, const char *el)
{
	struct xmldata *xml_data = data;
	struct delta_xml *delta_xml = xml_data->xml_data;
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA)
			err(1, "parse failed - exited delta "
			    "elem unexpectedely");
		delta_xml->scope = DELTA_SCOPE_END;
	}
	/*
	 * TODO does this allow <publish></withdraw> or is that caught by basic
	 * xml parsing
	 */
	else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_PUBLISH)
			err(1, "parse failed - exited publish "
			    "elem unexpectedely");
		if (!delta_xml->publish_uri)
			err(1, "parse failed - no data recovered from "
			    "publish elem");
		/*
		 * TODO should we never keep this much and stream it straight to
		 * staging file?
		 */
		if (!verify_publish(xml_data))
			err(1, "failed to verify delta hash");

		if (strcmp("publish", el) == 0) {
			write_delta(xml_data, 0);
		} else
			write_delta(xml_data, 1);
		free_delta_publish_data(delta_xml);
		delta_xml->scope = DELTA_SCOPE_DELTA;
	} else
		err(1, "parse failed - unexpected elem exit found");
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
			err(1, "%s", __func__);

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
	xml_data->parser = XML_ParserCreate(NULL);
	if (xml_data->parser == NULL)
		err(1, "XML_ParserCreate");
	XML_SetElementHandler(xml_data->parser, delta_elem_start,
	    delta_elem_end);
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
	if (fetch_xml_uri(&xml_data) != 0)
		ret = 1;
	free_delta_xml_data(&xml_data);
	return ret;
}

