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
print_delta_xml(struct delta_xml *delta_xml)
{
	printf("scope: %d\n", delta_xml->scope);
	printf("xmlns: %s\n", delta_xml->xmlns ?: "NULL");
	printf("version: %d\n", delta_xml->version);
	printf("session_id: %s\n", delta_xml->session_id ?: "NULL");
	printf("serial: %d\n", delta_xml->serial);
}

enum validate_return {
	VALIDATE_RETURN_NO_FILE,
	VALIDATE_RETURN_FILE_DEL,
	VALIDATE_RETURN_HASH_MISMATCH,
	VALIDATE_RETURN_HASH_MATCH
};


static enum validate_return
validate_publish_hash(char *filename, char *hash)
{
	int BUFF_SIZE = 200;
	char read_buff[BUFF_SIZE];
	size_t buff_len;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	unsigned char bin_hash[SHA256_DIGEST_LENGTH];
	int first_read = 1;
	FILE *f = fopen(filename, "r");
	printf("validating file: %s...\n", filename);
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
	char *filename = NULL;
	enum validate_return v_return;
	/* Check working dir first */
	filename = generate_filename_from_uri(delta_xml->publish_uri,
	    xml_data->opts->basedir_working, NULL);
	v_return = validate_publish_hash(filename, delta_xml->publish_hash);
	/* Check the primary dir if we haven't seen the file this delta run */
	if (v_return == VALIDATE_RETURN_NO_FILE) {
		free(filename);
		filename = generate_filename_from_uri(delta_xml->publish_uri,
		    xml_data->opts->basedir_primary, NULL);
		v_return = validate_publish_hash(filename,
		    delta_xml->publish_hash);
	}
	free(filename);
	/* delta expects file to exist and match */
	if (delta_xml->publish_hash) {
		return v_return == VALIDATE_RETURN_HASH_MATCH;
	/* delta expects file to not exist (or have been deleted) */
	} else {
		return v_return <= VALIDATE_RETURN_FILE_DEL;
	}
}

static FILE *
open_delta_file(const char *publish_uri, const char *basedir)
{
	if (!publish_uri)
		err(1, "tried to write to defunct publish uri");
	/*
	 * TODO what are our max lengths? 4096 seems to be safe catchall
	 * according to RFC-8181
	 */
	char *filename = generate_filename_from_uri(publish_uri, basedir, NULL);
	/* TODO quick and dirty getting path */
	/* create dir if necessary */
	char *path_delim = strrchr(filename, '/');
	path_delim[0] = '\0';
	mkpath(filename, 0777);
	path_delim[0] = '/';
	FILE *f = fopen(filename, "w");
	free(filename);
	return f;
}

static int
write_delta_publish(struct xmldata *xml_data)
{
	struct delta_xml *delta_xml = xml_data->xml_data;
	unsigned char *data_decoded;
	int decoded_len = 0;
	FILE *f;
	if (!(f = open_delta_file(delta_xml->publish_uri,
	    xml_data->opts->basedir_working)))
		err(1, "file open error");
	/* decode b64 message */
	decoded_len = b64_decode(delta_xml->publish_data, &data_decoded);
	if (decoded_len > 0) {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);
	return delta_xml->publish_data_length;
}

static int
write_delta_withdraw(struct xmldata* xml_data)
{
	/*
	 * TODO files to remove could be in working or primary. best way to
	 * solve?
	 * I think adding the file as empty and then applying in order and then
	 * after applying to primary removing empty files should track correctly
	 * or keep list in memory and append or remove as we progress...
	 */
	struct delta_xml *delta_xml = xml_data->xml_data;
	FILE *f;
	if (!(f = open_delta_file(delta_xml->publish_uri,
	    xml_data->opts->basedir_working)))
		err(1, "file open error withdraw");
	fclose(f);
	return 0;
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
			write_delta_publish(xml_data);
		} else
			write_delta_withdraw(xml_data);
		free(delta_xml->publish_uri);
		delta_xml->publish_uri = NULL;
		free(delta_xml->publish_hash);
		delta_xml->publish_hash = NULL;
		free(delta_xml->publish_data);
		delta_xml->publish_data = NULL;
		delta_xml->publish_data_length = 0;
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

struct xmldata *
new_delta_xml_data(char *uri, char *hash, struct opts *opts,
    struct notification_xml *nxml)
{
	struct xmldata *xml_data;

	if ((xml_data = calloc(1, sizeof(struct xmldata))) == NULL)
		err(1, NULL);

	if ((xml_data->xml_data = calloc(1, sizeof(struct delta_xml))) == NULL)
		err(1, NULL);

	xml_data->uri = uri;
	xml_data->opts = opts;
	xml_data->hash = hash;
	((struct delta_xml*)xml_data->xml_data)->nxml = nxml;

	xml_data->parser = XML_ParserCreate(NULL);
	if (xml_data->parser == NULL)
		err(1, "XML_ParserCreate");
	XML_SetElementHandler(xml_data->parser, delta_elem_start,
	    delta_elem_end);
	XML_SetCharacterDataHandler(xml_data->parser, delta_content_handler);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

