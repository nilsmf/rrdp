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

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <curl/curl.h>

#include "fetch_util.h"

#define USER_AGENT "rrdp-client v0.1"

static size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct xmldata *xml_data = userdata;
	XML_Parser p = xml_data->parser;
	if (xml_data->hash) {
		SHA256_Update(&xml_data->ctx, (const u_int8_t *)ptr, nmemb);
	}
	if (!p) {
		return 0;
	}
	if (!XML_Parse(p, ptr, nmemb, 0)) {
		fprintf(stderr, "Parse error at line %lu:\n%s\n",
			XML_GetCurrentLineNumber(p),
			XML_ErrorString(XML_GetErrorCode(p)));
		err(1, "parse failed - basic xml error");
	}
	return nmemb;
}

int
fetch_xml_uri(struct xmldata *data)
{
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	char obuff_hex[SHA256_DIGEST_LENGTH*2 + 1];
	int n;

	if (!data || !data->uri) {
		err(1, "missing url");
	}
	CURL *curl = curl_easy_init();
	if (curl) {
		printf("starting curl: %s\n", data->uri);
		fflush(stdout);
		if (data->hash) {
			SHA256_Init(&data->ctx);
			if (strlen(data->hash) != SHA256_DIGEST_LENGTH*2) {
				err(1, "invalid hash");
			}
		}
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, data->uri);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
		res = curl_easy_perform(curl);
		printf("curl response: %d\n", res);
		fflush(stdout);
		curl_easy_cleanup(curl);
		if (data->hash) {
			SHA256_Final(obuff, &data->ctx);
			for (n = 0; n < SHA256_DIGEST_LENGTH; n++)
				sprintf(obuff_hex + 2*n, "%02x", (unsigned int)obuff[n]);
			if(strncasecmp(data->hash, obuff_hex, SHA256_DIGEST_LENGTH*2)) {
				printf("hash '%.*s'\nvs   '%.*s'\n", SHA256_DIGEST_LENGTH*2, data->hash, SHA256_DIGEST_LENGTH*2, obuff_hex);
				fflush(stdout);
				err(1, "invalid hash");
			}
		}
		return res;
	} else {
		err(1, "curl init failure");
	}
}

