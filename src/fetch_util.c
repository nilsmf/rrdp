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
#include <time.h>
#include <curl/curl.h>

#include "fetch_util.h"
#include "log.h"

#define USER_AGENT "rrdp-client v0.1"
#define IF_MODIFIED_SINCE "If-Modified-Since"
#define DATE "Date"


static size_t
write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct xmldata *xml_data = userdata;
	XML_Parser p = xml_data->parser;
	if (xml_data->hash)
		SHA256_Update(&xml_data->ctx, (const u_int8_t *)ptr, nmemb);
	if (!p)
		return 0;
	if (!XML_Parse(p, ptr, nmemb, 0)) {
		fprintf(stderr, "Parse error at line %lu:\n%s\n",
			XML_GetCurrentLineNumber(p),
			XML_ErrorString(XML_GetErrorCode(p)));
		err(1, "parse failed - basic xml error");
	}
	return nmemb;
}

/* if we cant set curl options we are not going to be able to do much */
static void
xcurl_easy_setopt(CURL *handle, CURLoption option, void *parameter) {
	if (curl_easy_setopt(handle, option, parameter) != CURLE_OK)
		fatalx("failed to set curl option");
}

long
fetch_xml_uri(struct xmldata *data)
{
	CURL *curl;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	char obuff_hex[SHA256_DIGEST_LENGTH*2 + 1];
	char curl_errors[CURL_ERROR_SIZE];
	struct curl_slist *headers = NULL;
	char *modified_since = NULL;
	time_t current_time;
	struct tm *gmt_time;
	int n;
	long response_code;

	if (!data || !data->uri) {
		log_warnx("missing url");
		return -1;
	}
	if (data->hash && strlen(data->hash) != SHA256_DIGEST_LENGTH*2) {
		log_warnx("invalid hash");
		return -1;
	}
	if ((curl = curl_easy_init()) == NULL)
		fatal("curl init failure");

	log_info("starting curl: %s", data->uri);
	if (data->hash)
		SHA256_Init(&data->ctx);
	/* abuse that we never use modified since if we have a hash */
	else {
		if (strlen(data->modified_since) != 0) {
			if ((asprintf(&modified_since, "%s: %s",
			    IF_MODIFIED_SINCE, data->modified_since)) == -1)
				fatal("%s - asprintf", __func__);
			headers = curl_slist_append(headers, modified_since);
		}
		/*
		 * XXXNF time from client should all be backup in case we cant
		 * get a last_modified or date header
		 */
		/* get current gmt time to save for next time */
		if ((current_time = time(NULL)) == (time_t)-1)
			fatal("%s - time", __func__);
		if ((gmt_time = gmtime(&current_time)) == NULL)
			fatal("%s - gmtime", __func__);
		/*
		 * XXXNF function is not allowed to be called again now in case
		 * of network failure
		 */
		/* XXXNF what to do about localisation */
		if (strftime(data->modified_since, TIME_LEN, TIME_FORMAT,
		    gmt_time) != TIME_LEN - 1)
			fatal("%s - strftime", __func__);
	}
	CURLcode res;
	xcurl_easy_setopt(curl, CURLOPT_URL, data->uri);
	xcurl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	xcurl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
	xcurl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	xcurl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
	xcurl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errors);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK)
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	else
		log_warnx("curl not ok (%d): %s", res, curl_errors);

	curl_slist_free_all(headers);
	free(modified_since);
	curl_easy_cleanup(curl);
	/* always clean the ctx up */
	if (data->hash)
		SHA256_Final(obuff, &data->ctx);
	if (res != CURLE_OK)
		return -1;
	if (data->hash) {
		for (n = 0; n < SHA256_DIGEST_LENGTH; n++) {
			sprintf(obuff_hex + 2*n, "%02x",
			    (unsigned int)obuff[n]);
		}
		if (strncasecmp(data->hash, obuff_hex,
		    SHA256_DIGEST_LENGTH*2)) {
			log_warnx("hash mismatch \n   '%.*s'\nvs '%.*s'",
			    SHA256_DIGEST_LENGTH*2, data->hash,
			    SHA256_DIGEST_LENGTH*2, obuff_hex);
			return -1;
		}
	}
	return response_code;
}

