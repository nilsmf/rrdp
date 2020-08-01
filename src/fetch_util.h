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

#ifndef _FETCHUTILH_
#define _FETCHUTILH_

#include <stdio.h>
#include <expat.h>
#include <openssl/sha.h>

#include "util.h"

#define TIME_FORMAT "%a, %d %b %Y %T GMT"
#define TIME_LEN 30

/* save everyone doing this code over and over */
#define PARSE_FAIL(p, ...) do {		\
	XML_StopParser(p, XML_FALSE);	\
	log_warnx(__VA_ARGS__);		\
	return;				\
} while(0)

struct xmldata {
	struct opts *opts;
	char *uri;
	char *hash;
	char modified_since[TIME_LEN];
	SHA256_CTX ctx;
	XML_Parser parser;
	void *xml_data;
};

long fetch_xml_uri(struct xmldata *);
long ftp_fetch_xml(struct xmldata *);

#endif

