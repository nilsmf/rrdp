#ifndef _FETCHUTILH_
#define _FETCHUTILH_

#include <stdio.h>
#include <expat.h>
#include <openssl/sha.h>

#include <src/util.h>

typedef struct xmldata {
	OPTS *opts;
	char *uri;
	char *hash;
	SHA256_CTX ctx;
	XML_Parser parser;
	void *xml_data;
} XML_DATA;

int fetch_xml_uri(XML_DATA *data);
void fetch_file(char *filename, FILE* stream_in);

#endif

