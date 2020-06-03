#include <stdio.h>
#include <expat.h>

typedef struct xmldata {
	XML_Parser parser;
	void *xml_data;
} XML_DATA;

int fetch_xml_url(char *url, XML_DATA *data);
void fetch_file(char *filename, FILE* stream_in);
