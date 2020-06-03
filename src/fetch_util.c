#include <stdio.h>
#include <err.h>
#include <curl/curl.h>

#include <src/fetch_util.h>

#define USER_AGENT "rrdp-client v0.1"

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
	XML_Parser p = ((XML_DATA*)userdata)->parser;
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

int fetch_xml_url(char *url, XML_DATA *data) {
	if (!url) {
		err(1, "missing url");
	}
	CURL *curl = curl_easy_init();
	if (curl) {
		printf("starting curl: %s\n", url);
		fflush(stdout);
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
		res = curl_easy_perform(curl);
		printf("curl response: %d\n", res);
		fflush(stdout);
		curl_easy_cleanup(curl);
		return res;
	} else {
		err(1, "curl init failure");
	}
}

void fetch_file(char *filename, FILE* stream_in) {
	FILE *f;
	if (!filename) {
		err(1, "missing filename");
	}
	if ((f = fopen(filename, "r"))) {
		char read_buffer[200];
		//printf("reading\n");
		while (fgets(read_buffer, 200, f)) {
			//printf("%ld chars read:\n", strlen(read_buffer));
			fprintf(stream_in, "%.200s", read_buffer);
			fflush(stream_in);
		}
	} else {
		err(1, "fopen fail: %s", filename);
	}
}

