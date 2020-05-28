#include <stdio.h>
#include <err.h>
#include <curl/curl.h>

#define USER_AGENT "rrdp-client v0.1"

void fetch_url(char *url, FILE* stream_in) {
	int res = -1;
	if (!url) {
		err(1, "missing url");
	}
	CURL *curl = curl_easy_init();
	if (curl) {
		printf("starting curl\n");
		fflush(stdout);
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream_in);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
		res = curl_easy_perform(curl);
		printf("curl response: %d\n", res);
		fflush(stdout);
		curl_easy_cleanup(curl);
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

