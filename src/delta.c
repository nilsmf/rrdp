#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <err.h>

#include <expat.h>
#include <openssl/sha.h>

#include <src/delta.h>

typedef enum delta_scope {
	DELTA_SCOPE_NONE,
	DELTA_SCOPE_DELTA,
	DELTA_SCOPE_PUBLISH,
	DELTA_SCOPE_END
} DELTA_SCOPE;

typedef struct deltaXML {
	DELTA_SCOPE scope;
	char *xmlns;
	char *version;
	char *session_id;
	int serial;
	char *publish_uri;
	char *publish_hash;
	char *publish_data;
	unsigned int publish_data_length;
} DELTA_XML;

void print_delta_xml(DELTA_XML *delta_xml) {
	printf("scope: %d\n", delta_xml->scope);
	printf("xmlns: %s\n", delta_xml->xmlns ?: "NULL");
	printf("version: %s\n", delta_xml->version ?: "NULL");
	printf("session_id: %s\n", delta_xml->session_id ?: "NULL");
	printf("serial: %d\n", delta_xml->serial);
}

char *get_hex_hash(FILE *f, char *obuff_hex) {
	int BUFF_SIZE = 200;
	char read_buff[BUFF_SIZE];
	size_t buff_len;
	unsigned char obuff[SHA256_DIGEST_LENGTH];
	if (f && obuff_hex) {
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		while ((buff_len = fread(read_buff, 1, BUFF_SIZE, f))) {
			SHA256_Update(&ctx, (const u_int8_t *)read_buff, buff_len);
		}
		SHA256_Final(obuff, &ctx);
		for (int n = 0; n < SHA256_DIGEST_LENGTH; n++)
			sprintf(obuff_hex + 2*n, "%02x", (unsigned int)obuff[n]);
		return obuff_hex;
	}
	return NULL;
}

int verify_publish(XML_DATA *xml_data) {
	DELTA_XML *delta_xml = (DELTA_XML *)xml_data->xml_data;
	char obuff_hex[SHA256_DIGEST_LENGTH*2];
	char *filename = NULL;
	FILE *f = NULL;
	//delta expects file to exist
	if (delta_xml->publish_hash) {
		filename = generate_filename_from_uri(delta_xml->publish_uri, xml_data->opts->basedir_primary, NULL);
		printf("validating file: %s...", filename);
		f = fopen(filename, "r");
	}
	if (!get_hex_hash(f, obuff_hex)) {
		if (f) {
			fclose(f);
			f = NULL;
		}
		free(filename);
		filename = NULL;
		//verify from working dir if not found in base in case of multiple applied deltas this run
		filename = generate_filename_from_uri(delta_xml->publish_uri, xml_data->opts->basedir_working, NULL);
		f = fopen(filename, "r");
		if (!get_hex_hash(f, obuff_hex)) {
			//delta expected hash but was not found
			if (delta_xml->publish_hash) {
				printf("2 didn't find expected hash for file %s\n", filename);
				free(filename);
				if (f)
					fclose(f);
				//return 1;
				fflush(stdout);
				return 0;
			}
		//delta didn't expect hash but was found
		} else if (!delta_xml->publish_hash) {
			printf("2 found unexpected hash (%s) for file %s\n", obuff_hex, filename);
			free(filename);
			if (f)
				fclose(f);
			//return 1;
			fflush(stdout);
			err(1, "omg");
			return 0;
		}

		free(filename);
		if (f)
			fclose(f);
	} else if (!delta_xml->publish_hash) {
		//delta didn't expect hash but was found
		//return 1;
		printf("1 found unexpected hash (%s) for file %s\n", obuff_hex, filename);
		free(filename);
		if (f)
			fclose(f);
		return 0;
	}
	if (delta_xml->publish_hash)
		printf("old: %s\nvs\nexpected hash:%s\n", obuff_hex, delta_xml->publish_hash);

	//TODO: turn this back on
	//return !strncmp(obuff_hex, delta->xml_publish_hash, SHA256_DIGEST_LENGTH*2);

	return 0;
}

FILE *open_delta_file(const char *publish_uri, const char *basedir) {
	if (!publish_uri) {
		err(1, "tried to write to defunct publish uri");
	}
	//TODO what are our max lengths? 4096 seems to be safe catchall according to RFC-8181
	char *filename = generate_filename_from_uri(publish_uri, basedir, NULL);
	// TODO quick and dirty getting path
	//create dir if necessary
	char *path_delim = strrchr(filename, '/');
	path_delim[0] = '\0';
	mkpath(filename, 0777);
	path_delim[0] = '/';
	FILE *f = fopen(filename, "w");
	free(filename);
	return f;
}

int write_delta_publish(XML_DATA *xml_data) {
	DELTA_XML *delta_xml = xml_data->xml_data;
	unsigned char *data_decoded;
	int decoded_len = 0;
	FILE *f;
	if (!(f = open_delta_file(delta_xml->publish_uri, xml_data->opts->basedir_working))) {
		err(1, "file open error");
	}
	//TODO decode b64 message
	decoded_len = b64_decode(delta_xml->publish_data, delta_xml->publish_data_length, &data_decoded);
	if (decoded_len > 0) {
		fwrite(data_decoded, 1, decoded_len, f);
		free(data_decoded);
	}
	fclose(f);
	return delta_xml->publish_data_length;
}

int write_delta_withdraw(XML_DATA* xml_data) {
	//TODO files to remove could be in working or primary. best way to solve?
	// I think adding the file as empty and then applying in order and then after applying to primary removing empty files should track correctly
	// or keep list in memory and append or remove as we progress...
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
	FILE *f;
	if (!(f = open_delta_file(delta_xml->publish_uri, xml_data->opts->basedir_working))) {
		err(1, "file open error");
	}
	fclose(f);
	return 0;
}

void delta_elem_start(void *data, const char *el, const char **attr) {
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
	// Can only enter here once as we should have no ways to get back to NONE scope
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_NONE) {
			err(1, "parse failed - entered delta elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("xmlns", attr[i]) == 0) {
				delta_xml->xmlns = strdup(attr[i+1]);
			} else if (strcmp("version", attr[i]) == 0) {
				delta_xml->version = strdup(attr[i+1]);
			} else if (strcmp("session_id", attr[i]) == 0) {
				delta_xml->session_id = strdup(attr[i+1]);
			} else if (strcmp("serial", attr[i]) == 0) {
				delta_xml->serial = (int)strtol(attr[i+1],NULL,BASE10);
			} else {
				err(1, "parse failed - non conforming attribute found in delta elem");
			}
		}
		if (!(delta_xml->xmlns &&
		      delta_xml->version &&
		      delta_xml->session_id &&
		      delta_xml->serial)) {
			err(1, "parse failed - incomplete delta attributes");
		}

		delta_xml->scope = DELTA_SCOPE_DELTA;
		//print_delta_xml(delta_xml);
	// Will enter here multiple times, BUT never nested. will start collecting character data in that handler
	// mem is cleared in end block, (TODO or on parse failure)
	} else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA) {
			err(1, "parse failed - entered publish elem unexpectedely");
		}
		for (int i = 0; attr[i]; i += 2) {
			if (strcmp("uri", attr[i]) == 0) {
				delta_xml->publish_uri = strdup(attr[i+1]);
			} else if (strcmp("hash", attr[i]) == 0) {
				delta_xml->publish_hash = strdup(attr[i+1]);
			} else if (strcmp("xmlns", attr[i]) == 0) {
			} else {
				err(1, "parse failed - non conforming attribute found in publish elem");
			}
		}
		if (!delta_xml->publish_uri) {
			err(1, "parse failed - incomplete publish attributes");
		}
		delta_xml->scope = DELTA_SCOPE_PUBLISH;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void delta_elem_end(void *data, const char *el) {
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
	if (strcmp("delta", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_DELTA) {
			err(1, "parse failed - exited delta elem unexpectedely");
		}
		delta_xml->scope = DELTA_SCOPE_END;
		//print_delta_xml(delta_xml);
		//printf("end %s\n", el);
	}
	//TODO does this allow <publish></withdraw> or is that caught by basic xml parsing
	else if (strcmp("publish", el) == 0 || strcmp("withdraw", el) == 0) {
		if (delta_xml->scope != DELTA_SCOPE_PUBLISH) {
			err(1, "parse failed - exited publish elem unexpectedely");
		}
		if (!delta_xml->publish_uri) {
			err(1, "parse failed - no data recovered from publish elem");
		}
		//TODO should we never keep this much and stream it straight to staging file?
		//printf("publish: '%.*s'\n", delta_xml->publish_data ? delta_xml->publish_data_length : 4, delta_xml->publish_data ?: "NULL");
		if (strcmp("publish", el) == 0) {
			if (verify_publish(xml_data)) {
				err(1, "failed to verify delta hash");
			}
			write_delta_publish(xml_data);
		} else {
			write_delta_withdraw(xml_data);
		}
		free(delta_xml->publish_uri);
		delta_xml->publish_uri = NULL;
		free(delta_xml->publish_hash);
		delta_xml->publish_hash = NULL;
		free(delta_xml->publish_data);
		delta_xml->publish_data = NULL;
		delta_xml->publish_data_length = 0;
		delta_xml->scope = DELTA_SCOPE_DELTA;
	} else {
		err(1, "parse failed - unexpected elem exit found");
	}
}

void delta_content_handler(void *data, const char *content, int length)
{
	int new_length;
	XML_DATA *xml_data = (XML_DATA*)data;
	DELTA_XML *delta_xml = (DELTA_XML*)xml_data->xml_data;
	if (delta_xml->scope == DELTA_SCOPE_PUBLISH) {
		//optmisiation atm this often gets called with '\n' as the only data... seems wasteful
		if (length == 1 && content[0] == '\n') {
			return;
		}
		//printf("parse chunk %d\n", length);
		//append content to publish_data
		if (delta_xml->publish_data) {
			new_length = delta_xml->publish_data_length + length;
			delta_xml->publish_data = realloc(delta_xml->publish_data, sizeof(char)*(new_length + 1));
			strncpy(delta_xml->publish_data + delta_xml->publish_data_length, content, length);
			delta_xml->publish_data[new_length] = '\0';
		} else {
			delta_xml->publish_data = strndup(content, length);
			new_length = length;
		}
		delta_xml->publish_data_length = new_length;
	}
	else {
		//printf("chars found '%.*s'\n", length, content);
	}
}

XML_DATA *new_delta_xml_data(char *uri, OPTS *opts) {
	XML_DATA *xml_data = calloc(1, sizeof(XML_DATA));

	xml_data->xml_data = calloc(1, sizeof(DELTA_XML));
	xml_data->uri = uri;
	xml_data->opts = opts;
	xml_data->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(xml_data->parser, delta_elem_start, delta_elem_end);
	XML_SetCharacterDataHandler(xml_data->parser, delta_content_handler);
	XML_SetUserData(xml_data->parser, xml_data);

	return xml_data;
}

