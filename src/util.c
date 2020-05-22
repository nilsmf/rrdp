// Truncate non base64 chars
int strip_non_b64(const char * str, int len, char *out) {
	char c;
	int i;
	int offset = 0;
	if (!out || !str) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		c = str[i];
		if (c == '+' || c == '/' || c == '=' || c == '\0' ||
		    (c >= '0' && c <= '9') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z')) {
			out[i - offset] = c;
			if (c == '\0') {
				break;
			}
		} else {
			offset++;
		}
	}
	return i - offset;
}

