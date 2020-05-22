#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <src/util.h>

static void test(const char *test_name, char *str_in, int in_len, char *expected_str_out, int expected_ret) {
	//char* out = NULL;
	char *out = strndup(str_in, in_len);

	int ret = strip_non_b64(out, in_len, out);
	if (ret != expected_ret) {
		errx(1, "strip_non_b64 (%s) failure %s, %d\n\t ret %d != %d",
		     test_name, str_in, in_len, ret, expected_ret);
	} else if (strncmp(out, expected_str_out, ret) != 0) {
		errx(1, "strip_non_b64 (%s) failure %s, %d\n\t ret %.*s != %.*s",
		     test_name, str_in, in_len, ret, out, expected_ret, expected_str_out);
	}
	free(out);

}
static void test_bad_mem() {
	int ret;

	ret = strip_non_b64("asdf", 4, NULL);
	if (ret != -1) {
		errx(1, "strip_non_b64 (test bad mem) failure");
	}
	//ret = strip_non_b64("asdf", 4, "asdf");
	//if (ret != -1) {
	//	errx(1, "strip_non_b64 (test bad mem) failure");
	//}
	ret = strip_non_b64(NULL, 4, NULL);
	if (ret != -1) {
		errx(1, "strip_non_b64 (test bad mem) failure");
	}
}

int main(int argc, char *argv[]) {
	test_bad_mem();
	test("basic", "asdf", 4, "asdf", 4);
	test("longer len input", "asdf", 100, "asdf", 4);
	test("whitespace start end padding", " asdf ", 6, "asdf", 4);
	test("random chars", " a#s # & & df ", 14, "asdf", 4);
	test("random chars + longer len input", " a#s # & & df ", 100, "asdf", 4);
	test("all b64 chars",
	     "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=",
	     65,
	     "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=",
	     65);
}
