#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

#include <src/util.h>

static int opts_equal(OPTS *o1, OPTS *o2) {
	if (o1 && o1->basedir_primary && o1->basedir_working &&
	    o2 && o2->basedir_primary && o2->basedir_working) {
		return !(strcmp(o1->basedir_primary, o2->basedir_primary) +
			 strcmp(o1->basedir_working, o2->basedir_working));
	} else if (o1 || o2) {
		return 0;
	}
	//both NULL
	return 0;
}

static void test_buildopts() {
	OPTS expected = {"/asdf/qwer/zxcv", "/asdf/poiu/poiu"};
	char *test_args[] = {"something", "-p", "/asdf/qwer/zxcv", "-w", "/asdf/poiu/poiu"};
	char *test_args_same[] = {"something", "-p", "/asdf/qwer/zxcv", "-w", "/asdf/qwer/zxcv"};
	char *test_args_missing[] = {"something", "-p", "/asdf/qwer/zxcv"};
	OPTS *test;

	test = buildopts(5, test_args);
	if(!opts_equal(&expected, test))
		err(1, "opts not equal");
	free(test);
	test = buildopts(5, test_args_same);
	if(test)
		err(1, "primary and working allowed to be same");
	test = buildopts(3, test_args_missing);
	if(test)
		err(1, "alowed missing argument");
}

static void test_b64decode() {
	int len;
	unsigned char *b64_out;
	char *input = "dGVhcG90";
	char *expected_output = "teapot";
	char *short_input = "dGV";

	len = b64_decode(input, &b64_out);
	if (len != strlen(expected_output) || strcmp((char*)b64_out, expected_output))
		err(1, "teapot is not a teapot b64 error");
	free(b64_out);

	len = b64_decode(short_input, &b64_out);
	if (len != -1 || b64_out) {
		err(1, "didnt fail on bad b64");
	}
}

int main(int argc, char *argv[]) {
	test_buildopts();
	test_b64decode();
}
