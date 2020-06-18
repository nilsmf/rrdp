#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int rm_dir(char *dir) {
	char *command = malloc(sizeof(char)*(strlen(dir) + 9 + 1));
	int ret = 0;
	sprintf(command, "rm -rf \"%s\"", dir);
	ret = system(command);
	free(command);
	return ret;
}

int mv_dir(char *from, char *to) {
	char *command = malloc(sizeof(char)*(strlen(from) + strlen(to) + 8 + 1));
	int ret = 0;
	sprintf(command, "mv \"%s\" \"%s\"", from, to);
	ret = system(command);
	free(command);
	return ret;
}
