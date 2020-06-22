#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <fts.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>

int mkpath(char *dir, mode_t mode)
{
	struct stat sb;

	if (!dir) {
		errno = EINVAL;
		return 1;
	}
	if (!stat(dir, &sb))
		return 0;

	char *newdir;
	mkpath(dirname(newdir = strdup(dir)), mode);
	int ret = mkdir(newdir, mode);
	free(newdir);
	return ret;
}

//TODO replace this with a better one
int rm_dir(char *dir) {
	char *command = malloc(sizeof(char)*(strlen(dir) + 9 + 1));
	int ret = 0;
	sprintf(command, "rm -rf \"%s\"", dir);
	ret = system(command);
	free(command);
	return ret;
}

int mv_delta(char *from, char *to) {
	int LENGTH = 50;
	FTSENT *node;
	FTS *tree;
	char *vals[] = {from, NULL};
	char *newpath;
	int from_len;
	int to_len;
	int new_len;
	int newpath_len = LENGTH;

	if (!from || !to)
		return 1;
	from_len = strlen(from);
	to_len = strlen(to);

	tree = fts_open(vals, FTS_NOCHDIR|FTS_PHYSICAL, 0);
	if (!tree)
		return 1;
	newpath = malloc(sizeof(char)*LENGTH);
	printf("migrating %s -> %s\n", from, to);

	while ((node = fts_read(tree))) {
		//replace "from" with "to"
		new_len = node->fts_pathlen - from_len + to_len + 1;
		if (new_len > newpath_len)
			newpath = realloc(newpath, sizeof(char)*(new_len));
		sprintf(newpath, "%s%s", to, node->fts_path + from_len);

		//create dirs in "to" as we discover them
		if (node->fts_info & FTS_D) {
			printf("making path %s\n", newpath);
			mkpath(newpath, 0777);
			continue;
		}
		//clear "from" directories as leave them
		if (node->fts_info & FTS_DP) {
			printf("removing path %s\n", node->fts_path);
			rmdir(node->fts_path);
			continue;
		}
		//TODO probably unlink anything we dont want to copy?
		if (!(node->fts_info & FTS_F) || !(node->fts_info & (FTS_NS|FTS_NSOK)))
			continue;
		//zero sized files are delta "withdraws"
		if (node->fts_statp->st_size == 0) {
			printf("deleting %s\n", node->fts_path);
			unlink(node->fts_path);
		//otherwise move the file to the new location
		} else {
			printf("moving %s\nto    %s\n\n", node->fts_path, newpath);
			rename(node->fts_path, newpath);
		}
	}
	free(newpath);
	return 0;
}

