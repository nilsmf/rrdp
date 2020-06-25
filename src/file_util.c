/*
 * Copyright (c) 2020 Nils Fisher <nils_fisher@hotmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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

#include "file_util.h"

int
mkpath(char *dir, mode_t mode)
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

int
rm_dir(char *dir)
{
	FTSENT *node;
	FTS *tree;
	char *vals[] = {dir, NULL};

	if (!dir)
		return 1;
	tree = fts_open(vals, FTS_NOCHDIR|FTS_PHYSICAL, 0);
	if (!tree)
		return 1;
	printf("deleting %s\n", dir);

	while ((node = fts_read(tree))) {
		//clear "from" directories as leave them
		if (node->fts_info & FTS_D)
			continue;
		// perhaps unlink would be enough for everything but this is more sure
		if (node->fts_info & FTS_DP) {
			printf("removing path %s\n", node->fts_path);
			if(rmdir(node->fts_path)) {
				printf("failed to delete %s\n", node->fts_path);
				return 1;
			}
			continue;
		}
		if (unlink(node->fts_path)) {
			printf("failed to delete %s\n", node->fts_path);
			return 1;
		}
	}
	return 0;
}


int
mv_delta(char *from, char *to)
{
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
	if (!newpath)
		err(1, "malloc");
	printf("migrating %s -> %s\n", from, to);

	while ((node = fts_read(tree))) {
		//replace "from" with "to"
		new_len = node->fts_pathlen - from_len + to_len + 1;
		if (new_len > newpath_len)
			newpath = realloc(newpath, sizeof(char)*(new_len));
		if (!newpath)
			err(1, "realloc");
		sprintf(newpath, "%s%s", to, node->fts_path + from_len);

		//create dirs in "to" as we discover them
		if (node->fts_info & FTS_D) {
			printf("making path %s\n", newpath);
			if(mkpath(newpath, 0777)) {
				printf("failed to delete %s\n", node->fts_path);
				free(newpath);
				return 1;
			}
			continue;
		}
		//clear "from" directories as leave them
		if (node->fts_info & FTS_DP) {
			printf("removing path %s\n", node->fts_path);
			if(rmdir(node->fts_path)) {
				printf("failed to delete %s\n", node->fts_path);
				free(newpath);
				return 1;
			}
			continue;
		}
		//TODO probably unlink anything we dont want to copy?
		if (!(node->fts_info & FTS_F) || !(node->fts_info & (FTS_NS|FTS_NSOK)))
			continue;
		//zero sized files are delta "withdraws"
		if (node->fts_statp->st_size == 0) {
			if(unlink(node->fts_path)) {
				printf("failed to delete %s\n", node->fts_path);
				free(newpath);
				return 1;
			}
		//otherwise move the file to the new location
		} else {
			if(rename(node->fts_path, newpath)) {
				printf("failed to move %s to %s \n", node->fts_path, newpath);
				free(newpath);
				return 1;
			}
		}
	}
	free(newpath);
	return 0;
}

