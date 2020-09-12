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

#include "log.h"
#include "rrdp.h"

int
mkpath_at(int fd, const char *dir)
{
	struct stat sb;
	char *path;
	char *delim;
	int len;

	if (!dir) {
		errno = EINVAL;
		return 1;
	}
	while (strlen(dir) > 0 && dir[0] == '/')
		dir++;
	path = xstrdup(dir);
	delim = path;
	for (;;) {
		if (delim[0] == '\0')
			break;
		delim = strchr(delim, '/');
		if (delim != NULL)
			delim[0] = '\0';
		if ((len = strlen(path)) >= 2 &&
		    path[len - 1] == '.' && path[len - 2] == '.' &&
		    (len == 2 || path[strlen(path) - 3] == '/')) {
			warnx("Tried to use .. when making path");
			free(path);
			errno = EINVAL;
			return 1;
		}
		if (len > 0 && fstatat(fd, path, &sb, 0) != 0) {
			if (mkdirat(fd, path, S_IRWXU) != 0) {
				free(path);
				return 1;
			}
		}
		if (delim == NULL)
			break;
		delim[0] = '/';
		delim++;
	}
	free(path);
	return 0;
}

int
rm_dir(char *dir, int min_del_level)
{
	FTSENT *node;
	FTS *tree;
	char *vals[] = {dir, NULL};

	if (!dir)
		return 1;
	tree = fts_open(vals, FTS_NOCHDIR|FTS_PHYSICAL, 0);
	if (!tree)
		return 1;
	log_debuginfo("deleting %s", dir);

	while ((node = fts_read(tree))) {
		/* clear "from" directories as leave them */
		if (node->fts_info & FTS_D)
			continue;
		/*
		 * perhaps unlink would be enough for everything but this is
		 * more sure
		 */
		if (node->fts_info & FTS_DP) {
			if(node->fts_level < min_del_level)
				continue;

			if(rmdir(node->fts_path)) {
				log_warn("failed to delete %s", node->fts_path);
				return 1;
			}
			continue;
		}
		if (unlink(node->fts_path)) {
			log_warn("failed to delete %s", node->fts_path);
			return 1;
		}
	}
	return 0;
}

int
mv_delta(int from_fd, int to_fd, struct file_list *file_list)
{
	struct file_delta *file_delta;
	char *f;
	char *sep;

	SLIST_FOREACH(file_delta, file_list, file_list) {
		f = file_delta->filename;
		if (file_delta->action == ACTION_DELETE) {
			if (unlinkat(from_fd, f, 0) == -1) {
				log_warn("failed to delete %s", f);
			}
			/* we allow file not existing on removal of original */
			if (unlinkat(to_fd, f, 0) == -1) {
				if (errno != ENOENT) {
					log_warn("failed to delete %s", f);
					return 1;
				}
			}
		} else {
			if ((sep = strrchr(f, '/')) != NULL)
				sep[0] = '\0';
			if (mkpath_at(to_fd, f) != 0)
				return 1;
			if (sep != NULL)
				sep[0] = '/';
			if (renameat(from_fd, f, to_fd, f) == -1)
				log_warn("failed to move %s", f);
		}
	}
	return 0;
}

void
add_to_file_list(struct file_list *file_list, const char *filename, int withdraw,
    int check_duplicates) {
	struct file_delta *file_delta;

	if (check_duplicates == 1) {
		log_debug("Refound same file %s", filename);
		SLIST_FOREACH(file_delta, file_list, file_list) {
			if (strcmp(filename, file_delta->filename) == 0) {
				if (withdraw == 0)
					file_delta->action = ACTION_COPY;
				else
					file_delta->action = ACTION_DELETE;
				return;
			}
		}
	} else {
		if ((file_delta = calloc(1, sizeof(struct file_delta))) == NULL)
			fatal("%s - calloc", __func__);
		file_delta->filename = xstrdup(filename);
		if (withdraw == 0)
			file_delta->action = ACTION_COPY;
		else
			file_delta->action = ACTION_DELETE;
		SLIST_INSERT_HEAD(file_list, file_delta, file_list);
	}
}

int
empty_file_list(struct file_list *file_list) {
	struct file_delta *file_delta;
	while (!SLIST_EMPTY(file_list)) {
		file_delta = SLIST_FIRST(file_list);
		SLIST_REMOVE_HEAD(file_list, file_list);
		free(file_delta->filename);
		free(file_delta);
	}
}
