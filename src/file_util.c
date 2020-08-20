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

/* XXXNF this also deletes the directory being copied */
int
mv_delta(char *from, char *to, int to_fd)
{
	FTSENT *node;
	FTS *tree;
	char *vals[] = {from, NULL};
	char *newpath;
	char *newpath_at;
	int from_len;

	if (!from || !to)
		return 1;
	from_len = strlen(from);

	tree = fts_open(vals, FTS_NOCHDIR|FTS_PHYSICAL, 0);
	if (!tree) {
		log_warnx("failed to open tree");
		return 1;
	}
	log_debuginfo("migrating %s -> %s", from, to);

	while ((node = fts_read(tree))) {
		/* replace "from" with "to" */
		newpath_at = node->fts_path + from_len;
		if (asprintf(&newpath, "%s%s", to, newpath_at) == -1)
			err(1, "asprintf");

		/* create dirs in "to" as we discover them */
		if (node->fts_info & FTS_D) {
			if (mkpath_at(to_fd, newpath_at) != 0) {
				log_warn("failed to create %s", newpath_at);
				free(newpath);
				return 1;
			}
			free(newpath);
			continue;
		}
		/* clear "from" directories as leave them */
		if (node->fts_info & FTS_DP) {
			if (rmdir(node->fts_path)) {
				log_warn("failed to delete %s",
				    node->fts_path);
				free(newpath);
				return 1;
			}
			free(newpath);
			continue;
		}
		/* TODO probably unlink anything we dont want to copy? */
		if (!(node->fts_info & FTS_F) ||
		    !(node->fts_info & (FTS_NS|FTS_NSOK))) {
			free(newpath);
			continue;
		}
		/* zero sized files are delta "withdraws" */
		if (node->fts_statp->st_size == 0) {
			if (unlink(node->fts_path)) {
				log_warn("failed to delete %s", node->fts_path);
				free(newpath);
				return 1;
			}
			if (unlink(newpath) == -1) {
				if (errno != ENOENT) {
					log_warn("failed to delete %s", newpath);
					free(newpath);
					return 1;
				}
			}
			/* XXXNF check and delete newpath file as well */
		/* otherwise move the file to the new location */
		} else {
			if (rename(node->fts_path, newpath)) {
				log_warn("failed to move %s to %s",
				    node->fts_path, newpath);
				free(newpath);
				return 1;
			}
		}
		free(newpath);
	}
	return 0;
}

