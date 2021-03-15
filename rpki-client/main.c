/*	$OpenBSD: main.c,v 1.119 2021/03/15 08:56:31 claudio Exp $ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <fts.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>
#include <imsg.h>

#include "extern.h"

/*
 * Maximum number of TAL files we'll load.
 */
#define	TALSZ_MAX	8

struct filepath;
RB_HEAD(filepath_tree, filepath);

/*
 * An rsync repository.
 */
#define REPO_MAX_URI	2
struct	repo {
	SLIST_ENTRY(repo)	entry;
	char		*repouri;	/* CA repository base URI */
	char		*local;		/* local path name */
	char		*temp;		/* temporary file / dir */
	char		*uris[REPO_MAX_URI];	/* URIs to fetch from */
	struct entityq	 queue;		/* files waiting for this repo */
	size_t		 id;		/* identifier (array index) */
	int		 uriidx;	/* which URI is fetched */
	int		 loaded;	/* whether loaded or not */
	struct filepath_tree	added;
	struct filepath_tree	deleted;
};

size_t	entity_queue;
int	timeout = 60*60;
volatile sig_atomic_t killme;
void	suicide(int sig);

/*
 * Table of all known repositories.
 */
SLIST_HEAD(, repo)	repos = SLIST_HEAD_INITIALIZER(repos);
size_t			repoid;

/*
 * Database of all file path accessed during a run.
 */
struct filepath {
	RB_ENTRY(filepath)	entry;
	char			*file;
};

static inline int
filepathcmp(struct filepath *a, struct filepath *b)
{
	return strcasecmp(a->file, b->file);
}

RB_PROTOTYPE(filepath_tree, filepath, entry, filepathcmp);

static struct filepath_tree	fpt = RB_INITIALIZER(&fpt);
static struct msgbuf		procq, rsyncq, httpq, rrdpq;
static int			cachefd, outdirfd;

const char	*bird_tablename = "ROAS";

int	verbose;
int	noop;
int	rrdpon;

struct stats	 stats;

static void	 repo_fetch(struct repo *);
static char	*ta_filename(const struct repo *, int);

/*
 * Log a message to stderr if and only if "verbose" is non-zero.
 * This uses the err(3) functionality.
 */
void
logx(const char *fmt, ...)
{
	va_list		 ap;

	if (verbose && fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}

/*
 * Functions to lookup which files have been accessed during computation.
 */
static int
filepath_add(struct filepath_tree *tree, char *file)
{
	struct filepath *fp;

	if ((fp = malloc(sizeof(*fp))) == NULL)
		err(1, NULL);
	if ((fp->file = strdup(file)) == NULL)
		err(1, NULL);

	if (RB_INSERT(filepath_tree, tree, fp) != NULL) {
		/* already in the tree */
		free(fp->file);
		free(fp);
		return 0;
	}

	return 1;
}

/*
 * Lookup a file path in the tree and return the object if found or NULL.
 */
static struct filepath *
filepath_find(struct filepath_tree *tree, char *file)
{
	struct filepath needle;

	needle.file = file;
	return RB_FIND(filepath_tree, tree, &needle);
}

/*
 * Returns true if file exists in the tree.
 */
static int
filepath_exists(struct filepath_tree *tree, char *file)
{
	return filepath_find(tree, file) != NULL;
}

/*
 * Remove entry from tree and free it.
 */
static void
filepath_put(struct filepath_tree *tree, struct filepath *fp)
{
	RB_REMOVE(filepath_tree, tree, fp);
	free((void *)fp->file);
	free(fp);
}

RB_GENERATE(filepath_tree, filepath, entry, filepathcmp);

void
entity_free(struct entity *ent)
{

	if (ent == NULL)
		return;

	free(ent->pkey);
	free(ent->file);
	free(ent->descr);
	free(ent);
}

/*
 * Read a queue entity from the descriptor.
 * Matched by entity_buffer_req().
 * The pointer must be passed entity_free().
 */
void
entity_read_req(int fd, struct entity *ent)
{

	io_simple_read(fd, &ent->type, sizeof(enum rtype));
	io_str_read(fd, &ent->file);
	io_simple_read(fd, &ent->has_pkey, sizeof(int));
	if (ent->has_pkey)
		io_buf_read_alloc(fd, (void **)&ent->pkey, &ent->pkeysz);
	io_str_read(fd, &ent->descr);
}

/*
 * Write the queue entity.
 * Matched by entity_read_req().
 */
static void
entity_write_req(const struct entity *ent)
{
	struct ibuf *b;

	if ((b = ibuf_dynamic(sizeof(*ent), UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &ent->type, sizeof(ent->type));
	io_str_buffer(b, ent->file);
	io_simple_buffer(b, &ent->has_pkey, sizeof(int));
	if (ent->has_pkey)
		io_buf_buffer(b, ent->pkey, ent->pkeysz);
	io_str_buffer(b, ent->descr);
	ibuf_close(&procq, b);
}

/*
 * Scan through all queued requests and see which ones are in the given
 * repo, then flush those into the parser process.
 */
static void
entityq_flush(struct repo *repo)
{
	struct entity	*p, *np;

	TAILQ_FOREACH_SAFE(p, &repo->queue, entries, np) {
		entity_write_req(p);
		TAILQ_REMOVE(&repo->queue, p, entries);
		entity_free(p);
	}
}

/*
 * Add the heap-allocated file to the queue for processing.
 */
static void
entityq_add(char *file, enum rtype type, struct repo *rp,
    const unsigned char *pkey, size_t pkeysz, char *descr)
{
	struct entity	*p;

	if (filepath_add(&fpt, file) == 0) {
		warnx("%s: File already visited", file);
		return;
	}

	if ((p = calloc(1, sizeof(struct entity))) == NULL)
		err(1, NULL);

	p->type = type;
	p->file = file;
	p->has_pkey = pkey != NULL;
	if (p->has_pkey) {
		p->pkeysz = pkeysz;
		if ((p->pkey = malloc(pkeysz)) == NULL)
			err(1, NULL);
		memcpy(p->pkey, pkey, pkeysz);
	}
	if (descr != NULL)
		if ((p->descr = strdup(descr)) == NULL)
			err(1, NULL);

	entity_queue++;

	/*
	 * Write to the queue if there's no repo or the repo has already
	 * been loaded else enqueue it for later.
	 */

	if (rp == NULL || rp->loaded) {
		entity_write_req(p);
		entity_free(p);
	} else
		TAILQ_INSERT_TAIL(&rp->queue, p, entries);
}

/*
 * Function to create all missing directories to a path.
 * This functions alters the path temporarily.
 */
static void
repo_mkpath(char *file)
{
	char *slash;

	/* build directory hierarchy */
	slash = strrchr(file, '/');
	assert(slash != NULL);
	*slash = '\0';
	if (mkpath(file) == -1)
		err(1, "%s", file);
	*slash = '/';
}

/*
 * Build local file name base on the URI and the repo info.
 */
static char *
repo_filename(const struct repo *repo, const char *uri, int temp)
{
	char *nfile;
	char *dir = repo->local;

	if (temp)
		dir = repo->temp;

	if (strstr(uri, repo->repouri) != uri) {
		warnx("%s: URI %s outside of repository", repo->local, uri);
		return NULL;
	}

	uri += strlen(repo->repouri) + 1;	/* skip base and '/' */

	if (asprintf(&nfile, "%s/%s", dir, uri) == -1)
		err(1, NULL);
	return nfile;
}

/*
 * Build TA file name based on the repo info.
 * If temp is set add Xs for mkostemp.
 */
static char *
ta_filename(const struct repo *repo, int temp)
{
	const char *file;
	char *nfile;

	/* does not matter which URI, all end with same filename */
	file = strrchr(repo->uris[0], '/');
	assert(file);

	if (asprintf(&nfile, "%s%s%s", repo->local, file,
	    temp ? ".XXXXXXXX": "") == -1)
		err(1, NULL);

	return nfile;
}

/*
 * Build RRDP state file name based on the repo info.
 * If temp is set add Xs for mkostemp.
 */
static char *
rrdp_state_filename(const struct repo *repo, int temp)
{
	char *nfile;

	if (asprintf(&nfile, "%s/.state%s", repo->local,
	    temp ? ".XXXXXXXX": "") == -1)
		err(1, NULL);

	return nfile;
}

/*
 * Parse the RRDP state file if it exists and set the session struct
 * based on that information.
 */
static void
rrdp_parse_state(const struct repo *r, struct rrdp_session *state)
{
	FILE *f;
	int fd, ln = 0;
	const char *errstr;
	char *line = NULL, *file;
	size_t len = 0;
	ssize_t n;

	file = rrdp_state_filename(r, 0);
	if ((fd = openat(cachefd, file, O_RDONLY)) == -1) {
		free(file);
		if (errno != ENOENT)
			warn("%s: open state file", r->local);
		return;
	}
	free(file);
	f = fdopen(fd, "r");
	if (f == NULL)
		err(1, "fdopen");

	while ((n = getline(&line, &len, f)) != -1) {
		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		switch (ln) {
		case 0:
			if ((state->session_id = strdup(line)) == NULL)
				err(1, "%s", __func__);
			break;
		case 1:
			state->serial = strtonum(line, 1, LLONG_MAX, &errstr);
			if (errstr)
				goto fail;
			break;
		case 2:
			if ((state->last_mod = strdup(line)) == NULL)
				err(1, "%s", __func__);
			break;
		default:
			goto fail;
		}
		ln++;
	}

	free(line);
	if (ferror(f))
		goto fail;
	fclose(f);
	return;

fail:
	warnx("%s: troubles reading state file", r->local);
	fclose(f);
	free(state->session_id);
	free(state->last_mod);
	memset(state, 0, sizeof(*state));
}

/*
 * Carefully write the RRDP session state file back.
 */
static void
rrdp_save_state(const struct repo *r, struct rrdp_session *state)
{
	char *temp, *file;
	FILE *f;
	int fd;

	file = rrdp_state_filename(r, 0);
	temp = rrdp_state_filename(r, 1);

	if ((fd = mkostemp(temp, O_CLOEXEC)) == -1)
		err(1, "%s: mkostemp: %s", r->local, temp);
	(void) fchmod(fd, 0644);
	f = fdopen(fd, "w");
	if (f == NULL)
		err(1, "fdopen");

	/* write session state file out */
	if (fprintf(f, "%s\n%lld\n", state->session_id,
	    state->serial) < 0) {
		fclose(f);
		goto fail;
	}
	if (state->last_mod != NULL) {
		if (fprintf(f, "%s\n", state->last_mod) < 0) {
			fclose(f);
			goto fail;
		}
	}
	if (fclose(f) != 0)
		goto fail;

	if (renameat(cachefd, temp, cachefd, file) == -1)
		warn("%s: rename state file", r->local);

	free(temp);
	free(file);
	return;

fail:
	warnx("%s: failed to save state", r->local);
	unlinkat(cachefd, temp, 0);
	free(temp);
	free(file);
}

static void
rrdp_handle_file(struct repo *rp, enum publish_type pt, char *uri,
    char *hash, size_t hlen, char *data, size_t dlen)
{
	enum rrdp_msg type = RRDP_FILE;
	struct filepath *fp;
	struct ibuf *b;
	ssize_t s;
	char *fn;
	int fd;
	int ok = 0;

	/* belt and suspenders */
	if (!valid_uri(uri, strlen(uri), "rsync://")) {
		warnx("%s: bad file URI", rp->local);
		goto done;
	}
	/*
	 * XXX ignore files outside the repo for now.
	 * Workaround for apnic.
	 */
	if (strstr(uri, rp->repouri) != uri) {
		ok = 1;
		goto done;
	}

	if (pt == PUB_UPD || pt == PUB_DEL) {
		if (filepath_exists(&rp->deleted, uri)) {
			warnx("%s: already deleted", uri);
			goto done;
		}
		fp = filepath_find(&rp->added, uri);
		if (fp == NULL) {
			if ((fn = repo_filename(rp, uri, 0)) == NULL)
				goto done;
		} else {
			filepath_put(&rp->added, fp);
			if ((fn = repo_filename(rp, uri, 1)) == NULL)
				goto done;
		}
		if (!valid_filehash(fn, hash, hlen)) {
			warnx("%s: bad message digest", fn);
			free(fn);
			goto done;
		}
		free(fn);
	}

	if (pt == PUB_DEL) {
		filepath_add(&rp->deleted, uri);
	} else {
		/* add new file to temp dir */
		if ((fn = repo_filename(rp, uri, 1)) == NULL)
			goto done;

		repo_mkpath(fn);
		fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (fd == -1) {
			warn("open %s", fn);
			free(fn);
			goto done;
		}

		if ((s = write(fd, data, dlen)) == -1) {
			warn("write %s", fn);
			free(fn);
			close(fd);
			goto done;
		}
		close(fd);
		if ((size_t)s != dlen) {
			warnx("short write %s", fn);
			free(fn);
			goto done;
		}
		free(fn);
		filepath_add(&rp->added, uri);
	}

	/* all OK */
	ok = 1;

done:
	/* send back response */
	if ((b = ibuf_open(sizeof(type) + sizeof(rp->id) + sizeof(ok))) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &type, sizeof(type));
	io_simple_buffer(b, &rp->id, sizeof(rp->id));
	io_simple_buffer(b, &ok, sizeof(ok));
	ibuf_close(&rrdpq, b);
}

/*
 * Initiate a RRDP sync, create the required temporary directory and
 * parse a possible state file before sending the request to the RRDP process.
 */
static void
rrdp_fetch(struct repo *rp)
{
	enum rrdp_msg type = RRDP_START;
	struct rrdp_session state = { 0 };
	struct ibuf *b;

	if (!rrdpon)
		errx(1, "%s: RRDP is off but trying to fetch", rp->local);

	if (asprintf(&rp->temp, "%s.XXXXXXXX", rp->local) == -1)
		err(1, NULL);
	if (mkdtemp(rp->temp) == NULL)
		err(1, "mkdtemp %s", rp->temp);

	rrdp_parse_state(rp, &state);

	if ((b = ibuf_dynamic(256, UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &type, sizeof(type));
	io_simple_buffer(b, &rp->id, sizeof(rp->id));
	io_str_buffer(b, rp->local);
	io_str_buffer(b, rp->uris[rp->uriidx]);
	io_str_buffer(b, state.session_id);
	io_simple_buffer(b, &state.serial, sizeof(state.serial));
	io_str_buffer(b, state.last_mod);
	ibuf_close(&rrdpq, b);

	free(state.session_id);
	free(state.last_mod);
}

static void
rrdp_merge_repo(struct repo *rp)
{
	struct filepath *fp, *nfp;
	char *fn, *rfn;

	/* XXX should delay deletes */
	RB_FOREACH_SAFE(fp, filepath_tree, &rp->deleted, nfp) {
		if ((fn = repo_filename(rp, fp->file, 0)) != NULL) {
			if (unlink(fn) == -1)
				warn("%s: unlink", fn);
			free(fn);
		}
		filepath_put(&rp->deleted, fp);
	}

	RB_FOREACH_SAFE(fp, filepath_tree, &rp->added, nfp) {
		if ((fn = repo_filename(rp, fp->file, 1)) != NULL &&
		    (rfn = repo_filename(rp, fp->file, 0)) != NULL) {
			repo_mkpath(rfn);
			if (rename(fn, rfn) == -1)
				warn("%s: link", rfn);
			free(rfn);
		}
		free(fn);
		filepath_put(&rp->added, fp);
	}
}

static void
rrdp_clean_temp(struct repo *rp)
{
	struct filepath *fp, *nfp;
	char *fn;

	RB_FOREACH_SAFE(fp, filepath_tree, &rp->deleted, nfp) {
		filepath_put(&rp->deleted, fp);
	}

	RB_FOREACH_SAFE(fp, filepath_tree, &rp->added, nfp) {
		if ((fn = repo_filename(rp, fp->file, 1)) != NULL) {
			if (unlink(fn) == -1)
				warn("%s: unlink", fn);
			free(fn);
		}
		filepath_put(&rp->added, fp);
	}
}

/*
 * RRDP fetch finalized, either with or without success.
 */
static int
rrdp_done(struct repo *rp, int ok)
{
	if (ok) {
		rrdp_merge_repo(rp);
		logx("%s: loaded from network", rp->local);
	} else if (rp->uriidx < REPO_MAX_URI - 1 &&
	    rp->uris[rp->uriidx + 1] != NULL) {
		rrdp_clean_temp(rp);
		logx("%s: load from network failed, retry", rp->local);

		rp->uriidx++;
		repo_fetch(rp);
		return 0;
	} else {
		rrdp_clean_temp(rp);
		logx("%s: load from network failed, "
		    "fallback to cache", rp->local);
	}
	return 1;
}

/*
 * Allocate and insert a new repository.
 */
static struct repo *
repo_alloc(void)
{
	struct repo *rp;

	if ((rp = calloc(1, sizeof(*rp))) == NULL)
		err(1, NULL);

	rp->id = ++repoid;
	RB_INIT(&rp->added);
	RB_INIT(&rp->deleted);
	TAILQ_INIT(&rp->queue);
	SLIST_INSERT_HEAD(&repos, rp, entry);

	return rp;
}

static struct repo *
repo_find(size_t id)
{
	struct repo *rp;

	SLIST_FOREACH(rp, &repos, entry)
		if (id == rp->id)
			break;
	return rp;
}

/*
 * Request some XML file on behalf of the rrdp parser.
 * Create a pipe and pass the pipe endpoints to the http and rrdp process.
 */
static void
http_rrdp_fetch(size_t id, const char *uri, const char *last_mod)
{
	enum rrdp_msg	type = RRDP_HTTP_INI;
	struct ibuf	*b1, *b2;
	int pi[2];

	if (pipe2(pi, O_CLOEXEC | O_NONBLOCK) == -1)
		err(1, "pipe");

	if ((b1 = ibuf_open(sizeof(type) + sizeof(id))) == NULL)
		err(1, NULL);
	io_simple_buffer(b1, &type, sizeof(type));
	io_simple_buffer(b1, &id, sizeof(id));
	b1->fd = pi[0];
	ibuf_close(&rrdpq, b1);

	if ((b2 = ibuf_dynamic(256, UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b2, &id, sizeof(id));
	io_str_buffer(b2, uri);
	io_str_buffer(b2, last_mod);
	/* pass pipe as fd */
	b2->fd = pi[1];
	ibuf_close(&httpq, b2);
}

/*
 * Request a TA certificate, write it to a temporary file and rename
 * it into place on success.
 */
static void
http_ta_fetch(struct repo *rp)
{
	struct ibuf	*b;
	int		 filefd;

	rp->temp = ta_filename(rp, 1);
	
	filefd = mkostemp(rp->temp, O_CLOEXEC);
	if (filefd == -1) {
		err(1, "mkostemp: %s", rp->temp);
		/* XXX switch to soft fail and restart with next file */
	}
	(void) fchmod(filefd, 0644);

	if ((b = ibuf_dynamic(256, UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &rp->id, sizeof(rp->id));
	io_str_buffer(b, rp->uris[rp->uriidx]);
	/* TODO last modified time */
	io_str_buffer(b, NULL);
	/* pass file as fd */
	b->fd = filefd;
	ibuf_close(&httpq, b);
}

/*
 * Handle responses from the http process. For TA file, either rename
 * or delete the temporary file. For RRDP requests relay the request
 * over to the rrdp process.
 */
static int
http_done(struct repo *rp, int ok, int status, char *last_mod)
{
	struct ibuf	*b;
	enum rrdp_msg	type = RRDP_HTTP_FIN;

	if (rp->repouri == NULL) {
		/* Move downloaded TA file into place, or unlink on failure. */
		if (ok) {
			char *file;

			file = ta_filename(rp, 0);
			if (renameat(cachefd, rp->temp, cachefd, file) == -1)
				warn("rename to %s", file);
		} else {
			if (unlinkat(cachefd, rp->temp, 0) == -1)
				warn("unlink %s", rp->temp);
		}
		free(rp->temp);
		rp->temp = NULL;

		if (ok) {
			logx("%s: loaded from network", rp->local);
		} else if (rp->uriidx < REPO_MAX_URI - 1 &&
		    rp->uris[rp->uriidx + 1] != NULL) {
			logx("%s: load from network failed, retry", rp->local);

			rp->uriidx++;
			repo_fetch(rp);
			return 0;
		} else {
			logx("%s: load from network failed, "
			    "fallback to cache", rp->local);
		}
		return 1;
	}

	/* RRDP request, relay response over to the rrdp process */
	if ((b = ibuf_dynamic(256, UINT_MAX)) == NULL)
		err(1, NULL);
	io_simple_buffer(b, &type, sizeof(type));
	io_simple_buffer(b, &rp->id, sizeof(rp->id));
	io_simple_buffer(b, &status, sizeof(status));
	io_str_buffer(b, last_mod);
	ibuf_close(&rrdpq, b);
	return 0;
}

static void
repo_fetch(struct repo *rp)
{
	struct ibuf	*b;

	if (noop) {
		rp->loaded = 1;
		logx("%s: using cache", rp->local);
		stats.repos++;
		/* there is nothing in the queue so no need to flush */
		return;
	}

	/*
	 * Create destination location.
	 * Build up the tree to this point.
	 */

	if (mkpath(rp->local) == -1)
		err(1, "%s", rp->local);

	logx("%s: pulling from %s", rp->local, rp->uris[rp->uriidx]);

	if (strncasecmp(rp->uris[rp->uriidx], "rsync://", 8) == 0) {
		if ((b = ibuf_dynamic(256, UINT_MAX)) == NULL)
			err(1, NULL);
		io_simple_buffer(b, &rp->id, sizeof(rp->id));
		io_str_buffer(b, rp->local);
		io_str_buffer(b, rp->uris[rp->uriidx]);
		ibuf_close(&rsyncq, b);
	} else {
		/*
		 * Two cases for https. TA files load directly while
		 * for RRDP XML files are downloaded and parsed to build
		 * the repo. TA repos have a NULL repouri.
		 */
		if (rp->repouri == NULL) {
			http_ta_fetch(rp);
		} else {
			rrdp_fetch(rp);
		}
	}
}

/*
 * Look up a trust anchor, queueing it for download if not found.
 */
static struct repo *
ta_lookup(const struct tal *tal)
{
	struct repo	*rp;
	char		*local;
	size_t		i, j;

	if (asprintf(&local, "ta/%s", tal->descr) == -1)
		err(1, NULL);

	/* Look up in repository table. (Lookup should actually fail here) */
	SLIST_FOREACH(rp, &repos, entry) {
		if (strcmp(rp->local, local) != 0)
			continue;
		free(local);
		return rp;
	}

	rp = repo_alloc();
	rp->local = local;
	for (i = 0, j = 0; i < tal->urisz && j < 2; i++) {
		if ((rp->uris[j++] = strdup(tal->uri[i])) == NULL)
			err(1, NULL);
	}
	if (j == 0)
		errx(1, "TAL %s has no URI", tal->descr);

	repo_fetch(rp);
	return rp;
}

/*
 * Look up a repository, queueing it for discovery if not found.
 */
static struct repo *
repo_lookup(const char *uri, const char *notify)
{
	char		*local, *repo;
	struct repo	*rp;
	size_t		 i;

	if ((repo = rsync_base_uri(uri)) == NULL)
		return NULL;

	/* Look up in repository table. */
	SLIST_FOREACH(rp, &repos, entry) {
		if (rp->repouri == NULL ||
		    strcmp(rp->repouri, repo) != 0)
			continue;
		free(repo);
		return rp;
	}

	rp = repo_alloc();
	rp->repouri = repo;
	local = strchr(repo, ':') + strlen("://");
	if ((rp->local = strdup(local)) == NULL)
		err(1, NULL);
	i = 0;
	if (rrdpon && notify != NULL)
		if ((rp->uris[i++] = strdup(notify)) == NULL)
			err(1, "strdup");
	if ((rp->uris[i] = strdup(repo)) == NULL)
		err(1, "strdup");

	repo_fetch(rp);
	return rp;
}

/*
 * Add a file (CER, ROA, CRL) from an MFT file, RFC 6486.
 * These are always relative to the directory in which "mft" sits.
 */
static void
queue_add_from_mft(const char *mft, const struct mftfile *file, enum rtype type)
{
	char		*cp, *nfile;

	/* Construct local path from filename. */
	cp = strrchr(mft, '/');
	assert(cp != NULL);
	assert(cp - mft < INT_MAX);
	if (asprintf(&nfile, "%.*s/%s", (int)(cp - mft), mft, file->file) == -1)
		err(1, NULL);

	/*
	 * Since we're from the same directory as the MFT file, we know
	 * that the repository has already been loaded.
	 */

	entityq_add(nfile, type, NULL, NULL, 0, NULL);
}

/*
 * Loops over queue_add_from_mft() for all files.
 * The order here is important: we want to parse the revocation
 * list *before* we parse anything else.
 * FIXME: set the type of file in the mftfile so that we don't need to
 * keep doing the check (this should be done in the parser, where we
 * check the suffix anyway).
 */
static void
queue_add_from_mft_set(const struct mft *mft)
{
	size_t			 i, sz;
	const struct mftfile	*f;

	for (i = 0; i < mft->filesz; i++) {
		f = &mft->files[i];
		sz = strlen(f->file);
		assert(sz > 4);
		if (strcasecmp(f->file + sz - 4, ".crl") != 0)
			continue;
		queue_add_from_mft(mft->file, f, RTYPE_CRL);
	}

	for (i = 0; i < mft->filesz; i++) {
		f = &mft->files[i];
		sz = strlen(f->file);
		assert(sz > 4);
		if (strcasecmp(f->file + sz - 4, ".crl") == 0)
			continue;
		else if (strcasecmp(f->file + sz - 4, ".cer") == 0)
			queue_add_from_mft(mft->file, f, RTYPE_CER);
		else if (strcasecmp(f->file + sz - 4, ".roa") == 0)
			queue_add_from_mft(mft->file, f, RTYPE_ROA);
		else if (strcasecmp(f->file + sz - 4, ".gbr") == 0)
			queue_add_from_mft(mft->file, f, RTYPE_GBR);
		else
			logx("%s: unsupported file type: %s", mft->file,
			    f->file);
	}
}

/*
 * Add a local TAL file (RFC 7730) to the queue of files to fetch.
 */
static void
queue_add_tal(const char *file)
{
	char	*nfile, *buf;

	if ((nfile = strdup(file)) == NULL)
		err(1, NULL);
	buf = tal_read_file(file);

	/* Record tal for later reporting */
	if (stats.talnames == NULL) {
		if ((stats.talnames = strdup(file)) == NULL)
			err(1, NULL);
	} else {
		char *tmp;
		if (asprintf(&tmp, "%s %s", stats.talnames, file) == -1)
			err(1, NULL);
		free(stats.talnames);
		stats.talnames = tmp;
	}

	/* Not in a repository, so directly add to queue. */
	entityq_add(nfile, RTYPE_TAL, NULL, NULL, 0, buf);
	/* entityq_add makes a copy of buf */
	free(buf);
}

/*
 * Add URIs (CER) from a TAL file, RFC 8630.
 */
static void
queue_add_from_tal(const struct tal *tal)
{
	char		*nfile;
	struct repo	*repo;

	assert(tal->urisz);

	/* Look up the repository. */
	repo = ta_lookup(tal);

	nfile = ta_filename(repo, 0);
	entityq_add(nfile, RTYPE_CER, repo, tal->pkey,
	    tal->pkeysz, tal->descr);
}

/*
 * Add a manifest (MFT) found in an X509 certificate, RFC 6487.
 */
static void
queue_add_from_cert(const struct cert *cert)
{
	struct repo	*repo;
	char		*nfile;

	repo = repo_lookup(cert->repo, cert->notify);
	if (repo == NULL) {
		warnx("%s: repository lookup failed", cert->repo);
		return;
	}

	nfile = repo_filename(repo, cert->mft, 0);
	if (nfile == NULL)
		return;

	entityq_add(nfile, RTYPE_MFT, repo, NULL, 0, NULL);
}

/*
 * Process parsed content.
 * For non-ROAs, we grok for more data.
 * For ROAs, we want to extract the valid info.
 * In all cases, we gather statistics.
 */
static void
entity_process(int proc, struct stats *st, struct vrp_tree *tree)
{
	enum rtype	type;
	struct tal	*tal;
	struct cert	*cert;
	struct mft	*mft;
	struct roa	*roa;
	int		 c;

	/*
	 * For most of these, we first read whether there's any content
	 * at all---this means that the syntactic parse failed (X509
	 * certificate, for example).
	 * We follow that up with whether the resources didn't parse.
	 */
	io_simple_read(proc, &type, sizeof(type));

	switch (type) {
	case RTYPE_TAL:
		st->tals++;
		tal = tal_read(proc);
		queue_add_from_tal(tal);
		tal_free(tal);
		break;
	case RTYPE_CER:
		st->certs++;
		io_simple_read(proc, &c, sizeof(int));
		if (c == 0) {
			st->certs_fail++;
			break;
		}
		cert = cert_read(proc);
		if (cert->valid) {
			/*
			 * Process the revocation list from the
			 * certificate *first*, since it might mark that
			 * we're revoked and then we don't want to
			 * process the MFT.
			 */
			queue_add_from_cert(cert);
		} else
			st->certs_invalid++;
		cert_free(cert);
		break;
	case RTYPE_MFT:
		st->mfts++;
		io_simple_read(proc, &c, sizeof(int));
		if (c == 0) {
			st->mfts_fail++;
			break;
		}
		mft = mft_read(proc);
		if (mft->stale)
			st->mfts_stale++;
		queue_add_from_mft_set(mft);
		mft_free(mft);
		break;
	case RTYPE_CRL:
		st->crls++;
		break;
	case RTYPE_ROA:
		st->roas++;
		io_simple_read(proc, &c, sizeof(int));
		if (c == 0) {
			st->roas_fail++;
			break;
		}
		roa = roa_read(proc);
		if (roa->valid)
			roa_insert_vrps(tree, roa, &st->vrps, &st->uniqs);
		else
			st->roas_invalid++;
		roa_free(roa);
		break;
	case RTYPE_GBR:
		st->gbrs++;
		break;
	default:
		abort();
	}

	entity_queue--;
}

/*
 * Assign filenames ending in ".tal" in "/etc/rpki" into "tals",
 * returning the number of files found and filled-in.
 * This may be zero.
 * Don't exceded "max" filenames.
 */
static size_t
tal_load_default(const char *tals[], size_t max)
{
	static const char *confdir = "/etc/rpki";
	size_t s = 0;
	char *path;
	DIR *dirp;
	struct dirent *dp;

	dirp = opendir(confdir);
	if (dirp == NULL)
		err(1, "open %s", confdir);
	while ((dp = readdir(dirp)) != NULL) {
		if (fnmatch("*.tal", dp->d_name, FNM_PERIOD) == FNM_NOMATCH)
			continue;
		if (s >= max)
			err(1, "too many tal files found in %s",
			    confdir);
		if (asprintf(&path, "%s/%s", confdir, dp->d_name) == -1)
			err(1, NULL);
		tals[s++] = path;
	}
	closedir (dirp);
	return (s);
}

static char **
add_to_del(char **del, size_t *dsz, char *file)
{
	size_t i = *dsz;

	del = reallocarray(del, i + 1, sizeof(*del));
	if (del == NULL)
		err(1, NULL);
	if ((del[i] = strdup(file)) == NULL)
		err(1, NULL);
	*dsz = i + 1;
	return del;
}

static size_t
repo_cleanup(void)
{
	size_t i, delsz = 0;
	char *argv[3], **del = NULL;
	struct repo *rp;
	FTS *fts;
	FTSENT *e;

	SLIST_FOREACH(rp, &repos, entry) {
		argv[0] = rp->local;
		argv[1] = rp->temp;
		argv[2] = NULL;
		if ((fts = fts_open(argv, FTS_PHYSICAL | FTS_NOSTAT,
		    NULL)) == NULL)
			err(1, "fts_open");
		errno = 0;
		while ((e = fts_read(fts)) != NULL) {
			switch (e->fts_info) {
			case FTS_NSOK:
				if (!filepath_exists(&fpt, e->fts_path))
					del = add_to_del(del, &delsz,
					    e->fts_path);
				break;
			case FTS_D:
				break;
			case FTS_DP:
				if (rmdir(e->fts_accpath) == -1) {
					if (errno != ENOTEMPTY)
						warn("rmdir %s", e->fts_path);
				} else if (verbose > 1)
					logx("deleted %s", e->fts_path);
				break;
			case FTS_SL:
			case FTS_SLNONE:
				warnx("symlink %s", e->fts_path);
				del = add_to_del(del, &delsz, e->fts_path);
				break;
			case FTS_NS:
			case FTS_ERR:
				warnx("fts_read %s: %s", e->fts_path,
				    strerror(e->fts_errno));
				break;
			default:
				warnx("unhandled[%x] %s", e->fts_info,
				    e->fts_path);
				break;
			}

			errno = 0;
		}
		if (errno)
			err(1, "fts_read");
		if (fts_close(fts) == -1)
			err(1, "fts_close");
	}

	for (i = 0; i < delsz; i++) {
		if (unlink(del[i]) == -1)
			warn("unlink %s", del[i]);
		if (verbose > 1)
			logx("deleted %s", del[i]);
		free(del[i]);
	}
	free(del);

	return delsz;
}

void
suicide(int sig __attribute__((unused)))
{
	killme = 1;

}

int
main(int argc, char *argv[])
{
	int		 rc = 1, c, st, proc, rsync, http, rrdp, ok,
			 fl = SOCK_STREAM | SOCK_CLOEXEC;
	size_t		 i, id, outsz = 0, talsz = 0;
	pid_t		 procpid, rsyncpid, httppid, rrdppid;
	int		 fd[2];
	struct pollfd	 pfd[4];
	struct msgbuf	*queues[4];
	struct roa	**out = NULL;
	struct repo	*rp;
	char		*rsync_prog = "openrsync";
	char		*bind_addr = NULL;
	const char	*cachedir = NULL, *outputdir = NULL;
	const char	*tals[TALSZ_MAX], *errs;
	struct vrp_tree	 v = RB_INITIALIZER(&v);
	struct rusage	ru;
	struct timeval	start_time, now_time;

	gettimeofday(&start_time, NULL);

	/* If started as root, priv-drop to _rpki-client */
	if (getuid() == 0) {
		struct passwd *pw;

		pw = getpwnam("_rpki-client");
		if (!pw)
			errx(1, "no _rpki-client user to revoke to");
		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			err(1, "unable to revoke privs");

	}
	cachedir = RPKI_PATH_BASE_DIR;
	outputdir = RPKI_PATH_OUT_DIR;

	if (pledge("stdio rpath wpath cpath inet fattr dns sendfd recvfd "
	    "proc exec unveil", NULL) == -1)
		err(1, "pledge");

	while ((c = getopt(argc, argv, "b:Bcd:e:jnoRs:t:T:v")) != -1)
		switch (c) {
		case 'b':
			bind_addr = optarg;
			break;
		case 'B':
			outformats |= FORMAT_BIRD;
			break;
		case 'c':
			outformats |= FORMAT_CSV;
			break;
		case 'd':
			cachedir = optarg;
			break;
		case 'e':
			rsync_prog = optarg;
			break;
		case 'j':
			outformats |= FORMAT_JSON;
			break;
		case 'n':
			noop = 1;
			break;
		case 'o':
			outformats |= FORMAT_OPENBGPD;
			break;
		case 'R':
			rrdpon = 1;
			break;
		case 's':
			timeout = strtonum(optarg, 0, 24*60*60, &errs);
			if (errs)
				errx(1, "-s: %s", errs);
			break;
		case 't':
			if (talsz >= TALSZ_MAX)
				err(1,
				    "too many tal files specified");
			tals[talsz++] = optarg;
			break;
		case 'T':
			bird_tablename = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			goto usage;
		}

	argv += optind;
	argc -= optind;
	if (argc == 1)
		outputdir = argv[0];
	else if (argc > 1)
		goto usage;

	if (timeout) {
		signal(SIGALRM, suicide);
		/* Commit suicide eventually - cron will normally start a new one */
		alarm(timeout);
	}

	if (cachedir == NULL) {
		warnx("cache directory required");
		goto usage;
	}
	if (outputdir == NULL) {
		warnx("output directory required");
		goto usage;
	}

	if ((cachefd = open(cachedir, O_RDONLY, 0)) == -1)
		err(1, "cache directory %s", cachedir);
	if ((outdirfd = open(outputdir, O_RDONLY, 0)) == -1)
		err(1, "output directory %s", outputdir);

	if (outformats == 0)
		outformats = FORMAT_OPENBGPD;

	if (talsz == 0)
		talsz = tal_load_default(tals, TALSZ_MAX);
	if (talsz == 0)
		err(1, "no TAL files found in %s", "/etc/rpki");

	/* change working directory to the cache directory */
	if (fchdir(cachefd) == -1)
		err(1, "fchdir");

	/*
	 * Create the file reader as a jailed child process.
	 * It will be responsible for reading all of the files (ROAs,
	 * manifests, certificates, etc.) and returning contents.
	 */

	if (socketpair(AF_UNIX, fl, 0, fd) == -1)
		err(1, "socketpair");
	if ((procpid = fork()) == -1)
		err(1, "fork");

	if (procpid == 0) {
		close(fd[1]);

		/* Only allow access to the cache directory. */
		if (unveil(".", "r") == -1)
			err(1, "%s: unveil", cachedir);
		if (pledge("stdio rpath", NULL) == -1)
			err(1, "pledge");
		proc_parser(fd[0]);
		errx(1, "parser process returned");
	}

	close(fd[0]);
	proc = fd[1];

	/*
	 * Create a process that will do the rsync'ing.
	 * This process is responsible for making sure that all the
	 * repositories referenced by a certificate manifest (or the
	 * TAL) exists and has been downloaded.
	 */

	if (!noop) {
		if (socketpair(AF_UNIX, fl, 0, fd) == -1)
			err(1, "socketpair");
		if ((rsyncpid = fork()) == -1)
			err(1, "fork");

		if (rsyncpid == 0) {
			close(proc);
			close(fd[1]);

			if (pledge("stdio rpath proc exec unveil", NULL) == -1)
				err(1, "pledge");

			proc_rsync(rsync_prog, bind_addr, fd[0]);
			errx(1, "rsync process returned");
		}

		close(fd[0]);
		rsync = fd[1];
	} else
		rsync = -1;

	/*
	 * Create a process that will fetch data via https.
	 * With every request the http process receives a file descriptor
	 * where the data should be written to.
	 */

	if (!noop) {
		if (socketpair(AF_UNIX, fl, 0, fd) == -1)
			err(1, "socketpair");
		if ((httppid = fork()) == -1)
			err(1, "fork");

		if (httppid == 0) {
			close(proc);
			close(rsync);
			close(fd[1]);

			/* change working directory to the cache directory */
			if (fchdir(cachefd) == -1)
				err(1, "fchdir");

			if (pledge("stdio rpath inet dns recvfd", NULL) == -1)
				err(1, "pledge");

			proc_http(bind_addr, fd[0]);
			errx(1, "http process returned");
		}

		close(fd[0]);
		http = fd[1];
	} else
		http = -1;

	/*
	 * Create a process that will process RRDP.
	 * The rrdp process requires the http process to fetch the various
	 * XML files and does this via the main process.
	 */

	if (!noop && rrdpon) {
		if (socketpair(AF_UNIX, fl, 0, fd) == -1)
			err(1, "socketpair");
		if ((rrdppid = fork()) == -1)
			err(1, "fork");

		if (rrdppid == 0) {
			close(proc);
			close(rsync);
			close(http);
			close(fd[1]);

			/* change working directory to the cache directory */
			if (fchdir(cachefd) == -1)
				err(1, "fchdir");

			if (pledge("stdio recvfd", NULL) == -1)
				err(1, "pledge");

			proc_rrdp(fd[0]);
			/* NOTREACHED */
		}

		close(fd[0]);
		rrdp = fd[1];
	} else
		rrdp = -1;

	/* TODO unveil chachedir and outputdir, no other access allowed */
	if (pledge("stdio rpath wpath cpath fattr sendfd", NULL) == -1)
		err(1, "pledge");

	msgbuf_init(&procq);
	msgbuf_init(&rsyncq);
	msgbuf_init(&httpq);
	msgbuf_init(&rrdpq);
	procq.fd = proc;
	rsyncq.fd = rsync;
	httpq.fd = http;
	rrdpq.fd = rrdp;

	/*
	 * The main process drives the top-down scan to leaf ROAs using
	 * data downloaded by the rsync process and parsed by the
	 * parsing process.
	 */

	pfd[0].fd = rsync;
	queues[0] = &rsyncq;
	pfd[1].fd = proc;
	queues[1] = &procq;
	pfd[2].fd = http;
	queues[2] = &httpq;
	pfd[3].fd = rrdp;
	queues[3] = &rrdpq;

	/*
	 * Prime the process with our TAL file.
	 * This will contain (hopefully) links to our manifest and we
	 * can get the ball rolling.
	 */

	for (i = 0; i < talsz; i++)
		queue_add_tal(tals[i]);

	while (entity_queue > 0 && !killme) {
		for (i = 0; i < 4; i++) {
			pfd[i].events = POLLIN;
			if (queues[i]->queued)
				pfd[i].events |= POLLOUT;
		}

		if ((c = poll(pfd, 4, INFTIM)) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "poll");
		}

		for (i = 0; i < 4; i++) {
			if (pfd[i].revents & (POLLERR|POLLNVAL))
				errx(1, "poll[%zu]: bad fd", i);
			if (pfd[i].revents & POLLHUP)
				errx(1, "poll[%zu]: hangup", i);
			if (pfd[i].revents & POLLOUT) {
				/*
				 * XXX work around deadlocks because of
				 * blocking vs non-blocking sockets.
				 */
				if (i > 1)
					io_socket_nonblocking(pfd[i].fd);
				switch (msgbuf_write(queues[i])) {
				case 0:
					errx(1, "write: connection closed");
				case -1:
					err(1, "write");
				}
				if (i > 1)
					io_socket_blocking(pfd[i].fd);
			}
		}

		/*
		 * Check the rsync and http process.
		 * This means that one of our modules has completed
		 * downloading and we can flush the module requests into
		 * the parser process.
		 */

		if ((pfd[0].revents & POLLIN)) {
			io_simple_read(rsync, &id, sizeof(id));
			io_simple_read(rsync, &ok, sizeof(ok));

			rp = repo_find(id);
			if (rp == NULL)
				errx(1, "unknown repository id: %zu", id);

			assert(!rp->loaded);
			if (ok)
				logx("%s: loaded from network", rp->local);
			else
				logx("%s: load from network failed, "
				    "fallback to cache", rp->local);
			rp->loaded = 1;
			stats.repos++;
			entityq_flush(rp);
		}
		if ((pfd[2].revents & POLLIN)) {
			int status;
			char *last_mod;

			io_simple_read(http, &id, sizeof(id));
			io_simple_read(http, &ok, sizeof(ok));
			io_simple_read(http, &status, sizeof(status));
			io_str_read(http, &last_mod);

			rp = repo_find(id);
			if (rp == NULL)
				errx(1, "unknown repository id: %zu", id);

			assert(!rp->loaded);
			if (http_done(rp, ok, status, last_mod)) {
				rp->loaded = 1;
				stats.repos++;
				entityq_flush(rp);
			}
			free(last_mod);
		}

		/*
		 * Handle RRDP requests here.
		 */
		if ((pfd[3].revents & POLLIN)) {
			enum rrdp_msg type;
			enum publish_type pt;
			struct rrdp_session s;
			char *uri, *last_mod, *data;
			char hash[SHA256_DIGEST_LENGTH];
			size_t dsz;

			io_simple_read(rrdp, &type, sizeof(type));
			io_simple_read(rrdp, &id, sizeof(id));

			rp = repo_find(id);
			if (rp == NULL)
				errx(1, "unknown repository id: %zu", id);

			assert(!rp->loaded);
			switch (type) {
			case RRDP_END:
				io_simple_read(rrdp, &ok, sizeof(ok));
				if (rrdp_done(rp, ok)) {
					rp->loaded = 1;
					stats.repos++;
					entityq_flush(rp);
				}
				break;
			case RRDP_HTTP_REQ:
				io_str_read(rrdp, &uri);
				io_str_read(rrdp, &last_mod);
				http_rrdp_fetch(id, uri, last_mod);
				break;
			case RRDP_SESSION:
				io_str_read(rrdp, &s.session_id);
				io_simple_read(rrdp, &s.serial,
				    sizeof(s.serial));
				io_str_read(rrdp, &s.last_mod);
				rrdp_save_state(rp, &s);
				free(s.session_id);
				free(s.last_mod);
				break;
			case RRDP_FILE:
				io_simple_read(rrdp, &pt, sizeof(pt));
				if (pt != PUB_ADD)
					io_simple_read(rrdp, &hash,
					    sizeof(hash));
				io_str_read(rrdp, &uri);
				io_buf_read_alloc(rrdp, (void **)&data, &dsz);

				rrdp_handle_file(rp, pt, uri,
				    hash, sizeof(hash), data, dsz);

				free(uri);
				free(data);
				break;
			default:
				errx(1, "unexpected rrdp response");
			}
		}

		/*
		 * The parser has finished something for us.
		 * Dequeue these one by one.
		 */

		if ((pfd[1].revents & POLLIN)) {
			entity_process(proc, &stats, &v);
		}
	}

	if (killme) {
		syslog(LOG_CRIT|LOG_DAEMON,
		    "excessive runtime (%d seconds), giving up", timeout);
		errx(1, "excessive runtime (%d seconds), giving up", timeout);
	}

	assert(entity_queue == 0);
	logx("all files parsed: generating output");
	rc = 0;

	/*
	 * For clean-up, close the input for the parser and rsync
	 * process.
	 * This will cause them to exit, then we reap them.
	 */

	close(proc);
	close(rsync);
	close(http);
	close(rrdp);

	if (waitpid(procpid, &st, 0) == -1)
		err(1, "waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		warnx("parser process exited abnormally");
		rc = 1;
	}
	if (!noop) {
		if (waitpid(rsyncpid, &st, 0) == -1)
			err(1, "waitpid");
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			warnx("rsync process exited abnormally");
			rc = 1;
		}

		if (waitpid(httppid, &st, 0) == -1)
			err(1, "waitpid");
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			warnx("http process exited abnormally");
			rc = 1;
		}

		if (rrdpon) {
			if (waitpid(rrdppid, &st, 0) == -1)
				err(1, "waitpid");
			if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
				warnx("rrdp process exited abnormally");
				rc = 1;
			}
		}
	}

	stats.del_files = repo_cleanup();

	gettimeofday(&now_time, NULL);
	timersub(&now_time, &start_time, &stats.elapsed_time);
	if (getrusage(RUSAGE_SELF, &ru) == 0) {
		stats.user_time = ru.ru_utime;
		stats.system_time = ru.ru_stime;
	}
	if (getrusage(RUSAGE_CHILDREN, &ru) == 0) {
		timeradd(&stats.user_time, &ru.ru_utime, &stats.user_time);
		timeradd(&stats.system_time, &ru.ru_stime, &stats.system_time);
	}

	/* change working directory to the cache directory */
	if (fchdir(outdirfd) == -1)
		err(1, "fchdir output dir");

	if (outputfiles(&v, &stats))
		rc = 1;


	logx("Route Origin Authorizations: %zu (%zu failed parse, %zu invalid)",
	    stats.roas, stats.roas_fail, stats.roas_invalid);
	logx("Certificates: %zu (%zu failed parse, %zu invalid)",
	    stats.certs, stats.certs_fail, stats.certs_invalid);
	logx("Trust Anchor Locators: %zu", stats.tals);
	logx("Manifests: %zu (%zu failed parse, %zu stale)",
	    stats.mfts, stats.mfts_fail, stats.mfts_stale);
	logx("Certificate revocation lists: %zu", stats.crls);
	logx("Ghostbuster records: %zu", stats.gbrs);
	logx("Repositories: %zu", stats.repos);
	logx("Files removed: %zu", stats.del_files);
	logx("VRP Entries: %zu (%zu unique)", stats.vrps, stats.uniqs);

	/* Memory cleanup. */
	while ((rp = SLIST_FIRST(&repos)) != NULL) {
		SLIST_REMOVE_HEAD(&repos, entry);
		free(rp->repouri);
		free(rp->local);
		free(rp->temp);
		free(rp->uris[0]);
		free(rp->uris[1]);
		free(rp);
	}

	for (i = 0; i < outsz; i++)
		roa_free(out[i]);
	free(out);

	return rc;

usage:
	fprintf(stderr,
	    "usage: rpki-client [-Bcjnov] [-b sourceaddr] [-d cachedir]"
	    " [-e rsync_prog]\n"
	    "                   [-s timeout] [-T table] [-t tal]"
	    " [outputdir]\n");
	return 1;
}
