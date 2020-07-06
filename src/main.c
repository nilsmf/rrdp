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
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>

#include "notification.h"
#include "snapshot.h"
#include "delta.h"
#include "file_util.h"

/*
 * - use If-Modified-Since header for notification requests
 * - handle network failures with retries
 * - start to handle errors better
 * - nice to have optimise with keep alives etc.
 * - deal with withdraws (either ignore or leave as is)
 * - should we ensure versions match between calls?
 * - exit early from xml parsing if we know we are ok already?
 *   I think no since we need to make sure it is valid still...
 * - curl -> ftp
 * - dont allow basedirs outside our dirs (check for ..)

 * - check for error of malloc/calloc and strdup functions
 * - replace printf with more elaborate reporting (log_warn / log_debug...)
 * - check for memleaks (e.g. no call to XML_ParserFree())
 */

static int
rm_working_dir(struct opts *opts) {
	if (close(opts->working_dir))
		err(1, __func__);
	return rm_dir(opts->basedir_working, 0);
}

static int
rm_primary_dir(struct opts *opts) {
	/*
	 * Don't delete the primary dir itself. It has an open fd we will use.
	 */
	return rm_dir(opts->basedir_primary, 1);
}

static void
fetch_delta_xml(char *uri, char *hash, struct opts *opts,
    struct notification_xml* nxml) {
	struct xmldata *delta_xml_data =
	    new_delta_xml_data(uri, hash, opts, nxml);
	if (fetch_xml_uri(delta_xml_data) != 0)
		err(1, "failed to curl");
	/*
	 * TODO free this
	 * free_delta_xml(delta_xml_data);
	 */
}

static void
fetch_snapshot_xml(char *uri, char *hash, struct opts *opts,
    struct notification_xml* nxml) {
	struct xmldata *snapshot_xml_data =
	    new_snapshot_xml_data(uri, hash, opts, nxml);
	if (fetch_xml_uri(snapshot_xml_data) != 0)
		err(1, "failed to curl");
	/*
	 * TODO free this
	 * free_snapshot_xml(snapshot_xml_data);
	 */
}

static void
fetch_notification_xml(char* uri, struct opts *opts)
{
	struct xmldata *xml_data = new_notification_xml_data(uri, opts);
	if (fetch_xml_uri(xml_data) != 0)
		err(1, "failed to curl");
	struct notification_xml *nxml = xml_data->xml_data;

	if (nxml) {
		print_notification_xml(nxml);

		switch (nxml->state) {
		case NOTIFICATION_STATE_ERROR:
			err(1, "NOTIFICATION_STATE_ERROR");
		case NOTIFICATION_STATE_NONE:
			rm_working_dir(opts);
			printf("up to date\n");
			return;
		case NOTIFICATION_STATE_DELTAS:
			printf("fetching deltas\n");
			while (!TAILQ_EMPTY(&(nxml->delta_q))) {
				struct delta_item *d =
				    TAILQ_FIRST(&(nxml->delta_q));
				TAILQ_REMOVE(&(nxml->delta_q), d, q);
				/* XXXCJ check that uri points to same host */
				fetch_delta_xml(d->uri, d->hash, opts, nxml);
				free_delta(d);
			}
			/*
			 * TODO should we apply as many deltas as possible or
			 * roll them all back? (maybe an option?) ie. do a
			 * mv_delta after each loop above if failed to
			 * fetch/apply deltas then fallthrough to snapshot
			 */
			if (!mv_delta(opts->basedir_working,
			    opts->basedir_primary)) {
				printf("delta migrate passed\n");
				break;
			}
			rm_working_dir(opts);
			printf("delta move failed going to snapshot\n");
			/* FALLTHROUGH */
		case NOTIFICATION_STATE_SNAPSHOT:
			printf("fetching snapshot\n");
			/* XXXCJ check that uri points to same host */
			fetch_snapshot_xml(nxml->snapshot_uri,
			    nxml->snapshot_hash, opts, nxml);
			rm_primary_dir(opts);
			if (mv_delta(opts->basedir_working,
			    opts->basedir_primary))
				err(1, "failed to update");
		}
		save_notification_data(xml_data);
	} else
		err(1, "no notification_xml available");
}

static __dead void
usage(void)
{
	fprintf(stderr, "usage: rrdp [-d cachedir] uri\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct opts opts;
	char *cachedir = "/tmp/rrdp";
	char *uri = NULL;
	char *basedir, *workdir;
	int opt;

	while ((opt = getopt(argc, argv, "d:")) != -1) {
		switch (opt) {
		case 'd':
			cachedir = optarg;
			break;
		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	/* XXX hack for now for quick testing */
	if (argc == 0)
		uri = "https://ca.rg.net/rrdp/notify.xml";
	else if (argc == 1)
		uri = argv[0];
	else
		usage();

	basedir = generate_basepath_from_uri(uri, cachedir, "https://");
	mkpath(basedir, USR_RWX_MODE);
	workdir = make_workdir(basedir);
	opts.basedir_primary = basedir;
	opts.basedir_working = workdir;
	opts.primary_dir = open(opts.basedir_primary, O_RDONLY|O_DIRECTORY);
	if (opts.primary_dir < 0)
		err(1, "failed to open dir: %s", basedir);
	opts.working_dir = open(opts.basedir_working, O_RDONLY|O_DIRECTORY);
	if (opts.working_dir < 0)
		err(1, "failed to open dir: %s", workdir);

	fetch_notification_xml(uri, &opts);
	free(workdir);
}
