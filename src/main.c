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

static struct xmldata*
fetch_notification_xml(char* uri, struct opts *opts)
{
	struct xmldata *xml_data = new_notification_xml_data(uri, opts);
	if (fetch_xml_uri(xml_data) != 0)
		err(1, "failed to curl");
	struct notification_xml *nxml = xml_data->xml_data;

	if (!nxml)
		err(1, "no notification_xml available");
	print_notification_xml(nxml);
	return xml_data;
}

static void
process_notification_xml(struct xmldata *xml_data, struct opts *opts) {
	struct notification_xml *nxml = xml_data->xml_data;
	int num_deltas = 0;
	int expected_deltas = 0;
	struct delta_item *d;

	switch (nxml->state) {
	case NOTIFICATION_STATE_ERROR:
		err(1, "NOTIFICATION_STATE_ERROR");
	case NOTIFICATION_STATE_NONE:
		rm_working_dir(opts);
		printf("up to date\n");
		return;
	case NOTIFICATION_STATE_DELTAS:
		expected_deltas = nxml->serial - nxml->current_serial;
		if (opts->single_delta)
			expected_deltas = 1;
		printf("fetching deltas\n");
		while (!TAILQ_EMPTY(&(nxml->delta_q))) {
			d = TAILQ_FIRST(&(nxml->delta_q));
			TAILQ_REMOVE(&(nxml->delta_q), d, q);
			/* XXXCJ check that uri points to same host */
			if (num_deltas < 1 || !opts->single_delta) {
				if (fetch_delta_xml(d->uri, d->hash,
				    opts, nxml) == 0)
					num_deltas++;
				else {
					printf("failed to fetch delta %s\n",
					    d->uri);
					break;
				}
			}
			free_delta(d);
			/* in case we wrote fewer deltas */
			nxml->serial = nxml->current_serial + num_deltas;
		}
		/*
		 * TODO should we apply as many deltas as possible or
		 * roll them all back? (maybe an option?) ie. do a
		 * mv_delta after each loop above if failed to
		 * fetch/apply deltas then fallthrough to snapshot
		 */
		if (num_deltas == expected_deltas) {
			if (mv_delta(opts->basedir_working,
			    opts->basedir_primary) == 0) {
				rm_working_dir(opts);
				printf("delta migrate passed\n");
				break;
			} else
				printf("delta migration failed\n");
		} else
			printf("not all deltas processed: %d/%d\n", num_deltas,
			    expected_deltas);
		/* Clean up the snapshot delta dir and make a new one */
		rm_working_dir(opts);
		free_workdir(opts);
		make_workdir(opts->basedir_primary, opts);
		printf("deltas failed going to snapshot\n");
		/* FALLTHROUGH */
	case NOTIFICATION_STATE_SNAPSHOT:
		printf("fetching snapshot\n");
		/* XXXCJ check that uri points to same host */
		if (fetch_snapshot_xml(nxml->snapshot_uri,
		    nxml->snapshot_hash, opts, nxml) != 0) {
			rm_working_dir(opts);
			err(1, "failed to run snapshot");
		}
		/*
		 * XXXNF bad things can happen here if we fail we have no
		 * primary dir left :s
		 */
		rm_primary_dir(opts);
		if (mv_delta(opts->basedir_working,
		    opts->basedir_primary) != 0) {
			rm_primary_dir(opts);
			rm_working_dir(opts);
			err(1, "failed to update");
		}
		printf("snapshot move success\n");
	}
	save_notification_data(xml_data);
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
	char *basedir;
	int opt;
	struct xmldata *xml_data;
	opts.single_delta = 0;

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
	make_workdir(basedir, &opts);
	opts.basedir_primary = basedir;
	opts.primary_dir = open(opts.basedir_primary, O_RDONLY|O_DIRECTORY);
	if (opts.primary_dir < 0)
		err(1, "failed to open dir: %s", basedir);
	xml_data = fetch_notification_xml(uri, &opts);
	process_notification_xml(xml_data, &opts);
	free_workdir(&opts);
}
