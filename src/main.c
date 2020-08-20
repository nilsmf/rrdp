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
#include <syslog.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "log.h"
#include "rrdp.h"

static int
rm_working_dir(struct opts *opts)
{
	int ret;
	if (close(opts->working_dir))
		fatal("%s - close", __func__);
	if ((ret = rm_dir(opts->basedir_working, 0)) != 0) {
		log_warnx("%s - failed to remove working dir", __func__);
		ret = 1;
	}
	return ret;
}

static int
rm_primary_dir(struct opts *opts)
{
	/*
	 * Don't delete the primary dir itself (use flag).
	 * It has an open fd we will use.
	 */
	return rm_dir(opts->basedir_primary, 1);
}

static struct xmldata*
fetch_notification_xml(char* uri, struct opts *opts)
{
	struct xmldata *xml_data = new_notification_xml_data(uri, opts);
	long res;
	res = fetch_xml_uri(xml_data);
	if (res != 200 && res != 304)
		fatalx("%s", __func__);

	struct notification_xml *nxml = xml_data->xml_data;

	if (!nxml)
		fatalx("no notification_xml available");
	if (res == 304) {
		log_debuginfo("Got up to date return code from server");
		nxml->state = NOTIFICATION_STATE_NONE;
	} else {
		/* one last check in case empty values returned */
		check_state(nxml);
	}
	log_notification_xml(nxml);
	return xml_data;
}

static void
process_notification_xml(struct xmldata *xml_data, struct opts *opts)
{
	struct notification_xml *nxml = xml_data->xml_data;
	int num_deltas = 0;
	int expected_deltas = 0;
	struct delta_item *d;

	switch (nxml->state) {
	case NOTIFICATION_STATE_ERROR:
		fatalx("NOTIFICATION_STATE_ERROR");
	case NOTIFICATION_STATE_NONE:
		rm_working_dir(opts);
		log_debuginfo("up to date");
		return;
	case NOTIFICATION_STATE_DELTAS:
		expected_deltas = nxml->serial - nxml->current_serial;
		if (opts->delta_limit &&
		    opts->delta_limit < expected_deltas) {
			expected_deltas = opts->delta_limit;
			/* XXXNF Hack to make this work */
			xml_data->modified_since[0] = '\0';
		}
		log_debuginfo("fetching deltas");
		while (!TAILQ_EMPTY(&(nxml->delta_q))) {
			d = TAILQ_FIRST(&(nxml->delta_q));
			TAILQ_REMOVE(&(nxml->delta_q), d, q);
			/* XXXCJ check that uri points to same host */
			if (num_deltas < opts->delta_limit ||
			    !opts->delta_limit) {
				if (fetch_delta_xml(d->uri, d->hash,
				    opts, nxml) == 0)
					num_deltas++;
				else {
					log_warnx("failed to fetch delta %s",
					    d->uri);
					free_delta(d);
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
			    opts->basedir_primary, opts->primary_dir) == 0) {
				log_debuginfo("delta migrate passed");
				break;
			} else
				log_warnx("delta migration failed");
		} else
			log_warnx("not all deltas processed: %d/%d", num_deltas,
			    expected_deltas);
		/* Clean up the snapshot delta dir and make a new one */
		rm_working_dir(opts);
		free_workdir(opts);
		log_warnx("deltas failed going to snapshot");
		make_workdir(opts->basedir_primary, opts);
		/* FALLTHROUGH */
	case NOTIFICATION_STATE_SNAPSHOT:
		log_debuginfo("fetching snapshot");
		/* XXXCJ check that uri points to same host */
		if (fetch_snapshot_xml(nxml->snapshot_uri,
		    nxml->snapshot_hash, opts, nxml) != 0) {
			rm_working_dir(opts);
			fatalx("failed to run snapshot");
		}
		/*
		 * XXXNF bad things can happen here if we fail we have no
		 * primary dir left :s
		 */
		rm_primary_dir(opts);
		if (mv_delta(opts->basedir_working,
		    opts->basedir_primary, opts->primary_dir) != 0) {
			rm_primary_dir(opts);
			rm_working_dir(opts);
			fatal("failed to update");
		}
		log_debuginfo("snapshot move success");
	}
	save_notification_data(xml_data);
}

static __dead void
usage(void)
{
	fprintf(stderr, "usage: rrdp [-l delta_limit][-f ftp_bin]"
	    "[-i] -d cachedir uri\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct opts opts;
	char *cachedir = NULL;
	char *uri = NULL;
	char *basedir;
	struct stat st;
	int opt;
	struct xmldata *xml_data;
	opts.delta_limit = 0;
	opts.ignore_withdraw = 0;
	opts.ftp_prog = "/usr/bin/ftp";

	if (pledge("stdio rpath wpath cpath fattr proc unveil exec", NULL) == -1)
		fatal("pledge");
	while ((opt = getopt(argc, argv, "d:f:il:")) != -1) {
		switch (opt) {
		case 'd':
			cachedir = optarg;
			break;
		case 'f':
			opts.ftp_prog = optarg;
			break;
		case 'i':
			opts.ignore_withdraw = 1;
			break;
		case 'l':
			opts.delta_limit = (int)strtol(optarg, NULL, BASE10);
			break;
		default:
			usage();
		}
	}

#ifdef DEBUG
	log_init(1, LOG_USER);
#else
	log_init(0, LOG_USER);
#endif
	argv += optind;
	argc -= optind;

	if (argc == 1)
		uri = argv[0];
	else
		usage();

	if (cachedir == NULL)
		usage();
	basedir = xstrdup(cachedir);
	if (stat(basedir, &st) != 0)
		fatal("cachedir missing");
	opts.basedir_primary = basedir;
	opts.primary_dir = open(opts.basedir_primary, O_RDONLY|O_DIRECTORY);
	if (opts.primary_dir < 0)
		fatal("failed to open dir: %s", basedir);
	make_workdir(basedir, &opts);
	if (unveil(basedir, "crw") == -1)
		fatal("%s: unveil", basedir);

	xml_data = fetch_notification_xml(uri, &opts);
	process_notification_xml(xml_data, &opts);
	free_xml_data(xml_data);
	close(opts.primary_dir);
	free_workdir(&opts);
	free(basedir);
}
