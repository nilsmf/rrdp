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

#include "notification.h"
#include "snapshot.h"
#include "delta.h"
#include "file_util.h"

// libxm (l?)
// ftp/curl
//
// xml has urls to download the files
//
// rrdp servers
// step 0. fetch notification files
// 	step 0.1 process notification files
// step 1. fetch snapshot
// 	step 1.1 process snapshot files
// step 2. fetch delta
// 	step 2.1 process deltas
//
// ? If 1 delta fails should we try other snapshots
//  if parsing a delta fails whole snapshot must fail since we wont be able to update all the bits and pieces... hmmm tends to imply an intermediate dir...
//
// nice to have optimise with keep alives etc.
//
// * start to check which things need to be updated (serial #)
// * start to validate file existance and hash
// * add 2nd layer of files in case of error
// * fix b64 file saving
// * migrate snapshot from working dir
// * migrate deltas from working dir
// * fix file_util.c to not use built calls to system
// * validate hash of snapshot and delta files
// - validate session_ids match notification files
// - use If-Modified-Since header for notification requests
// - handle network failures with retries
// - ensure snapshot/notification serial must be greater than previous
// - ensure mismatching session_ids between notification calls invoke a snapshot
// - handle unordered deltas
// - version in notification, snapshot and delta elems must always == 1
// - oops dont verify withdraws atm
// - enforce that withdraws have a hash
// - validate hosts etc stay the same between calls / or only ever use the notification hostname for the folder location
// - exit early from xml parsing if we know we are ok already?
// - start to handle errors better

static void
fetch_delta_xml(char *uri, char *hash, struct opts *opts)
{
	struct xmldata *delta_xml_data = new_delta_xml_data(uri, hash, opts);
	if (fetch_xml_uri(delta_xml_data) != 0) {
		err(1, "failed to curl");
	}
	//TODO free this
	//free_delta_xml(delta_xml_data);
}

static void
fetch_snapshot_xml(char *uri, char *hash, struct opts *opts)
{
	struct xmldata *snapshot_xml_data = new_snapshot_xml_data(uri, hash, opts);
	if (fetch_xml_uri(snapshot_xml_data) != 0) {
		err(1, "failed to curl");
	}
	//TODO free this
	//free_snapshot_xml(snapshot_xml_data);
}

static void
fetch_notification_xml(char* uri, struct opts *opts)
{
	struct xmldata *xml_data = new_notification_xml_data(uri, opts);
	if (fetch_xml_uri(xml_data) != 0) {
		err(1, "failed to curl");
	}
	struct notification_xml *nxml = xml_data->xml_data;

	if (nxml) {
		print_notification_xml(nxml);
		char *primary_path = opts->basedir_primary;
		char *working_path = opts->basedir_working;

		switch (nxml->state) {
		case NOTIFICATION_STATE_ERROR:
			err(1, "NOTIFICATION_STATE_ERROR");
		case NOTIFICATION_STATE_NONE:
			printf("up to date\n");
			return;
		case NOTIFICATION_STATE_DELTAS:
			printf("fetching deltas\n");
			while (!TAILQ_EMPTY(&(nxml->delta_q))) {
				struct delta_item *d = TAILQ_FIRST(&(nxml->delta_q));
				TAILQ_REMOVE(&(nxml->delta_q), d, q);
				/* XXXCJ check that uri points to same host */
				fetch_delta_xml(d->uri, d->hash, opts);
				free_delta(d);
			}
			//TODO should we apply as many deltas as possible or roll them all back? (maybe an option?)
			// ie. do a mv_delta after each loop above
			//if failed to fetch/apply deltas then fallthrough to snapshot
			if (!mv_delta(working_path, primary_path)) {
				printf("delta migrate passed\n");
				break;
			}
			rm_dir(working_path);
			printf("delta move failed going to snapshot\n");
			/* FALLTHROUGH */
		case NOTIFICATION_STATE_SNAPSHOT:
			printf("fetching snapshot\n");
			/* XXXCJ check that uri points to same host */
			fetch_snapshot_xml(nxml->snapshot_uri, nxml->snapshot_hash, opts);
			rm_dir(primary_path);
			if (mv_delta(working_path, primary_path))
				err(1, "failed to update");
		}
		save_notification_data(xml_data);
	} else {
		err(1, "no notification_xml available");
	}
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
	struct opts *opts;
	char *cachedir = "/tmp/rrdp";
	char *uri, *basedir, *workdir;
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
	workdir = make_workdir(basedir);

	opts = newOpt(basedir, workdir);
	fetch_notification_xml(uri, opts);
	cleanopts(opts);
}
