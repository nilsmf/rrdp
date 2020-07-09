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

#ifndef _UTILH_
#define _UTILH_

#define BASE10 10
#define MAX_VERSION 1

#define USR_RW_MODE S_IRUSR|S_IWUSR
#define USR_RWX_MODE USR_RW_MODE|S_IXUSR

struct opts {
	char *basedir_primary;
	char *basedir_working;
	int primary_dir;
	int working_dir;
	int single_delta;
};

int	b64_decode(char *, unsigned char **);

char	*generate_basepath_from_uri(const char *, const char *, const char *);
FILE 	*open_primary_uri_read(char *, struct opts *);
FILE 	*open_working_uri_read(char *, struct opts *);
FILE 	*open_working_uri_write(char *, struct opts *);
void	make_workdir(const char *, struct opts *);
void	free_workdir(struct opts *);

#endif

