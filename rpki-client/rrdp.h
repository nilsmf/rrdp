#ifndef _RRDPH_
#define _RRDPH_

#include <stdio.h>
#include <sys/queue.h>
#include <expat.h>
#include <openssl/sha.h>

/* util */
#define MAX_VERSION 1

#define log_debuginfo(format, ...) logx(format, ##__VA_ARGS__)

char 	*xstrdup(const char *);
int	 hex_to_bin(const char *, char *, size_t);

struct opts;

FILE 		*open_primary_uri_read(char *, struct opts *);
FILE 		*open_working_uri_read(char *, struct opts *);
FILE 		*open_working_uri_write(char *, struct opts *);
void		 make_workdir(const char *, struct opts *);
void		 free_workdir(struct opts *);
const char	*fetch_filename_from_uri(const char *, const char *);

/* file_util */
enum action {
	ACTION_COPY,
	ACTION_DELETE
};

struct file_delta {
	char *filename;
	enum action action;
	SLIST_ENTRY(file_delta) file_list;
};

SLIST_HEAD(file_list, file_delta);

int mkpath_at(int, const char *);
int rm_dir(char *, int);
int mv_delta(int, int, struct file_list *);
int empty_file_list(struct file_list *);
void add_to_file_list(struct file_list *, const char *, int, int);

/* save everyone doing this code over and over */
#define PARSE_FAIL(p, ...) do {		\
	XML_StopParser(p, XML_FALSE);	\
	warnx(__VA_ARGS__);		\
	return;				\
} while(0)

struct rrdp_session {
	char			*last_mod;
	char			*session_id;
	long long		 serial;
};

/* notification */
struct notification_xml;

struct notification_xml	*new_notification_xml(XML_Parser,
			    struct rrdp_session *);
void		 	 free_notification_xml(struct notification_xml *);
void			 log_notification_xml(struct notification_xml *);
const char		*notification_get_next(struct notification_xml *,
			    char *, size_t, int);

/* snapshot */
struct snapshot_xml;

struct snapshot_xml	*new_snapshot_xml(XML_Parser, struct rrdp_session *);
void			 free_snapshot_xml(struct snapshot_xml *);
void			 log_snapshot_xml(struct snapshot_xml *);

/* delta */
struct delta_xml;

struct delta_xml	*new_delta_xml(XML_Parser, struct rrdp_session *);
void			 free_delta_xml(struct delta_xml *);
void			 log_delta_xml(struct delta_xml *);

#endif /* _RRDPH_ */
