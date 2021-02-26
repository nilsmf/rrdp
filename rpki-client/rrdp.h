#ifndef _RRDPH_
#define _RRDPH_

#define MAX_VERSION 1

#define log_debuginfo(format, ...) logx(format, ##__VA_ARGS__)

/* save everyone doing this code over and over */
#define PARSE_FAIL(p, ...) do {		\
	XML_StopParser(p, XML_FALSE);	\
	warnx(__VA_ARGS__);		\
	return;				\
} while(0)

enum publish_type {
	PUB_ADD,
	PUB_DEL,
};

/* rrdp generic */
char 	*xstrdup(const char *);
int	 hex_to_bin(const char *, char *, size_t);

/* publish or withdraw element */
struct publish_xml;

struct publish_xml	*new_publish_xml(enum publish_type, char *,
			    char *, size_t);
void			 free_publish_xml(struct publish_xml *);
void			 publish_xml_add_content(struct publish_xml *,
			    const char *, int);
int			 publish_xml_done(struct publish_xml *);

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
