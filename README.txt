This project is to implement RPKI Repository Delta Protocol (RRDP) fetching for
the openbsd rpki implementation.

To build on OpenBSD use make in the src directory.

rrdp expects a notification url, and a directory (-d) to put the repo it is
associated with.

Expected to be used in association with changes in rpki-client which call this
instead of rsync.
