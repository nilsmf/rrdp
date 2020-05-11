CC=gcc
INCLUDES=
CFLAGS=-Wall -c
MAKE=make

TOPTARGETS := all clean obj

SUBDIRS:=src
SUBDIRS+= regress

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

subdirs:
	echo "x${SUBDIRS}x"

.PHONY: $(TOPTARGETS) $(SUBDIRS)

