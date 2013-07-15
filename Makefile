PACKAGE := exxe
VERSION := 0.1

CFLAGS := -g -Wall -O0
LDFLAGS := -g -Wall -O0

SOURCE_FILES := \
	Makefile \
	README \
	TODO \
	buffer.c \
	buffer.h \
	error.c \
	error.h \
	exxe.c \
	list.h \
	parse.c \
	parse.h \
	xalloc.c \
	xalloc.h \
	tests/all \
	tests/Makefile \
	tests/test-lib.sh

export srcdir := $(CURDIR)
export abs_top_builddir := $(CURDIR)

all: exxe

exxe: exxe.o buffer.o xalloc.o parse.o error.o

check: exxe
	$(MAKE) -C tests $@

dist:
	@rm -f $(PACKAGE)-$(VERSION)
	ln -s . $(PACKAGE)-$(VERSION)
	tar cfz $(PACKAGE)-$(VERSION).tar.gz $(SOURCE_FILES:%=$(PACKAGE)-$(VERSION)/%)
	rm -f $(PACKAGE)-$(VERSION)

clean:
	rm -f exxe exxe.o error.o parse.o xalloc.o buffer.o

distclean: clean
	rm -f $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION).tar.gz
