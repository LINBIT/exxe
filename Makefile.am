SUBDIRS = exxe python tests

AM_MAKEFLAGS = --no-print-directory

distclean-local:
	rm -rf build

EXTRA_DIST = $(top_srcdir)/.version \
				 $(top_srcdir)/build-aux/git-version-gen \
				 $(top_srcdir)/build-aux/gitlog-to-changelog \
				 $(top_srcdir)/debian/changelog \
				 $(top_srcdir)/debian/compat \
				 $(top_srcdir)/debian/control \
				 $(top_srcdir)/debian/copyright \
				 $(top_srcdir)/debian/rules \
				 $(top_srcdir)/python/setup.py
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version

.PHONY: gen-ChangeLog
gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then					\
	  $(top_srcdir)/build-aux/gitlog-to-changelog > $(distdir)/cl-t;	\
	  rm -f $(distdir)/ChangeLog;						\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;				\
        fi

rpm: dist
	rpmbuild -ba \
		--define "_topdir $(CURDIR)/build" \
		--define "_sourcedir $(CURDIR)" \
		--clean \
		$(PACKAGE).spec

deb:
	debuild -us -uc -i -b
