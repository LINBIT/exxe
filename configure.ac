AC_INIT([exxe],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [Andreas Gruenbacher <andreas.gruenbacher@gmail.com>],
        ,
        [http://git.drbd.org/exxe.git])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_FILES([
	Makefile
	exxe/Makefile
	tests/Makefile
	python/Makefile
	exxe.spec
])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AM_PATH_PYTHON

AC_PROG_CC
AC_PROG_CC_STDC
AC_OUTPUT
