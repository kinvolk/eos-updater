testlib = libeos-updater-test.la
noinst_LTLIBRARIES = $(testlib)

libeos_updater_test_la_CPPFLAGS = \
	$(GIO_CFLAGS) \
	-DTEST_SERVICES_DIRECTORY=\""$(abs_top_builddir)/tests/services"\" \
	-DOSTREE_BINARY=\""$(OSTREE)"\" \
	-DEOS_AUTOUPDATER_BINARY=\""$(abs_top_builddir)/src/eos-autoupdater"\" \
	-DEOS_UPDATER_BINARY=\""$(abs_top_builddir)/src/eos-updater"\" \
	-DGPG_HOME_DIRECTORY=\""$(abs_top_builddir)/tests/gpghome"\" \
	-DGPG_BINARY=\""$(GPG)"\" \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	$(NULL)

libeos_updater_test_la_LIBADD = $(GIO_LIBS)
libeos_updater_test_la_SOURCES = \
	spawn-utils.c \
	spawn-utils.h \
	misc-utils.c \
	misc-utils.h \
	ostree-spawn.c \
	ostree-spawn.h \
	eos-test-utils.c \
	eos-test-utils.h \
	$(NULL)

check_PROGRAMS = \
	test-update-from-main \
	$(NULL)

TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = \
	G_DEBUG=gc-friendly,fatal-criticals,fatal-warnings \
	MALLOC_CHECK_=3 \
	MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256)) \
	$(if $(EOS_UPDATER_GDB),EOS_CHECK_UPDATER_GDB_BASH_PATH=$(EOS_UPDATER_GDB)) \
	$(NULL)

test_cflags = \
	$(GIO_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	$(NULL)

test_ldadd = \
	$(GIO_LIBS) \
	$(testlib) \
	$(NULL)

test_update_from_main_CPPFLAGS = $(test_cflags)
test_update_from_main_LDADD = $(test_ldadd)
test_update_from_main_SOURCES = test-update-from-main.c
