AM_CFLAGS = -I$(top_srcdir)/include \
			-I$(top_srcdir)/src \
			-I$(top_srcdir)/tests/utils/ \
			-I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBOTR=$(top_builddir)/src/libotr.la

noinst_PROGRAMS = test_auth test_proto

test_auth_SOURCES = test_auth.c
test_auth_LDADD = $(LIBTAP) $(LIBOTR)

test_proto_SOURCES = test_proto.c
test_proto_LDADD = $(LIBTAP) $(LIBOTR)
