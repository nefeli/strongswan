AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon
AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sa-notify.la
else
plugin_LTLIBRARIES = libstrongswan-sa-notify.la
endif

libstrongswan_sa_notify_la_SOURCES = \
	sa_notify_plugin.h sa_notify_plugin.c \
	sa_notify_listener.h sa_notify_listener.c
libstrongswan_sa_notify_la_LDFLAGS = -module -avoid-version
