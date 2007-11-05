noinst_PROGRAMS = pam_ccreds.so cc_test cc_dump
sbin_PROGRAMS = ccreds_chkpwd
EXTRA_DIST = COPYING.LIB CVSVersionInfo.txt ChangeLog README \
	     ldap.conf pam.conf pam_ccreds.spec

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS)
AM_CFLAGS = -fno-strict-aliasing
LDADD = $(LIBGCRYPT_LIBS)

pam_ccreds_so_SOURCES = cc_db.c cc_lib.c cc_pam.c cc.h
pam_ccreds_so_LDFLAGS = @pam_ccreds_so_LDFLAGS@

cc_test_SOURCES = cc_test.c
cc_test_LDFLAGS = -Wl,-rpath -Wl,$(libdir)/security pam_ccreds.so -lpam -lpam_misc

cc_dump_SOURCES = cc_dump.c
cc_dump_LDFLAGS = -Wl,-rpath -Wl,$(libdir)/security pam_ccreds.so -lpam -lpam_misc

ccreds_chkpwd_SOURCES = ccreds_chkpwd.c
ccreds_chkpwd_LDFLAGS = -Wl,-rpath -Wl,$(libdir)/security pam_ccreds.so -lpam -lpam_misc

DEFS = @DEFS@

if USE_NATIVE_LINKER
NATIVE_LINK = $(pam_ccreds_so_LD) $(AM_LDFLAGS) -o $@ 
else
GNU_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
endif

# This is horrible but appears to be the only way to work with
# recent versions of automake. Any better ideas, let me know.
LINK = $(NATIVE_LINK) $(GNU_LINK)

install-exec-local: pam_ccreds.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/security
if EXTENSION_SO
	$(INSTALL_PROGRAM) -o root -g root pam_ccreds.so $(DESTDIR)$(libdir)/security/pam_ccreds.so
else
if EXTENSION_1
	$(INSTALL_PROGRAM) -o root -g root pam_ccreds.so $(DESTDIR)$(libdir)/security/libpam_ccreds.1
else
	$(INSTALL_PROGRAM) -o root -g root pam_ccreds.so $(DESTDIR)$(libdir)/security/pam_ccreds.so.1
	(cd $(DESTDIR)$(libdir)/security; rm -f pam_ccreds.so; ln -s pam_ccreds.so.1 pam_ccreds.so)
endif
endif

