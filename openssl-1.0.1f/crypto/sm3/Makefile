#
# OpenSSL/crypto/sm3/Makefile
#

DIR=    sm3
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST= sm3test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=sm3_dgst.c sm3_one.c m_sm3.c
LIBOBJ=sm3_dgst.o sm3_one.o m_sm3.o

SRC= $(LIBSRC)

EXHEADER= sm3.h
HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.
sm3_dgst.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm3_dgst.o: ../../include/openssl/sm3.h ../../include/openssl/opensslconf.h
sm3_dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm3_dgst.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
sm3_dgst.o: ../../include/openssl/symhacks.h ../md32_common.h sm3_dgst.c
sm3_one.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm3_one.o: ../../include/openssl/sm3.h ../../include/openssl/opensslconf.h
sm3_one.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm3_one.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
sm3_one.o: ../../include/openssl/symhacks.h sm3_one.c

m_sm3.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
m_sm3.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
m_sm3.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
m_sm3.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
m_sm3.o: ../../include/openssl/err.h ../../include/openssl/evp.h
m_sm3.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
m_sm3.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
m_sm3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
m_sm3.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
m_sm3.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
m_sm3.o: ../../include/openssl/symhacks.h ../../include/openssl/sm3.h
m_sm3.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
m_sm3.o: m_sm3.c