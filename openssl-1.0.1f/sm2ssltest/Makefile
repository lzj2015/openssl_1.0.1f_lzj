#
# sm2ssltest/Makefile
#

DIR=		sm2ssltest
TOP=		..
CC=		cc
INCLUDES=	-I$(TOP) -I../include $(KRB5_INCLUDES)
CFLAG=		-g
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
PERL=		perl
# KRB5 stuff
KRB5_INCLUDES=
LIBKRB5=

PEX_LIBS=
EX_LIBS= #-lnsl -lsocket

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile maketests.com 

DLIBCRYPTO= ../libcrypto.a
DLIBSSL= ../libssl.a
LIBCRYPTO= -L.. -lcrypto
LIBSSL= -L.. -lssl


SM2SSLTEST=	sm2ssltest
SM2SERVERTEST = sm2servertest
SM2CLIENTTEST = sm2clienttest


TESTS=		alltests

EXE=	$(SM2SSLTEST)$(EXE_EXT)  $(SM2SERVERTEST)$(EXE_EXT) $(SM2CLIENTTEST)$(EXE_EXT)
	

# $(METHTEST)$(EXE_EXT)

OBJ=	$(SM2SSLTEST).o $(SM2SERVERTEST).o $(SM2CLIENTTEST).o 
SRC=	$(SM2SSLTEST).c $(SM2SERVERTEST).c $(SM2CLIENTTEST).c 
	

EXHEADER= 
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ..; $(MAKE) DIRS=$(DIR) TESTS=$(TESTS) all)

all:	exe

exe:	$(EXE)

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:

errors:

install:

tags:
	ctags $(SRC)

tests:	exe apps $(TESTS)

apps:
	@(cd ..; $(MAKE) DIRS=apps all)

alltests:  test_sm2ssltest  test_sm2servertest test_sm2clienttest


test_sm2ssltest:
	../util/shlib_wrap.sh ./$(SM2SSLTEST)

test_sm2servertest:
	../util/shlib_wrap.sh ./$(SM2SERVERTEST)

test_sm2clienttest:
	../util/shlib_wrap.sh ./$(SM2CLIENTTEST)


lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@if [ -z "$(THIS)" ]; then \
	    $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; \
	else \
	    $(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(SRC); \
	fi

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f $(SRC) $(SHA256TEST).c $(SHA512TEST).c evptests.txt newkey.pem testkey.pem \
			testreq.pem

clean:
	rm -f .rnd tmp.bntest tmp.bctest *.o *.obj *.dll lib tags core .pure .nfs* *.old *.bak fluff $(EXE) *.ss *.srl log 


$(DLIBSSL):
	(cd ..; $(MAKE) DIRS=ssl all)

$(DLIBCRYPTO):
	(cd ..; $(MAKE) DIRS=crypto all)

BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO) $(LIBKRB5)"; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC="$${CC}" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}

FIPS_BUILD_CMD=shlib_target=; if [ -n "$(SHARED_LIBS)" ]; then \
		shlib_target="$(SHLIB_TARGET)"; \
	fi; \
	LIBRARIES="$(LIBSSL) $(LIBCRYPTO) $(LIBKRB5)"; \
	if [ -z "$(SHARED_LIBS)" -a -n "$(FIPSCANLIB)" ] ; then \
		FIPSLD_CC="$(CC)"; CC=$(FIPSDIR)/bin/fipsld; export CC FIPSLD_CC; \
	fi; \
	$(MAKE) -f $(TOP)/Makefile.shared -e \
		CC="$${CC}" APPNAME=$$target$(EXE_EXT) OBJECTS="$$target.o" \
		LIBDEPS="$(PEX_LIBS) $$LIBRARIES $(EX_LIBS)" \
		link_app.$${shlib_target}



$(SM2SSLTEST)$(EXE_EXT): $(SM2SSLTEST).o $(DLIBCRYPTO)
	@target=$(SM2SSLTEST); $(BUILD_CMD)

$(SM2SERVERTEST)$(EXE_EXT): $(SM2SERVERTEST).o $(DLIBCRYPTO)
	@target=$(SM2SERVERTEST); $(BUILD_CMD)

$(SM2CLIENTTEST)$(EXE_EXT): $(SM2CLIENTTEST).o $(DLIBCRYPTO)
	@target=$(SM2CLIENTTEST); $(BUILD_CMD)



# DO NOT DELETE THIS LINE -- make depend depends on it.

sm2ssltest.o: sm2ssltest.c
sm2servertest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sm2servertest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
sm2servertest.o: ../include/openssl/comp.h ../include/openssl/conf.h
sm2servertest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
sm2servertest.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
sm2servertest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sm2servertest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sm2servertest.o: ../include/openssl/engine.h ../include/openssl/err.h
sm2servertest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
sm2servertest.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
sm2servertest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sm2servertest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sm2servertest.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sm2servertest.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sm2servertest.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
sm2servertest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
sm2servertest.o: ../include/openssl/sha.h ../include/openssl/srp.h
sm2servertest.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
sm2servertest.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
sm2servertest.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sm2servertest.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sm2servertest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
sm2servertest.o: ../include/openssl/x509v3.h sm2servertest.c
sm2clienttest.o: ../e_os.h ../include/openssl/asn1.h ../include/openssl/bio.h
sm2clienttest.o: ../include/openssl/bn.h ../include/openssl/buffer.h
sm2clienttest.o: ../include/openssl/comp.h ../include/openssl/conf.h
sm2clienttest.o: ../include/openssl/crypto.h ../include/openssl/dh.h
sm2clienttest.o: ../include/openssl/dsa.h ../include/openssl/dtls1.h
sm2clienttest.o: ../include/openssl/e_os2.h ../include/openssl/ec.h
sm2clienttest.o: ../include/openssl/ecdh.h ../include/openssl/ecdsa.h
sm2clienttest.o: ../include/openssl/engine.h ../include/openssl/err.h
sm2clienttest.o: ../include/openssl/evp.h ../include/openssl/hmac.h
sm2clienttest.o: ../include/openssl/kssl.h ../include/openssl/lhash.h
sm2clienttest.o: ../include/openssl/obj_mac.h ../include/openssl/objects.h
sm2clienttest.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
sm2clienttest.o: ../include/openssl/ossl_typ.h ../include/openssl/pem.h
sm2clienttest.o: ../include/openssl/pem2.h ../include/openssl/pkcs7.h
sm2clienttest.o: ../include/openssl/pqueue.h ../include/openssl/rand.h
sm2clienttest.o: ../include/openssl/rsa.h ../include/openssl/safestack.h
sm2clienttest.o: ../include/openssl/sha.h ../include/openssl/srp.h
sm2clienttest.o: ../include/openssl/srtp.h ../include/openssl/ssl.h
sm2clienttest.o: ../include/openssl/ssl2.h ../include/openssl/ssl23.h
sm2clienttest.o: ../include/openssl/ssl3.h ../include/openssl/stack.h
sm2clienttest.o: ../include/openssl/symhacks.h ../include/openssl/tls1.h
sm2clienttest.o: ../include/openssl/x509.h ../include/openssl/x509_vfy.h
sm2clienttest.o: ../include/openssl/x509v3.h sm2clienttest.c