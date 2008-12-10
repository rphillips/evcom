PREFIX = $(HOME)/local/oi

# libev
EVINC  = $(HOME)/local/libev/include
EVLIB  = $(HOME)/local/libev/lib
EVLIBS = -L${EVLIB} -lev

# libeio
EIOINC  = $(HOME)/local/libeio/include
EIOLIB  = $(HOME)/local/libeio/lib
EIOLIBS = -L${EIOLIB} -leio

# GnuTLS, comment out if you don't want it
GNUTLSLIB   = /usr/lib
GNUTLSINC   = /usr/include
GNUTLSLIBS  = -L${GNUTLSLIB} -lgnutls
GNUTLSFLAGS = -DHAVE_GNUTLS

# includes and libs
INCS = -I${EIOINC} -I${EVINC} -I${GNUTLSINC}
LIBS =   ${EIOLIBS}  ${EVLIBS}  ${GNUTLSLIBS} -lefence

# flags
CPPFLAGS = -DVERSION=\"$(VERSION)\" ${GNUTLSFLAGS}
CFLAGS   = -g -Wall ${INCS} ${CPPFLAGS} -fPIC # -O2 
LDFLAGS  = -s ${LIBS}
LDOPT    = -shared
SUFFIX   = so
SONAME   = -Wl,-soname,$(OUTPUT_LIB)

# Solaris
#CFLAGS  = -fast ${INCS} -DVERSION=\"$(VERSION)\" -fPIC
#LDFLAGS = ${LIBS}
#SONAME  = 

# Darwin
#LDOPT  = -dynamiclib 
#SUFFIX = dylib
#SONAME = -current_version $(VERSION) -compatibility_version $(VERSION)

# compiler and linker
CC = cc
RANLIB = ranlib
