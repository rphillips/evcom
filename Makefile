include config.mk

CFLAGS  += -fPIC -I.
LDFLAGS += -pthread
LDOPT    = -shared
SUFFIX   = so
SONAME   = -Wl,-soname,$(OUTPUT_LIB)

ifeq ($(uname_S),Linux)
	CFLAGS += -D__linux=1
endif
ifeq ($(uname_S),FreeBSD)
	CFLAGS += -D__freebsd=1
endif
ifeq ($(uname_S),SunOS)
	CFLAGS += -D__solaris=1
endif
ifeq ($(uname_S),HP-UX)
	CFLAGS += -D__hpux=1
endif
ifeq ($(uname_S),Darwin)
	CFLAGS += -D__darwin=1
	SUFFIX = dylib
endif

ifdef EVDIR
	CFLAGS += -I$(EVDIR)/include
	LDFLAGS += -L$(EVDIR)/lib
endif
LDFLAGS += -lev

ifdef GNUTLSDIR
	CFLAGS += -I$(GNUTLSDIR)/include
	LDFLAGS += -L$(GNUTLSDIR)/lib
endif
LDFLAGS += -lgnutls

ifdef NO_PREAD
	CFLAGS += -DHAVE_PREADWRITE=0
else
	CFLAGS += -DHAVE_PREADWRITE=1
endif

ifdef NO_SENDFILE
	CFLAGS += -DHAVE_SENDFILE=0
else
	CFLAGS += -DHAVE_SENDFILE=1
endif

DEP = oi_socket.h oi_async.h oi_file.h
SRC = oi_socket.c oi_async.c oi_file.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

TESTS = test/test_ping_pong_tcp_secure test/test_ping_pong_unix_secure test/test_ping_pong_tcp_clear test/test_ping_pong_unix_clear test/test_connection_interruption_tcp_secure test/test_connection_interruption_unix_secure test/test_connection_interruption_tcp_clear test/test_connection_interruption_unix_clear test/test_stdout test/test_sleeping_tasks test/fancy_copy

all: $(OUTPUT_LIB) $(OUTPUT_A) $(TESTS)

$(OUTPUT_LIB): $(OBJ) 
	$(LINKER) -o $(OUTPUT_LIB) $(OBJ) $(SONAME) $(LDFLAGS)

$(OUTPUT_A): $(OBJ)
	$(AR) cru $(OUTPUT_A) $(OBJ)
	$(RANLIB) $(OUTPUT_A)

.c.o:
	$(CC) -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=echo "FAIL"
PASS=echo "PASS"

/tmp/oi_fancy_copy_src:
	@perl -e "print('C'x(1024*40))" > /tmp/oi_fancy_copy_src

test: $(TESTS) /tmp/oi_fancy_copy_src
	@for i in test/test_*; do \
	  echo -n "$$i: ";	\
		$$i && $(PASS) || $(FAIL); \
	done 
	@echo -n "fancy copy execute: "
	@test/fancy_copy /tmp/oi_fancy_copy_src /tmp/oi_fancy_copy_dst && $(PASS) || $(FAIL)
	md5sum /tmp/oi_fancy_copy*

test/test_ping_pong_tcp_secure: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_ping_pong_unix_secure: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_ping_pong_tcp_clear: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_ping_pong_unix_clear: test/ping_pong.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0

test/test_connection_interruption_tcp_secure: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_connection_interruption_unix_secure: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_connection_interruption_tcp_clear: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_connection_interruption_unix_clear: test/connection_interruption.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0

test/test_stdout: test/stdout.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

test/test_sleeping_tasks: test/sleeping_tasks.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

test/fancy_copy: test/fancy_copy.c $(OUTPUT_A)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

doc: oi.3
oi.3: oi.pod
	pod2man -s 3 -c "liboi - evented I/O" oi.pod > oi.3

clean:
	rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	rm -f test/test_* test/fancy_copy
	rm -f oi.3

install: $(OUTPUT_LIB) $(OUTPUT_A)
	@echo INSTALLING ${OUTPUT_A} and ${OUTPUT_LIB} to ${PREFIX}/lib
	install -d -m755 ${PREFIX}/lib
	install -d -m755 ${PREFIX}/include
	install -m644 ${OUTPUT_A} ${PREFIX}/lib
	install -m755 ${OUTPUT_LIB} ${PREFIX}/lib
	ln -sfn $(PREFIX)/lib/$(OUTPUT_LIB) $(PREFIX)/lib/$(NAME).so
	@echo INSTALLING headers to ${PREFIX}/include
	install -m644 oi_*.h ${PREFIX}/include 

uninstall:
	@echo REMOVING so from ${PREFIX}/lib
	rm -f ${PREFIX}/lib/${NAME}.*
	@echo REMOVING headers from ${PREFIX}/include
	rm -f ${PREFIX}/include/oi_*.h

.PHONY: all options clean clobber install uninstall test 
