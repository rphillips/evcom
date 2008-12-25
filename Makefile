include config.mk

DEP = oi_socket.h oi_async.h oi_file.h oi_queue.h
SRC = oi_socket.c oi_async.c oi_file.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

TESTS = test/test_ping_pong_tcp_secure test/test_ping_pong_unix_secure test/test_ping_pong_tcp_clear test/test_ping_pong_unix_clear test/test_connection_interruption_tcp_secure test/test_connection_interruption_unix_secure test/test_connection_interruption_tcp_clear test/test_connection_interruption_unix_clear test/test_file test/test_sleeping_tasks test/fancy_copy

all: options $(OUTPUT_LIB) $(OUTPUT_A) $(TESTS)

options:
	@echo ${NAME} build options:
	@echo "CC       = ${CC}"
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "LDOPT    = ${LDOPT}"
	@echo "SUFFIX   = ${SUFFIX}"
	@echo "SONAME   = ${SONAME}"
	@echo

$(OUTPUT_LIB): $(OBJ) 
	@echo LINK $@
	@$(LINKER) -o $(OUTPUT_LIB) $(OBJ) $(SONAME) $(LIBS)

$(OUTPUT_A): $(OBJ)
	@echo AR $@
	@$(AR) cru $(OUTPUT_A) $(OBJ)
	@echo RANLIB $@
	@$(RANLIB) $(OUTPUT_A)

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=echo "\033[1;31mFAIL\033[m"
PASS=echo "\033[1;32mPASS\033[m"
TEST= && $(PASS) || $(FAIL)

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
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_ping_pong_unix_secure: test/ping_pong.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_ping_pong_tcp_clear: test/ping_pong.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_ping_pong_unix_clear: test/ping_pong.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0

test/test_connection_interruption_tcp_secure: test/connection_interruption.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=1

test/test_connection_interruption_unix_secure: test/connection_interruption.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=1

test/test_connection_interruption_tcp_clear: test/connection_interruption.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=1 -DSECURE=0

test/test_connection_interruption_unix_clear: test/connection_interruption.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^ -DTCP=0 -DSECURE=0


test/test_file: test/file.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^

test/test_sleeping_tasks: test/sleeping_tasks.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^

test/fancy_copy: test/fancy_copy.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -o $@ $^

clean:
	@echo CLEANING
	@rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	@rm -f test/test_* test/fancy_copy

install: $(OUTPUT_LIB) $(OUTPUT_A)
	@echo INSTALLING ${OUTPUT_A} and ${OUTPUT_LIB} to ${PREFIX}/lib
	install -d -m755 ${PREFIX}/lib
	install -d -m755 ${PREFIX}/include
	install -m644 ${OUTPUT_A} ${PREFIX}/lib
	install -m755 ${OUTPUT_LIB} ${PREFIX}/lib
	ln -sfn $(PREFIX)/lib/$(OUTPUT_LIB) $(PREFIX)/lib/$(NAME).so
	@echo INSTALLING headers to ${PREFIX}/include
	install -m644 oi.h ${PREFIX}/include 

uninstall:
	@echo REMOVING so from ${PREFIX}/lib
	rm -f ${PREFIX}/lib/${NAME}.*
	@echo REMOVING headers from ${PREFIX}/include
	rm -f ${PREFIX}/include/oi.h

.PHONY: all options clean clobber install uninstall test 
