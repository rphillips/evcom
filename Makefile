include config.mk

DEP = oi_socket.h oi_async.h oi_file.h oi_queue.h
SRC = oi_socket.c oi_async.c oi_file.c
OBJ = ${SRC:.c=.o}

VERSION = 0.1
NAME=liboi
OUTPUT_LIB=$(NAME).$(SUFFIX).$(VERSION)
OUTPUT_A=$(NAME).a

LINKER=$(CC) $(LDOPT)

TESTS = test/test_ping_pong test/test_connection_interruption test/test_file test/test_sleeping_tasks test/test_fancy_copy
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
	${CC} -c ${CFLAGS} $<

${OBJ}: ${DEP}

FAIL=echo "\033[1;31mFAIL\033[m"
PASS=echo "\033[1;32mPASS\033[m"
TEST= && $(PASS) || $(FAIL)

test: $(TESTS)
	@echo "ping pong"
	@echo -n "- unix: "
	@./test/test_ping_pong unix $(TEST)
	@echo -n "- tcp: "
	@./test/test_ping_pong tcp $(TEST)
	@echo -n "- unix secure: "
	@./test/test_ping_pong unix secure $(TEST)
	@echo -n "- tcp secure: "
	@./test/test_ping_pong tcp secure $(TEST)
	@echo "connection interruption"
	@echo -n "- unix: "
	@./test/test_connection_interruption unix $(TEST)
	@echo -n "- tcp: "
	@./test/test_connection_interruption tcp $(TEST)
	@echo -n "- unix secure: "
	@./test/test_connection_interruption unix secure $(TEST)
	@echo -n "- tcp secure: "
	@./test/test_connection_interruption tcp secure $(TEST)
	@echo -n "sleeping tasks: "
	@./test/test_sleeping_tasks $(TEST)
	@echo -n "fancy copy copy: "
	@rm -f /tmp/oi_fancy_copy_*
	@perl -e "print('C'x(1024*40))" > /tmp/oi_fancy_copy_src
	@./test/test_fancy_copy /tmp/oi_fancy_copy_src /tmp/oi_fancy_copy_dst $(TEST)
	md5sum /tmp/oi_fancy_copy*



test/test_ping_pong: test/ping_pong.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

test/test_connection_interruption: test/connection_interruption.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

test/test_file: test/file.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

test/test_sleeping_tasks: test/sleeping_tasks.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^

test/test_fancy_copy: test/fancy_copy.c $(OUTPUT_A)
	@echo BUILDING $@
	@$(CC) -I. $(LIBS) $(CFLAGS) -lev -o $@ $^


clean:
	@echo CLEANING
	@rm -f ${OBJ} $(OUTPUT_A) $(OUTPUT_LIB) $(NAME)-${VERSION}.tar.gz 
	@rm -f test/test_*

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
