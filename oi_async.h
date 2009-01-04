#include <ev.h>
#include <pthread.h>
#include <netdb.h>
#include <oi.h>

#ifndef oi_async_h
#define oi_async_h

typedef struct oi_async oi_async;
typedef struct oi_task  oi_task;

struct oi_async {
  /* private */
  ev_async watcher;  
  struct ev_loop *loop;

  oi_queue finished_tasks;
  oi_queue new_tasks;

  /* public */
  void *data;
}; 

struct oi_task {
  /* private */
  oi_async *async;
  oi_queue queue;
  int type;
  union {

    struct {
      const char *pathname;
      int flags;
      mode_t mode;
      void (*cb) (oi_task *, int result);
      int result;
    } open;

    struct {
      int fd;
      void *buf;
      size_t count;
      void (*cb) (oi_task *, ssize_t result);
      ssize_t result;
    } read;

    struct {
      int fd;
      const void *buf;
      size_t count;
      void (*cb) (oi_task *, ssize_t result);
      ssize_t result;
    } write;

    struct {
      int fd;
      void (*cb) (oi_task *, int result);
      int result;
    } close;

    struct {
      unsigned int seconds;
      void (*cb) (oi_task *, unsigned int result);
      unsigned int result;
    } sleep;

    struct {
      int ofd;
      int ifd;
      off_t offset;
      size_t count;
      void (*cb) (oi_task *, ssize_t result);
      ssize_t result;
    } eio__sendfile;

    struct {
      const char *nodename; /* restrict ? */
      const char *servname; /* restrict ? */
      struct addrinfo *hints;
      struct addrinfo **res; /* restrict ? */
      void (*cb) (oi_task *, int result);
      int result;
    } getaddrinfo;
    
  } params;

  /* read-only */
  volatile unsigned active:1;
  int errorno;

  /* public */
  void *data;
}; 

void oi_async_init    (oi_async *);
void oi_async_attach  (struct ev_loop *loop, oi_async *);
void oi_async_detach  (oi_async *);
void oi_async_submit  (oi_async *, oi_task *);

/* To submit a task for async processing
 * (0) allocate memory for your task
 * (1) initialize the task with one of the functions below
 * (2) optionally set the task->data pointer
 * (3) oi_async_submit() the task 
 */

enum { OI_TASK_OPEN
     , OI_TASK_READ
     , OI_TASK_WRITE
     , OI_TASK_CLOSE
     , OI_TASK_SLEEP
     , OI_TASK_SENDFILE
     , OI_TASK_GETADDRINFO
     };

#define oi_task_init_common(task) do {\
  (task)->active = 0;\
  (task)->async = NULL;\
} while(0)

#define oi_task_init_open(task, _cb, _pathname, _flags, _mode) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_OPEN; \
  (task)->params.open.cb = _cb; \
  (task)->params.open.pathname = _pathname; \
  (task)->params.open.flags = _flags; \
  (task)->params.open.mode = _mode; \
} while(0)

#define oi_task_init_read(task, _cb, _fd, _buf, _count) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_READ; \
  (task)->params.read.cb = _cb; \
  (task)->params.read.fd = _fd; \
  (task)->params.read.buf = _buf; \
  (task)->params.read.count = _count; \
} while(0)

#define oi_task_init_write(task, _cb, _fd, _buf, _count) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_WRITE; \
  (task)->params.write.cb = _cb; \
  (task)->params.write.fd = _fd; \
  (task)->params.write.buf = _buf; \
  (task)->params.write.count = _count; \
} while(0)

#define oi_task_init_close(task, _cb, _fd) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_CLOSE; \
  (task)->params.close.cb = _cb; \
  (task)->params.close.fd = _fd; \
} while(0)

#define oi_task_init_sleep(task, _cb, _seconds) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_SLEEP; \
  (task)->params.sleep.cb = _cb; \
  (task)->params.sleep.seconds = _seconds; \
} while(0)

#define oi_task_init_sendfile(task, _cb, _ofd, _ifd, _offset, _count) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_SENDFILE; \
  (task)->params.eio__sendfile.cb = _cb; \
  (task)->params.eio__sendfile.ofd = _ofd; \
  (task)->params.eio__sendfile.ifd = _ifd; \
  (task)->params.eio__sendfile.offset = _offset; \
  (task)->params.eio__sendfile.count = _count; \
} while(0)

#define oi_task_init_getaddrinfo(task, _cb, _nodename, _servname, _ai_family, _ai_socktype, _ai_flags, _res) do { \
  oi_task_init_common(task); \
  (task)->type = OI_TASK_GETADDRINFO; \
  (task)->params.getaddrinfo.cb = _cb; \
  (task)->params.getaddrinfo.nodename = _nodename; \
  (task)->params.getaddrinfo.servname = _servname; \
  (task)->params.getaddrinfo.hints = _hints; \
  (task)->params.getaddrinfo.res = _res; \
} while(0)

#endif /* oi_async_h */
