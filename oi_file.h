#include "oi.h"
#include "oi_async.h"
#include "ngx_queue.h"
#include <ev.h>

#ifndef oi_file_h
#define oi_file_h

typedef struct oi_file oi_file;

int  oi_file_init         (oi_file *);

void oi_file_attach       (oi_file *, struct ev_loop *);
void oi_file_detach       (oi_file *);

void oi_file_open_path    (oi_file *, const char *path, int flags, mode_t mode);
void oi_file_open_stdin   (oi_file *);
void oi_file_open_stdout  (oi_file *);
void oi_file_open_stderr  (oi_file *);

int  oi_file_read         (oi_file *, oi_buf *to_be_filled);
int  oi_file_read_simple  (oi_file *, size_t len);
void oi_file_write        (oi_file *, oi_buf *);
void oi_file_write_simple (oi_file *, const char *, size_t);
int  oi_file_send         (oi_file *source, oi_socket *destination, off_t offset, size_t length);
void oi_file_close        (oi_file *);

struct oi_file {
  /* private */
  oi_async async;
  oi_task io_task;
  struct ev_loop *loop;
  ngx_queue_t write_queue;
  oi_buf *read_buf;
  oi_buf *write_buf;
  oi_socket *write_socket;

  /* read-only */
  int fd;
   
  /* public */
  void (*on_open)      (oi_file *);
  void (*on_read)      (oi_file *, oi_buf *, size_t recved);
  void (*on_drain)     (oi_file *);
  void (*on_error)     (oi_file *, int domain, int code);
  void (*on_close)     (oi_file *);
  void *data;
};

#endif /*  oi_file_h */
