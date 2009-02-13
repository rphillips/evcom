#ifndef oi_buf_h
#define oi_buf_h

#include <oi_queue.h>

typedef struct oi_buf oi_buf;

struct oi_buf {
  /* public */
  char *base;
  size_t len;
  void (*release) (oi_buf *); /* called when oi is done with the object */
  void *data;

  /* private */
  size_t written;
  oi_queue queue;
};

#endif // oi_buf_h
