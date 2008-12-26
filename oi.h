#ifndef oi_h
#define oi_h

#include <stddef.h> /* offsetof() */

/* Copyright (C) Igor Sysoev * from nginx ngx_queue.h */
typedef struct oi_queue oi_queue_t;
struct oi_queue {
    oi_queue_t  *prev;
    oi_queue_t  *next;
};

#define oi_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q

#define oi_queue_empty(h)                                                    \
    (h == (h)->prev)

#define oi_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x

#define oi_queue_head(h)                                                     \
    (h)->next

#define oi_queue_last(h)                                                     \
    (h)->prev

#define oi_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#define oi_queue_data(q, type, link)                                         \
    (type *) ((unsigned char *) q - offsetof(type, link))

typedef struct oi_buf oi_buf;

struct oi_buf {
  /* public */
  char *base;
  size_t len;
  void (*release) (oi_buf *); /* called when oi_socket is done with the object */
  void *data;

  /* private */
  size_t written;
  oi_queue_t queue;
};

#include <oi_socket.h>
#include <oi_async.h>
#include <oi_file.h>

#endif
