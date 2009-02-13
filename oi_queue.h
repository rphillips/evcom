#ifndef oi_queue_h
#define oi_queue_h
/* Copyright (C) Igor Sysoev * from nginx ngx_queue.h */
#include <stddef.h> /* offsetof() */
typedef struct oi_queue oi_queue;
struct oi_queue {
    oi_queue  *prev;
    oi_queue  *next;
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

#endif // oi_queue_h
