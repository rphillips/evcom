
/*
 * Copyright (C) Igor Sysoev
 * from nginx ngx_queue.h
 */


/*
#include <ngx_config.h>
#include <ngx_core.h>
*/
#include <stddef.h> /* offsetof() */


#ifndef _OI_QUEUE_H_INCLUDED_
#define _OI_QUEUE_H_INCLUDED_


typedef struct oi_queue_s  oi_queue_t;

struct oi_queue_s {
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


#if (NGX_DEBUG)

#define oi_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define oi_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define oi_queue_data(q, type, link)                                         \
    (type *) ((unsigned char *) q - offsetof(type, link))


#endif /* _OI_QUEUE_H_INCLUDED_ */
