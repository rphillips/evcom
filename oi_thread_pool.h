#include <ev.h>
#include <pthread.h>
#include "ngx_queue.h"

#ifndef oi_thread_pool_h
#define oi_thread_pool_h

typedef struct oi_thread_pool       oi_thread_pool;
typedef struct oi_thread_pool_task  oi_thread_pool_task;

struct oi_thread_pool {
  /* private */
  ev_async watcher;  
  struct ev_loop *loop;

  pthread_mutex_t lock;
  ngx_queue_t finished_tasks;
  ngx_queue_t new_tasks;

  /* public */
  void *data;
}; 

struct oi_thread_pool_task {
  /* private */
  oi_thread_pool *pool;
  ngx_queue_t queue;

  /* public */
  void (*run) (void *data);
  void (*on_completion) (oi_thread_pool_task *);
  void *data;
}; 

void oi_thread_pool_init        (oi_thread_pool *);
void oi_thread_pool_destroy     (oi_thread_pool *);
void oi_thread_pool_attach      (struct ev_loop *loop, oi_thread_pool *);
void oi_thread_pool_detach      (struct ev_loop *loop, oi_thread_pool *);
void oi_thread_pool_execute     (oi_thread_pool *, oi_thread_pool_task *);

void oi_thread_pool_task_init   (oi_thread_pool_task *);

#endif /* oi_thread_pool_h */
