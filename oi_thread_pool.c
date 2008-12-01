#include <unistd.h> /* read(), write() */
#include <stdlib.h> /* malloc() */
#include <stdio.h> /* perror() */
#include <assert.h>
#include <pthread.h>
#include <ev.h>

#include "oi_thread_pool.h"
#include "ngx_queue.h"

#define NWORKERS 4

static int active_thread_pool_watchers = 0;
static int active_workers = 0;
static int readiness_pipe[2] = {-1, -1};
static ngx_queue_t waiting_tasks;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

struct worker {
  pthread_t thread;
  pthread_attr_t thread_attr;
  struct ev_loop *loop;  
  ev_io watcher;
};

static void
free_worker(struct worker *worker) 
{
  /* worker->task = NULL */
  ev_unloop(worker->loop, EVUNLOOP_ALL);
  ev_loop_destroy(worker->loop);
  active_workers--;
}

static void
on_task(struct ev_loop *loop, ev_io *watcher, int revents)
{
  struct worker *worker = watcher->data;

  if(revents & EV_ERROR) {
    goto shutdown;
  }

  assert(watcher == &worker->watcher);

  char dummy;
  int red = read(readiness_pipe[0], &dummy, 1);

  assert(red == 1); /* TODO real error checking */

  // 1 pop task from queue
  pthread_mutex_lock(&queue_lock);
    ngx_queue_t *last = NULL;
    if(!ngx_queue_empty(&waiting_tasks)) {
      last = ngx_queue_last(&waiting_tasks);
      ngx_queue_remove(last);
    }
  pthread_mutex_unlock(&queue_lock);

  if(last == NULL) return;

  oi_thread_pool_task *task = ngx_queue_data(last, oi_thread_pool_task, queue);
  
  // 2 run task->task
  assert(task->run != NULL);
  task->run(task->data);
  
  // 3 notify complition
  oi_thread_pool *pool = task->pool;
  assert(pool != NULL);
  pthread_mutex_lock(&pool->lock);
    ngx_queue_insert_head(&pool->finished_tasks, &task->queue);
  pthread_mutex_unlock(&pool->lock);
  ev_async_send(task->pool->loop, &task->pool->watcher);

  /* attempt to pull another task */
  return on_task(loop, watcher, revents);

shutdown:
  ev_io_stop(loop, watcher);
  ev_unloop(worker->loop, EVUNLOOP_ALL);
}

void *
worker_loop(void *data)
{
  struct worker *worker = data;
  ev_loop(worker->loop, 0);
  free_worker(worker);
  return NULL;
}

static struct worker*
new_worker()
{
  int r;
  struct worker *worker = malloc(sizeof(struct worker));
  if(worker == NULL ) { return NULL; }

  worker->loop = ev_loop_new(EVFLAG_AUTO);

  ev_io_init( &worker->watcher
            , on_task
            , readiness_pipe[0]
            , EV_READ | EV_ERROR
            );
  worker->watcher.data = worker;
  ev_io_start(worker->loop, &worker->watcher);

  pthread_attr_setdetachstate(&worker->thread_attr, PTHREAD_CREATE_DETACHED);
  r = pthread_create( &worker->thread
                    , &worker->thread_attr
                    , worker_loop
                    , worker
                    ); 
  if(r < 0) goto error; /* TODO: Check return value */

  active_workers++;

  return worker;
error:
  free(worker);
  return NULL;
}

static void
start_workers()
{
  int r = pipe(readiness_pipe);
  if(r < 0) {
    perror("pipe()");
    assert(0 && "TODO HANDLE ME"); 
  }
  /* TODO set non-blocking */

  int i;
  for(i = 0; i < NWORKERS; i++) {
    new_worker();
  }

  ngx_queue_init(&waiting_tasks);
}

static void
stop_workers()
{
  assert(0 && "TODO implement me");
}

static void
on_completion(struct ev_loop *loop, ev_async *watcher, int revents)
{
  oi_thread_pool *pool = watcher->data;
  /* TODO get current task */
  pthread_mutex_lock(&pool->lock);
    ngx_queue_t *last = NULL;
    if(!ngx_queue_empty(&pool->finished_tasks)) {
      last = ngx_queue_last(&pool->finished_tasks);
      ngx_queue_remove(last); 
    }
  pthread_mutex_unlock(&pool->lock);

  if(last == NULL) return;

  oi_thread_pool_task *task = ngx_queue_data(last, oi_thread_pool_task, queue);

  assert(task->on_completion != NULL);
  task->on_completion(task);
  /* this task is possibly freed by on_completion. do not access it below
   * this point */
  task = NULL;

  /* Try again */
  on_completion(loop, watcher, revents);
}

void
oi_thread_pool_init (oi_thread_pool *pool)
{
  ev_async_init(&pool->watcher, on_completion);

  ngx_queue_init(&pool->finished_tasks);
  ngx_queue_init(&pool->new_tasks);

  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pool->lock = lock; /* FIXME */

  pool->watcher.data = pool;
  pool->data = NULL;
}

void
oi_thread_pool_destroy (oi_thread_pool *pool)
{
  pthread_mutex_destroy(&pool->lock);
}

static void
dispatch_tasks(oi_thread_pool *pool)
{
  while(!ngx_queue_empty(&pool->new_tasks)) {
    ngx_queue_t *last = ngx_queue_last(&pool->new_tasks);
    ngx_queue_remove(last);
    oi_thread_pool_task *task = ngx_queue_data(last, oi_thread_pool_task, queue);

    // 1. add task to task queue.
    pthread_mutex_lock(&queue_lock);
      ngx_queue_insert_head(&waiting_tasks, &task->queue);
    pthread_mutex_unlock(&queue_lock);
    
    // 2. write byte to pipe
    char dummy;
    int written = write(readiness_pipe[1], &dummy, 1);

    // 3. TODO make sure byte is written
    assert(written == 1);
  }
}

void
oi_thread_pool_attach (struct ev_loop *loop, oi_thread_pool *pool)
{
  if(active_thread_pool_watchers == 0) {
    start_workers();
  }
  active_thread_pool_watchers++;

  ev_async_start(loop, &pool->watcher);
  pool->loop = loop;

  dispatch_tasks(pool);
}

void
oi_thread_pool_detach (struct ev_loop *loop, oi_thread_pool *pool)
{
  ev_async_stop(loop, &pool->watcher);
  pool->loop = NULL;
  active_thread_pool_watchers--;
  if(active_thread_pool_watchers == 0) {
    //stop_workers();
  }
}

void
oi_thread_pool_execute (oi_thread_pool *pool, oi_thread_pool_task *task)
{
  assert(task->pool == NULL);
  assert(task->on_completion != NULL);
  assert(task->run != NULL);
  task->pool = pool;

  ngx_queue_insert_head(&pool->new_tasks, &task->queue);
  if(ev_is_active(&pool->watcher)) {
    dispatch_tasks(pool);
  }
}

void oi_thread_pool_task_init (oi_thread_pool_task *task)
{
  task->pool = NULL;
  task->run = NULL;
  task->on_completion = NULL;
  task->data = NULL;
}
