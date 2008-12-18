#include <stdlib.h> /* malloc()        */
#include <stdio.h>  /* perror()        */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> /* read(), write() */
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#if HAVE_SENDFILE
# if __linux
#  include <sys/sendfile.h>
# elif __freebsd
#  include <sys/socket.h>
#  include <sys/uio.h>
# elif __hpux
#  include <sys/socket.h>
# elif __solaris /* not yet */
#  include <sys/sendfile.h>
# else
#  error sendfile support requested but not available
# endif
#endif

#include <ev.h>
#include "oi_async.h"
#include "ngx_queue.h"

#define NWORKERS 4 
/* TODO make adjustable 
 * once it is fix sleeping_tasks
 */

static int active_watchers = 0;
static int active_workers = 0;
static int readiness_pipe[2] = {-1, -1};
static ngx_queue_t waiting_tasks;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

struct worker {
  oi_task *task;
  pthread_t thread;
  pthread_attr_t thread_attr;
};

/* Sendfile and pread emulation come from Marc Lehmann's libeio */

#if !HAVE_PREADWRITE
/*
 * make our pread/pwrite emulation safe against themselves, but not against
 * normal read/write by using a mutex. slows down execution a lot,
 * but that's your problem, not mine.
 */
static pthread_mutex_t preadwritelock = PTHREAD_MUTEX_INITIALIZER;
#endif

#if !HAVE_PREADWRITE
# undef pread
# undef pwrite
# define pread  eio__pread
# define pwrite eio__pwrite

static ssize_t
eio__pread (int fd, void *buf, size_t count, off_t offset)
{
  ssize_t res;
  off_t ooffset;

  pthread_mutex_lock(&preadwritelock);
    ooffset = lseek (fd, 0, SEEK_CUR);
    lseek (fd, offset, SEEK_SET);
    res = read (fd, buf, count);
    lseek (fd, ooffset, SEEK_SET);
  pthread_mutex_unlock(&preadwritelock);

  return res;
}

static ssize_t
eio__pwrite (int fd, void *buf, size_t count, off_t offset)
{
  ssize_t res;
  off_t ooffset;

  pthread_mutex_lock(&preadwritelock);
    ooffset = lseek (fd, 0, SEEK_CUR);
    lseek (fd, offset, SEEK_SET);
    res = write (fd, buf, count);
    lseek (fd, offset, SEEK_SET);
  pthread_mutex_unlock(&preadwritelock);

  return res;
}
#endif


/* sendfile always needs emulation */
static ssize_t
eio__sendfile (int ofd, int ifd, off_t offset, size_t count)
{
  ssize_t res;

  if (!count)
    return 0;

#if HAVE_SENDFILE
# if __linux
  res = sendfile (ofd, ifd, &offset, count);

# elif __freebsd
  /*
   * Of course, the freebsd sendfile is a dire hack with no thoughts
   * wasted on making it similar to other I/O functions.
   */
  {
    off_t sbytes;
    res = sendfile (ifd, ofd, offset, count, 0, &sbytes, 0);

    if (res < 0 && sbytes)
      /* maybe only on EAGAIN: as usual, the manpage leaves you guessing */
      res = sbytes;
  }

# elif __hpux
  res = sendfile (ofd, ifd, offset, count, 0, 0);

# elif __solaris
  {
    struct sendfilevec vec;
    size_t sbytes;

    vec.sfv_fd   = ifd;
    vec.sfv_flag = 0;
    vec.sfv_off  = offset;
    vec.sfv_len  = count;

    res = sendfilev (ofd, &vec, 1, &sbytes);

    if (res < 0 && sbytes)
      res = sbytes;
  }

# endif
#else
  res = -1;
  errno = ENOSYS;
#endif

  if (res <  0
    && (errno == ENOSYS || errno == EINVAL || errno == ENOTSOCK
#if __solaris
      || errno == EAFNOSUPPORT || errno == EPROTOTYPE
#endif
       )
     )
  {
    /* emulate sendfile. this is a major pain in the ass */
/* buffer size for various temporary buffers */
#define EIO_BUFSIZE 65536
    char *eio_buf = malloc (EIO_BUFSIZE);
    errno = ENOMEM;
    if (!eio_buf)
      return -1;

    res = 0;

    while (count) {
      ssize_t cnt;
      
      cnt = pread (ifd, eio_buf, count > EIO_BUFSIZE ? EIO_BUFSIZE : count, offset);

      if (cnt <= 0) {
        if (cnt && !res) res = -1;
        break;
      }

      cnt = write (ofd, eio_buf, cnt);

      if (cnt <= 0) {
        if (cnt && !res) res = -1;
        break;
      }

      offset += cnt;
      res    += cnt;
      count  -= cnt;
    }
  }

  return res;
}

static oi_task*
queue_shift(pthread_mutex_t *lock, ngx_queue_t *queue)
{
  ngx_queue_t *last = NULL;
  pthread_mutex_lock(lock);
    if(!ngx_queue_empty(queue)) {
      last = ngx_queue_last(queue);
      ngx_queue_remove(last); 
    }
  pthread_mutex_unlock(lock);

  if(last == NULL) 
    return NULL;

  return ngx_queue_data(last, oi_task, queue);
}

static void
worker_free(struct worker *worker) 
{
  /* worker->task = NULL */
  active_workers--;
}

#define P1(name,a) { \
  t->params.name.result = name( t->params.name.a ); \
  break; \
}

#define P3(name,a,b,c) { \
  t->params.name.result = name( t->params.name.a \
                              , t->params.name.b \
                              , t->params.name.c \
                              ); \
  break; \
}

#define P4(name,a,b,c,d) { \
  t->params.name.result = name( t->params.name.a \
                              , t->params.name.b \
                              , t->params.name.c \
                              , t->params.name.d \
                              ); \
  break; \
}

static void
execute_task(oi_task *t)
{
  errno = 0;
  switch(t->type) {
    case OI_TASK_OPEN:  P3(open, pathname, flags, mode);
    case OI_TASK_READ:  P3(read, fd, buf, count);
    case OI_TASK_WRITE: P3(write, fd, buf, count);
    case OI_TASK_CLOSE: P1(close, fd);
    case OI_TASK_SLEEP: P1(sleep, seconds);
    case OI_TASK_SENDFILE: P4(eio__sendfile, ofd, ifd, offset, count);
    default: 
      assert(0 && "unknown task type");
      break;
  }
  t->errorno = errno;
}

static void
attempt_to_get_a_task(struct worker *worker)
{
  char dummy;
  assert(readiness_pipe[0] > 0);
  int red = read(readiness_pipe[0], &dummy, 1);
  if(red == -1) {
    if(errno == EAGAIN)
      return;
    perror("read()");
    return;
  }

  // 1 pop task from queue
  assert(worker->task == NULL);
  oi_task *task =  queue_shift(&queue_lock, &waiting_tasks);
  if(task == NULL) return;
  worker->task = task;
  
  // 2 run task
  execute_task(task);
  
  // 3 notify complition
  oi_async *async = task->async;
  assert(async != NULL);
  pthread_mutex_lock(&async->lock);
    ngx_queue_insert_head(&async->finished_tasks, &task->queue);
  pthread_mutex_unlock(&async->lock);
  ev_async_send(async->loop, &async->watcher);
  worker->task = NULL;

  /* attempt to pull another task */
  return attempt_to_get_a_task(worker);
}

void *
worker_loop(void *data)
{
  struct worker *worker = data;
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(readiness_pipe[0], &readfds);

  active_workers++;

  while(1) {
    select(1+readiness_pipe[0], &readfds, 0, 0, 0);
    attempt_to_get_a_task(worker);
  }

  worker_free(worker);
  return NULL;
}

static struct worker*
worker_new()
{
  int r;
  struct worker *worker = malloc(sizeof(struct worker));
  if(worker == NULL ) { return NULL; }

  worker->task = NULL;
  pthread_attr_setdetachstate(&worker->thread_attr, PTHREAD_CREATE_DETACHED);

  r = pthread_create( &worker->thread
                    , &worker->thread_attr
                    , worker_loop
                    , worker
                    ); 
  if(r < 0) goto error; /* TODO: Check return value */

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

  /* TODO set non-blocking*/

  int i;
  for(i = 0; i < NWORKERS; i++) {
    worker_new();
  }

  ngx_queue_init(&waiting_tasks);
}

/*
static void
stop_workers()
{
  assert(0 && "TODO implement me");
}
*/

static void
on_completion(struct ev_loop *loop, ev_async *watcher, int revents)
{
  oi_async *async = watcher->data;
  oi_task *task;

  while((task = queue_shift(&async->lock, &async->finished_tasks))) {
    assert(task->active);
    task->active = 0;
    errno = task->errorno;
#   define done_cb(kind) { \
      assert(task->params.kind.cb); \
      task->params.kind.cb(task, task->params.kind.result); \
      break; \
    }
    switch(task->type) {
      case OI_TASK_OPEN:  done_cb(open);
      case OI_TASK_READ:  done_cb(read);
      case OI_TASK_WRITE: done_cb(write);
      case OI_TASK_CLOSE: done_cb(close);
      case OI_TASK_SLEEP: done_cb(sleep);
      case OI_TASK_SENDFILE: done_cb(eio__sendfile);
    }
    /* the task is possibly freed by callback. do not access it again. */
  }
}

void
oi_async_init (oi_async *async)
{
  ev_async_init(&async->watcher, on_completion);

  ngx_queue_init(&async->finished_tasks);
  ngx_queue_init(&async->new_tasks);

  /* FIXME */
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  async->lock = lock;

  async->watcher.data = async;
  async->data = NULL;
}

void
oi_async_deinit (oi_async *async)
{
  pthread_mutex_destroy(&async->lock);
}

static void
dispatch_tasks(oi_async *async)
{
  while(!ngx_queue_empty(&async->new_tasks)) {
    ngx_queue_t *last = ngx_queue_last(&async->new_tasks);
    ngx_queue_remove(last);
    oi_task *task = ngx_queue_data(last, oi_task, queue);

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
oi_async_attach (struct ev_loop *loop, oi_async *async)
{
  if(active_watchers == 0) {
    start_workers();
  }
  active_watchers++;

  ev_async_start(loop, &async->watcher);
  async->loop = loop;

  dispatch_tasks(async);
}

void
oi_async_detach (oi_async *async)
{
  if(async->loop == NULL)
    return;
  ev_async_stop(async->loop, &async->watcher);
  async->loop = NULL;
  active_watchers--;
  if(active_watchers == 0) {
    //stop_workers();
  }
}

void
oi_async_submit (oi_async *async, oi_task *task)
{
  assert(!task->active);
  assert(task->async == NULL);
  task->async = async;
  task->active = 1;

  ngx_queue_insert_head(&async->new_tasks, &task->queue);
  if(ev_is_active(&async->watcher)) {
    dispatch_tasks(async);
  }
}

