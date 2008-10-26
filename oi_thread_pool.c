#include "oi.h"
#include "oi_thread_pool.h"

#define READ_FD(pipe)  pipe[0]
#define WRITE_FD(pipe) pipe[1]
#define pipe_send(pipe, buf, len, flags) send(WRITE_FD(pipe), buf, len, flags) 
#define pipe_recv(pipe, buf, len, flags) recv(READ_FD(pipe), buf, len, flags) 
#define EXECUTION_SIGNAL 'E'
#define KILL_SIGNAL 'K'

#define THREAD_COMMON         \
{                             \
  pthread_t thread;           \
  pthread_attr_t thread_attr; \
  struct ev_loop *loop;       \
}

struct thread_pool_worker {
  THREAD_COMMON;
  ev_io new_task_watcher;
  int new_task_pipe[2];
  int id;
  oi_thread_pool_task *task;
};

struct thread_pool_worker *workers[OI_MAX_THREAD_POOL_WORKERS];

static struct {
  THREAD_COMMON;
  oi_server server;
  int worker_readyness_pipe[2];
} master;

static void
execute_task(oi_async_task *task)
{
  
}

static void
free_worker(thread_pool_worker *worker) 
{
  /* worker->task = NULL */
  close(READ_FD(worker->new_task_pipe));
  ev_unloop(worker->loop, EVUNLOOP_ALL);
  ev_loop_destory(worker->loop);
}

void *
worker_loop(void *data)
{
  thread_pool_worker *worker = data;
  // send master id number
  ev_loop(worker->loop, 0);
  free_worker(worker);
  return NULL;
}

static void
on_new_task(struct ev_loop *loop, ev_io *watcher, int revents)
{
  thread_pool_worker *worker = watcher->data;

  if(revents & EV_ERROR) {
    goto shutdown;
  }

  assert(revents & EV_READ);

  char buf[2];
  int got = pipe_recv(worker->new_task_pipe, buf, 1, 0);
  if(got < 0) {
    goto shutdown;
  } else if(got == 0) {
    goto shutdown;
  }

  /* If there is an 'E' character in then pipe then we execute the task
   * sitting at worker->task. Otherwise shutdown (e.g. we recv KILL_SIGNAL)
   */
  if(buf[0] == EXECUTION_SIGNAL) {
    assert(worker->task != NULL);
    execute_task(worker->task);
    pipe_send(master.worker_readyness_pipe, worker->id, 1, 0);
    return;
  }

shutdown:
  ev_io_stop(worker);
  ev_unloop(worker->loop, EVUNLOOP_ALL);
}

static thread_pool_worker*
new_worker()
{
  int r;
  thread_pool_worker *worker = malloc(sizeof(thread_pool_worker));
  if(worker == NULL ) {
    /* TODO: out of memory */
    return NULL;
  }  

  r = pipe(&worker->new_task_pipe);
  if(r < 0) {
    perror("worker creation pipe()");
    goto error;
  }

  worker->task = NULL;
  worker->loop = ev_loop_new(EVFLAG_AUTO);

  ev_io_init( &worker->new_task_watcher
            , on_new_task
            , READ_FD(worker->new_task_pipe)
            , EV_READ | EV_ERROR
            );
  worker->new_task_watcher.data = worker;
  ev_io_start(worker->loop, &worker->new_task_watcher);

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
on_master_connection_read(oi_socket *socket, const void *base, size_t len)
{
}

static void 
on_master_connection_close(oi_socket *socket)
{
  free(socket);
}

oi_socket*
on_master_connection (oi_server *_, struct sockaddr *_, socklen_t _)
{
  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, 1.0);
  socket->on_read = on_master_connection_read;
  socket->on_close = on_master_connection_close;
  
  return socket;
}

void *
master_loop(void *data)
{
  ev_loop(master.loop, 0);
  return NULL;
}

int
oi_thread_pool_init (int number_workers)
{
  int r; 

  assert(master->loop == NULL);

  if(number_workers < 0 || number_workers > OI_MAX_THREAD_POOL_WORKERS) {
    printf("bad number of workers\n"); /* FIXME */
    return -1;
  }

  master->loop = ev_loop_new(EVFLAG_AUTO);

  r = oi_server_init(&master.server, OI_MAX_THREAD_POOL_CONNECTIONS);
  if(r < 0)
    return r;
  master.server.on_connection = on_master_connection;
  oi_server_listen_unix(&master.server, OI_THREAD_POOL_SOCKET, 0700);
  oi_server_attach(&master.server, master.loop);

  pthread_attr_setdetachstate(&master.thread_attr, PTHREAD_CREATE_DETACHED);
  r = pthread_create( &master.thread
                    , &master.thread_attr
                    , master_loop
                    , NULL
                    ); 

  /* start worker threads */
  int i;
  for(i = 0; i < OI_MAX_THREAD_POOL_WORKERS; i++) {
    workers[i] = i < number_workers ? new_worker() : NULL;
    workers[i]->id = i;
  }

  return 1;
}

void
oi_thread_pool_destroy (void)
{
  int i;
  for(i = 0; i < OI_MAX_THREAD_POOL_WORKERS; i++) {
    if(workers[i] != NULL) {
      char kill_signal = KILL_SIGNAL;
      send_pipe(worker->new_task_pipe, &kill_signal, 1, 0);
    }
  }
}

