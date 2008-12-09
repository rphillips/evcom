#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <eio.h>
#include <ev.h>

#include "oi_file.h"

/* forwards */
static void read_chunk(oi_file *file);

static void 
want_poll(struct eio_queue *queue)
{
  oi_file *file = queue->data;

  if(file->loop) {
    ev_async_send(file->loop, &file->thread_pool_result_watcher);
  }
}

static void 
done_poll(struct eio_queue *queue)
{
  //oi_file *file = queue->data;
}

static void
poll_thread_pool(struct ev_loop *loop, ev_async *watcher, int revents)
{
  oi_file *file = watcher->data;
  eio_poll(&file->task_queue);
}

int 
oi_file_init (oi_file *file)
{
  eio_init(&file->task_queue, want_poll, done_poll);
  file->task_queue.data = file;

  ev_async_init (&file->thread_pool_result_watcher, poll_thread_pool);
  file->thread_pool_result_watcher.data = file;

  file->max_chunksize = 1024 * 50; /* 50kb ? */

  file->on_open = NULL;
  file->on_connect = NULL;
  file->on_read = NULL;
  file->on_drain = NULL;
  file->on_error = NULL;
  file->on_close = NULL;
  return 0;
}

static int
after_read(eio_req *req)
{
  oi_file *file = req->data;

  if(req->result == -1) {
    printf("file read: error!\n");
    return -1;
  }

  if(file->on_read) { file->on_read(file, req->ptr2, req->result); }

  free(req->ptr2);

  if(req->result != 0)
    read_chunk(file);

  return 0;
}

static void
read_chunk(oi_file *file)
{
  /* TODO: 
   *  - check the fd is open 
   *  - check that we're reading 
   */
  eio_read ( file->fd
           , NULL
           , file->max_chunksize
           , 0
           , &file->task_queue 
           , EIO_PRI_DEFAULT
           , after_read
           , file
           );
}

static int 
after_open(eio_req *req)
{
  oi_file *file = req->data;

  if(req->result == -1) {
    printf("file opened: error!\n");
    return -1;
  }

  file->fd = req->result;

  if(file->on_open) { file->on_open(file); }

  read_chunk(file);

  return 0;
}

void
oi_file_open_path (oi_file *file, const char *path, int flags, mode_t mode)
{
  eio_open( path
          , flags
          , mode 
          , &file->task_queue
          , EIO_PRI_DEFAULT
          , after_open
          , file
          );
}

void
oi_file_attach (oi_file *file, struct ev_loop *loop)
{
  ev_async_start (loop, &file->thread_pool_result_watcher);
  file->loop = loop;
  ev_async_send(file->loop, &file->thread_pool_result_watcher);
}

void
oi_file_detach (oi_file *file)
{
  ev_async_stop (file->loop, &file->thread_pool_result_watcher);
  file->loop = NULL;
}

void oi_file_read_start   (oi_file *);
void oi_file_read_stop    (oi_file *);
void oi_file_write        (oi_file *, oi_buf *);
void oi_file_stream       (oi_file *, oi_socket *);
void oi_file_write_simple (oi_file *, const char *, size_t);
void oi_file_close        (oi_file *);
