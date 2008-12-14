#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <eio.h>
#include <ev.h>

#include "oi_file.h"
#include "ngx_queue.h"

/* forwards */
static void dispatch_write_buf(oi_file *file);

static void 
want_poll(struct eio_queue *queue)
{
  oi_file *file = queue->data;

  if(file->loop) {
    ev_async_send(file->loop, &file->thread_pool_result_watcher);
  }
}

/* 
static void 
done_poll(struct eio_queue *queue)  
{ 
  ;  
}
*/

static void
poll_thread_pool(struct ev_loop *loop, ev_async *watcher, int revents)
{
  oi_file *file = watcher->data;
  eio_poll(&file->task_queue);
}

int 
oi_file_init (oi_file *file)
{
  eio_init(&file->task_queue, want_poll, NULL /* done_poll */);
  file->task_queue.data = file;

  ev_async_init (&file->thread_pool_result_watcher, poll_thread_pool);
  file->thread_pool_result_watcher.data = file;

  ngx_queue_init(&file->write_queue);

  file->fd = -1;
  file->loop = NULL;
  file->read_buf = NULL;
  file->write_buf = NULL;

  file->on_open = NULL;
  file->on_read = NULL;
  file->on_drain = NULL;
  file->on_error = NULL;
  file->on_close = NULL;
  return 0;
}

/* TODO this is not good enough buf->base is a pointer its not contained
 * in the structure! 
 */
#define get_buf_from_base(ptr) (oi_buf*) ((unsigned char *) (ptr) - offsetof(oi_buf, base))

static int
after_read(eio_req *req)
{
  oi_file *file = req->data;

  if(req->result == -1) {
    printf("file read: error!\n");
    return -1;
  }

  assert(file->read_buf != NULL);

  size_t recved = req->result;

  if(file->on_read) { 
    file->on_read(file, file->read_buf, recved);
  }

  if(file->read_buf->release) {
    file->read_buf->release(file->read_buf);
  }
  file->read_buf = NULL;
  return 0;
}

int 
oi_file_read (oi_file *file, oi_buf *to_be_filled)
{
  assert(file->fd > -1 && "file not open!");
  if(file->read_buf != NULL)
    /* only one read can be submitted at a time */
    return -1;

  file->read_buf = to_be_filled;

  eio_read ( file->fd
           , to_be_filled->base
           , to_be_filled->len
           , -1   /* offset */
           , &file->task_queue 
           , EIO_PRI_DEFAULT
           , after_read
           , file
           );
  return 0;
}

void
oi_api_free_buf_with_heap_base(oi_buf *buf)
{
  free(buf->base);
  free(buf);
}

int
oi_file_read_simple (oi_file *file, size_t len)
{
  if(file->read_buf != NULL)
    /* only one read can be submitted at a time */
    return -1;

  oi_buf *buf = malloc(sizeof(oi_buf));
  buf->base = malloc(len);
  buf->len = len;
  buf->release = oi_api_free_buf_with_heap_base;
  return oi_file_read(file, buf);
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

  if(file->on_open) { 
    file->on_open(file);
  }

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
oi_file_open_stdin (oi_file *file)
{
  file->fd = STDIN_FILENO;
  if(file->on_open)
    file->on_open(file);
}

void
oi_file_open_stdout (oi_file *file)
{
  file->fd = STDOUT_FILENO;
  if(file->on_open)
    file->on_open(file);
}

void
oi_file_open_stderr (oi_file *file)
{
  file->fd = STDERR_FILENO;
  if(file->on_open)
    file->on_open(file);
}

void
oi_file_attach (oi_file *file, struct ev_loop *loop)
{
  ev_async_start (loop, &file->thread_pool_result_watcher);
  file->loop = loop;
  /* use ev_feed_event? */
  ev_async_send(file->loop, &file->thread_pool_result_watcher);
}

void
oi_file_detach (oi_file *file)
{
  ev_async_stop (file->loop, &file->thread_pool_result_watcher);
  file->loop = NULL;
}


static int 
after_write(eio_req *req)
{
  oi_file *file = req->data;

  if(req->result == -1) {
    perror("write()");
    return -1;
  }

  assert(file->write_buf != NULL);
  oi_buf *buf = file->write_buf;

  buf->written += req->result;
  if(buf->written < buf->len) {
    eio_write ( file->fd
              , buf->base + buf->written
              , buf->len - buf->written
              , -1
              , &file->task_queue
              , EIO_PRI_DEFAULT
              , after_write
              , file
              );
    return 0;
  }

  assert(buf->written == buf->len);
  file->write_buf = NULL;

  if(buf->release)
    buf->release(buf);

  if(ngx_queue_empty(&file->write_queue)) {
    if(file->on_drain) { file->on_drain(file); }
  } else {
    dispatch_write_buf(file);
  }

  return 0;
}

static void
dispatch_write_buf(oi_file *file)
{
  if(file->write_buf != NULL)
    return;
  if(ngx_queue_empty(&file->write_queue)) 
    return;

  ngx_queue_t *q = ngx_queue_last(&file->write_queue);
  ngx_queue_remove(q);
  file->write_buf = ngx_queue_data(q, oi_buf, queue);

  eio_write ( file->fd
            , file->write_buf->base
            , file->write_buf->len
            , -1
            , &file->task_queue
            , EIO_PRI_DEFAULT
            , after_write
            , file
            );
}

void
oi_file_write (oi_file *file, oi_buf *buf)
{
  assert(file->fd >= 0 && "file not open!");
  buf->written = 0;
  ngx_queue_insert_head(&file->write_queue, &buf->queue);
  dispatch_write_buf(file);
}

/* Writes a string to the file. 
 * NOTE: Allocates memory. Avoid for performance applications.
 */ 
void
oi_file_write_simple (oi_file *file, const char *str, size_t len)
{
  assert(file->fd >= 0 && "file not open!");

  oi_buf *buf = malloc(sizeof(oi_buf));
  buf->base = malloc(len);
  memcpy(buf->base, str, len);
  buf->len = len;
  buf->release = oi_api_free_buf_with_heap_base;

  oi_file_write(file, buf);
}

static int
after_sendfile(eio_req *req)
{
  oi_file *file = req->data;

  if(req->result == -1) {
    perror("write()");
    return -1;
  }

  assert(file->write_socket != NULL);
  if(file->write_socket->on_drain) {
    file->write_socket->on_drain(file->write_socket);
  }
  file->write_socket = NULL;

  if(file->on_drain) {
    file->on_drain(file);
  }

  return 0;
}

int
oi_file_send (oi_file *file, oi_socket *socket, off_t offset, size_t length)
{
  if(!ngx_queue_empty(&file->write_queue)) 
    /* cannot call when there is stuff to write */
    return -1;

  if(file->write_socket != NULL)
    /* cannot call this multiple times */
    return -1;

  file->write_socket = socket; 
  eio_sendfile ( socket->fd
               , file->fd
               , offset
               , length
               , &file->task_queue
               , EIO_PRI_DEFAULT
               , after_sendfile
               , file
               );
  return 0;
}

static void
clear_write_queue(oi_file *file)
{
  while(!ngx_queue_empty(&file->write_queue)) {
    ngx_queue_t *q = ngx_queue_last(&file->write_queue);
    ngx_queue_remove(q);
    oi_buf *buf = ngx_queue_data(q, oi_buf, queue);
    if(buf->release) {
      buf->release(buf);
    }
  }
}

static int 
after_close(eio_req *req)
{
  oi_file *file = req->data;

  assert(ngx_queue_empty(&file->write_queue));

  if(req->result == -1) {
    perror("close()");
    return -1;
    /* try to close again? */
  }

  file->fd = -1;
  /* TODO deinit task_queue, detach thread_pool_result_watcher */

  if(file->on_close) {
    file->on_close(file);
  }

  return 0;
}

void
oi_file_close (oi_file *file)
{
  assert(file->fd >= 0 && "file not open!");
  clear_write_queue(file);
  eio_close ( file->fd
            , &file->task_queue
            , EIO_PRI_DEFAULT
            , after_close
            , file
            ); 
}
