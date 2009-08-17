/* Copyright (c) 2008,2009 Ryan Dahl
 *
 * evcom_queue comes from ngx_queue.h
 * Copyright (C) 2002-2009 Igor Sysoev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h> /* memset */

#include <netinet/tcp.h> /* TCP_NODELAY */
#include <sys/types.h>
#include <sys/socket.h> /* shutdown */
#include <sys/un.h>
#include <netinet/in.h> /* sockaddr_in, sockaddr_in6 */

#include <ev.h>
#include <evcom.h>

#if EV_MULTIPLICITY
# define D_LOOP_(d)  (d)->loop,
# define D_LOOP_SET(d, _loop)  do { (d)->loop = (_loop); } while (0)
#else
# define D_LOOP_(d)
# define D_LOOP_SET(d, _loop)
#endif // EV_MULTIPLICITY

#if EVCOM_HAVE_GNUTLS
static int secure_hangup (evcom_descriptor *);
#endif
static int recv_send (evcom_descriptor *);

#undef TRUE
#define TRUE 1
#undef FALSE
#define FALSE 0
#undef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define OKAY  0
#define AGAIN 1

#define ATTACHED(s)         ((s)->flags & EVCOM_ATTACHED)
#define LISTENING(s)        ((s)->flags & EVCOM_LISTENING)
#define CONNECTED(s)        ((s)->flags & EVCOM_CONNECTED)
#define SECURE(s)           ((s)->flags & EVCOM_SECURE)
#define GOT_HALF_CLOSE(s)   ((s)->flags & EVCOM_GOT_HALF_CLOSE)
#define GOT_FULL_CLOSE(s)   ((s)->flags & EVCOM_GOT_FULL_CLOSE)
#define PAUSED(s)           ((s)->flags & EVCOM_PAUSED)
#define READABLE(s)         ((s)->flags & EVCOM_READABLE)
#define WRITABLE(s)         ((s)->flags & EVCOM_WRITABLE)
#define GOT_WRITE_EVENT(s)  ((s)->flags & EVCOM_GOT_WRITE_EVENT)

static int too_many_connections = 0;

EV_INLINE int
set_nonblock (int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return -1;

  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (r == -1) return -1;

  return 0;
}

evcom_buf *
evcom_buf_new2 (size_t len)
{
  void *data = malloc(sizeof(evcom_buf) + len);
  if (!data) return NULL;

  evcom_buf *buf = data;
  buf->len = len;
  buf->release = (void (*)(evcom_buf*))free;
  buf->base = data + sizeof(evcom_buf);

  return buf;
}

evcom_buf *
evcom_buf_new (const char *base, size_t len)
{
  evcom_buf* buf = evcom_buf_new2(len);
  if (!buf) return NULL;

  memcpy(buf->base, base, len);

  return buf;
}

static int
close_asap (evcom_descriptor *d)
{
  if (d->fd < 0) return OKAY;

  int r = close(d->fd);

  if (r < 0) {
    if (errno == EINTR) {
      d->action = close_asap;
      return AGAIN;
    } else {
      d->errorno = errno;
    }
  }

  d->action = NULL;
  d->fd = -1;

  return OKAY;
}

#define release_write_buffer(writer) \
do { \
  while (!evcom_queue_empty(&(writer)->out)) { \
    evcom_queue *q = evcom_queue_last(&(writer)->out); \
    evcom_buf *buf = evcom_queue_data(q, evcom_buf, queue); \
    evcom_queue_remove(q); \
    if (buf->release) buf->release(buf); \
  } \
} while (0)

static int
close_writer_asap (evcom_writer *writer)
{
  release_write_buffer(writer);
  ev_feed_event(D_LOOP_(writer) &writer->write_watcher, EV_WRITE);
  return close_asap((evcom_descriptor*)writer);
}

static int
close_stream_asap (evcom_stream *stream)
{
  if (too_many_connections && stream->server) {
#if EV_MULTIPLICITY
    struct ev_loop *loop = stream->server->loop;
#endif
    evcom_server_attach(EV_A_ stream->server);
  }
  too_many_connections = 0;

  release_write_buffer(stream);

  /* In any case we need to feed an event in order
   * to get the on_close callback. In the case of EINTR
   * we need an event so that we can call close() again.
   */
  ev_io_start(D_LOOP_(stream) &stream->read_watcher);
  ev_feed_event(D_LOOP_(stream) &stream->read_watcher, EV_READ);
  ev_io_start(D_LOOP_(stream) &stream->write_watcher);
  ev_feed_event(D_LOOP_(stream) &stream->write_watcher, EV_WRITE);

  int r = close_asap((evcom_descriptor*)stream);
  if (r == AGAIN) return AGAIN;

  return OKAY;
}

static inline void
evcom_perror (const char *msg, int errorno)
{
  fprintf(stderr, "(evcom) %s %s\n", msg, strerror(errorno));
}

// This is to be called when ever the out is empty
// and we need to change state.
static inline void
change_state_for_empty_out (evcom_stream *stream)
{
  if (GOT_FULL_CLOSE(stream)) {
#if EVCOM_HAVE_GNUTLS
    if (SECURE(stream) && READABLE(stream) && WRITABLE(stream)) {
      secure_hangup((evcom_descriptor*)stream);
    } else
#endif
    {
      close_stream_asap(stream);
    }
    return;
  }

  if (GOT_HALF_CLOSE(stream)) {
    if (WRITABLE(stream)) {
      stream->action = recv_send;
      recv_send((evcom_descriptor*)stream);
    } else {
      close_stream_asap(stream);
    }
    return;
  }

  if (ATTACHED(stream)) {
    ev_io_stop(D_LOOP_(stream) &stream->write_watcher);
  }
}

static inline ssize_t
nosigpipe_send (int fd, const void *buf, size_t len)
{
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif
  return send(fd, buf, len, flags);
}

#if EVCOM_HAVE_GNUTLS
static ssize_t
nosigpipe_push (gnutls_transport_ptr_t data, const void *buf, size_t len)
{
  evcom_stream *stream = (evcom_stream*)data;
  assert(SECURE(stream));

  return nosigpipe_send(stream->fd, buf, len);
}

#define SET_DIRECTION(stream) \
do { \
  if (0 == gnutls_record_get_direction((stream)->session)) { \
    ev_io_stop(D_LOOP_(stream) &(stream)->write_watcher);  \
    ev_io_start(D_LOOP_(stream) &(stream)->read_watcher);  \
  } else { \
    ev_io_stop(D_LOOP_(stream) &(stream)->read_watcher); \
    ev_io_start(D_LOOP_(stream) &(stream)->write_watcher); \
  } \
} while (0)

static int
secure_handshake (evcom_descriptor *d)
{
  evcom_stream *stream = (evcom_stream*) d;

  assert(SECURE(stream));

  int r = gnutls_handshake(stream->session);

  if (gnutls_error_is_fatal(r)) {
    stream->gnutls_errorno = r;
    return close_stream_asap(stream);
  }

  if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
    SET_DIRECTION(stream);
    stream->action = secure_handshake;
    return AGAIN;
  }

  stream->action = recv_send;

  assert(!CONNECTED(stream));
  stream->flags |= EVCOM_CONNECTED;
  if (stream->on_connect) stream->on_connect(stream);

  evcom_stream_reset_timeout(stream);

  return recv_send((evcom_descriptor*)stream);
}

static int
secure_hangup (evcom_descriptor *d)
{
  evcom_stream *stream = (evcom_stream*)d;

  assert(SECURE(stream));

  int r = gnutls_bye(stream->session, GNUTLS_SHUT_RDWR);

  if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
    SET_DIRECTION(stream);
    stream->action = secure_hangup;
    return AGAIN;
  }

  if (gnutls_error_is_fatal(r)) {
    stream->gnutls_errorno = r;
  }

  return close_stream_asap(stream);
}

void
evcom_stream_set_secure_session (evcom_stream *stream, gnutls_session_t session)
{
  stream->session = session;
  stream->flags |= EVCOM_SECURE;
}
#endif /* HAVE GNUTLS */

static inline int
recv_data (evcom_stream *stream)
{
  char buf[EVCOM_CHUNKSIZE];
  size_t buf_size = EVCOM_CHUNKSIZE;
  ssize_t recved;

  while (stream->fd >= 0) {
    assert(READABLE(stream));

    if (PAUSED(stream)) {
      ev_io_stop(D_LOOP_(stream) &stream->read_watcher);
      return AGAIN;
    }

    if (!SECURE(stream)) {
      recved = recv(stream->fd, buf, buf_size, 0);
    }

#if EVCOM_HAVE_GNUTLS
    else {
      recved = gnutls_record_recv(stream->session, buf, buf_size);

      if (gnutls_error_is_fatal(recved)) {
        stream->gnutls_errorno = recved;
        return close_stream_asap(stream);
      }

      if (recved == GNUTLS_E_INTERRUPTED || recved == GNUTLS_E_AGAIN) {
        SET_DIRECTION(stream);
        return AGAIN;
      }

      /* A server may also receive GNUTLS_E_REHANDSHAKE when a client has
       * initiated a handshake. In that case the server can only initiate a
       * handshake or terminate the connection. */
      if (recved == GNUTLS_E_REHANDSHAKE) {
        if (READABLE(stream) && WRITABLE(stream)) {
          stream->action = secure_handshake;
          return OKAY;
        } else {
          stream->gnutls_errorno = GNUTLS_E_REHANDSHAKE;
          return close_stream_asap(stream);
        }
      }
    }
#endif /* EVCOM_HAVE_GNUTLS */

    if (recved < 0) {
      if (errno == EAGAIN || errno == EINTR) return AGAIN;
      stream->errorno = errno;
      return close_stream_asap(stream);
    }

    evcom_stream_reset_timeout(stream);

    assert(recved >= 0);

    if (recved == 0) {
      stream->flags &= ~EVCOM_READABLE;
      ev_io_stop(D_LOOP_(stream) &stream->read_watcher);
    }

    /* NOTE: EOF is signaled with recved == 0 on callback */
    if (stream->on_read) stream->on_read(stream, buf, recved);

    if (recved == 0) {
      if (!WRITABLE(stream)) return close_stream_asap(stream);
      return OKAY;
    }
  }
  return AGAIN;
}

static int
send_data (evcom_stream *stream)
{
  ssize_t sent;

  while (stream->fd >= 0 && !evcom_queue_empty(&stream->out)) {
    assert(WRITABLE(stream));

    evcom_queue *q = evcom_queue_last(&stream->out);
    evcom_buf *buf = evcom_queue_data(q, evcom_buf, queue);

#if EVCOM_HAVE_GNUTLS
    if (SECURE(stream)) {
      sent = gnutls_record_send(stream->session,
          buf->base + buf->written,
          buf->len - buf->written);

      if (gnutls_error_is_fatal(sent)) {
        stream->gnutls_errorno = sent;
        return close_stream_asap(stream);
      }
    } else
#endif // EVCOM_HAVE_GNUTLS
    {
      /* TODO use writev() here? */
      sent = nosigpipe_send(stream->fd,
          buf->base + buf->written,
          buf->len - buf->written);
    }

    if (sent <= 0) {
      switch (errno) {
        case EAGAIN:
        case EINTR:
          return AGAIN;

        case ECONNRESET:
        case EPIPE:
          stream->flags &= ~EVCOM_WRITABLE;
          if (!READABLE(stream)) return close_stream_asap(stream);
          sent = 0;
          break;

        default:
          stream->errorno = errno;
          evcom_perror("send()", errno);
          return close_stream_asap(stream);
      }
    }

    evcom_stream_reset_timeout(stream);

    assert(sent >= 0);

    buf->written += sent;

    if (buf->written == buf->len) {
      evcom_queue_remove(q);
      if (buf->release) buf->release(buf);
    }
  }

  assert(evcom_queue_empty(&stream->out));
  change_state_for_empty_out(stream);

  return AGAIN;
}

static int
shutdown_write (evcom_stream *stream)
{
  int r;

#if EVCOM_HAVE_GNUTLS
  if (SECURE(stream)) {
    r = gnutls_bye(stream->session, GNUTLS_SHUT_WR);

    if (gnutls_error_is_fatal(r))  {
      stream->gnutls_errorno = r;
      return close_stream_asap(stream);
    }

    if (r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN) {
      SET_DIRECTION(stream);
    }
  }
#endif

  r = shutdown(stream->fd, SHUT_WR);

  if (r < 0) {
    stream->errorno = errno;
    evcom_perror("shutdown()", errno);
    return close_stream_asap(stream);
  }

  stream->flags &= ~EVCOM_WRITABLE;

  return OKAY;
}

static int
recv_send (evcom_descriptor *d)
{
  evcom_stream *stream = (evcom_stream*) d;

  int r = AGAIN;

  if (READABLE(stream) && !PAUSED(stream)) {
    r = recv_data(stream);
  }

  if (stream->fd < 0) return AGAIN;

  if (WRITABLE(stream)) {
    if (GOT_HALF_CLOSE(stream) && evcom_queue_empty(&stream->out)) {

      if (READABLE(stream)) {
        return shutdown_write(stream);
      } else {
        return close_stream_asap(stream);
      }

    } else {
      return send_data(stream);
    }
  }

  return r;
}

static inline int
connection_established (evcom_stream *stream)
{
  ev_io_start(D_LOOP_(stream) &stream->read_watcher);
  assert(!CONNECTED(stream));

#if EVCOM_HAVE_GNUTLS
  if (SECURE(stream)) {
    stream->action = secure_handshake;
    return secure_handshake((evcom_descriptor*)stream);
  } else
#endif  /* EVCOM_HAVE_GNUTLS */
  {
    stream->flags |= EVCOM_CONNECTED;
    if (stream->on_connect) stream->on_connect(stream);

    stream->action = recv_send;
    return recv_send((evcom_descriptor*)stream);
  }
}

static int
wait_for_connection (evcom_descriptor *d)
{
  evcom_stream *stream = (evcom_stream*)d;

  if (!GOT_WRITE_EVENT(d)) {
    ev_io_stop(D_LOOP_(stream) &stream->read_watcher);
    return AGAIN;
  }

  int connect_error;
  socklen_t len = sizeof(int);
  int r = getsockopt(d->fd, SOL_SOCKET, SO_ERROR, &connect_error, &len);
  if (r < 0) {
    d->errorno = r;
    return close_asap(d);
  }

  switch (connect_error) {
    case 0:
      return connection_established((evcom_stream*)d);

    case EINTR:
    case EINPROGRESS:
      return AGAIN;

    default:
      d->errorno = connect_error;
      return close_asap(d);
  }
}

static void
assign_file_descriptor (evcom_stream *stream, int fd)
{
#ifdef SO_NOSIGPIPE
  int flags = 1;
  int r = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof(flags));
  if (r < 0) {
    evcom_perror("setsockopt(SO_NOSIGPIPE)", errno);
  }
#endif

  ev_io_set(&stream->read_watcher, fd, EV_READ);
  ev_io_set(&stream->write_watcher, fd, EV_WRITE);

  stream->fd = fd;
  stream->action = wait_for_connection;

  stream->flags |= EVCOM_READABLE;
  stream->flags |= EVCOM_WRITABLE;

#if EVCOM_HAVE_GNUTLS
  if (SECURE(stream)) {
    gnutls_transport_set_lowat(stream->session, 0);
    gnutls_transport_set_push_function(stream->session, nosigpipe_push);
    gnutls_transport_set_ptr2(stream->session,
        (gnutls_transport_ptr_t)(intptr_t)fd, /* recv */
        stream); /* send */
  }
#endif
}


/* Retruns evcom_stream if a connection could be accepted.
 * The returned stream is not yet attached to the event loop.
 * Otherwise NULL
 */
static evcom_stream*
accept_connection (evcom_server *server)
{
  struct sockaddr address; /* connector's address information */
  socklen_t addr_len = sizeof(address);

  int fd = accept(server->fd, &address, &addr_len);
  if (fd < 0) {
    switch (errno) {
      case EMFILE:
        too_many_connections = 1;
        evcom_server_detach(server);
        return NULL;

      case EINTR:
      case EAGAIN:
        return NULL;

      default:
        evcom_perror("accept()", errno);
        return NULL;
    }
    assert(0 && "no reach");
  }

  evcom_stream *stream = NULL;

  if (server->on_connection) {
    stream = server->on_connection(server, &address);
  }

  if (stream == NULL) {
    close(fd);
    return NULL;
  }

  if (set_nonblock(fd) != 0) {
    evcom_perror("set_nonblock()", errno);
    return NULL;
  }

  stream->server = server;
  assign_file_descriptor(stream, fd);

  return stream;
}

/* Internal callback
 * Called by server->watcher.
 */
static int
accept_connections (evcom_descriptor *d)
{
  evcom_server *server = (evcom_server *)d;

  assert(LISTENING(server));

  /* accept as many connections as possible */
  evcom_stream *stream;
  while (server->fd >= 0 && (stream = accept_connection(server))) {
    evcom_stream_attach(D_LOOP_(server) stream);
    connection_established(stream);
  }

  return AGAIN;
}

static inline socklen_t
address_length (struct sockaddr *address)
{
  struct sockaddr_un* unix_address = (struct sockaddr_un*)address;

  switch (address->sa_family) {
    case AF_INET:
      return sizeof(struct sockaddr_in);

    case AF_INET6:
      return sizeof(struct sockaddr_in6);

    case AF_UNIX:
      return strlen(unix_address->sun_path) + sizeof(unix_address->sun_family);

    default:
      assert(0 && "Unsupported socket family");
  }
  return 0;
}

int
evcom_server_listen (evcom_server *server, struct sockaddr *address, int backlog)
{
  assert(!LISTENING(server));

  int fd = socket(address->sa_family, SOCK_STREAM, 0);
  if (fd < 0) {
    server->errorno = errno;
    evcom_perror("socket()", errno);
    return -1;
  }

  server->fd = fd;
  ev_io_set(&server->watcher, server->fd, EV_READ);

  if (set_nonblock(fd) != 0) {
    server->errorno = errno;
    evcom_perror("set_nonblock()", errno);
    close(fd);
    return -1;
  }

  int flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));

  /* XXX: Sending single byte chunks in a response body? Perhaps there is a
   * need to enable the Nagel algorithm dynamically. For now disabling.
   */
  //setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

  if (bind(fd, address, address_length(address)) < 0) {
    server->errorno = errno;
    evcom_perror("bind()", errno);
    close(fd);
    return -1;
  }

  if (listen(fd, backlog) < 0) {
    server->errorno = errno;
    evcom_perror("listen()", errno);
    close(fd);
    return -1;
  }

  server->flags |= EVCOM_LISTENING;
  server->action = accept_connections;

  return 0;
}

/**
 * Stops the server. Will not accept new connections.  Does not drop
 * existing connections.
 */
void
evcom_server_close (evcom_server *server)
{
  ev_io_start(D_LOOP_(server) &server->watcher);
  ev_feed_event(D_LOOP_(server) &server->watcher, EV_READ);

  close_asap((evcom_descriptor*)server);
}

void
evcom_server_attach (EV_P_ evcom_server *server)
{
  ev_io_start (EV_A_ &server->watcher);
  D_LOOP_SET(server, EV_A);
  server->flags |= EVCOM_ATTACHED;
}

void
evcom_server_detach (evcom_server *server)
{
  ev_io_stop (D_LOOP_(server) &server->watcher);
  D_LOOP_SET(server, NULL);
  server->flags &= ~EVCOM_ATTACHED;
}

static void
io_event(EV_P_ ev_io *watcher, int revents)
{
  evcom_descriptor *d = watcher->data;

#if EV_MULTIPLICITY
  assert(d->loop == loop);
#endif

  int r = OKAY;

  if (revents & EV_ERROR) {
    d->errorno = 1;
    r = close_asap(d);
  }

  if (revents & EV_WRITE) {
    d->flags |= EVCOM_GOT_WRITE_EVENT;
  }

  while (r == OKAY && d->action && d->fd >= 0) {
    r = d->action(d);
  }

  if (d->fd < 0) {
    assert(d->action == NULL);
    ev_clear_pending(EV_A_ watcher);
    ev_io_stop(EV_A_ watcher);
    if (d->on_close) d->on_close(d);
  }
}

static void
evcom_descriptor_init (evcom_descriptor *d)
{
  d->fd = -1;
  D_LOOP_SET(d, NULL);
  d->flags = 0;
  d->errorno = 0;
  d->action = NULL;
}

void
evcom_server_init (evcom_server *server)
{
  evcom_descriptor_init((evcom_descriptor*)server);
  ev_init (&server->watcher, io_event);
  server->watcher.data = server;
  server->on_connection = NULL;
}

/* Internal callback. called by stream->timeout_watcher */
static void
on_timeout (EV_P_ ev_timer *watcher, int revents)
{
  evcom_stream *stream = watcher->data;

#if EV_MULTIPLICITY
  assert(stream->loop == loop);
#endif
  assert(revents == EV_TIMEOUT);
  assert(watcher == &stream->timeout_watcher);

  if (PAUSED(stream)) {
    evcom_stream_reset_timeout(stream);
    return;
  }

  if (stream->on_timeout) stream->on_timeout(stream);
  // timeout does not automatically kill your connection. you must!
}

/**
 * If using SSL do consider setting
 *   gnutls_db_set_retrieve_function (stream->session, _);
 *   gnutls_db_set_remove_function (stream->session, _);
 *   gnutls_db_set_store_function (stream->session, _);
 *   gnutls_db_set_ptr (stream->session, _);
 */
void
evcom_stream_init (evcom_stream *stream, float timeout)
{
  evcom_descriptor_init((evcom_descriptor*)stream);

  // reader things
  ev_init(&stream->read_watcher, io_event);
  stream->read_watcher.data = stream;
  stream->on_read = NULL;

  // writer things
  ev_init(&stream->write_watcher, io_event);
  stream->write_watcher.data = stream;
  evcom_queue_init(&stream->out);

  // stream things
  stream->server = NULL;
#if EVCOM_HAVE_GNUTLS
  stream->gnutls_errorno = 0;
  stream->session = NULL;
#endif
  ev_timer_init(&stream->timeout_watcher, on_timeout, 0., timeout);
  stream->timeout_watcher.data = stream;
  stream->action = NULL;
  stream->on_connect = NULL;
  stream->on_timeout = NULL;
}

void
evcom_stream_close (evcom_stream *stream)
{
  stream->flags |= EVCOM_GOT_HALF_CLOSE;
  if (evcom_queue_empty(&stream->out)) {
    change_state_for_empty_out(stream);
  }
}

void
evcom_stream_full_close (evcom_stream *stream)
{
  stream->flags |= EVCOM_GOT_FULL_CLOSE;
  if (evcom_queue_empty(&stream->out)) {
    change_state_for_empty_out(stream);
  }
}

void evcom_stream_force_close (evcom_stream *stream)
{
  close_stream_asap(stream);

  // Even if close returned EINTR
  stream->action = NULL;
  stream->fd = -1;

  evcom_stream_detach(stream);
}

void
evcom_stream_write (evcom_stream *stream, const char *str, size_t len)
{
  if (!WRITABLE(stream) || GOT_FULL_CLOSE(stream) || GOT_HALF_CLOSE(stream)) {
    assert(0 && "Do not write to a closed stream");
    return;
  }

  ssize_t sent = 0;

  if (evcom_queue_empty(&stream->out)) {
#if EVCOM_HAVE_GNUTLS
    if (SECURE(stream)) {
      sent = gnutls_record_send(stream->session, str, len);

      if (gnutls_error_is_fatal(sent)) {
        stream->gnutls_errorno = sent;
        goto close;
      }
    } else
#endif // EVCOM_HAVE_GNUTLS
    {
      /* TODO use writev() here? */
      sent = nosigpipe_send(stream->fd, str, len);
    }

    if (sent < 0) {
      switch (errno) {
        case ECONNRESET:
        case EPIPE:
          goto close;

        case EINTR:
        case EAGAIN:
          sent = 0;
          break;

        default:
          stream->errorno = errno;
          evcom_perror("send()", stream->errorno);
          goto close;
      }
    }
  } /* TODO else { memcpy to last buffer on head } */

  assert(sent >= 0);
  if ((size_t)sent == len) return; /* sent the whole buffer */

  len -= sent;
  str += sent;

  evcom_buf *b = evcom_buf_new(str, len);
  evcom_queue_insert_head(&stream->out, &b->queue);
  b->written = 0;

  assert(stream->fd >= 0);

  if (ATTACHED(stream)) {
    ev_io_start(D_LOOP_(stream) &stream->write_watcher);
  }
  return;

close:
  close_stream_asap(stream);
}

void
evcom_stream_reset_timeout (evcom_stream *stream)
{
  ev_timer_again(D_LOOP_(stream) &stream->timeout_watcher);
}

void
evcom_stream_attach (EV_P_ evcom_stream *stream)
{
  D_LOOP_SET(stream, EV_A);
  stream->flags |= EVCOM_ATTACHED;

  ev_timer_again(EV_A_ &stream->timeout_watcher);

  if (!CONNECTED(stream)) {
    ev_io_start(EV_A_ &stream->write_watcher);
  } else {
    if (READABLE(stream) && !PAUSED(stream)) {
      ev_io_start(EV_A_ &stream->read_watcher);
    }

    if (WRITABLE(stream)) {
      ev_io_start(EV_A_ &stream->write_watcher);
    }

    ev_feed_fd_event(D_LOOP_(stream) stream->fd, EV_WRITE);
  }
}

void
evcom_stream_detach (evcom_stream *stream)
{
  ev_io_stop(D_LOOP_(stream) &stream->write_watcher);
  ev_io_stop(D_LOOP_(stream) &stream->read_watcher);
  ev_timer_stop(D_LOOP_(stream) &stream->timeout_watcher);
  D_LOOP_SET(stream, NULL);
  stream->flags &= ~EVCOM_ATTACHED;
}

void
evcom_stream_read_pause (evcom_stream *stream)
{
  ev_io_stop(D_LOOP_(stream) &stream->read_watcher);
  ev_clear_pending(D_LOOP_(stream) &stream->read_watcher);
  stream->flags |= EVCOM_PAUSED;
}

void
evcom_stream_read_resume (evcom_stream *stream)
{
  evcom_stream_reset_timeout(stream);

  stream->flags &= ~EVCOM_PAUSED;

  if (READABLE(stream)) {
    ev_io_start(D_LOOP_(stream) &stream->read_watcher);
  }
}

int
evcom_stream_connect (evcom_stream *stream, struct sockaddr *address)
{
  int fd = socket(address->sa_family, SOCK_STREAM, 0);

  if (fd < 0) {
    evcom_perror("socket()", errno);
    return -1;
  }

  int r = set_nonblock(fd);
  if (r < 0) {
    stream->errorno = errno;
    evcom_perror("set_nonblock()", errno);
    close(fd);
    return -1;
  }

  r = connect(fd, address, address_length(address));

  if (r < 0 && errno != EINPROGRESS) {
    stream->errorno = errno;
    evcom_perror("connect", errno);
    close(fd);
    return -1;
  }

  assign_file_descriptor(stream, fd);

  return 0;
}

enum evcom_stream_state
evcom_stream_state (evcom_stream *stream)
{
  if (stream->fd < 0 && stream->flags == 0) return EVCOM_INITIALIZED;

  if (stream->fd < 0) return EVCOM_CLOSED;

  if (!CONNECTED(stream)) return EVCOM_CONNECTING;

  if (GOT_FULL_CLOSE(stream)) return EVCOM_CLOSING;

  if (GOT_HALF_CLOSE(stream)) {
    if (READABLE(stream)) {
      return EVCOM_CONNECTED_RO;
    } else {
      return EVCOM_CLOSING;
    }
  }

  if (READABLE(stream) && WRITABLE(stream)) return EVCOM_CONNECTED_RW;

  if (WRITABLE(stream)) return EVCOM_CONNECTED_WO;

  if (READABLE(stream)) return EVCOM_CONNECTED_RO;

  return EVCOM_CLOSING;
}

static int
reader_recv (evcom_descriptor *d)
{
  evcom_reader* reader = (evcom_reader*) d;

  char buf[EVCOM_CHUNKSIZE];
  size_t buf_size = EVCOM_CHUNKSIZE;
  ssize_t recved;

  while (reader->fd >= 0) {
    recved = read(reader->fd, buf, buf_size);

    if (recved < 0) {
      if (errno == EAGAIN || errno == EINTR) return AGAIN;
      reader->errorno = errno;
      evcom_perror("read()", reader->errorno);
      return close_asap(d);
    }

    /* NOTE: EOF is signaled with recved == 0 on callback */
    if (reader->on_read) reader->on_read(reader, buf, recved);

    if (recved == 0) return close_asap(d);
  }
  return AGAIN;
}

void
evcom_reader_init (evcom_reader *reader)
{
  evcom_descriptor_init((evcom_descriptor*)reader);

  reader->on_close = NULL;
  reader->on_read = NULL;

  ev_init(&reader->read_watcher, io_event);
  reader->read_watcher.data = reader;
}

void
evcom_reader_set (evcom_reader *reader, int fd)
{
  assert(fd >= 0);
  reader->fd = fd;

  ev_io_set(&reader->read_watcher, fd, EV_READ);
  reader->action = reader_recv;
}

void
evcom_reader_attach (EV_P_ evcom_reader *reader)
{
  ev_io_start(EV_A_ &reader->read_watcher);
  D_LOOP_SET(reader, EV_A);
}

void
evcom_reader_detach (evcom_reader *reader)
{
  ev_io_stop(D_LOOP_(reader) &reader->read_watcher);
  D_LOOP_SET(reader, NULL);
}

void
evcom_reader_close (evcom_reader *reader)
{
  ev_io_start(D_LOOP_(reader) &reader->read_watcher);
  ev_feed_event(D_LOOP_(reader) &reader->read_watcher, EV_READ);

  close_asap((evcom_descriptor*)reader);
}

static int
writer_send (evcom_descriptor *d)
{
  evcom_writer* writer = (evcom_writer*) d;
  assert(writer->fd >= 0);

  while (!evcom_queue_empty(&writer->out)) {
    evcom_queue *q = evcom_queue_last(&writer->out);
    evcom_buf *buf = evcom_queue_data(q, evcom_buf, queue);

    ssize_t sent = write(writer->fd, buf->base + buf->written,
        buf->len - buf->written);

    if (sent < 0) {
      switch (errno) {
        case ECONNRESET:
        case EPIPE:
          return close_writer_asap(writer);

        case EINTR:
        case EAGAIN:
          sent = 0;
          return AGAIN;

        default:
          writer->errorno = errno;
          evcom_perror("send()", writer->errorno);
          return close_writer_asap(writer);
      }
    }
    assert(sent >= 0);

    buf->written += sent;

    if (buf->written == buf->len) {
      evcom_queue_remove(q);
      if (buf->release) buf->release(buf);
    }
  }

  if (GOT_FULL_CLOSE(writer)) {
    assert(evcom_queue_empty(&writer->out));
    return close_writer_asap(writer);
  } else {
    ev_io_stop(D_LOOP_(writer) &writer->write_watcher);
    return AGAIN;
  }
}

void
evcom_writer_init (evcom_writer* writer)
{
  evcom_descriptor_init((evcom_descriptor*)writer);

  writer->on_close = NULL;

  ev_init(&writer->write_watcher, io_event);
  writer->write_watcher.data = writer;

  evcom_queue_init(&writer->out);
}

void
evcom_writer_set (evcom_writer* writer, int fd)
{
  assert(fd >= 0);
  writer->fd = fd;

  ev_io_set(&writer->write_watcher, fd, EV_WRITE);
  writer->action = writer_send;
}

void
evcom_writer_attach (EV_P_ evcom_writer* writer)
{
  if (!evcom_queue_empty(&writer->out)) {
    ev_io_start (EV_A_ &writer->write_watcher);
  }
  D_LOOP_SET(writer, EV_A);
}

void
evcom_writer_detach (evcom_writer* writer)
{
  ev_io_stop(D_LOOP_(writer) &writer->write_watcher);
  D_LOOP_SET(writer, NULL);
}

void
evcom_writer_write (evcom_writer* writer, const char* buf, size_t len)
{
  assert(writer->fd >= 0);

  ssize_t sent = 0;

  if (evcom_queue_empty(&writer->out)) {
    sent = write(writer->fd, buf, len);

    if (sent < 0) {
      switch (errno) {
        case ECONNRESET:
        case EPIPE:
          goto close;

        case EINTR:
        case EAGAIN:
          sent = 0;
          break;

        default:
          writer->errorno = errno;
          evcom_perror("send()", writer->errorno);
          goto close;
      }
    }
  } /* TODO else { memcpy to last buffer on head } */

  assert(sent >= 0);
  if ((size_t)sent == len) return; /* sent the whole buffer */

  len -= sent;
  buf += sent;

  evcom_buf *b = evcom_buf_new(buf, len);
  evcom_queue_insert_head(&writer->out, &b->queue);
  b->written = 0;

  assert(writer->fd >= 0);
  ev_io_start(D_LOOP_(writer) &writer->write_watcher);
  return;

close:
  close_writer_asap(writer);
}

void
evcom_writer_close (evcom_writer* writer)
{
  writer->flags |= EVCOM_GOT_FULL_CLOSE;
  if (evcom_queue_empty(&writer->out)) close_writer_asap(writer);
}
