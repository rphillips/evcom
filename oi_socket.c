#include <stdio.h>
#include <assert.h>
#include <unistd.h> /* close() */
#include <fcntl.h>  /* fcntl() */
#include <netinet/tcp.h> /* TCP_NODELAY */
#include <errno.h> /* for the default methods */
#include <string.h> /* memset */
#include <netinet/in.h>  /* inet_ntoa */
#include <arpa/inet.h>   /* inet_ntoa */

#include <ev.h>

#include "oi.h"
#include "oi_socket.h"

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# include "oi_ssl_cache.h"

# define GNUTLS_NEED_WRITE (gnutls_record_get_direction(socket->session) == 1)
# define GNUTLS_NEED_READ (gnutls_record_get_direction(socket->session) == 0)
#endif


static ssize_t 
nosigpipe_push(void *data, const void *buf, size_t len)
{
  int fd = (int)data;
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif
  return send(fd, buf, len, flags);
}

static void 
close_socket(oi_socket *socket)
{
#ifdef HAVE_GNUTLS
  if(socket->secure)
    ev_io_stop(socket->loop, &socket->handshake_watcher);
#endif
  ev_io_stop(socket->loop, &socket->error_watcher);
  ev_io_stop(socket->loop, &socket->read_watcher);
  ev_io_stop(socket->loop, &socket->write_watcher);
  ev_timer_stop(socket->loop, &socket->timeout_watcher);

  if(0 > close(socket->fd))
    oi_error("problem closing socket fd");

  socket->open = FALSE;

  if(socket->on_close)
    socket->on_close(socket);
  /* No access to the socket past this point! 
   * The user is allowed to free in the callback
   */
}

#ifdef HAVE_GNUTLS
static void 
on_handshake(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  printf("on_handshake\n");

  assert(ev_is_active(&socket->timeout_watcher));
  assert(!ev_is_active(&socket->read_watcher));
  assert(!ev_is_active(&socket->write_watcher));

  if(EV_ERROR & revents) {
    oi_error("on_handshake() got error event, closing socket.n");
    goto error;
  }

  int r = gnutls_handshake(socket->session);
  if(r < 0) {
    if(gnutls_error_is_fatal(r)) goto error;
    if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
      ev_io_set( watcher
               , socket->fd
               , EV_ERROR | (GNUTLS_NEED_WRITE ? EV_WRITE : EV_READ)
               );
    return;
  }

  oi_socket_reset_timeout(socket);
  ev_io_stop(loop, watcher);

  ev_io_start(loop, &socket->read_watcher);
  if(socket->write_buffer != NULL)
    ev_io_start(loop, &socket->write_watcher);

  return;
error:
  close_socket(socket);
}
#endif /* HAVE_GNUTLS */


/* Internal callback 
 * called by socket->timeout_watcher
 */
static void 
on_timeout(struct ev_loop *loop, ev_timer *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  assert(watcher == &socket->timeout_watcher);

  printf("on_timeout\n");

  if(socket->on_timeout) {
    socket->on_timeout(socket);
    oi_socket_reset_timeout(socket);
  }

  oi_socket_close(socket);
}

/* Internal callback 
 * called by socket->read_watcher
 */
static void 
on_readable(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  char recv_buffer[TCP_MAXWIN];
  size_t recv_buffer_size = TCP_MAXWIN;
  ssize_t recved;

  printf("on_readable\n");

  //assert(ev_is_active(&socket->timeout_watcher)); // TODO -- why is this broken?
  assert(watcher == &socket->read_watcher);
  assert(revents == EV_READ);

#ifdef HAVE_GNUTLS
  assert(!ev_is_active(&socket->handshake_watcher));

  if(socket->secure) {
    recved = gnutls_record_recv( socket->session
                               , recv_buffer
                               , recv_buffer_size
                               );
    if(recved <= 0) {
      if(gnutls_error_is_fatal(recved)) goto error;
      if( (recved == GNUTLS_E_INTERRUPTED || recved == GNUTLS_E_AGAIN)
       && GNUTLS_NEED_WRITE
        ) ev_io_start(loop, &socket->write_watcher);
      return; 
    } 
  } else {
#endif /* HAVE_GNUTLS */

    recved = recv(socket->fd, recv_buffer, recv_buffer_size, 0);
    if(recved < 0) goto error;
    if(recved == 0) goto error; /* XXX is this correct ? */

#ifdef HAVE_GNUTLS
  }
#endif 

  oi_socket_reset_timeout(socket);

  if(socket->on_read) {
    socket->on_read(socket, recv_buffer, recved);
  }

  return;
error:
  oi_socket_close(socket);
}

static void 
on_error(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  assert(watcher == &socket->write_watcher);
  assert(revents == EV_ERROR);

  oi_error("error on socket");
  if(socket->on_error) {
    socket->on_error(socket);
  }
  close_socket(socket);
}

/* Internal callback 
 * called by socket->write_watcher
 */
static void 
on_writable(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  ssize_t sent;
  
  printf("on_writable\n");

  oi_buf *to_write = socket->write_buffer;

  assert(revents == EV_WRITE);
  assert(to_write != NULL);
//  assert(ev_is_active(&socket->timeout_watcher)); // TODO -- why is this broken?
  assert(watcher == &socket->write_watcher);

#ifdef HAVE_GNUTLS
  assert(!ev_is_active(&socket->handshake_watcher));

  if(socket->secure) {
    sent = gnutls_record_send( socket->session
                             , to_write->base + to_write->written
                             , to_write->len - to_write->written
                             ); 
    if(sent <= 0) {
      if(gnutls_error_is_fatal(sent)) goto error;
      if( (sent == GNUTLS_E_INTERRUPTED || sent == GNUTLS_E_AGAIN)
       && GNUTLS_NEED_READ
        ) ev_io_stop(loop, watcher);
      return; 
    }
  } else {
#endif /* HAVE_GNUTLS */

    /* TODO use writev() here */
    sent = nosigpipe_push( (void*)socket->fd
                         , to_write->base + to_write->written
                         , to_write->len - to_write->written
                         );
    if(sent < 0) goto error;
    if(sent == 0) return;

#ifdef HAVE_GNUTLS
  }
#endif /* HAVE_GNUTLS */

  oi_socket_reset_timeout(socket);

  to_write->written += sent;
  socket->written += sent;

  if(to_write->written == to_write->len) {
    if(to_write->release)
      to_write->release(to_write);
    socket->write_buffer = to_write->next;
    if(socket->write_buffer == NULL) {
      ev_io_stop(loop, watcher);
      if(socket->on_drain)
        socket->on_drain(socket);
    }
  }
  return;
error:
  oi_error("close socket on write.");
  oi_socket_close(socket);
}

#ifdef HAVE_GNUTLS
static void 
on_goodbye_tls(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  assert(watcher == &socket->goodbye_tls_watcher);

  if(EV_ERROR & revents) {
    oi_error("on_goodbye() got error event, closing socket.");
    goto die;
  }

  int r = gnutls_bye(socket->session, GNUTLS_SHUT_RDWR);
  if(r < 0) {
    if(gnutls_error_is_fatal(r)) goto die;
    if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
      ev_io_set( watcher
               , socket->fd
               , EV_ERROR | (GNUTLS_NEED_WRITE ? EV_WRITE : EV_READ)
               );
    return;
  }

die:
  ev_io_stop(loop, watcher);
  if(socket->session) 
    gnutls_deinit(socket->session);
  close_socket(socket);
}
#endif /* HAVE_GNUTLS*/

static void 
on_goodbye(struct ev_loop *loop, ev_timer *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  assert(watcher == &socket->goodbye_watcher);
  close_socket(socket);
}

/**
 * If using SSL do consider setting
 *   gnutls_db_set_retrieve_function (socket->session, _);
 *   gnutls_db_set_remove_function (socket->session, _);
 *   gnutls_db_set_store_function (socket->session, _);
 *   gnutls_db_set_ptr (socket->session, _);
 * To provide a better means of storing SSL session caches. libebb provides
 * only a simple default implementation. 
 */
void 
oi_socket_init(oi_socket *socket, float timeout)
{
  socket->fd = -1;
  socket->server = NULL;
  socket->loop = NULL;
  socket->ip = NULL;
  socket->open = FALSE;

  ev_init (&socket->write_watcher, on_writable);
  socket->write_watcher.data = socket;
  socket->write_buffer = NULL;

  ev_init(&socket->read_watcher, on_readable);
  socket->read_watcher.data = socket;

  ev_init(&socket->error_watcher, on_error);
  socket->error_watcher.data = socket;

#ifdef HAVE_GNUTLS
  socket->handshake_watcher.data = socket;
  ev_init(&socket->handshake_watcher, on_handshake);

  ev_init(&socket->goodbye_tls_watcher, on_goodbye_tls);
  socket->goodbye_tls_watcher.data = socket;

  socket->session = NULL;
#endif /* HAVE_GNUTLS */

  ev_timer_init(&socket->goodbye_watcher, on_goodbye, 0., 0.);
  socket->goodbye_watcher.data = socket;  

  ev_timer_init(&socket->timeout_watcher, on_timeout, timeout, 0.);
  socket->timeout_watcher.data = socket;  

  socket->on_connected = NULL;
  socket->on_read = NULL;
  socket->on_drain = NULL;
  socket->on_error = NULL;
  socket->on_timeout = NULL;
  socket->data = NULL;
}

void 
oi_socket_close (oi_socket *socket)
{
  ev_io_stop(socket->loop, &socket->read_watcher);
  ev_io_stop(socket->loop, &socket->write_watcher);
  ev_io_stop(socket->loop, &socket->error_watcher);
  ev_timer_stop(socket->loop, &socket->timeout_watcher);
  /* If using SSL attempt to close the socket properly
   * this may require exchanging more data.
   */
#ifdef HAVE_GNUTLS
  if(socket->secure) {
    ev_io_stop(socket->loop, &socket->handshake_watcher);
    ev_io_set(&socket->goodbye_tls_watcher, socket->fd, EV_ERROR | EV_READ | EV_WRITE);
    ev_io_start(socket->loop, &socket->goodbye_tls_watcher);
    return;
  }  
#endif
  ev_timer_start(socket->loop, &socket->goodbye_watcher);
}

/* 
 * Resets the timeout to stay alive for another socket->timeout seconds
 */
void 
oi_socket_reset_timeout(oi_socket *socket)
{
  ev_timer_again(socket->loop, &socket->timeout_watcher);
}

/**
 * Writes a string to the socket. This is actually sets a watcher
 * which may take multiple iterations to write the entire string.
 *
 * This can only be called once at a time. If you call it again
 * while the socket is writing another buffer the oi_socket_write
 * will return FALSE and ignore the request.
 */
void 
oi_socket_write(oi_socket *socket, oi_buf *buf)
{
  oi_buf *n;

  /* ugly */
  if(socket->write_buffer == NULL) {
    socket->write_buffer = buf;
  } else {
    for(n = socket->write_buffer; n->next; n = n->next) {;} /* TODO O(N) should be O(C) */
    n->next = buf;
  }


  buf->written = 0;
  buf->next = NULL;
  /* TODO if handshaking do not start write_watcher */
  if(socket->write_buffer == buf)
    ev_io_start(socket->loop, &socket->write_watcher);
}

void
oi_socket_attach(oi_socket *socket, struct ev_loop *loop)
{
  socket->loop = loop;
  ev_timer_start(loop, &socket->timeout_watcher);
  ev_io_start(loop, &socket->error_watcher);
#ifdef HAVE_GNUTLS
  if(socket->secure) {
    ev_io_start(loop, &socket->handshake_watcher);
    return;
  }
#endif
  ev_io_start(loop, &socket->read_watcher);
}

void
oi_socket_init_peer(oi_socket *socket, oi_server *server, 
    int fd, struct sockaddr_in *addr, socklen_t addr_len)
{
  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    oi_error("error setting peer socket non-blocking");
  }

  socket->fd = fd;
  socket->open = TRUE;
  socket->server = server;
  socket->secure = server->secure;
  memcpy(&socket->sockaddr, &addr, addr_len);
  if(server->port[0] != '\0')
    socket->ip = inet_ntoa(socket->sockaddr.sin_addr);  

#ifdef SO_NOSIGPIPE
  int arg = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &arg, sizeof(int));
#endif

#ifdef HAVE_GNUTLS
  if(socket->secure) {
    gnutls_init(&socket->session, GNUTLS_SERVER);
    gnutls_transport_set_lowat(socket->session, 0); 
    gnutls_set_default_priority(socket->session);
    gnutls_credentials_set(socket->session, GNUTLS_CRD_CERTIFICATE, socket->server->credentials);

    gnutls_transport_set_ptr(socket->session, (gnutls_transport_ptr) fd); 
    gnutls_transport_set_push_function(socket->session, nosigpipe_push);

    oi_ssl_cache_session(&server->ssl_cache, socket->session);
  }

  ev_io_set(&socket->handshake_watcher, fd, EV_READ | EV_WRITE | EV_ERROR);
#endif /* HAVE_GNUTLS */

  ev_io_set(&socket->write_watcher, fd, EV_WRITE);
  ev_io_set(&socket->read_watcher, fd, EV_READ);
  ev_io_set(&socket->error_watcher, fd, EV_ERROR);
}
