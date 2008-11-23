#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h> /* close() */
#include <fcntl.h>  /* fcntl() */
#include <errno.h> /* for the default methods */
#include <string.h> /* memset */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> /* TCP_NODELAY */
#include <arpa/inet.h>


#include "oi.h"
 
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

#define oi_error(FORMAT, ...) fprintf(stderr, "error: " FORMAT "\n", ##__VA_ARGS__)

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# define GNUTLS_NEED_WRITE (gnutls_record_get_direction(socket->session) == 1)
# define GNUTLS_NEED_READ (gnutls_record_get_direction(socket->session) == 0)
# define GNUTLS_SET_DIRECTION(socket)                       \
{                                                           \
      if(GNUTLS_NEED_WRITE) {                               \
        ev_io_start (socket->loop, &socket->write_watcher); \
        ev_io_stop  (socket->loop, &socket->read_watcher ); \
      } else {                                              \
        ev_io_start (socket->loop, &socket->read_watcher ); \
        ev_io_stop  (socket->loop, &socket->write_watcher); \
      }                                                     \
}             

#endif

#define is_inet_address(address) (address.in.sun_family == AF_INET)


#ifdef HAVE_GNUTLS
static ssize_t 
nosigpipe_push(gnutls_transport_ptr_t data, const void *buf, size_t len)
{
  oi_socket *socket = (oi_socket*)data;
  assert(socket->secure);
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif
  int r = send(socket->fd, buf, len, flags);

  if(r == -1) {
    /* necessary ? */
    gnutls_transport_set_errno(socket->session, errno);
  }

  return r;
}

static void
set_transport_gnutls(oi_socket *socket)
{
  assert(socket->secure);
  gnutls_transport_set_lowat(socket->session, 0); 
  gnutls_transport_set_push_function(socket->session, nosigpipe_push);
  gnutls_transport_set_ptr2 ( socket->session
                            , (gnutls_transport_ptr_t)socket->fd /*recv*/
                            , socket /* send */
                            );
}

/* Tells the socket to use transport layer security (SSL). liboi does not
 * want to make any decisions about security requirements, so the
 * majoirty of GnuTLS configuration is left to the user. Only the transport
 * layer of GnuTLS is controlled by liboi.
 *
 * That is, do not use gnutls_transport_* functions. 
 * Do use the rest of GnuTLS's API.
 */
void
oi_socket_set_secure_session (oi_socket *socket, gnutls_session_t session)
{
  socket->session = session;
  socket->secure = TRUE;
}
#endif /* HAVE GNUTLS */


/* Internal callback 
 * Called by server->connection_watcher.
 */
static void 
on_connection(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_server *server = watcher->data;

 // printf("on connection!\n");

  assert(server->listening);
  assert(server->loop == loop);
  assert(&server->connection_watcher == watcher);
  
  if(EV_ERROR & revents) {
    oi_error("on_connection() got error event, closing server.");
    oi_server_close(server);
    return;
  }
  
  union oi_address address; /* connector's address information */
  socklen_t addr_len = sizeof(address);
  
  /* TODO accept all possible connections? currently: just one */
  int fd = accept(server->fd, (struct sockaddr*) &address, &addr_len);
  if(fd < 0) {
    perror("accept()");
    return;
  }

  oi_socket *socket = NULL;
  if(server->on_connection)
    socket = server->on_connection(server, (struct sockaddr*)&address, addr_len);

  if(socket == NULL) {
    oi_error("problem getting peer socket");
    close(fd);
    return;
  } 
  
  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    oi_error("error setting peer socket non-blocking");
  }
  
#ifdef SO_NOSIGPIPE
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof(flags));
#endif

  socket->fd = fd;
  socket->state = OI_OPENING;
  socket->server = server;
  memcpy(&socket->remote_address, &address, addr_len);

#ifdef HAVE_GNUTLS
  if(socket->secure) {
    set_transport_gnutls(socket);
  }
#endif /* HAVE_GNUTLS */

  ev_io_set(&socket->write_watcher, fd, EV_WRITE);
  ev_io_set(&socket->read_watcher,  fd, EV_READ);
  ev_io_set(&socket->error_watcher, fd, EV_ERROR);

  oi_socket_attach(socket, loop);
}

static int 
listen_on_fd(oi_server *server, const int fd)
{
  assert(server->listening == FALSE);

  if (listen(fd, server->max_connections) < 0) {
    perror("listen()");
    return -1;
  }
  

  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    oi_error("error setting server socket non-blocking");
  }
  
  server->fd = fd;
  server->listening = TRUE;
  
  ev_io_set (&server->connection_watcher, server->fd, EV_READ | EV_ERROR);
  
  return server->fd;
}


/**
 * Begin the server listening on a file descriptor This DOES NOT start the
 * event loop. Start the event loop after making this call.
 *
 * FIXME For now only listening on any address. the host arg is ignored.
 */
int 
oi_server_listen_tcp(oi_server *server, const char *host, int port)
{
  int fd = -1;
  struct linger ling = {0, 0};
  int flags = 1;
  int r;
  
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket()");
    goto error;
  }
  
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
  setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));

  /* XXX: Sending single byte chunks in a response body? Perhaps there is a
   * need to enable the Nagel algorithm dynamically. For now disabling.
   */
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
  
  /* the memset call clears nonstandard fields in some impementations that
   * otherwise mess things up.
   */
  memset(&server->address, 0, sizeof(union oi_address));
  
  server->address.in.sin_family = AF_INET;
  server->address.in.sin_port = htons(port);
  server->address.in.sin_addr.s_addr = htonl(INADDR_ANY);

  r = bind( fd
          , (struct sockaddr *)&server->address
          , sizeof(server->address.in)
          );
  if (r < 0) {
    perror("bind()");
    goto error;
  }
  
  int ret = listen_on_fd(server, fd);
  return ret;
error:
  if(fd > 0) close(fd);
  return -1;
}

/* access mask = 0700 */
int
oi_server_listen_unix (oi_server *server, const char *socketfile, int access_mask)
{
  int fd = -1;
  struct linger ling = {0, 0};
  int flags = 1;
  int r;
  struct stat tstat;
  int old_umask;
  
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket()");
    return -1;
  }
  
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
  setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));

  /* the memset call clears nonstandard fields in some impementations that
   * otherwise mess things up.
   */
  memset(&server->address, 0, sizeof(union oi_address));
  
  /* FIXME 
   * current: delete the socket if it exists already 
   * want: return -1 if file exists or not writable. let the app decide this
   * one
   * also: FIXME BLOCKING
   */ 
  if (lstat(socketfile, &tstat) == 0) {
    if (S_ISSOCK(tstat.st_mode))
      unlink(socketfile);
  }
  
  server->address.un.sun_family = AF_UNIX;
  strcpy(server->address.un.sun_path, socketfile);

  old_umask=umask( ~(access_mask&0777)); /* FIXME BLOCKING */

  r = bind( fd
          , (struct sockaddr *)&server->address
          , sizeof(server->address.un)
          );

  umask(old_umask); /* FIXME BLOCKING */

  if (r < 0) {
    perror("bind()");
    goto error;
  }
  
  int ret = listen_on_fd(server, fd);
  return ret;
error:
  if(fd > 0) close(fd);
  return -1;
}


/**
 * Stops the server. Will not accept new connections.  Does not drop
 * existing connections.
 */
void 
oi_server_close(oi_server *server)
{
  if(server->listening) {
    oi_server_detach(server);
    close(server->fd);
    server->listening = FALSE;
  }
}

#ifdef HAVE_GNUTLS
#endif /* HAVE_GNUTLS */

void
oi_server_attach (oi_server *server, struct ev_loop *loop)
{
  ev_io_start (loop, &server->connection_watcher);
  server->loop = loop;
}

void
oi_server_detach (oi_server *server)
{
  ev_io_stop (server->loop, &server->connection_watcher);
  server->loop = NULL;
}

void 
oi_server_init(oi_server *server, int max_connections)
{
  server->max_connections = max_connections;
  server->listening = FALSE;
  server->fd = -1;
  server->connection_watcher.data = server;
  ev_init (&server->connection_watcher, on_connection);

  memset(&server->address, 0, sizeof(union oi_address));

  server->on_connection = NULL;
  server->on_error = NULL;
  server->data = NULL;
}

static void 
close_socket(oi_socket *socket)
{
  oi_socket_detach(socket);

  if(0 > close(socket->fd))
    oi_error("problem closing socket fd");

  socket->state = OI_CLOSED;

  if(socket->on_close)
    socket->on_close(socket);
  /* No access to the socket past this point! 
   * The user is allowed to free in the callback
   */
}

/* Internal callback 
 * called by socket->timeout_watcher
 */
static void 
on_timeout(struct ev_loop *loop, ev_timer *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  assert(watcher == &socket->timeout_watcher);

 // printf("on_timeout\n");

  if(socket->on_timeout) {
    socket->on_timeout(socket);
  }

  oi_socket_schedule_close(socket);
}

static void 
on_error(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  assert(watcher == &socket->write_watcher);
  assert(revents == EV_ERROR);

  oi_error("error on socket");
  if(socket->on_error) {
    socket->on_error(socket, OI_LOOP_ERROR, 0);
  }
  close_socket(socket);
}

static void
update_write_buffer_after_send(oi_socket *socket, ssize_t sent)
{
  oi_buf *to_write = socket->write_buffer;
  to_write->written += sent;
  socket->written += sent;

  if(to_write->written == to_write->len) {

    socket->write_buffer = to_write->next;

    if(to_write->release) {
      to_write->release(to_write);
    }  

    if(socket->write_buffer == NULL) {
      ev_io_stop(socket->loop, &socket->write_watcher);
      if(socket->on_drain)
        socket->on_drain(socket);
    }
  }
}

#ifdef HAVE_GNUTLS
static void
secure_socket_send(oi_socket *socket)
{
  ssize_t sent;
  oi_buf *to_write = socket->write_buffer;

  if(to_write == NULL) {
    ev_io_stop(socket->loop, &socket->write_watcher);
    return;
  }

  assert(socket->secure);
  assert(socket->state == OI_OPENED);

  sent = gnutls_record_send( socket->session
                           , to_write->base + to_write->written
                           , to_write->len - to_write->written
                           ); 
  if(sent <= 0) {
    if(gnutls_error_is_fatal(sent))  {
      oi_error("close socket on write.");
      oi_socket_schedule_close(socket);
    }
    if(sent == GNUTLS_E_INTERRUPTED || sent == GNUTLS_E_AGAIN)
      GNUTLS_SET_DIRECTION(socket);
    return; 
  }
  oi_socket_reset_timeout(socket);
  update_write_buffer_after_send(socket, sent);
}

static void
secure_socket_recv(oi_socket *socket)
{
  char recv_buffer[TCP_MAXWIN];
  size_t recv_buffer_size = TCP_MAXWIN;
  ssize_t recved;

  assert(socket->secure);
  assert(socket->state == OI_OPENED);

  recved = gnutls_record_recv(socket->session, recv_buffer, recv_buffer_size);
  if(recved <= 0) {
    if( gnutls_error_is_fatal(recved) ) 
      // TODO: on_error and close_socket()
      close_socket(socket);
    if( recved == GNUTLS_E_INTERRUPTED || recved == GNUTLS_E_AGAIN) 
      GNUTLS_SET_DIRECTION(socket);
    return; 
  }
  oi_socket_reset_timeout(socket);
  if(socket->on_read) {
    socket->on_read(socket, recv_buffer, recved);
  }
}

static void
secure_handshake(oi_socket *socket)
{
  assert(socket->secure);

  int r = gnutls_handshake(socket->session);
  if(r < 0) {
    if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
      GNUTLS_SET_DIRECTION(socket);
    if(gnutls_error_is_fatal(r)) {
      if(socket->on_error) {
        socket->on_error(socket, OI_HANDSHAKE_ERROR, r);
      }
      close_socket(socket);
    }
    return;
  }
  oi_socket_reset_timeout(socket);

  socket->state = OI_OPENED;
  if(socket->on_connect)
    socket->on_connect(socket);

  if(socket->write_buffer != NULL)
    ev_io_start(socket->loop, &socket->write_watcher);
}

static void
secure_goodbye(oi_socket *socket)
{
  assert(socket->secure);

  int r = gnutls_bye(socket->session, GNUTLS_SHUT_RDWR);
  if(r < 0) {
    if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
      GNUTLS_SET_DIRECTION(socket);
    if(gnutls_error_is_fatal(r)) 
      if(socket->on_error) {
        socket->on_error(socket, OI_BYE_ERROR, r);
      }
      goto die;
    return;
  }

die:
  close_socket(socket);
}
#endif /* HAVE_GNUTLS */

static void
socket_send(oi_socket *socket)
{
  ssize_t sent;
  oi_buf *to_write = socket->write_buffer;

  if(to_write == NULL) {
    ev_io_stop(socket->loop, &socket->write_watcher);
    return;
  }

  assert(socket->secure == FALSE);
  assert(socket->state == OI_OPENED || socket->state == OI_OPENING);
  
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif

  /* TODO use writev() here */
  sent = send( socket->fd
             , to_write->base + to_write->written
             , to_write->len - to_write->written
             , flags
             );

  if(sent < 0) {
    oi_error("close socket on write.");
    oi_socket_schedule_close(socket);
    return;
  }
  if(sent == 0) return; /* XXX is this the right action? */

  oi_socket_reset_timeout(socket);
  update_write_buffer_after_send(socket, sent);
}

static void
socket_recv(oi_socket *socket)
{
  char buf[TCP_MAXWIN];
  size_t buf_size = TCP_MAXWIN;
  ssize_t recved;

  assert(socket->secure == FALSE);
  assert(socket->state == OI_OPENED || socket->state == OI_OPENING);

  recved = recv(socket->fd, buf, buf_size, 0);

  if(recved < 0) {
    switch(errno) {
      case EAGAIN: return;
      default:
        perror("recv()");
        oi_socket_schedule_close(socket);
        return;
    }
  }
  if(recved == 0)  {
    /* TODO callback? for half-closed connections? */
    oi_socket_schedule_close(socket);
    return;
  }

  oi_socket_reset_timeout(socket);

  if(socket->on_read) {
    socket->on_read(socket, buf, recved);
  }
}

/* Internal callback. called by socket->read_watcher */
static void 
on_readable(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;

 // printf("on_readable\n");

  //assert(ev_is_active(&socket->timeout_watcher)); // TODO -- why is this broken?
  assert(watcher == &socket->read_watcher);
  assert(revents == EV_READ);

  if(socket->secure) {
    switch(socket->state) {
    case OI_OPENING: 
      secure_handshake(socket); 
      break;
    case OI_OPENED:    
      secure_socket_recv(socket);           
      break;
    case OI_CLOSING: 
      secure_goodbye(socket);   
      break;
    default: 
      assert(0 && "Should not recv data when the secure socket is OI_CLOSED");
    }
  } else {
    switch(socket->state) {
    case OI_OPENING: 
      socket->state = OI_OPENED;
      if(socket->on_connect)
        socket->on_connect(socket);
    case OI_OPENED:    
      socket_recv(socket);
      break;
    case OI_CLOSING: 
      close_socket(socket);
      break;
    default: 
      assert(0 && "Should not recv data when the socket is OI_CLOSED");
    }
  }
}

/* Internal callback. called by socket->write_watcher */
static void 
on_writable(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;
  
 // printf("on_writable\n");

  assert(revents == EV_WRITE);
//  assert(ev_is_active(&socket->timeout_watcher)); // TODO -- why is this broken?
  assert(watcher == &socket->write_watcher);

  if(socket->secure) {
    switch(socket->state) {
    case OI_OPENING: 
      secure_handshake(socket); 
      break;
    case OI_OPENED:    
      secure_socket_send(socket);           
      break;
    case OI_CLOSING: 
      secure_goodbye(socket);   
      break;
    default: 
      assert(0 && "Should not send data when the secure socket is OI_CLOSED");
    }
  } else {
    switch(socket->state) {
    case OI_OPENING: 
      socket->state = OI_OPENED;
      if(socket->on_connect)
        socket->on_connect(socket);
    case OI_OPENED:    
      socket_send(socket);
      break;
    case OI_CLOSING: 
      close_socket(socket);
      break;
    default: 
      assert(0 && "Should not send data when the socket is OI_CLOSED");
    }
  }
}

/**
 * If using SSL do consider setting
 *   gnutls_db_set_retrieve_function (socket->session, _);
 *   gnutls_db_set_remove_function (socket->session, _);
 *   gnutls_db_set_store_function (socket->session, _);
 *   gnutls_db_set_ptr (socket->session, _);
 */
void 
oi_socket_init(oi_socket *socket, float timeout)
{
  socket->fd = -1;
  socket->server = NULL;
  socket->loop = NULL;
  socket->write_buffer = NULL;
  socket->state = OI_CLOSED;

  ev_init (&socket->write_watcher, on_writable);
  socket->write_watcher.data = socket;

  ev_init(&socket->read_watcher, on_readable);
  socket->read_watcher.data = socket;

  ev_init(&socket->error_watcher, on_error);
  socket->error_watcher.data = socket;

  socket->secure = FALSE;
#ifdef HAVE_GNUTLS
  socket->session = NULL;
#endif 

  ev_timer_init(&socket->timeout_watcher, on_timeout, timeout, 0.);
  socket->timeout_watcher.data = socket;  

  socket->on_connect = NULL;
  socket->on_read = NULL;
  socket->on_drain = NULL;
  socket->on_error = NULL;
  socket->on_timeout = NULL;
}

void 
oi_socket_schedule_close (oi_socket *socket)
{
  socket->state = OI_CLOSING;
  /* cannot simply call close_socket() here because that would 
   * invoke the socket->on_close() which may free the socket.
   * instead we must return the event loop and close on the 
   * next cycle. If the socket is secure, we have to do the
   * goodbye exchange.
   */
  ev_feed_event(socket->loop, &socket->write_watcher, EV_WRITE);
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
 * Writes a string to the socket. This is actually sets a watcher which may
 * take multiple iterations to write the entire string.
 */
void 
oi_socket_write(oi_socket *socket, oi_buf *buf)
{
  oi_buf *n;

  /* ugly */
  if(socket->write_buffer == NULL) {
    socket->write_buffer = buf;
  } else {
    for(n = socket->write_buffer; n->next; n = n->next) {;} /* TODO O(N) should be O(1) */
    n->next = buf;
  }

  buf->written = 0;
  buf->next = NULL;
  if(socket->state == OI_OPENED)
    ev_io_start(socket->loop, &socket->write_watcher);
}

/* Writes a string to the socket. 
 * NOTE: Allocates memory. Avoid for performance applications.
 */ 
void
oi_socket_write_simple(oi_socket *socket, const char *str, size_t len)
{
  oi_buf *buf = malloc(sizeof(oi_buf));
  buf->release = (void (*)(oi_buf*))free;
  buf->base = strdup(str);
  buf->len = len;

  oi_socket_write(socket, buf);
}

void
oi_socket_attach(oi_socket *socket, struct ev_loop *loop)
{
  socket->loop = loop;
  ev_timer_start(loop, &socket->timeout_watcher);
  ev_io_start(loop, &socket->error_watcher);
  ev_io_start(loop, &socket->read_watcher);
  ev_io_start(loop, &socket->write_watcher);
}

void
oi_socket_detach(oi_socket *socket)
{
  ev_io_stop(socket->loop, &socket->write_watcher);
  ev_io_stop(socket->loop, &socket->read_watcher);
  ev_io_stop(socket->loop, &socket->error_watcher);
  ev_timer_stop(socket->loop, &socket->timeout_watcher);
  socket->loop = NULL;
}

void
oi_socket_read_stop (oi_socket *socket)
{
  ev_io_stop(socket->loop, &socket->read_watcher);
}

void
oi_socket_read_start (oi_socket *socket)
{
  ev_io_start(socket->loop, &socket->read_watcher);
}

/* for now host is only allowed to be an IP address */
int
oi_socket_open_tcp (oi_socket *s, const char *host, int port)
{
  int fd;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    return -1;
  }

  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    oi_error("error setting peer socket non-blocking");
    return r;
  }

#ifdef SO_NOSIGPIPE
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof(flags));
#endif
  
  memset(&s->remote_address, 0, sizeof(union oi_address));

  s->remote_address.in.sin_family = AF_INET;
  s->remote_address.in.sin_port = htons(port);
  s->remote_address.in.sin_addr.s_addr = inet_addr(host);

  r = connect( fd
             , (struct sockaddr*)&s->remote_address.in
             , sizeof s->remote_address.in
             );

  if(r < 0 && errno != EINPROGRESS) {
    perror("connect");
    close(fd);
    return fd;
  }

  s->fd = fd;
  s->state = OI_OPENING;

  ev_io_set (&s->read_watcher, fd, EV_READ);
  ev_io_set (&s->write_watcher, fd, EV_WRITE);
  ev_io_set (&s->error_watcher, fd, EV_ERROR);

  if(s->secure) {
    set_transport_gnutls(s);
  }

  return fd;
}

int
oi_socket_open_unix (oi_socket *s, const char *socketfile)
{
  int fd;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    return -1;
  }

  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    oi_error("error setting peer socket non-blocking");
    return r;
  }

#ifdef SO_NOSIGPIPE
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof(flags));
#endif
  
  memset(&s->remote_address, 0, sizeof(union oi_address));

  s->remote_address.un.sun_family = AF_UNIX;
  strcpy(s->remote_address.un.sun_path, socketfile);

  r = connect( fd
             , (struct sockaddr*)&s->remote_address.un
             , sizeof s->remote_address.un
             );

  if(r < 0 && errno != EINPROGRESS) {
    perror("connect");
    close(fd);
    return fd;
  }

  s->fd = fd;
  s->state = OI_OPENING;

  ev_io_set (&s->read_watcher, fd, EV_READ);
  ev_io_set (&s->write_watcher, fd, EV_WRITE);
  ev_io_set (&s->error_watcher, fd, EV_ERROR);

  if(s->secure) {
    set_transport_gnutls(s);
  }

  return fd;
}

int
oi_socket_open_pair (oi_socket *a, oi_socket *b)
{
  /* TODO */
  return -1;
}

