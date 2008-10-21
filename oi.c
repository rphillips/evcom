#include <stdio.h>
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
# include "oi_ssl_cache.h"
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

/* Internal callback 
 * Called by server->connection_watcher.
 */
static void 
on_connection(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_server *server = watcher->data;

  printf("on connection!\n");

  assert(server->listening);
  assert(server->loop == loop);
  assert(&server->connection_watcher == watcher);
  
  if(EV_ERROR & revents) {
    oi_error("on_connection() got error event, closing server.");
    oi_server_close(server);
    return;
  }
  
  struct sockaddr_in addr; // connector's address information
  socklen_t addr_len = sizeof(addr); 
  int fd = accept(server->fd, (struct sockaddr*) & addr, & addr_len);
  if(fd < 0) {
    perror("accept()");
    return;
  }

  oi_socket *socket = NULL;
  if(server->on_connection)
    socket = server->on_connection(server, &addr, addr_len);

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
  socket->secure = server->secure;
  memcpy(&socket->sockaddr, &addr, addr_len);
  if(server->port[0] != '\0')
    socket->ip = inet_ntoa(socket->sockaddr.sin_addr);  

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
 */
int 
oi_server_listen_tcp(oi_server *server, const int port)
{
  int fd = -1;
  struct linger ling = {0, 0};
  struct sockaddr_in addr;
  int flags = 1;
  
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
  memset(&addr, 0, sizeof(addr));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind()");
    goto error;
  }
  
  int ret = listen_on_fd(server, fd);
  if (ret >= 0) {
    sprintf(server->port, "%d", port);
  }
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
    server->port[0] = '\0';
    server->listening = FALSE;
  }
}

#ifdef HAVE_GNUTLS
/* similar to server_init. 
 *
 * the user of secure server might want to set additional callbacks from
 * GNUTLS. In particular 
 * gnutls_global_set_mem_functions() 
 * gnutls_global_set_log_function()
 * Also see the note above oi_connection_init() about setting gnutls cache
 * access functions
 *
 * cert_file: the filename of a PEM certificate file
 *
 * key_file: the filename of a private key. Currently only PKCS-1 encoded
 * RSA and DSA private keys are accepted. 
 */
int 
oi_server_set_secure (server, cert_file, key_file, type)
  oi_server *server;
  const char *cert_file, *key_file;
  gnutls_x509_crt_fmt_t type;
{
  server->secure = TRUE;
  gnutls_global_init();
  gnutls_certificate_allocate_credentials(&server->credentials);
  /* todo gnutls_certificate_free_credentials */
  int r = gnutls_certificate_set_x509_key_file( server->credentials
                                              , cert_file
                                              , key_file
                                              , GNUTLS_X509_FMT_PEM
                                              );
  if(r < 0) {
    oi_error("loading certificates");
    return -1;
  }
  return 1;
}
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
  server->port[0] = '\0';
  server->fd = -1;
  server->connection_watcher.data = server;
  ev_init (&server->connection_watcher, on_connection);
  server->secure = FALSE;

#ifdef HAVE_GNUTLS
  oi_ssl_cache_init(&server->ssl_cache);
  server->credentials = NULL;
#endif

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

  printf("on_timeout\n");

  if(socket->on_timeout) {
    socket->on_timeout(socket);
    oi_socket_reset_timeout(socket);
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
    socket->on_error(socket);
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
    if(to_write->release)
      to_write->release(to_write);
    socket->write_buffer = to_write->next;
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

  assert(socket->secure == TRUE);
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
    if(gnutls_error_is_fatal(r))
      close_socket(socket);
    return;
  }
  socket->state = OI_OPENED;
  oi_socket_reset_timeout(socket);
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
      goto die;
    return;
  }

die:
  if(socket->session) 
    gnutls_deinit(socket->session);
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
  assert(socket->state == OI_OPENED);

  /* TODO use writev() here */
  sent = nosigpipe_push( (void*)socket->fd /* yes, funky. XXX */
                       , to_write->base + to_write->written
                       , to_write->len - to_write->written
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
  char recv_buffer[TCP_MAXWIN];
  size_t recv_buffer_size = TCP_MAXWIN;
  ssize_t recved;

  assert(socket->secure == FALSE);
  assert(socket->state == OI_OPENED);

  recved = recv(socket->fd, recv_buffer, recv_buffer_size, 0);

  if(recved < 0) goto error;
  if(recved == 0) goto error; /* XXX is this correct ? */

  oi_socket_reset_timeout(socket);

  if(socket->on_read) {
    socket->on_read(socket, recv_buffer, recved);
  }

  return;
error:
  oi_socket_schedule_close(socket);
}

/* Internal callback. called by socket->read_watcher */
static void 
on_readable(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  printf("on_readable\n");

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
  
  printf("on_writable\n");

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
  socket->write_buffer = NULL;
  socket->state = OI_CLOSED;
  socket->secure = FALSE;

  ev_init (&socket->write_watcher, on_writable);
  socket->write_watcher.data = socket;

  ev_init(&socket->read_watcher, on_readable);
  socket->read_watcher.data = socket;

  ev_init(&socket->error_watcher, on_error);
  socket->error_watcher.data = socket;

#ifdef HAVE_GNUTLS
  socket->session = NULL;
#endif /* HAVE_GNUTLS */

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

