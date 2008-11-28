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

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# define GNUTLS_NEED_WRITE (gnutls_record_get_direction(socket->session) == 1)
# define GNUTLS_NEED_READ (gnutls_record_get_direction(socket->session) == 0)
#endif

#define OI_OKAY  0
#define OI_AGAIN 1
#define OI_ERROR 2 

#define MIN(a,b) (a < b ? a : b)

#define RAISE_OI_ERROR(s, code)     { if(s->on_error) { s->on_error(s, OI_ERROR_DOMAIN_OI    , code); } }
#define RAISE_SYSTEM_ERROR(s)       { if(s->on_error) { s->on_error(s, OI_ERROR_DOMAIN_SYSTEM, errno); } }
#define RAISE_GNUTLS_ERROR(s, code) { if(s->on_error) { s->on_error(s, OI_ERROR_DOMAIN_GNUTLS, code); } }

const char*
oi_strerror(int domain, int code)
{
  switch(domain) {
    case OI_ERROR_DOMAIN_OI:
      assert(0 && "no error codes in OI domain yet");
    case OI_ERROR_DOMAIN_SYSTEM:
      return (const char*)strerror(code);
    case OI_ERROR_DOMAIN_GNUTLS:
      return gnutls_strerror(code);
    default:
      assert(0 && "(unknown error domain)");
  }
}

static int 
full_close(oi_socket *socket)
{
  if(-1 == close(socket->fd) && errno == EINTR) {
    /* TODO fd still open. next loop call close again? */
    assert(0);  
  }

  socket->read_action = NULL;
  socket->write_action = NULL;

  /* TODO set timer to zero/idle watcher?  so we get a callback soon */
  return OI_OKAY;
}

static int 
half_close(oi_socket *socket)
{
  int r = shutdown(socket->fd, SHUT_WR);

  if(r == -1) {
    RAISE_SYSTEM_ERROR(socket);
    return OI_ERROR;
  }

  socket->write_action = NULL;

  /* TODO set timer to zero  so we get a callback soon */
  return OI_OKAY;
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
static int secure_socket_send(oi_socket *socket);
static int secure_socket_recv(oi_socket *socket);

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

static int
secure_handshake(oi_socket *socket)
{
  assert(socket->secure);

  int r = gnutls_handshake(socket->session);

  if(gnutls_error_is_fatal(r)) {
    RAISE_GNUTLS_ERROR(socket, r);
    return OI_ERROR;
  }

  if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
    return OI_AGAIN;

  oi_socket_reset_timeout(socket);

  if(!socket->connected && socket->on_connect)
    socket->on_connect(socket);
  socket->connected = TRUE;

  if(socket->read_action)
    socket->read_action = secure_socket_recv;
 
  if(socket->write_action)
    socket->write_action = secure_socket_send;

  return OI_OKAY;
}

static int
secure_socket_send(oi_socket *socket)
{
  ssize_t sent;
  oi_buf *to_write = socket->write_buffer;

  assert(socket->secure);

  if(to_write == NULL) {
    ev_io_stop(socket->loop, &socket->write_watcher);
    return OI_AGAIN;
  }

  sent = gnutls_record_send( socket->session
                           , to_write->base + to_write->written
                           , to_write->len - to_write->written
                           ); 

  if(gnutls_error_is_fatal(sent)) {
    RAISE_GNUTLS_ERROR(socket, sent);
    return OI_ERROR;
  }

  if(sent == 0)
    return OI_AGAIN;

  oi_socket_reset_timeout(socket);

  if(sent == GNUTLS_E_INTERRUPTED || sent == GNUTLS_E_AGAIN) {
    if(GNUTLS_NEED_READ) {
      if(socket->read_action) {
        socket->read_action = secure_socket_send;
      } else {
        /* GnuTLS needs read but already got EOF */
        RAISE_OI_ERROR(socket, OI_ERROR_NEEDS_READ_BUT_ALREADY_GOT_EOF);
        return OI_ERROR;
      }
    }
    return OI_AGAIN;
  }

  if(sent > 0) {
    /* make sure the callbacks are correct */
    if(socket->read_action)
      socket->read_action = secure_socket_recv;
    update_write_buffer_after_send(socket, sent);
    return OI_OKAY;
  }

  assert(0 && "Unhandled return code from gnutls_record_send()!");
  return OI_ERROR;
}

static int
secure_socket_recv(oi_socket *socket)
{
  char recv_buffer[TCP_MAXWIN];
  size_t recv_buffer_size = MIN(TCP_MAXWIN, socket->max_chunksize);
  ssize_t recved;

  assert(socket->secure);

  recved = gnutls_record_recv(socket->session, recv_buffer, recv_buffer_size);

  if(gnutls_error_is_fatal(recved)) {
    RAISE_GNUTLS_ERROR(socket, recved);
    return OI_ERROR;
  }

  if(recved == GNUTLS_E_INTERRUPTED || recved == GNUTLS_E_AGAIN)  {
    if(GNUTLS_NEED_WRITE) {
      if(socket->write_action) {
        socket->write_action = secure_socket_recv;
      } else {
        /* GnuTLS needs send but already closed write end */
        RAISE_OI_ERROR(socket, OI_ERROR_NEEDS_WRITE_BUT_CANNOT);
        return OI_ERROR;
      }
    }
    return OI_AGAIN;
  }

  oi_socket_reset_timeout(socket);

  /* A server may also receive GNUTLS_E_REHANDSHAKE when a client has
   * initiated a handshake. In that case the server can only initiate a
   * handshake or terminate the connection. */
  if(recved == GNUTLS_E_REHANDSHAKE) {
    if(socket->write_action) {
      socket->read_action = secure_handshake;
      socket->write_action = secure_handshake;
      return OI_OKAY;
    } else {
      RAISE_OI_ERROR(socket, OI_ERROR_NEEDS_WRITE_BUT_CANNOT);
      return OI_ERROR;
    }
  }

  if(recved >= 0) {
    /* Got EOF */
    if(recved == 0)
      socket->read_action = NULL;

    if(socket->write_action) 
      socket->write_action = secure_socket_send;

    if(socket->on_read) { socket->on_read(socket, recv_buffer, recved); }

    return OI_OKAY;
  }

  assert(0 && "Unhandled return code from gnutls_record_send()!");
  return OI_ERROR;
}

static int
secure_goodbye(oi_socket *socket, gnutls_close_request_t how)
{
  assert(socket->secure);

  int r = gnutls_bye(socket->session, how);

  if(gnutls_error_is_fatal(r))  {
    RAISE_GNUTLS_ERROR(socket, r);
    return OI_ERROR;
  }

  if(r == GNUTLS_E_INTERRUPTED || r == GNUTLS_E_AGAIN)
    return OI_AGAIN;

  return OI_OKAY;
}

static int
secure_full_goodbye(oi_socket *socket)
{
  int r = secure_goodbye(socket, GNUTLS_SHUT_RDWR);
  if(OI_OKAY == r) {
    return full_close(socket);
  }
  return r;
}

static int
secure_half_goodbye(oi_socket *socket)
{
  int r = secure_goodbye(socket, GNUTLS_SHUT_WR);
  if(OI_OKAY == r) {
    return half_close(socket);
  }
  return r;
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

static int
socket_send(oi_socket *socket)
{
  ssize_t sent;
  oi_buf *to_write = socket->write_buffer;

  assert(socket->secure == FALSE);

  if(!socket->connected) {
    if(socket->on_connect) { socket->on_connect(socket); }
    socket->connected = TRUE;
    return OI_OKAY;
  }

  if(to_write == NULL) {
    ev_io_stop(socket->loop, &socket->write_watcher);
    return OI_AGAIN;
  }

  
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
    switch(errno) {
      case EAGAIN:
        return OI_AGAIN;

      case ECONNRESET:
        socket->write_action = NULL;
        /* TODO maybe just clear write buffer instead of error? 
         * They should be able to read still from the socket. 
         */
        RAISE_SYSTEM_ERROR(socket);
        return OI_ERROR;

      default:
        perror("send()");
        assert(0 && "oi shouldn't let this happen.");
    }
  }

  oi_socket_reset_timeout(socket);
  update_write_buffer_after_send(socket, sent);

  return OI_OKAY;
}

static int
socket_recv(oi_socket *socket)
{
  char buf[TCP_MAXWIN];
  size_t buf_size = TCP_MAXWIN;
  ssize_t recved;

  assert(socket->secure == FALSE);

  if(!socket->connected) {
    if(socket->on_connect) { socket->on_connect(socket); }
    socket->connected = TRUE;
    return OI_OKAY;
  }

  recved = recv(socket->fd, buf, buf_size, 0);

  if(recved < 0) {
    switch(errno) {
      case EAGAIN: 
      case EINTR:  
        return OI_AGAIN;

      /* A remote host refused to allow the network connection (typically
       * because it is not running the requested service). */
      case ECONNREFUSED:
        RAISE_SYSTEM_ERROR(socket);
        return OI_ERROR; 

      default:
        perror("recv()");
        assert(0 && "recv returned error that oi should have caught before.");
    }
  }

  oi_socket_reset_timeout(socket);

  if(recved == 0) {
    oi_socket_read_stop(socket);
    socket->read_action = NULL;
  }

  /* NOTE: EOF is signaled with recved == 0 on callback */
  if(socket->on_read) { socket->on_read(socket, buf, recved); }

  return OI_OKAY;
}

static void
assign_file_descriptor(oi_socket *socket, int fd)
{
  socket->fd = fd;

  ev_io_set (&socket->read_watcher, fd, EV_ERROR | EV_READ);
  ev_io_set (&socket->write_watcher, fd, EV_ERROR | EV_WRITE);

  socket->read_action = socket_recv;
  socket->write_action = socket_send;

#ifdef HAVE_GNUTLS
  if(socket->secure) {
    gnutls_transport_set_lowat(socket->session, 0); 
    gnutls_transport_set_push_function(socket->session, nosigpipe_push);
    gnutls_transport_set_ptr2 ( socket->session
                 /* recv */   , (gnutls_transport_ptr_t)fd 
                 /* send */   , socket 
                              );
    socket->read_action = secure_handshake;
    socket->write_action = secure_handshake;
  }
#endif 
}


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
    close(fd);
    return;
  } 
  
  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if(r < 0) {
    /* TODO error report */
  }
  
#ifdef SO_NOSIGPIPE
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof(flags));
#endif

  socket->server = server;
  memcpy(&socket->remote_address, &address, addr_len);

  assign_file_descriptor(socket, fd);

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
    /* TODO error report */
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

/* Internal callback 
 * called by socket->timeout_watcher
 */
static void 
on_timeout(struct ev_loop *loop, ev_timer *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  assert(watcher == &socket->timeout_watcher);

 // printf("on_timeout\n");

  if(socket->on_timeout) { socket->on_timeout(socket); }


  /* TODD set timer to zero */
  full_close(socket);
}

static void
release_write_buffer(oi_socket *socket)
{
  while(socket->write_buffer) {
    oi_buf *buf = socket->write_buffer;
    socket->write_buffer = buf->next;
    if(buf->release) { buf->release(buf); }
  }
}

/* Internal callback. called by socket->read_watcher */
static void 
on_io_event(struct ev_loop *loop, ev_io *watcher, int revents)
{
  oi_socket *socket = watcher->data;

  if(revents & EV_ERROR) {
    RAISE_OI_ERROR(socket, OI_ERROR_UNKNOWN_LIBEV_ERROR);
    goto close;
  }

  int r;
  int have_read_event = TRUE;
  int have_write_event = TRUE;

  while(have_read_event || have_write_event) {

    if(socket->read_action) {
      r = socket->read_action(socket);
      if(r == OI_ERROR) goto close;
      if(r == OI_AGAIN) have_read_event = FALSE;
    } else {
      have_read_event = FALSE;
    }

    if(socket->write_action) {
      r = socket->write_action(socket);
      if(r == OI_ERROR) goto close;
      if(r == OI_AGAIN) have_write_event = FALSE;
    } else {
      have_write_event = FALSE;
    }

  }

  if(socket->write_action == NULL && socket->read_action == NULL)
    goto close;

  return;

close:
  release_write_buffer(socket);
  oi_socket_detach(socket);
  if(socket->on_close) { socket->on_close(socket); }
  /* WARNING: user can free socket in on_close so no more 
   * access beyond this point. */
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
  socket->connected = FALSE;

  ev_init (&socket->write_watcher, on_io_event);
  socket->write_watcher.data = socket;

  ev_init(&socket->read_watcher, on_io_event);
  socket->read_watcher.data = socket;

  socket->secure = FALSE;
  socket->wait_for_secure_hangup = FALSE;
#ifdef HAVE_GNUTLS
  socket->session = NULL;
#endif 

  /* TODO higher resolution timer */
  ev_timer_init(&socket->timeout_watcher, on_timeout, timeout, 0.);
  socket->timeout_watcher.data = socket;  

  socket->read_action = NULL;
  socket->write_action = NULL;

  socket->max_chunksize = TCP_MAXWIN; 
  socket->on_connect = NULL;
  socket->on_read = NULL;
  socket->on_drain = NULL;
  socket->on_error = NULL;
  socket->on_timeout = NULL;
}

void 
oi_socket_write_eof (oi_socket *socket)
{
  /* try to hang up properly for secure connections */
  if( socket->secure 
   && socket->connected /* completed handshake */ 
   && socket->write_action /* write end is open */
    ) 
  {
    socket->write_action = secure_half_goodbye;
    if(socket->loop)
      ev_io_start(socket->loop, &socket->write_watcher);
    return;
  }

  if(socket->write_action)
    half_close(socket);
  else
    full_close(socket);
}

void 
oi_socket_close (oi_socket *socket)
{
  /* try to hang up properly for secure connections */
  if( socket->secure 
   && socket->connected /* completed handshake */ 
   && socket->write_action /* write end is open */
    ) 
  {
    if(socket->wait_for_secure_hangup && socket->read_action) {
      socket->write_action = secure_full_goodbye;
      socket->read_action = secure_full_goodbye;
    } else {
      socket->write_action = secure_half_goodbye;
      socket->read_action = NULL;
    }

    if(socket->loop)
      ev_io_start(socket->loop, &socket->write_watcher);

    return;
  }

  full_close(socket);
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

  if(socket->write_action == NULL)
    return;

  /* ugly */
  if(socket->write_buffer == NULL) {
    socket->write_buffer = buf;
  } else {
    /* TODO O(N) should be O(1) */
    for(n = socket->write_buffer; n->next; n = n->next) {;} 
    n->next = buf;
  }

  buf->written = 0;
  buf->next = NULL;
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

  if(socket->read_action) 
    ev_io_start(loop, &socket->read_watcher);

  if(socket->write_action) 
    ev_io_start(loop, &socket->write_watcher);
}

void
oi_socket_detach(oi_socket *socket)
{
  ev_io_stop(socket->loop, &socket->write_watcher);
  ev_io_stop(socket->loop, &socket->read_watcher);
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
  if(socket->read_action) {
    ev_io_start(socket->loop, &socket->read_watcher);
  }
}

/* for now host is only allowed to be an IP address 
 * ie no dns lookup
 */
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
    /* TODO error report */
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

  assign_file_descriptor(s, fd);

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
    /* TODO error report */
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

  assign_file_descriptor(s, fd);

  return fd;
}

