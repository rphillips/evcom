#include <netdb.h>
#include <ev.h>
#include <oi_queue.h>
#include <oi_buf.h>

#ifndef oi_socket_h
#define oi_socket_h
#ifdef __cplusplus
extern "C" {
#endif 

#ifndef HAVE_GNUTLS
# define HAVE_GNUTLS 0
#endif
#if HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

typedef struct oi_server  oi_server;
typedef struct oi_socket  oi_socket;

void oi_server_init          (oi_server *, int backlog);
 int oi_server_listen        (oi_server *, struct addrinfo *addrinfo);
void oi_server_attach        (EV_P_ oi_server *);
void oi_server_detach        (oi_server *);
void oi_server_close         (oi_server *); 

void oi_socket_init          (oi_socket *, float timeout);
 int oi_socket_connect       (oi_socket *, struct addrinfo *addrinfo);
void oi_socket_attach        (EV_P_ oi_socket *);
void oi_socket_detach        (oi_socket *);
void oi_socket_read_start    (oi_socket *);
void oi_socket_read_stop     (oi_socket *);

/* Resets the timeout to stay alive for another socket->timeout seconds
 */
void oi_socket_reset_timeout (oi_socket *);

/* Writes a buffer to the socket. 
 * (Do not send a NULL oi_buf or a buffer with oi_buf->base == NULL.)
 */
void oi_socket_write         (oi_socket *, oi_buf *);

void oi_socket_write_simple  (oi_socket *, const char *str, size_t len);

/* Once the write buffer is drained, oi_socket_close will shutdown the
 * writing end of the socket and will close the read end once the server
 * replies with an EOF. 
 */
void oi_socket_close         (oi_socket *);

/* Do not wait for the server to reply with EOF.  This will only be called
 * once the write buffer is drained.  
 * Warning: For TCP socket, the OS kernel may (should) reply with RST
 * packets if this is called when data is still being received from the
 * server.
 */
void oi_socket_full_close    (oi_socket *);

/* The most extreme measure. 
 * Will not wait for the write queue to complete. 
 */
void oi_socket_force_close (oi_socket *);


#if HAVE_GNUTLS
/* Tells the socket to use transport layer security (SSL). oi_socket does
 * not want to make any decisions about security requirements, so the
 * majoirty of GnuTLS configuration is left to the user. Only the transport
 * layer of GnuTLS is controlled by oi_socket. That is, do not use
 * gnutls_transport_* functions.  Do use the rest of GnuTLS's API.
 */
void oi_socket_set_secure_session (oi_socket *, gnutls_session_t);
#endif

struct oi_server {
  /* read only */
  int fd;
  int backlog;
#if EV_MULTIPLICITY
  struct ev_loop *loop;
#endif
  unsigned attached:1;
  unsigned listening:1;

  /* private */
  ev_io connection_watcher;

  /* public */
  oi_socket* (*on_connection) (oi_server *, struct sockaddr *remote_addr, socklen_t remove_addr_len);
  void       (*on_error)      (oi_server *);
  void *data;
};

struct oi_socket {
  /* read only */
  int fd;
#if EV_MULTIPLICITY
  struct ev_loop *loop;
#endif
  oi_server *server;
  oi_queue out_stream;
  size_t written;
  unsigned attached:1;
  unsigned connected:1;
  unsigned secure:1;
  unsigned got_full_close:1;
  unsigned got_half_close:1;

  /* NULL = that end of the socket is closed. */
  int (*read_action)  (oi_socket *);
  int (*write_action) (oi_socket *);

  /* ERROR CODES. 0 = no error. Check on_close. */
  int errorno; 
#if HAVE_GNUTLS
  int gnutls_errorno;
#endif

  /* private */  
  ev_io write_watcher;
  ev_io read_watcher;
  ev_timer timeout_watcher;
#if HAVE_GNUTLS
  gnutls_session_t session;
#endif
  
  /* public */
  size_t chunksize; /* the maximum chunk that on_read() will return */
  void (*on_connect)   (oi_socket *);
  void (*on_read)      (oi_socket *, const void *buf, size_t count);
  void (*on_drain)     (oi_socket *);
  void (*on_close)     (oi_socket *);
  void (*on_timeout)   (oi_socket *);
  void *data;
};

#ifdef __cplusplus
}
#endif 
#endif /* oi_socket_h */
