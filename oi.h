#ifndef oi_h
#define oi_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ev.h>
#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#define OI_OKAY    0
#define OI_AGAIN   1
#define OI_ERROR   2 

typedef struct oi_buf     oi_buf;
typedef struct oi_server  oi_server;
typedef struct oi_socket  oi_socket;

void oi_server_init               (oi_server *, int max_connections);
 int oi_server_listen_tcp         (oi_server *, const char *host, int port);
 int oi_server_listen_unix        (oi_server *, const char *socketfile, int access_mask);
void oi_server_attach             (oi_server *, struct ev_loop *loop);
void oi_server_detach             (oi_server *);
void oi_server_close              (oi_server *); 

void oi_socket_init               (oi_socket *, float timeout);
// TODO
// int oi_socket_open_stdio         (oi_socket *); 
// int oi_socket_open_stderr        (oi_socket *); 
// int oi_socket_open_pair       (oi_socket *a, oi_socket *b);
 int oi_socket_open_tcp           (oi_socket *, const char *host, int port); 
 int oi_socket_open_unix          (oi_socket *, const char *socketfile);
void oi_socket_attach             (oi_socket *, struct ev_loop *loop);
void oi_socket_detach             (oi_socket *);
void oi_socket_read_stop          (oi_socket *);
void oi_socket_read_start         (oi_socket *); /* TODO set chunksize */
void oi_socket_reset_timeout      (oi_socket *);
void oi_socket_write              (oi_socket *, oi_buf *);
void oi_socket_write_simple       (oi_socket *, const char *str, size_t len);
void oi_socket_close              (oi_socket *);
#ifdef HAVE_GNUTLS
void oi_socket_set_secure_session (oi_socket *, gnutls_session_t);
#endif 

union oi_address {
  struct sockaddr_un un;
  struct sockaddr_in in;
};

struct oi_server {
/* read only */
  int fd;
  int max_connections;
  struct ev_loop *loop;
  unsigned listening:1;
  union oi_address address;

/* private */
  ev_io connection_watcher;

/* public */
  oi_socket* (*on_connection) (oi_server *, struct sockaddr *, socklen_t);
  void       (*on_error)      (oi_server *);
  void *data;
};

struct oi_socket {
/* read only */
  int fd;
  struct ev_loop *loop;
  oi_server *server;
  oi_buf *write_buffer;
  size_t written;

  unsigned connected:1;

  /* if these are NULL then it means that end of the socket is closed. */
  int (*read_action)  (oi_socket *);
  int (*write_action) (oi_socket *);

  union oi_address remote_address;
  union oi_address local_address;

/* private */  
  ev_io write_watcher;
  ev_io read_watcher;
  ev_timer timeout_watcher;

  unsigned secure:1;
  unsigned wait_for_secure_hangup:1;
#ifdef HAVE_GNUTLS
  gnutls_session_t session;
#endif
  
/* public */
  void (*on_connect)   (oi_socket *);
  void (*on_read)      (oi_socket *, const void *buf, size_t count);
  void (*on_drain)     (oi_socket *);
  void (*on_error)     (oi_socket *);
  void (*on_close)     (oi_socket *);
  void (*on_timeout)   (oi_socket *);
  void *data;
};

struct oi_buf {
/* private */
  size_t written;
  oi_buf *next;

/* public */
  const void *base;
  size_t len;
  void (*release) (oi_buf *); /* called when oi_socket is done with the object */
  void *data;
};

#endif /* oi_h */
