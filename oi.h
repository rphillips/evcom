#ifndef oi_h
#define oi_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ev.h>

#ifdef HAVE_GNUTLS
# include "oi_ssl_cache.h"
#endif

/* socket state */
#define OI_CLOSED    1
#define OI_OPENING   2
#define OI_OPENED    3 
#define OI_CLOSING   4

typedef struct oi_buf     oi_buf;
typedef struct oi_server  oi_server;
typedef struct oi_socket  oi_socket;

void oi_server_init           (oi_server *, int max_connections);
 int oi_server_listen_tcp     (oi_server *, const char *host, int port);
 int oi_server_listen_unix    (oi_server *, const char *socketfile, int access_mask);
void oi_server_attach         (oi_server *, struct ev_loop *loop);
void oi_server_detach         (oi_server *);
void oi_server_close          (oi_server *); 
#ifdef HAVE_GNUTLS
 int oi_server_set_secure     (oi_server *, const char *cert_file, const char *key_file);
#endif 

void oi_socket_init           (oi_socket *, float timeout);
 int oi_socket_open_tcp       (oi_socket *, const char *host, int port); 
 int oi_socket_open_unix      (oi_socket *, const char *socketfile);
// int oi_socket_open_pair      (oi_socket *a, oi_socket *b);
void oi_socket_attach         (oi_socket *, struct ev_loop *loop);
void oi_socket_detach         (oi_socket *);
void oi_socket_read_stop      (oi_socket *);
void oi_socket_read_start     (oi_socket *);
void oi_socket_reset_timeout  (oi_socket *);
void oi_socket_schedule_close (oi_socket *);
void oi_socket_write          (oi_socket *, oi_buf *);
void oi_socket_write_simple   (oi_socket *, const char *str, size_t len);

union oi_address {
  struct sockaddr_un un;
  struct sockaddr_in in;
};

struct oi_server {
/* read only */
  int fd;
  int max_connections;
  struct ev_loop *loop;
  unsigned secure:1;
  unsigned listening:1;
  union oi_address address;

/* private */
  ev_io connection_watcher;
  ev_io error_watcher;
#ifdef HAVE_GNUTLS
  gnutls_certificate_credentials_t credentials;
  oi_ssl_cache ssl_cache;
#endif

/* public */
  oi_socket* (*on_connection) (oi_server *, struct sockaddr *, socklen_t);
  void       (*on_error)      (oi_server *);
  void *data;
};

struct oi_socket {
/* read only */
  int fd;
  int state;
  unsigned secure:1;
  struct ev_loop *loop;
  oi_server *server;
  oi_buf *write_buffer;
  size_t written;

  union oi_address remote_address;
  union oi_address local_address;

/* private */  
  ev_io error_watcher;
  ev_io write_watcher;
  ev_io read_watcher;
  ev_timer timeout_watcher;
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
