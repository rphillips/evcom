#ifndef oi_h
#define oi_h

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ev.h>

#ifdef HAVE_GNUTLS
# include "oi_ssl_cache.h"
#endif

#define OI_MAX_CONNECTIONS 1024

/* socket state */
#define OI_CLOSED    0x01
#define OI_OPENING   0x02
#define OI_OPENED    0x04 
#define OI_CLOSING   0x08

typedef struct oi_buf    oi_buf;
typedef struct oi_server oi_server;
typedef struct oi_socket oi_socket;

void oi_server_init           (oi_server *, struct ev_loop *loop);
 int oi_server_listen_tcp     (oi_server *, int port);
 int oi_server_listen_unix    (oi_server *, char *filename);
void oi_server_attach         (oi_server *, struct ev_loop *loop);
void oi_server_detach         (oi_server *);
 int oi_server_set_secure     (oi_server *, const char *cert_file, const char *key_file, gnutls_x509_crt_fmt_t type);
void oi_server_close          (oi_server *); 

void oi_socket_init           (oi_socket *, float timeout);
void oi_socket_open_tcp       (oi_socket *, char *host, int port); 
void oi_socket_open_unix      (oi_socket *, char *socketfile);
void oi_socket_attach         (oi_socket *, struct ev_loop *loop);
void oi_socket_detach         (oi_socket *);
void oi_socket_read_stop      (oi_socket *); /* by default on_read will always read! */
void oi_socket_read_start     (oi_socket *); /* sockets otherwise are always reading */
void oi_socket_reset_timeout  (oi_socket *);
void oi_socket_schedule_close (oi_socket *); /* also disables on_read - on_close callback made later*/
void oi_socket_write          (oi_socket *, oi_buf *);

struct oi_server {
/* read only */
  int fd;
  struct sockaddr_in sockaddr;
  socklen_t socklen;
  char port[6];
  char *socketfile;
  struct ev_loop *loop;
  unsigned listening:1;
  unsigned secure:1;

/* private */
  ev_io connection_watcher;
  ev_io error_watcher;
#ifdef HAVE_GNUTLS
  gnutls_certificate_credentials_t credentials;
  oi_ssl_cache ssl_cache;
#endif

  /* public */
  oi_socket* (*on_connection) (oi_server *, struct sockaddr_in *, socklen_t);
  void       (*on_error)      (oi_server *);
  void *data;
};

struct oi_socket {
/* read only */
  int fd;
  struct sockaddr_in sockaddr;
  socklen_t socklen;
  struct ev_loop *loop;
  oi_server *server;
  char *ip;
  unsigned secure:1;
  oi_buf *write_buffer;
  size_t written;
  int state;

/* private */  
  ev_io error_watcher;
  ev_io write_watcher;
  ev_io read_watcher;
  ev_timer timeout_watcher;
#ifdef HAVE_GNUTLS
  gnutls_session_t session;
#endif
  
/* public */
  void (*on_connected) (oi_socket *);
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
