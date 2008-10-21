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
#define oi_error(FORMAT, ...) fprintf(stderr, "error: " FORMAT "\n", ##__VA_ARGS__)
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif 
#ifndef MIN
# define MIN(a,b) (a < b ? a : b)
#endif

typedef struct oi_buf        oi_buf;
typedef struct oi_server     oi_server;
typedef struct oi_socket     oi_socket;

void oi_server_init        (oi_server *, struct ev_loop *loop);
 int oi_server_set_secure  (oi_server *, const char *cert_file, const char *key_file, gnutls_x509_crt_fmt_t type);
 int oi_server_listen_tcp  (oi_server *, int port);
 int oi_server_listen_unix (oi_server *, char *filename);
void oi_server_close       (oi_server *); 

void oi_socket_init           (oi_socket *, float timeout);
void oi_socket_open_tcp       (oi_socket *, char *host, int port); 
void oi_socket_open_unix      (oi_socket *, char *socketfile);
void oi_socket_attach         (oi_socket *, struct ev_loop *loop);
void oi_socket_read_stop      (oi_socket *); /* by default on_read will always read! */
void oi_socket_read_start     (oi_socket *); /* sockets otherwise are always reading */
void oi_socket_reset_timeout  (oi_socket *);
void oi_socket_schedule_close (oi_socket *); /* also disables on_read - on_close callback made later*/
void oi_socket_write          (oi_socket *, oi_buf *);

struct oi_server {
  int fd;                                       /* ro */
  struct sockaddr_in sockaddr;                  /* ro */
  socklen_t socklen;                            /* ro */
  char port[6];                                 /* ro */
  char *socketfile;                             /* ro */
  struct ev_loop *loop;                         /* ro */
  unsigned listening:1;                         /* ro */
  unsigned secure:1;                            /* ro */
  ev_io connection_watcher;                     /* private */
  ev_io error_watcher;                          /* private */
#ifdef HAVE_GNUTLS
  gnutls_certificate_credentials_t credentials; /* private */
  oi_ssl_cache ssl_cache;                       /* private */
#endif

  /* public */
  oi_socket* (*on_connection)(oi_server *server, struct sockaddr_in *, socklen_t);
  void       (*on_error)     (oi_server *server);
  void *data;
};

struct oi_socket {
  int fd;                      /* ro */
  struct sockaddr_in sockaddr; /* ro */
  socklen_t socklen;           /* ro */ 
  struct ev_loop *loop;        /* ro */
  oi_server *server;           /* ro */
  char *ip;                    /* ro */
  unsigned open:1;             /* ro */
  unsigned secure:1;           /* ro */
  oi_buf *write_buffer;        /* ro */
  size_t written;              /* ro */

  ev_io error_watcher;         /* private */
  ev_io write_watcher;         /* private */
  ev_io read_watcher;          /* private */
  ev_timer timeout_watcher;    /* private */
  ev_timer goodbye_watcher;    /* private */
#ifdef HAVE_GNUTLS
  ev_io handshake_watcher;     /* private */
  gnutls_session_t session;    /* private */
  ev_io goodbye_tls_watcher;   /* private */
#endif
  
  /* public */
  void (*on_connected)(oi_socket *socket); /* called when it's first connected 
                                            * for peer sockets this can be
                                            * NULL usually */
  void (*on_read)    (oi_socket *socket, const void *buf, size_t count);
  void (*on_drain)   (oi_socket *socket); /* called when the write buffer becomes empty */
  void (*on_error)   (oi_socket *socket);
  void (*on_close)   (oi_socket *socket);
  void (*on_timeout) (oi_socket *socket);
  void *data;
};

struct oi_buf {
  size_t written; /* private */
  oi_buf *next;   /* private */

  /* public */
  const void *base;
  size_t len;
  void (*release) (oi_buf *); /* called when oi_socket is done with the object */
  void *data;
};

#endif /* oi_h */
