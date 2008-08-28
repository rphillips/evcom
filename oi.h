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
typedef struct oi_file       oi_file;

struct oi_buf {
  size_t written; /* private */
  oi_buf *next;   /* private */

  /* public */
  const void *base;
  size_t len;
  void (*release) (oi_buf *); /* called when oi_socket is done with the object */
  void *data;
};

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

void oi_server_init(oi_server *server, struct ev_loop *loop);
int oi_server_set_secure(oi_server *server, const char *cert_file, const char *key_file, gnutls_x509_crt_fmt_t type);
int oi_server_listen_on_port(oi_server *server, int port);
int oi_server_listen_on_socketfile(oi_server *server, char *filename);
void oi_server_unlisten(oi_server *server); 

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

void oi_socket_init(oi_socket *socket, float timeout);
//void oi_socket_open_tcp(oi_socket *socket, blah blah blah); /* i don't want to do non-blcking dns resolve */
//void oi_socket_open_socketfile(oi_socket *socket, char *filename);
void oi_socket_attach(oi_socket *socket, struct ev_loop *loop);

void oi_socket_stop_reading(oi_socket *socket); /* by default on_read will always read! */
void oi_socket_resume_reading(oi_socket *socket); /* sockets otherwise are always reading */
void oi_socket_reset_timeout(oi_socket *socket);
void oi_socket_close(oi_socket *socket); /* also disables on_read - on_close callback made later*/
void oi_socket_write(oi_socket *socket, oi_buf *);
/* fast kernel operation.  socket.on_drain will be called normally when it
 * is complete. */
void oi_socket_write_file(oi_socket *socket, oi_file *); 

struct oi_file {
  oi_buf *write_buffer;

  /* public */
  void (*on_opened)  (oi_file *file, long pos);
  void (*on_read)    (oi_file *file, long pos, const void *buf, size_t count);
  void (*on_drain)   (oi_file *file, long pos); /* called when the write buffer becomes empty */
  void (*on_error)   (oi_file *file, long pos);
  void (*on_closure) (oi_file *file, long pos);
  void *data;
};

void oi_file_init(oi_file*);
void oi_file_open(char *filename, char *mode);
/* although many file operations will be done in a thread pool, they will
 * always return to the event loop to give the callbacks.
 * on some systems, file i/o might be able to take advantage of select()
 * and friends (like on FreeBSD where sendfile() is non-blocking).  */
void oi_file_attach(oi_file*, struct ev_loop *loop);


void oi_file_rewind(oi_file*);
void oi_file_seek(oi_file*, long offset, int whence);
/* main difference between files and sockets is you must schedule the reads
 * and the on_read callback gets made when data is available */
void oi_file_read(oi_file*, size_t count);
void oi_file_write(oi_file*, oi_buf *);
void oi_file_close(oi_file*);

#endif /* oi_h */
