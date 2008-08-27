#include <ev.h>

struct bp_server {

  /* public */
  bp_socket* (*on_connection)(bp_server *server);
  void *data;
}

void bp_server_init(bp_server *server);
void bp_server_set_secure(bp_server *server, const char *cert_file, const char *key_file);
void bp_server_attach(bp_server *server, ev_loop *loop);
void bp_server_listen_on_port(bp_server *server, int port);
void bp_server_listen_on_socketfile(bp_server *server, char *filename);
void bp_server_unlisten(bp_server *server); 

struct bp_buf {
  bp_buf *next;

  /* public */
  const void *buf;
  size_t count;
  void (*release) (bp_buf *); /* called when bp_socket is done with the object */
  void *data;
};

struct bp_socket {
  bp_buf *write_buffer;
  
  /* public */
  void (*on_connected)(bp_socket *socket); /* called when it's first connected 
                                            * for peer sockets this can be
                                            * NULL usually */
  void (*on_read)    (bp_socket *socket, const void *buf, size_t count);
  void (*on_drain)   (bp_socket *socket); /* called when the write buffer becomes empty */
  void (*on_error)   (bp_socket *socket);
  void (*on_closure) (bp_socket *socket);
  void (*on_timeout) (bp_socket *socket);
  void *data;
};

void bp_socket_init(bp_socket *socket, float timeout);
void bp_socket_tcp_connect(bp_socket *socket, blah blah blah); /* i don't want to do non-blcking dns resolve */
void bp_socket_unix_connect(bp_socket *socket, char *filename);
void bp_socket_attach(bp_socket *socket, ev_loop *loop);

void bp_socket_stop_reading(bp_socket *socket); /* by default on_read will always read! */
void bp_socket_resume_reading(bp_socket *socket); /* sockets otherwise are always reading */
void bp_socket_reset_timer(bp_socket *socket);
void bp_socket_close(bp_socket *socket); /* also disables on_read - on_closure callback made later*/
void bp_socket_write(bp_socket *socket, bp_buf *);
void bp_socket_write_file(bp_socket *socket, bp_file *); /* fast kernel operation.  
                                                          * socket.on_drain will be
                                                          * called normally when it 
                                                          * is complete. file#on_ready 
                                                          * will be called too */

struct bp_file {
  bp_buf *write_buffer;

  /* public */
  void (*on_ready)   (bp_file *file, long pos); /* called when it's first opened */
  void (*on_read)    (bp_file *file, long pos, const void *buf, size_t count);
  void (*on_drain)   (bp_file *file, long pos); /* called when the write buffer becomes empty */
  void (*on_error)   (bp_file *file, long pos);
  void (*on_closure) (bp_file *file, long pos);
  void (*on_eof)     (bp_file *file, long pos);
  void *data;
};

void bp_file_open(bp_file*, char *filename, char *mode);
/* although many file operations will be done in a thread pool, they will
 * always return to the event loop to give the callbacks 
 * on some systems, file i/o might be able to take advantage of select()
 * and friends (like on FreeBSD where sendfile() is non-blocking).  */
void bp_file_attach(bp_file*, ev_loop *loop);


void bp_file_rewind(bp_file*);
void bp_file_seek(bp_file*, long offset, int whence);
/* main difference between files and sockets is you must schedule the reads
 * and the on_read callback gets made when data is available */
void bp_file_read(bp_file*, size_t count);
void bp_file_write(bp_file*, bp_buf *);
void bp_file_close(bp_file*);


