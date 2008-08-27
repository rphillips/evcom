#include "oi.h"
#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# include "rbtree.h" /* for session_cache */
#endif

static void 
set_nonblock (int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  int r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  assert(0 <= r && "Setting socket non-block failed!");
}

#ifdef HAVE_GNUTLS
#define OI_MAX_SESSION_KEY 32
#define OI_MAX_SESSION_VALUE 512

struct session_cache {
  struct rbtree_node_t node;

  gnutls_datum_t key;
  gnutls_datum_t value;

  char key_storage[OI_MAX_SESSION_KEY];
  char value_storage[OI_MAX_SESSION_VALUE];
};

static int 
session_cache_compare (void *left, void *right) 
{
  gnutls_datum_t *left_key = left;
  gnutls_datum_t *right_key = right;
  if(left_key->size < right_key->size)
    return -1;
  else if(left_key->size > right_key->size)
    return 1;
  else
    return memcmp( left_key->data
                 , right_key->data
                 , MIN(left_key->size, right_key->size)
                 );
}

static int
session_cache_store(void *data, gnutls_datum_t key, gnutls_datum_t value)
{
  rbtree tree = data;

  if( tree == NULL
   || key.size > OI_MAX_SESSION_KEY
   || value.size > OI_MAX_SESSION_VALUE
    ) return -1;

  struct session_cache *cache = gnutls_malloc(sizeof(struct session_cache));

  memcpy (cache->key_storage, key.data, key.size);
  cache->key.size = key.size;
  cache->key.data = (void*)cache->key_storage;

  memcpy (cache->value_storage, value.data, value.size);
  cache->value.size = value.size;
  cache->value.data = (void*)cache->value_storage;

  cache->node.key = &cache->key;
  cache->node.value = &cache;

  rbtree_insert(tree, (rbtree_node)cache);

  //printf("session_cache_store\n");

  return 0;
}

static gnutls_datum_t
session_cache_retrieve (void *data, gnutls_datum_t key)
{
  rbtree tree = data;
  gnutls_datum_t res = { NULL, 0 };
  struct session_cache *cache = rbtree_lookup(tree, &key);

  if(cache == NULL)
    return res;

  res.size = cache->value.size;
  res.data = gnutls_malloc (res.size);
  if(res.data == NULL)
    return res;

  memcpy(res.data, cache->value.data, res.size);

  //printf("session_cache_retrieve\n");

  return res;
}

static int
session_cache_remove (void *data, gnutls_datum_t key)
{
  rbtree tree = data;

  if(tree == NULL)
    return -1;

  struct session_cache *cache = (struct session_cache *)rbtree_delete(tree, &key);
  if(cache == NULL)
    return -1;

  gnutls_free(cache);

  //printf("session_cache_remove\n");

  return 0;
}
#endif /* HAVE_GNUTLS */

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
    oi_server_unlisten(server);
    return;
  }
  
  struct sockaddr_in addr; // connector's address information
  socklen_t addr_len = sizeof(addr); 
  int fd = accept( server->fd
                 , (struct sockaddr*) & addr
                 , & addr_len
                 );
  if(fd < 0) {
    perror("accept()");
    return;
  }

  oi_socket *connection = NULL;
  if(server->new_connection)
    connection = server->new_connection(server, &addr, addr_len);

  if(connection == NULL) {
    error("problem getting peer socket");
    close(fd);
    return;
  } 
  
  set_nonblock(fd);
  connection->fd = fd;
  connection->open = TRUE;
  connection->server = server;
  memcpy(&connection->sockaddr, &addr, addr_len);
  if(server->port[0] != '\0')
    connection->ip = inet_ntoa(connection->sockaddr.sin_addr);  

#ifdef SO_NOSIGPIPE
  int arg = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &arg, sizeof(int));
#endif

#ifdef HAVE_GNUTLS
  if(server->secure) {
    gnutls_init(&connection->session, GNUTLS_SERVER);
    gnutls_transport_set_lowat(connection->session, 0); 
    gnutls_set_default_priority(connection->session);
    gnutls_credentials_set(connection->session, GNUTLS_CRD_CERTIFICATE, connection->server->credentials);

    gnutls_transport_set_ptr(connection->session, (gnutls_transport_ptr) fd); 
    gnutls_transport_set_push_function(connection->session, nosigpipe_push);

    gnutls_db_set_ptr (connection->session, &server->session_cache);
    gnutls_db_set_store_function (connection->session, session_cache_store);
    gnutls_db_set_retrieve_function (connection->session, session_cache_retrieve);
    gnutls_db_set_remove_function (connection->session, session_cache_remove);
  }

  ev_io_set(&connection->handshake_watcher, connection->fd, EV_READ | EV_WRITE | EV_ERROR);
#endif /* HAVE_GNUTLS */

  /* Note: not starting the write watcher until there is data to be written */
  ev_io_set(&connection->write_watcher, connection->fd, EV_WRITE);
  ev_io_set(&connection->read_watcher, connection->fd, EV_READ | EV_ERROR);
  /* XXX: seperate error watcher? */

  ev_timer_start(loop, &connection->timeout_watcher);

#ifdef HAVE_GNUTLS
  if(server->secure) {
    ev_io_start(loop, &connection->handshake_watcher);
    return;
  }
#endif

  ev_io_start(loop, &connection->read_watcher);
}

static int 
listen_on_fd(oi_server *server, const int fd)
{
  assert(server->listening == FALSE);

  if (listen(fd, OI_MAX_CONNECTIONS) < 0) {
    perror("listen()");
    return -1;
  }
  
  set_nonblock(fd); /* XXX superfluous? */
  
  server->fd = fd;
  server->listening = TRUE;
  
  ev_io_set (&server->connection_watcher, server->fd, EV_READ | EV_ERROR);
  ev_io_start (server->loop, &server->connection_watcher);
  
  return server->fd;
}


/**
 * Begin the server listening on a file descriptor This DOES NOT start the
 * event loop. Start the event loop after making this call.
 */
int 
oi_server_listen_on_port(oi_server *server, const int port)
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
  
  int ret = oi_server_listen_on_fd(server, fd);
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
oi_server_unlisten(oi_server *server)
{
  if(server->listening) {
    ev_io_stop(server->loop, &server->connection_watcher);
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
oi_server_set_secure (oi_server *server, const char *cert_file, const char *key_file)
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
oi_server_init(oi_server *server, struct ev_loop *loop)
{
  server->loop = loop;
  server->listening = FALSE;
  server->port[0] = '\0';
  server->fd = -1;
  server->connection_watcher.data = server;
  ev_init (&server->connection_watcher, on_connection);
  server->secure = FALSE;

#ifdef HAVE_GNUTLS
  rbtree_init(&server->session_cache, session_cache_compare);
  server->credentials = NULL;
#endif

  server->new_connection = NULL;
  server->data = NULL;
}



