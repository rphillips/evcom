#include "test/common.c"
#define NCONN 100

static oi_server server;

static void 
on_peer_read(oi_socket *socket, const void *base, size_t len)
{
  assert(len == 0);
  oi_socket_write_simple(socket, "BYE", 3);
}

static void 
on_peer_drain(oi_socket *socket)
{
  oi_socket_close(socket);
}

static oi_socket* 
on_server_connection(oi_server *server, struct sockaddr *addr, socklen_t len)
{
  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, 5.0);
  socket->on_read = on_peer_read;
  socket->on_drain = on_peer_drain;
  socket->on_error = on_peer_error;
  socket->on_close = on_peer_close;
  socket->on_timeout = on_peer_timeout;

#ifdef HAVE_GNUTLS
  if(is_secure) { anon_tls_server(socket); }
#endif

  //printf("on server connection\n");

  return socket;
}

static void 
on_client_connect(oi_socket *socket)
{
  oi_socket_write_eof(socket);
}

static void 
on_client_close(oi_socket *socket)
{
  printf("client connection closed\n");
  if(++nconnections == NCONN) {
    oi_server_detach(&server);
    printf("detaching server\n");
  }
}

static void 
on_client_read(oi_socket *socket, const void *base, size_t len)
{
  char buf[200000];
  strncpy(buf, base, len);
  buf[len] = 0;

  printf("client got message: %s\n", buf);
  
  if(strcmp(buf, "BYE") == 0) {
    oi_socket_close(socket);
  } else {
    exit(1);
  }
}

int 
main(int argc, const char *argv[])
{
  int r;
  struct ev_loop *loop = ev_default_loop(0);

  if(argc >= 2 && strcmp(argv[1], "tcp") == 0)
    is_tcp = 1;
  if(argc >= 3 && strcmp(argv[2], "secure") == 0)
    is_secure = 1;

  oi_server_init(&server, 1000);
  server.on_connection = on_server_connection;
#ifdef HAVE_GNUTLS
  if(is_secure) anon_tls_init();
#endif
  if(is_tcp) {
    r = oi_server_listen_tcp(&server, "127.0.0.1", PORT);
  } else {
    r = oi_server_listen_unix(&server, SOCKFILE, 0700);
  }
  assert(r >= 0 && "problem listening");
  oi_server_attach(&server, loop);

  int i;
  for(i = 0; i < NCONN; i++) {
    oi_socket *client = malloc(sizeof(oi_socket));
    oi_socket_init(client, 5.0);
    client->on_read    = on_client_read;
    client->on_error   = on_client_error;
    client->on_connect = on_client_connect;
    client->on_close   = on_client_close;
    client->on_timeout = on_client_timeout;
#ifdef HAVE_GNUTLS
    if(is_secure) { anon_tls_client(client); }
#endif
    if(is_tcp) {
      r = oi_socket_open_tcp(client, "127.0.0.1", PORT);
      //printf("connecting client to port 5000\n");
    } else {
      r = oi_socket_open_unix(client, SOCKFILE);
    }
    assert(r > 0 && "problem connecting");
    oi_socket_attach(client, loop);
  }

  ev_loop(loop, 0);

  assert(nconnections == NCONN);

  return 0;
}
