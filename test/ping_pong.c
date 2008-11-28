#include "test/common.c"

#define PING "PING"
#define PONG "PONG"
#define EXCHANGES 50

int successful_ping_count; 

static void 
on_peer_read(oi_socket *socket, const void *base, size_t len)
{
  if(len == 0) 
    return;

  char buf[200000];
  strncpy(buf, base, len);
  buf[len] = 0;
  //printf("server got message: %s\n", buf);

  oi_socket_write_simple(socket, PONG, sizeof PONG);
}

static void 
on_client_close(oi_socket *socket)
{
  //printf("client connection closed\n");
  ev_unloop(socket->loop, EVUNLOOP_ALL);
}

static oi_socket* 
on_server_connection(oi_server *server, struct sockaddr *addr, socklen_t len)
{
  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, 5.0);
  socket->on_read = on_peer_read;
  socket->on_error = on_peer_error;
  socket->on_close = on_peer_close;
  socket->on_timeout = on_peer_timeout;

  nconnections++;

#ifdef HAVE_GNUTLS
  if(is_secure) { anon_tls_server(socket); }
#endif

  //printf("on server connection\n");

  return socket;
}

static void 
on_client_connect(oi_socket *socket)
{
  //printf("client connected. sending ping\n");
  oi_socket_write_simple(socket, PING, sizeof PING);
}

static void 
on_client_read(oi_socket *socket, const void *base, size_t len)
{
  char buf[200000];
  strncpy(buf, base, len);
  buf[len] = 0;
  //printf("client got message: %s\n", buf);
  
  if(strcmp(buf, PONG) == 0) {

    if(++successful_ping_count > EXCHANGES) {
      oi_socket_close(socket);
      return;
    } 
    oi_socket_write_simple(socket, PING, sizeof PING);
  } else {
    exit(1);
  }
}

int 
main(int argc, const char *argv[])
{
  int r;
  struct ev_loop *loop = ev_default_loop(0);
  oi_server server;
  oi_socket client;

  //printf("sizeof(oi_server): %d\n", sizeof(oi_server));
  //printf("sizeof(oi_socket): %d\n", sizeof(oi_socket));

  if(argc >= 2 && strcmp(argv[1], "unix") == 0)
    is_tcp = 0;

  if(argc >= 3 && strcmp(argv[2], "secure") == 0)
    is_secure = 1;

  oi_server_init(&server, 10);
  server.on_connection = on_server_connection;

#ifdef HAVE_GNUTLS
  if(is_secure) { anon_tls_init(); }
#endif /* HAVE_GNUTLS */

  if(is_tcp) {
    r = oi_server_listen_tcp(&server, HOST, PORT);
    //printf("starting server on port 5000\n");
  } else {
    r = oi_server_listen_unix(&server, SOCKFILE, 0700);
  }
  assert(r >= 0 && "problem listening");

  oi_server_attach(&server, loop);

  oi_socket_init(&client, 5.0);
  client.on_read    = on_client_read;
  client.on_error   = on_client_error;
  client.on_connect = on_client_connect;
  client.on_close   = on_client_close;
  client.on_timeout = on_client_timeout;

#ifdef HAVE_GNUTLS
  if(is_secure) { anon_tls_client(&client); }
#endif /* HAVE_GNUTLS */

  if(is_tcp) {
    r = oi_socket_open_tcp(&client, HOST, PORT);
    //printf("connecting client to port 5000\n");
  } else {
    r = oi_socket_open_unix(&client, SOCKFILE);
  }

  assert(r > 0 && "problem connecting");
  oi_socket_attach(&client, loop);

  ev_loop(loop, 0);

  assert(successful_ping_count == EXCHANGES + 1);
  assert(nconnections == 1);


  return 0;
}
