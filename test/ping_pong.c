#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <ev.h>
#include "oi.h"
#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#define SOCKFILE "/tmp/oi.sock"
#define PORT 5000
#define HOST "127.0.0.1"


#define PING "PING"
#define PONG "PONG"
#define EXCHANGES 5

int successful_ping_count; 
static int is_secure = 0;

#ifdef HAVE_GNUTLS
#define DH_BITS 1024
gnutls_anon_server_credentials_t server_credentials;
const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
static gnutls_dh_params_t dh_params;
#endif

static void 
on_server_read(oi_socket *socket, const void *base, size_t len)
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
on_error(oi_socket *socket, int domain, int code)
{
  printf("an error happend on the peer socket\n");
  switch(domain) {
    case OI_HANDSHAKE_ERROR:
      printf("handshake error: %d\n", code);
      break;
    case OI_BYE_ERROR:
      printf("bye error: %d\n", code);
      break;
  }
  exit(1);
}

static void 
on_client_error(oi_socket *socket, int domain, int code)
{
  printf("an error happend on the client socket\n");
  switch(domain) {
    case OI_HANDSHAKE_ERROR:
      printf("handshake error: %d\n", code);
      break;
    case OI_BYE_ERROR:
      printf("bye error: %d\n", code);
      break;
  }
  exit(1);
}

static void 
on_close(oi_socket *socket)
{
#ifdef HAVE_GNUTLS
  if(is_secure) {
    gnutls_session_t session = socket->data;
    gnutls_deinit(session);
  }
#endif
  //printf("server connection closed\n");
  free(socket);
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
  oi_socket_init(socket, 30.0);
  socket->on_read = on_server_read;
  socket->on_error = on_error;
  socket->on_close = on_close;

#ifdef HAVE_GNUTLS
  if(is_secure) {
    gnutls_session_t session;
    socket->data = session;
    int r = gnutls_init(&session, GNUTLS_SERVER);
    assert(r == 0);
    gnutls_set_default_priority(session);
    gnutls_kx_set_priority (session, kx_prio);
    gnutls_credentials_set(session, GNUTLS_CRD_ANON, server_credentials);
    gnutls_dh_set_prime_bits(session, DH_BITS);

    oi_socket_set_secure_session(socket, session);
  }
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
      oi_socket_schedule_close(socket);
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


  int is_tcp = 1;

  //printf("sizeof(oi_server): %d\n", sizeof(oi_server));
  //printf("sizeof(oi_socket): %d\n", sizeof(oi_socket));

  if(argc >= 2 && strcmp(argv[1], "unix") == 0)
    is_tcp = 0;

  if(argc >= 3 && strcmp(argv[2], "secure") == 0)
    is_secure = 1;

  oi_server_init(&server, 10);
  server.on_connection = on_server_connection;

#ifdef HAVE_GNUTLS
  if(is_secure) {
    gnutls_global_init();

    gnutls_dh_params_init (&dh_params);
    gnutls_dh_params_generate2 (dh_params, DH_BITS);
    gnutls_anon_allocate_server_credentials (&server_credentials);
    gnutls_anon_set_server_dh_params (server_credentials, dh_params);
  }
#endif /* HAVE_GNUTLS */

  if(is_tcp) {
    r = oi_server_listen_tcp(&server, HOST, PORT);
    // printf("starting server on port 5000\n");
  } else {
    r = oi_server_listen_unix(&server, SOCKFILE, 0700);
  }
  assert(r >= 0 && "problem listening");

  oi_server_attach(&server, loop);

  oi_socket_init(&client, 30.0);
  client.on_read    = on_client_read;
  client.on_error   = on_client_error;
  client.on_connect = on_client_connect;
  client.on_close   = on_client_close;

#ifdef HAVE_GNUTLS
  gnutls_session_t client_session;
  gnutls_anon_client_credentials_t client_credentials;
  if(is_secure) {

    gnutls_anon_allocate_client_credentials (&client_credentials);
    gnutls_init (&client_session, GNUTLS_CLIENT);
    gnutls_set_default_priority(client_session);
    gnutls_kx_set_priority(client_session, kx_prio);
    /* Need to enable anonymous KX specifically. */
    gnutls_credentials_set (client_session, GNUTLS_CRD_ANON, client_credentials);

    oi_socket_set_secure_session(&client, client_session);

    printf("using ssl\n");
    assert(client.secure);
  }
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

#ifdef HAVE_GNUTLS
  if(is_secure) {
    gnutls_deinit (client_session);

    gnutls_anon_free_server_credentials (server_credentials);
    gnutls_anon_free_client_credentials (client_credentials);

    gnutls_global_deinit ();
  }
#endif

  return 0;
}
