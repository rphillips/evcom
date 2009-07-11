#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ev.h>
#include <oi_socket.h>
#include <gnutls/gnutls.h>

static const struct addrinfo server_tcp_hints = 
/* ai_flags      */ { AI_PASSIVE 
/* ai_family     */ , AF_UNSPEC
/* ai_socktype   */ , SOCK_STREAM
                    , 0
                    };

static const struct addrinfo client_tcp_hints = 
/* ai_flags      */ { 0
/* ai_family     */ , AF_UNSPEC
/* ai_socktype   */ , SOCK_STREAM
                    , 0
                    };

#define HOST "127.0.0.1"
#define SOCKFILE "/tmp/oi.sock"
#define PORT "5000"

static oi_server server;
int nconnections; 

static void 
common_on_peer_close(oi_socket *socket)
{
  assert(socket->errorno == 0);
  printf("server connection closed\n");
#if HAVE_GNUTLS
  assert(socket->gnutls_errorno == 0);
  gnutls_deinit(socket->session);
#endif
  free(socket);
}

static void 
common_on_client_timeout(oi_socket *socket)
{
  printf("client connection timeout\n");
  assert(0);
}

static void 
common_on_peer_timeout(oi_socket *socket)
{
  fprintf(stderr, "peer connection timeout\n");
  assert(0);
}

#if HAVE_GNUTLS
#define DH_BITS 768
gnutls_anon_server_credentials_t server_credentials;
const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
static gnutls_dh_params_t dh_params;

void anon_tls_server(oi_socket *socket)
{
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

void anon_tls_client(oi_socket *socket)
{
  gnutls_session_t client_session;
  gnutls_anon_client_credentials_t client_credentials;

  gnutls_anon_allocate_client_credentials (&client_credentials);
  gnutls_init (&client_session, GNUTLS_CLIENT);
  gnutls_set_default_priority(client_session);
  gnutls_kx_set_priority(client_session, kx_prio);
  /* Need to enable anonymous KX specifically. */
  gnutls_credentials_set (client_session, GNUTLS_CRD_ANON, client_credentials);

  oi_socket_set_secure_session(socket, client_session);
  assert(socket->secure);
}

#endif // HAVE_GNUTLS





#define PING "PING"
#define PONG "PONG"
#define EXCHANGES 500
#define PINGPONG_TIMEOUT 5.0

int successful_ping_count; 

static void 
pingpong_on_peer_read(oi_socket *socket, const void *base, size_t len)
{
  if (len == 0) {
    oi_socket_close(socket);
    return;
  }

  char buf[2000];
  strncpy(buf, base, len);
  buf[len] = 0;
  printf("server got message: %s\n", buf);

  oi_socket_write_simple(socket, PONG, sizeof PONG);
}

static void 
pingpong_on_client_close(oi_socket *socket)
{
  printf("client connection closed\n");
  oi_server_close(&server);
}

static oi_socket* 
pingpong_on_server_connection(oi_server *_server, struct sockaddr *addr, socklen_t len)
{
  assert(_server == &server);

  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, PINGPONG_TIMEOUT);
  socket->on_read = pingpong_on_peer_read;
  socket->on_close = common_on_peer_close;
  socket->on_timeout = common_on_peer_timeout;

  nconnections++;

#if HAVE_GNUTLS
  anon_tls_server(socket);
#endif

  printf("on server connection\n");

  return socket;
}

static void 
pingpong_on_client_connect (oi_socket *socket)
{
  printf("client connected. sending ping\n");
  oi_socket_write_simple(socket, PING, sizeof PING);
}

static void 
pingpong_on_client_read (oi_socket *socket, const void *base, size_t len)
{
  if(len == 0) {
    oi_socket_close(socket);
    return;
  }

  char buf[2000];
  strncpy(buf, base, len);
  buf[len] = 0;
  printf("client got message: %s\n", buf);
  
  assert(strcmp(buf, PONG) == 0);

  if(++successful_ping_count > EXCHANGES) {
    oi_socket_close(socket);
    return;
  } 
  oi_socket_write_simple(socket, PING, sizeof PING);
}

int
pingpong ( )
{
  int r;
  oi_socket client;

  nconnections = 0;

  printf("sizeof(oi_server): %d\n", sizeof(oi_server));
  printf("sizeof(oi_socket): %d\n", sizeof(oi_socket));

  oi_server_init(&server, 10);
  server.on_connection = pingpong_on_server_connection;

  struct addrinfo *servinfo;
#if TCP
    r = getaddrinfo(NULL, PORT, &server_tcp_hints, &servinfo);
    assert(r == 0);
#else
    struct stat tstat;
    if (lstat(SOCKFILE, &tstat) == 0) {
      if (S_ISSOCK(tstat.st_mode))
        unlink(SOCKFILE);
    }

    servinfo = malloc(sizeof(struct addrinfo));
    servinfo->ai_family = AF_UNIX;
    servinfo->ai_socktype = SOCK_STREAM;
    servinfo->ai_protocol = 0;

    struct sockaddr_un *sockaddr = calloc(sizeof(struct sockaddr_un), 1);
    sockaddr->sun_family = AF_UNIX;
    strcpy(sockaddr->sun_path, SOCKFILE);

    servinfo->ai_addr = (struct sockaddr*)sockaddr;
    servinfo->ai_addrlen = sizeof(struct sockaddr_un);
#endif
  r = oi_server_listen(&server, servinfo);
  assert(r == 0);
  oi_server_attach(EV_DEFAULT_ &server);

  oi_socket_init(&client, PINGPONG_TIMEOUT);
  client.on_read    = pingpong_on_client_read;
  client.on_connect = pingpong_on_client_connect;
  client.on_close   = pingpong_on_client_close;
  client.on_timeout = common_on_client_timeout;

#if HAVE_GNUTLS
  anon_tls_client(&client);
#endif

  r = oi_socket_connect(&client, servinfo);
  assert(r == 0 && "problem connecting");
  oi_socket_attach(EV_DEFAULT_ &client);

  ev_loop(EV_DEFAULT_ 0);

  assert(successful_ping_count == EXCHANGES + 1);
  assert(nconnections == 1);

#if TCP
  freeaddrinfo(servinfo);
#endif

  return 0;
}




#define NCONN 100
#define CONNINT_TIMEOUT 1000.0

static void 
connint_on_peer_read(oi_socket *socket, const void *base, size_t len)
{
  assert(len == 0);
  oi_socket_write_simple(socket, "BYE", 3);
  printf("server wrote bye\n");
}

static void 
connint_on_peer_drain(oi_socket *socket)
{
  oi_socket_close(socket);
}

static oi_socket* 
connint_on_server_connection(oi_server *_server, struct sockaddr *addr, socklen_t len)
{
  assert(_server == &server);

  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, CONNINT_TIMEOUT);
  socket->on_read    = connint_on_peer_read;
  socket->on_drain   = connint_on_peer_drain;
  socket->on_close   = common_on_peer_close;
  socket->on_timeout = common_on_peer_timeout;

#if HAVE_GNUTLS
  anon_tls_server(socket);
#endif

  printf("on server connection\n");

  return socket;
}

static void 
connint_on_client_connect(oi_socket *socket)
{
  printf("on client connection\n");
  oi_socket_close(socket);
}

static void 
connint_on_client_close(oi_socket *socket)
{
  oi_socket_close(socket); // already closed, but it shouldn't crash if we try to do it again

  printf("client connection closed\n");
  if(++nconnections == NCONN) {
    oi_server_detach(&server);
    printf("detaching server\n");
  }
}

static void 
connint_on_client_read(oi_socket *socket, const void *base, size_t len)
{
  if (len == 0) {
    oi_socket_close(socket);
    return;
  }

  char buf[200000];
  strncpy(buf, base, len);
  buf[len] = 0;

  printf("client got message: %s\n", buf);
  
  if (strcmp(buf, "BYE") == 0) {
    oi_socket_close(socket);
  } else {
    assert(0);
  }
}

int 
connint (void)
{
  int r;

  nconnections = 0;

  oi_server_init(&server, 1000);
  server.on_connection = connint_on_server_connection;

  struct addrinfo *servinfo;
#if TCP
    r = getaddrinfo(NULL, PORT, &server_tcp_hints, &servinfo);
    assert(r == 0);
#else
    struct stat tstat;
    if (lstat(SOCKFILE, &tstat) == 0) {
      if (S_ISSOCK(tstat.st_mode))
        unlink(SOCKFILE);
    }

    servinfo = malloc(sizeof(struct addrinfo));
    servinfo->ai_family = AF_UNIX;
    servinfo->ai_socktype = SOCK_STREAM;
    servinfo->ai_protocol = 0;

    struct sockaddr_un *sockaddr = calloc(sizeof(struct sockaddr_un), 1);
    sockaddr->sun_family = AF_UNIX;
    strcpy(sockaddr->sun_path, SOCKFILE);

    servinfo->ai_addr = (struct sockaddr*)sockaddr;
    servinfo->ai_addrlen = sizeof(struct sockaddr_un);
#endif

  oi_server_listen(&server, servinfo);
  oi_server_attach(EV_DEFAULT_ &server);

  oi_socket clients[NCONN];
  int i;
  for (i = 0; i < NCONN; i++) {
    oi_socket *client = &clients[i];
    oi_socket_init(client, CONNINT_TIMEOUT);
    client->on_read    = connint_on_client_read;
    client->on_connect = connint_on_client_connect;
    client->on_close   = connint_on_client_close;
    client->on_timeout = common_on_client_timeout;
#if HAVE_GNUTLS
    anon_tls_client(client);
#endif
    r = oi_socket_connect(client, servinfo);
    assert(r == 0 && "problem connecting");
    oi_socket_attach(EV_DEFAULT_ client);
  }

  ev_loop(EV_DEFAULT_ 0);

  assert(nconnections == NCONN);

#if TCP
  freeaddrinfo(servinfo);
#endif

  return 0;
}


int
main (void)
{
#if HAVE_GNUTLS
  gnutls_global_init();

  gnutls_dh_params_init (&dh_params);

  fprintf(stderr, "..");
  fsync((int)stderr);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);
  fprintf(stderr, ".");

  gnutls_anon_allocate_server_credentials (&server_credentials);
  gnutls_anon_set_server_dh_params (server_credentials, dh_params);
#endif

  assert(pingpong() == 0);
  assert(connint() == 0);

  return 0;
}
