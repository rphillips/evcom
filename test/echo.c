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

#define HOST "127.0.0.1"
#define SOCKFILE "/tmp/oi.sock"
#define PORT "5000"

int nconnections; 

static void 
on_peer_close(oi_socket *socket)
{
  assert(socket->errorno == 0);
  //printf("server connection closed\n");
  free(socket);
}

static void 
on_peer_timeout(oi_socket *socket)
{
  fprintf(stderr, "peer connection timeout\n");
  assert(0);
}



// timeout must match the timeout in timeout.rb
#define TIMEOUT 5.0

int successful_ping_count; 

static void 
on_peer_read(oi_socket *socket, const void *base, size_t len)
{
  if(len == 0) 
    return;

  oi_socket_write_simple(socket, base, len);
}

static oi_socket* 
on_server_connection(oi_server *server, struct sockaddr *addr, socklen_t len)
{
  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, TIMEOUT);
  socket->on_read = on_peer_read;
  socket->on_close = on_peer_close;
  socket->on_timeout = on_peer_timeout;

  nconnections++;


  //printf("on server connection\n");

  return socket;
}

int 
main(int argc, const char *argv[])
{
  int r;
  oi_server server;

  //printf("sizeof(oi_server): %d\n", sizeof(oi_server));
  //printf("sizeof(oi_socket): %d\n", sizeof(oi_socket));

  oi_server_init(&server, 10);
  server.on_connection = on_server_connection;

  struct addrinfo *servinfo;
  struct addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  r = getaddrinfo(NULL, PORT, &hints, &servinfo);
  assert(r == 0);

  r = oi_server_listen(&server, servinfo);
  assert(r == 0);
  oi_server_attach(EV_DEFAULT_ &server);

  ev_loop(EV_DEFAULT_ 0);

  freeaddrinfo(servinfo);

  return 0;
}
