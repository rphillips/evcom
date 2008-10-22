#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <ev.h>
#include "oi.h"

#define SOCKFILE "/tmp/oi.sock"
#define PORT 5000
#define HOST "127.0.0.1"

#define PING "PING"
#define PONG "PONG"

int successful_ping_count; 

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
on_error(oi_socket *socket)
{
  printf("an error happend on the peer socket\n");
  exit(1);
}

static void 
on_client_error(oi_socket *socket)
{
  printf("an error happend on the client socket\n");
  exit(1);
}

static void 
on_close(oi_socket *socket)
{
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

    if(++successful_ping_count > 10) {
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

  if(argc >= 2 && strcmp(argv[1], "unix") == 0)
    is_tcp = 0;

  oi_server_init(&server, 10);
  server.on_connection = on_server_connection;

  if(is_tcp) {
    r = oi_server_listen_tcp(&server, HOST, PORT);
  } else {
    r = oi_server_listen_unix(&server, SOCKFILE, 0700);
  }

  assert(r >= 0 && "problem listening");
  oi_server_attach(&server, loop);
  //printf("starting server on port 5000\n");

  oi_socket_init(&client, 3.0);
  client.on_read    = on_client_read;
  client.on_error   = on_client_error;
  client.on_connect = on_client_connect;
  client.on_close   = on_client_close;

  if(is_tcp) {
    r = oi_socket_open_tcp(&client, HOST, PORT);
  } else {
    r = oi_socket_open_unix(&client, SOCKFILE);
  }

  assert(r > 0 && "problem connecting");
  oi_socket_attach(&client, loop);
  //printf("connecting client to port 5000\n");

  ev_loop(loop, 0);

  return 0;
}
