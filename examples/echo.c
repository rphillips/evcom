#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <ev.h>
#include "oi.h"

static void 
on_read(oi_socket *socket, const void *base, size_t len)
{
  if(len == 0) 
    return;

  oi_buf *buf = malloc(sizeof(oi_buf));
  buf->release = (void (*)(oi_buf*))free;
  buf->base = base;
  buf->len = len;

  oi_socket_write(socket, buf);
}

static void 
on_error(oi_socket *socket)
{
  printf("an error happend on the peer socket\n");
}

static void 
on_close(oi_socket *socket)
{
  printf("connection closed\n");
  free(socket);
}

static oi_socket* 
on_connection(oi_server *server, struct sockaddr_in *addr, socklen_t len)
{
  oi_socket *socket = malloc(sizeof(oi_socket));
  oi_socket_init(socket, 30.0);
  socket->on_read = on_read;
  socket->on_error = on_error;
  socket->on_close = on_close;
  return socket;
}

int 
main()
{
  struct ev_loop *loop = ev_default_loop(0);
  oi_server server;

  oi_server_init(&server, 10);
  server.on_connection = on_connection;

  printf("echo listening on port 5000\n");
  oi_server_listen_tcp(&server, 5000);
  oi_server_attach(&server, loop);
  ev_loop(loop, 0);

  return 0;
}
