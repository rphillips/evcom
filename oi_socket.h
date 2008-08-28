#include "oi.h"

void
oi_socket_init_peer(oi_socket *socket, oi_server *server, 
    int fd, struct sockaddr_in *addr, socklen_t addr_len);
