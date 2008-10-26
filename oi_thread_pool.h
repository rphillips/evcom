
#define OI_MAX_THREAD_POOL_WORKERS 255 
#define OI_MAX_THREAD_POOL_CONNECTIONS 1024
#define OI_THREAD_POOL_SOCKET "/tmp/oi_thead_pool.sock"

struct oi_async {
  ev_io watcher;  
  queue;
/* public */
  void *data;
} 

 int oi_thread_pool_init   (int number); /* returns file descriptor */
void oi_thread_pool_free   (void);

typedef void (*oi_async_cb) (oi_async *, ssize_t result, int errorno);

void oi_async_init        (oi_async *);
void oi_async_free        (oi_async *);
void oi_async_attach      (oi_async *, struct ev_loop *loop);
void oi_async_detach      (oi_async *);

void oi_async_open        (oi_async *, oi_async_cb, const char *path, int flags, mode_t mode);
void oi_async_sendfile    (oi_async *, oi_async_cb, int out_fd, int in_fd, off_t in_offset, size_t length);
void oi_async_read        (oi_async *, oi_async_cb, int fd, void *buf, size_t length, off_t offset);
void oi_async_write       (oi_async *, oi_async_cb, int fd, void *buf, size_t length, off_t offset);
void oi_async_getaddrinfo (oi_async *, oi_async_cb, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

