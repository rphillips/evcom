#include <unistd.h> /* sleep() */
#include <stdlib.h> /* malloc(), free() */
#include <stdio.h> 
#include <errno.h> 
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ev.h>
#include "oi_file.h"

static void
on_open(oi_file *file)
{
  printf("opened the file!!!\n");

  int r = oi_file_read_simple(file, 100);
  assert(r >= 0);
}

static void
on_close(oi_file *file)
{
  printf("closed the file!!!\n");
  oi_file_detach(file);  
}

static void
on_read(oi_file *file, oi_buf *buf, size_t recved)
{
  printf("read chunk: \n-----\n");
  int r = write(STDOUT_FILENO, buf->base, recved);
  assert( r == recved && "if this assert fails, it doesn't imply something wrong ");
  printf("\n-----\n");

  oi_file_close(file);
}

int
main()
{
  struct ev_loop *loop = ev_default_loop(0);
  oi_file file; 

  oi_file_init(&file);
  file.on_open = on_open;
  file.on_read = on_read;
  file.on_close = on_close;
  oi_file_open_path(&file, "config.mk", O_RDONLY, 0);

  oi_file_attach(&file, loop);
  ev_loop(loop, 0);
  return 0;
}
