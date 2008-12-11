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

static  oi_file file; 
static  oi_file out; 

static void
on_open(oi_file *file)
{
#define OPEN_MSG "opened the file\n"
  oi_file_write_simple(&out, OPEN_MSG, sizeof(OPEN_MSG));
  
  int r = oi_file_read_simple(file, 100);
  assert(r >= 0);
}

static void
on_close(oi_file *file)
{
#define CLOSE_MSG "closed the file\n"
  oi_file_write_simple(&out, CLOSE_MSG, sizeof(CLOSE_MSG));

  oi_file_detach(file);  
}

static void
on_read(oi_file *file, oi_buf *buf, size_t recved)
{
  oi_file_write_simple(&out, buf->base, recved);
  oi_file_close(file);
}

int
main()
{
  struct ev_loop *loop = ev_default_loop(0);

  oi_file_init(&file);
  file.on_open = on_open;
  file.on_read = on_read;
  file.on_close = on_close;
  oi_file_open_path(&file, "config.mk", O_RDONLY, 0);
  oi_file_attach(&file, loop);

  oi_file_init(&out);
  oi_file_open_stdout(&out);
  oi_file_attach(&out, loop);

  ev_loop(loop, 0);
  return 0;
}
