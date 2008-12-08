#include <unistd.h> /* sleep() */
#include <stdlib.h> /* malloc(), free() */
#include <stdio.h> 
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
}

int
main()
{
  struct ev_loop *loop = ev_default_loop(0);
  oi_file file; 

  oi_file_init(&file);
  file.on_open = on_open;
  oi_file_open_path(&file, "config.mk", O_RDONLY, 0);

  oi_file_attach(&file, loop);
  ev_loop(loop, 0);
  return 0;
}
