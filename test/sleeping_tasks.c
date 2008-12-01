#include <unistd.h> /* sleep() */
#include <stdlib.h> /* malloc(), free() */
#include <assert.h>
#include <ev.h>
#include "oi_thread_pool.h"

#define SLEEPS 20
static int runs = 0;

void run(void *data)
{
  sleep(1);
}

void on_completion (oi_thread_pool_task *task)
{
  if(++runs == SLEEPS)
    oi_thread_pool_detach(task->pool->loop, task->pool);
  free(task);
}

int
main()
{
  struct ev_loop *loop = ev_default_loop(0);
  oi_thread_pool pool;
  int i;

  oi_thread_pool_init(&pool);

  for(i = 0; i < SLEEPS; i++) {
    oi_thread_pool_task *task = malloc(sizeof(oi_thread_pool_task));
    task->run = run;
    task->on_completion = on_completion;
    oi_thread_pool_execute(&pool, task);
  }

  oi_thread_pool_attach(loop, &pool);
  ev_loop(loop, 0);

  assert(runs == SLEEPS);

  return 0;
}
