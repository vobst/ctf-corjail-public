#define _GNU_SOURCE
#include <sched.h>

#include "errhandling.h"

#include "sched_stuff.h"

/* Pinns the calling thread to the specified CPU */
int setaffinity(int cpu)
{
  cpu_set_t cpu_set;
  int ret = 0;

  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  CHECK_ZERO(sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set),
      "sched_setaffinity");

  return ret;
}
