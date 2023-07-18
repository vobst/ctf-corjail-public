#define _GNU_SOURCE
#include <stdlib.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>

#include "errhandling.h"
#include "utils.h"

void hex_print(void* addr, size_t len)
{
  puts("");
  for (uint64_t tmp_addr = (uint64_t)addr;
       tmp_addr < (uint64_t)addr + len;
       tmp_addr += 0x10)
  {
    printf("0x%016lx: 0x%016lx 0x%016lx\n",
	tmp_addr, *(uint64_t*)tmp_addr,
	*(uint64_t*)(tmp_addr + 8));
  }
}

uint64_t read_uint64_t_from_file(const char* fname)
{
  uint64_t ret;
  size_t size = 0x100;

  FILE* f = fopen(fname, "r");
  char* buf = calloc(1, size + 1);

  // read content
  if (f == NULL) {
    error_out("fail to open %s", fname);
  }
  if (fread(buf, 1, size, f) <= 0) {
    error_out("fail to fread on %s", fname);
  }
  fclose(f);

  ret = (uint64_t)atol(buf);

  free(buf);

  return ret;
}

void setvbufs(void)
{
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);
  setvbuf(stderr, 0, _IONBF, 0);
}

static int _Noreturn exec_shell(void* arg)
{
  char* argv[] = { NULL };

  execvp("bash", arg ? (char**) arg : argv);

  err(EXIT_FAILURE, "execvp");
}

void _Noreturn fork_exec_shell(void)
{
  pid_t child_pid;
  void* child_stack;

  LOGI("Forking shell");

  CHECK_SYS(child_stack = (void*)((char*)mmap(NULL, CHILD_STACK_SZ,
	PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
        + CHILD_STACK_SZ), "mmap");

  CHECK_SYS(child_pid = clone(exec_shell, child_stack, SIGCHLD, NULL),
      "clone");

  LOGI("Launched shell (%d)", child_pid);

  wait(NULL);

  exit(EXIT_FAILURE);
}
