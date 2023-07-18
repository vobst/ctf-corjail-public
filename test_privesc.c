#define _GNU_SOURCE
#include <err.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEBUG

#include "./libexp/errhandling.h"
#include "./libexp/utils.h"

#define FLAG_c (1UL << 0)
#define FLAG_m (1UL << 1)
#define FLAG_f (1UL << 2)
#define FLAG_p (1UL << 3)
#define FLAG_s (1UL << 4)
#define FLAG_r (1UL << 5)

static const char* command = "/bin/sh -c '"
			     "echo Pid $$, euid `id -u`, uid `id -ru`, egid `id -g`, gid `id -rg` ; "
			     "cat /proc/self/status | grep 'Cap' ; "
			     "cat /proc/self/status | grep 'Seccomp' ; "
			     "echo Namespaces: ; readlink /proc/self/ns/*'";

static char** saved_argv;

static void _Noreturn usage(char* pname)
{
  fprintf(stderr, "Usage: %s [options] program [arg...]\n", pname);
  fprintf(stderr, "Options can be:\n");
  fprintf(stderr, "    -c   Update credentials\n");
  fprintf(stderr, "    -m   Update mount namespace and fs\n");
  fprintf(stderr, "    -p   Update pid namespace\n");
  fprintf(stderr, "    -s   Disable seccomp\n");
  fprintf(stderr, "    -r   Trigger ROP chain\n");
  fprintf(stderr, "    -f   fork before exec\n");
  exit(EXIT_FAILURE);
}

static void _Noreturn return_to_here(unsigned int flags)
{
  LOGD("after:");

  system(command);

  if (flags & FLAG_f) {
    if (!fork()) {
      execvp(saved_argv[optind], &saved_argv[optind]);
    } else {
      wait(NULL);
      exit(EXIT_SUCCESS);
    }
  } else {
    execvp(saved_argv[optind], &saved_argv[optind]);
  }

  err(EXIT_FAILURE, "execvp");
}

int main(int argc, char** argv)
{
  unsigned int flags, opt;

  saved_argv = argv;
  flags = 0;

  setvbufs();

  while ((int)(opt = (unsigned int)getopt(argc, argv, "rcmfsp")) != -1) {
    switch (opt) {
    case 'c':
      flags |= FLAG_c;
      LOGD("flag: %s", "FLAG_c");
      break;
    case 's':
      flags |= FLAG_s;
      LOGD("flag: %s", "FLAG_s");
      break;
    case 'p':
      flags |= FLAG_p;
      LOGD("flag: %s", "FLAG_p");
      break;
    case 'm':
      flags |= FLAG_m;
      LOGD("flag: %s", "FLAG_m");
      break;
    case 'f':
      flags |= FLAG_f;
      LOGD("flag: %s", "FLAG_f");
      break;
    case 'r':
      flags |= FLAG_r;
      LOGD("flag: %s", "FLAG_r");
      break;
    default:
      usage(argv[0]);
    }
  }

  LOGD("flags: 0x%04x", flags);

  if (optind >= argc)
    usage(argv[0]);

  LOGD("executing: %s", command);
  LOGD("before:");
  system(command);

  // trigger gdb script
  syscall(SYS_accept,		  // rax
      (int)(flags | (1UL << 31)), // rdi
      &return_to_here		  // rsi
  );

  if (flags & FLAG_r) {
    err(EXIT_FAILURE, "ROP did not work :(");
  } else {
    return_to_here(flags);
  }
}
