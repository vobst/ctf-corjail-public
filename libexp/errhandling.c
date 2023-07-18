#define _GNU_SOURCE
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "errhandling.h"

_Noreturn void error_out(const char* fmt, ...)
{
  char* buf;
  va_list ap;

  va_start(ap, fmt);
  if (vasprintf(&buf, fmt, ap) < 0) {
    perror("[error_out]");
    exit(-1);
  }
  va_end(ap);

  puts(buf);
  perror("[Reason] ");
  exit(-1);
}
