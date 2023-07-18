#ifndef TTY_WRITE_STUFF_H
#define TTY_WRITE_STUFF_H

#include <asm/termbits.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "errhandling.h"

// suspends output
// https://man7.org/linux/man-pages/man3/tcflow.3.html
void inline turn_off_ptmx(int fd)
{
  CHECK_ZERO(ioctl(fd, TCXONC, TCOOFF), "ioctl: turn off tty");
}

// flush non-transmitted output data and non-read input data
// https://man7.org/linux/man-pages/man3/tcflush.3p.html
void inline flush_ptmx(int fd)
{
  CHECK_ZERO(ioctl(fd, TCFLSH, TCOFLUSH),
      "ioctl: flush tty output");
  CHECK_ZERO(ioctl(fd, TCFLSH, TCIFLUSH),
      "ioctl: flush tty inpt");
}

void inline make_ptmx_non_blocking(int fd)
{
  int flags = 0;
  CHECK_SYS(flags = fcntl(fd, F_GETFL, 0), "fnctl: get tty flags");
  CHECK_ZERO(fcntl(fd, F_SETFL, flags | O_NONBLOCK),
      "fnctl: make tty nonblocking");
}

void inline spray_tty_write_buffer(int fd, void* buf, size_t size)
{
  assert(write(fd, buf, size) == -1 && errno == EAGAIN);
}

void inline spray_tty_write_buffers(int* fds, int num,
    void* buf, size_t size)
{
  for (int i = 0; i < num; i++) {
    spray_tty_write_buffer(fds[i], buf, size);
  }
}

extern int init_tty_nonblock_suspended(int* fds, int num);
extern void update_tty_write_buffer(int fd, void* buf, size_t size);

#endif // TTY_WRITE_STUFF_H
