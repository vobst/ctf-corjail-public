#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "errhandling.h"
#include "xattr.h"

#define MAX_XATTR_FILE_SIZE 0x100

/* the name of the file to set xattrs on */
char* xattr_file;

/* creates some file for which we can set extended attributes */
int init_xattr_file(void)
{
  char* home = NULL;
  int fd;
  int ret = 0;

  CHECK_PTR(xattr_file = malloc(MAX_XATTR_FILE_SIZE), "malloc");

  CHECK_PTR(home = getenv("HOME"), "getenv(HOME)");

  snprintf(xattr_file, MAX_XATTR_FILE_SIZE, "%s/hax", home);

  CHECK_FD(fd = open(xattr_file, O_CREAT | O_RDWR), "open xattr_file");

  CHECK_ZERO(chmod(xattr_file, S_IRUSR | S_IWUSR | S_IXUSR),
      "chmod xattr_file");

  close(fd);

  return ret;
}

