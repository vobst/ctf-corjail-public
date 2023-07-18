#ifndef XATTR_H
#define XATTR_H

#include <unistd.h>
#include <sys/xattr.h>

#include "errhandling.h"

extern char* xattr_file;

extern int init_xattr_file(void);

inline __attribute__((always_inline)) void set_xattr(void* xattr_value,
    size_t xattr_value_sz)
{
  CHECK_ZERO(setxattr(xattr_file, "user.foo", xattr_value,
	xattr_value_sz, 0), "setxattr");
}

#endif // XATTR_H

