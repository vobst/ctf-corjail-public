#ifndef ERRHANDLING_H
#define ERRHANDLING_H

#include <err.h>

#define likely(x)      __builtin_expect(!!(x), 1) 
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define CHECK_ZERO(checkexpr, errmsg)	if (unlikely(checkexpr)) \
  err(1, "[!] [ERR] %s", errmsg)

#define CHECK_SYS(checkexpr, errmsg)	({			\
    __auto_type __res = (checkexpr);				\
    if (unlikely(__res == (__typeof__(__res))-1)) 		\
  	err(1, "[!] [ERR] %s", (errmsg));			\
    __res;							\
    })

#define CHECK_NOT_ZERO(checkexpr, errmsg)	if (unlikely(!(checkexpr))) \
  err(1, "[!] [ERR] %s", errmsg)

#define CHECK_POS(x, errmsg)	if (unlikely((x) < 0)) \
  err(1, "[!] [ERR] %s", errmsg)

#define CHECK_FD(checkfd, errmsg)	CHECK_POS(checkfd, errmsg)

#define CHECK_PTR(checkptr, errmsg)	CHECK_NOT_ZERO(checkptr, errmsg)

extern _Noreturn void error_out(const char* fmt, ...);

#endif // ERRHANDLING_H
