#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "../config.h"
#include "errhandling.h"
#include "heap_defragment.h"

static int n_defragment_kmalloc32_fds;
static int defragment_kmalloc32_fds[N_DEFRAGMENT_KM32];

int defragment_kmalloc32(void)
{
  int ret = 0, fd;

  CHECK_ZERO(n_defragment_kmalloc32_fds,
      "invalid call to defragment_kmalloc32");

  for (int i = 0; i < N_DEFRAGMENT_KM32; i++) {
    CHECK_FD(fd = open("/proc/self/stat", O_RDONLY), "open stat");
    defragment_kmalloc32_fds[i] = fd;
    n_defragment_kmalloc32_fds++;
  }

  return ret;
}

/* free the last num defragmentation allocations */
int free_defragment_kmalloc32(int num)
{
  int ret = 0;

  if (unlikely(num > n_defragment_kmalloc32_fds || num < 0)) {
    return 1;
  }

  for (int i = 0; i < num; i++, n_defragment_kmalloc32_fds--) {
    CHECK_POS(close(defragment_kmalloc32_fds[n_defragment_kmalloc32_fds - 1]),
	"close defragment fd");
  }

  return ret;
}

/* free one slab worth of objects in kmalloc32 (most recent defragment 
 * allocations)
 */
int free_one_km32_slab(void)
{
  int ret = 0;

  CHECK_ZERO(free_defragment_kmalloc32(N_SLOTS_KM32), "free_defragment_kmalloc32");
  
  return ret;
}
