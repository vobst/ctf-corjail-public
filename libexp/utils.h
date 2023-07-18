#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000

#define MIN(x, y)	((x) < (y) ? (x) : (y))

#define ALIGN(x, sz) (((x) + (sz) - 1) & ~((sz)-1))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define PAGE_SHIFT 12
#define PAGE_SZ (1UL << PAGE_SHIFT)
#define CHILD_STACK_SZ (0x8 * PAGE_SZ)
#define PAGE_MASK (~(PAGE_SZ-1))
#define PAGE_ALIGN(x) ((x) & PAGE_MASK)
#define DIR_2_PADDR(x) (((uint64_t)(x)) - page_offset_base)
#define PADDR_2_DIR(x) (((uint64_t)(x)) + page_offset_base)
#define PADDR_2_PFN(x) (((uint64_t)(x)) >> PAGE_SHIFT)
#define STRUCT_PAGE_SZ 64
#define PADDR_2_PAGE(x) (vmemmap_base + PADDR_2_PFN(x) * STRUCT_PAGE_SZ)

#define LOG(fmt, ...) do { 	\
  printf(fmt, ##__VA_ARGS__); 	\
  } while(0)

#define LOGE(fmt, ...) ({           \
        LOG("[!] " fmt "\n", ##__VA_ARGS__);    \
})

#define LOGS(fmt, ...) ({           \
        LOG("[+] " fmt "\n", ##__VA_ARGS__);    \
})

#ifndef QUIET
#define LOGI(fmt, ...) ({           \
        LOG("[=] " fmt "\n", ##__VA_ARGS__);    \
})
#define HEXDUMPI(x, y) ({		\
    hex_print(x, y);			\
})
#else
#define LOGI(fmt, ...) ({})
#define HEXDUMPI(x, y) ({})
#endif

#ifdef DEBUG
#define LOGD(fmt, ...) ({           \
        LOG("[>] " fmt "\n", ##__VA_ARGS__);    \
})
#define HEXDUMPD(x, y) ({		\
    hex_print(x, y);			\
})
#else
#define LOGD(fmt, ...) ({})
#define HEXDUMPD(x, y) ({})
#endif // DEBUG

extern void hex_print(void* addr, size_t len);
extern uint64_t read_uint64_t_from_file(const char* fname);
extern void setvbufs(void);
extern void _Noreturn fork_exec_shell(void);

#endif // UTILS_H
