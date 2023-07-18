#ifndef LEAKS_H
#define LEAKS_H

#include <stdint.h>

extern uint64_t kernel_base;
extern uint64_t vmemmap_base;
extern uint64_t page_offset_base;

extern long leak_scan_buffer(void* leak, uint64_t size, 
    void* needle_buf, uint64_t needle_buf_sz, uint64_t align);

#endif // LEAKS_H
