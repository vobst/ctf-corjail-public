#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "leaks.h"

uint64_t kernel_base;
uint64_t vmemmap_base;
uint64_t page_offset_base;

long leak_scan_buffer(void* leak, uint64_t size, 
    void* needle_buf, uint64_t needle_buf_sz, uint64_t align)
{
  long offset = -1;

  if (align) {
    printf("ToDo: Implement alignment-aware scanning\n");
  }

  for (uint64_t current_offset = 0;
      current_offset + needle_buf_sz <= size; current_offset++)
  {
    if(!memcmp((void*)((uint64_t)leak + current_offset),
	  needle_buf, needle_buf_sz))
    {
      offset = (long)current_offset;
      break;
    }
  }

  return offset;
}
