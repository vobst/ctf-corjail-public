#ifndef HEAP_DEFRAGMENT_H
#define HEAP_DEFRAGMENT_H

extern int defragment_kmalloc32(void);
extern int free_defragment_kmalloc32(int num);
extern int free_one_km32_slab(void);

#endif // HEAP_DEFRAGMENT_H
