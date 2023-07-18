#ifndef POLL_STUFF_H
#define POLL_STUFF_H

#include <poll.h>
#include <stdint.h>
#include <pthread.h>

extern volatile int poll_list_corrupted;
extern pthread_barrier_t poll_list_barrier;
extern volatile uint64_t n_active_poll;

/* a poll thread that experiences poll_list corruption can instantly
 * spray objects to reclaim the victim object (arbitrary free)
 */
enum spray_object {
  OBJ_INVAL, // for sprays that _should_ not experience corruption
  OBJ_SEQ_OPS,
  OBJ_ROP,
  OBJ_TTY,
  OBJ_TTY_WRITE_BUF,
};

extern int create_poll_thread(int id, nfds_t nfds, int timeout,
    int barrier, enum spray_object reclaim_object);
extern int join_poll_threads(int num_threads);

#endif // POLL_STUFF_H
