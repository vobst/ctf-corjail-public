#ifndef SCHED_STUFF_H
#define SCHED_STUFF_H

#include "errhandling.h"

#define EXPLOIT_CPU 0
#define OTHER_CPU 3

#define PIN(cpuid)	CHECK_ZERO(setaffinity(cpuid), "setaffinity")

extern int setaffinity(int cpu);

#endif // SCHED_STUFF_H
