#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>
#include <stdint.h>

#include "tsfence.h"
#include "utils.h"
#include "sched_stuff.h"

#define CPU_FREQ_FILE "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq"
#define SCHED_GRAN_FILE "/proc/sys/kernel/sched_min_granularity_ns"
#define CPU_INFO_FILE "/proc/cpuinfo"

static uint64_t min_cpu_freq;
static uint64_t min_granularity;
static uint64_t min_slice_tsc;

static uint64_t cpu_num;

static uint64_t get_cpu_freq(void)
{
  char* line_buf = NULL;
  FILE* f = NULL;

  // try to read from uint64_t first
  if (access(CPU_FREQ_FILE, R_OK) == 0) {
    return read_uint64_t_from_file(CPU_FREQ_FILE);
  }

  perror("INFO: Unable to get CPU frequency"
	 " from '" CPU_FREQ_FILE "', falling back to /proc/cpuinfo");

  // try to read from /proc/cpuinfo
  if (access(CPU_INFO_FILE, R_OK) == 0) {
    char* freq_buf;
    size_t n;
    double freq;

    CHECK_PTR(f = fopen(CPU_INFO_FILE, "r"), "fopen");

    while (!feof(f)) {
      if (getline(&line_buf, &n, f) < 0) {
	goto out;
      }
      if (line_buf && strstr(line_buf, "cpu MHz"))
	break;
    }

    if (!line_buf) {
      goto out;
    }
    CHECK_PTR(freq_buf = strstr(line_buf, ":"), "strstr");
    freq_buf += 1;
    freq = atof(freq_buf) * 1000; // MHz to KHz

    free(line_buf);
    fclose(f);
    return (uint64_t)freq;
  }

out:
  if (line_buf)
    free(line_buf);
  if (f)
    fclose(f);
  error_out("failed to get cpu frequency");
}

static uint64_t get_min_gran(void)
{
  // try to read from file first
  if (access(SCHED_GRAN_FILE, R_OK) == 0) {
    return read_uint64_t_from_file(SCHED_GRAN_FILE);
  }

  perror("INFO: Unable to get minimum scheduler granularity "
	 "from file, '" SCHED_GRAN_FILE "', falling back to default value");

  // return a commonly used default value
  return 3000000;
}

static uint64_t get_cpu_num(void)
{
  long ret = sysconf(_SC_NPROCESSORS_ONLN);
  if (ret < 0) {
    error_out("sysconf");
  }
  return (uint64_t)ret;
}

void ts_fence(void)
{
  cpu_set_t my_set;

  // Step1: get current affinity mask
  if (sched_getaffinity(0, sizeof(my_set), &my_set))
    error_out("fail to get cpu affinity");

  // Step2: pin CPU to current CPU to avoid task migration and get wrong tsc
  setaffinity(sched_getcpu());

  // Step3: do context switch detection
  register uint64_t start = __rdtsc();
  register uint64_t prev = start;
  register uint64_t now;
  while (1) {
    now = __rdtsc();
    if (unlikely(now - prev > min_slice_tsc))
      break;
    if (unlikely(now - start > 5 * min_slice_tsc)) {
      puts("[Info] Have been waiting for a reschedule for too long, "
	   "gonna yield and hope next time we get a new time slice");
      sched_yield();
      break;
    }
    prev = now;
  }

  // Step4: restore affinity mask
  if (sched_setaffinity(0, sizeof(my_set), &my_set))
    error_out("fail to set cpu affinity");
}

void ts_fence_nopin(void)
{
  register uint64_t start = __rdtsc();
  register uint64_t prev = start;
  register uint64_t now;
  while (1) {
    now = __rdtsc();
    if (unlikely(now - prev > min_slice_tsc))
      break;
    if (unlikely(now - start > 5 * min_slice_tsc)) {
      puts("INFO: Have been waiting for a reschedule for too long, "
	   "gonna yield and hope next time we get a new time slice");
      sched_yield();
      break;
    }
    prev = now;
  }
}


void tsfence_init(void)
{
  // initialize parameters
  min_cpu_freq = get_cpu_freq();    // kHz
  min_granularity = get_min_gran(); // ns
  cpu_num = get_cpu_num();

  printf("INFO: NCPU = %lu\n", cpu_num);
  printf("INFO: minimum scheduler granularity: %lu ns\n",
      min_granularity);
  printf("INFO: minimum CPU frequency: %lu kHz\n",
      min_cpu_freq);

  // calculate lower bound on cycles per time slice:
  // (min_cpu_freq * 10^3) * (min_granularity / 10^9 ) =
  //   min_cpu_freq * min_granularity / (10 ^ 6)
  min_slice_tsc = (min_cpu_freq / 1000) * (min_granularity / 1000);

  printf("INFO: lower bound on cycles per time slice: %lu\n",
      min_slice_tsc);
}
