#include "const.h"
#include "csr.h"
#include "fdt.h"
#include "global.h"
#include "proc.h"
#include "proto.h"
#include "sbi.h"

#include <stdint.h>

unsigned int timebase_freq;
unsigned long context_switch_clock = 0;

extern void ssd_timer_interrupt(void);

void init_timer(void* dtb)
{
    unsigned long cpu = fdt_path_offset(dtb, "/cpus");

    const uint32_t* prop;
    if ((prop = fdt_getprop(dtb, cpu, "timebase-frequency", NULL)) != NULL) {
        timebase_freq = be32_to_cpup(prop);
    } else {
        panic("timebase-frequency not found in the DTS");
    }
}

uint64_t read_cycles()
{
    uint64_t n;

    /* TODO: spike complains about this, should use mtime to get cycles */
    __asm__ __volatile__("rdtime %0" : "=r"(n));
    return n;
}

time_ns_t current_time_ns(void)
{
    return read_cycles() * (1000000000ULL / timebase_freq);
}

void restart_local_timer()
{
    csr_set(sie, SIE_STIE);
    uint64_t cycles = read_cycles();
    /* sbi_set_timer(cycles + timebase_freq / SYSTEM_HZ); */
    sbi_set_timer(cycles + timebase_freq);
}

void setup_timer_oneshot(time_ns_t time)
{
    csr_set(sie, SIE_STIE);
    sbi_set_timer(time * timebase_freq / 1000000000ULL);
}

void timer_interrupt()
{
    csr_clear(sie, SIE_STIE);
    ssd_timer_interrupt();
}

void stop_context(struct proc* p)
{
    uint64_t cycles = read_cycles();
    uint64_t delta = cycles - context_switch_clock;

    uint64_t nsec = delta * 1000000000ULL / timebase_freq;

    if (p->counter_ns < nsec) {
        p->counter_ns = 0;
    } else {
        p->counter_ns -= nsec;
    }

    context_switch_clock = cycles;
}
