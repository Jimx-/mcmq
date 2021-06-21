#include "smp.h"
#include "const.h"
#include "fdt.h"
#include "global.h"
#include "irq.h"
#include "proto.h"
#include "sbi.h"
#include "string.h"

#include "ssd/hostif.h"
#include "ssd/ssd.h"

unsigned int hart_counter = 0;

#define BOOT_CPULOCALS_OFFSET 0
unsigned long __cpulocals_offset[CONFIG_SMP_MAX_CPUS] = {
    [0 ... CONFIG_SMP_MAX_CPUS - 1] = BOOT_CPULOCALS_OFFSET,
};

void* __cpu_stack_pointer[CONFIG_SMP_MAX_CPUS];
void* __cpu_task_pointer[CONFIG_SMP_MAX_CPUS];

static volatile int smp_commenced = 0;
static unsigned int cpu_nr;
static unsigned int bsp_hart_id;
static volatile unsigned int __cpu_ready;

extern char k_stacks_start;
static void* k_stacks;
#define get_k_stack_top(cpu) \
    ((void*)(((char*)(k_stacks)) + 2 * ((cpu) + 1) * KSTACK_SIZE))

DEFINE_CPULOCAL(unsigned int, cpu_number);

static void smp_start_cpu(int hart_id)
{
    unsigned int cpuid = cpu_nr++;

    __cpu_ready = -1;
    cpu_to_hart_id[cpuid] = hart_id;
    hart_to_cpu_id[hart_id] = cpuid;

    __asm__ __volatile__("fence rw, rw" : : : "memory");

    __cpu_stack_pointer[hart_id] = get_k_stack_top(cpuid);
    __cpu_task_pointer[hart_id] = (void*)(uintptr_t)cpuid;

    while (__cpu_ready != cpuid)
        ;
}

static int fdt_scan_hart(void* blob, unsigned long offset, const char* name,
                         int depth, void* arg)
{
    const char* type = fdt_getprop(blob, offset, "device_type", NULL);
    if (!type || strcmp(type, "cpu") != 0) return 0;

    const uint32_t* reg = fdt_getprop(blob, offset, "reg", NULL);
    if (!reg) return 0;

    uint32_t hart_id = be32_to_cpup(reg);
    if (hart_id >= CONFIG_SMP_MAX_CPUS) return 0;

    if (hart_id == bsp_hart_id) return 0;

    smp_start_cpu(hart_id);

    return 0;
}

static void setup_cpulocals(void)
{
    size_t size;
    char* ptr;
    int cpu;
    extern char _cpulocals_start[], _cpulocals_end[];

    size = roundup(_cpulocals_end - _cpulocals_start, PG_SIZE);
    ptr = vmalloc_pages((size * CONFIG_SMP_MAX_CPUS) >> PG_SHIFT, NULL);

    for (cpu = 0; cpu < CONFIG_SMP_MAX_CPUS; cpu++) {
        cpulocals_offset(cpu) = ptr - (char*)_cpulocals_start;
        memcpy(ptr, (void*)_cpulocals_start, _cpulocals_end - _cpulocals_start);

        get_cpu_var(cpu, cpu_number) = cpu;

        ptr += size;
    }
}

void send_ipi(unsigned int* cpu_mask)
{
#define MASK_LEN                                               \
    (CONFIG_SMP_MAX_CPUS + (sizeof(unsigned long) << 3) - 1) / \
        (sizeof(unsigned long) << 3)

    unsigned long hart_mask[MASK_LEN];
    int i, j;

    memset(hart_mask, 0, sizeof(hart_mask));
    for (i = 0; i < MASK_LEN; i++) {
        for (j = 0; j < sizeof(unsigned long) << 3; j++) {
            int cpuid = i * (sizeof(unsigned long) << 3) + j;

            if (cpuid >= CONFIG_SMP_MAX_CPUS) break;

            if (cpu_mask[i] & (1 << j)) {
                int hart_id = cpu_to_hart_id[cpuid];
                hart_mask[hart_id / (sizeof(unsigned long) << 3)] |=
                    1 << (hart_id % (sizeof(unsigned long) << 3));
            }
        }
    }

    sbi_send_ipi(hart_mask);
}

void send_ipi_single(unsigned int cpu)
{
    unsigned long hart_mask[MASK_LEN];
    int hart_id = cpu_to_hart_id[cpu];

    memset(hart_mask, 0, sizeof(hart_mask));
    hart_mask[hart_id / (sizeof(unsigned long) << 3)] =
        1 << (hart_id % (sizeof(unsigned long) << 3));

    sbi_send_ipi(hart_mask);
}

void smp_notify(unsigned int cpu) { send_ipi_single(cpu); }

void init_smp(unsigned int bsp_hart, void* dtb)
{
    bsp_hart_id = bsp_hart;

    cpu_to_hart_id[0] = bsp_hart_id;
    hart_to_cpu_id[bsp_hart_id] = 0;

    cpu_nr++;

    k_stacks = &k_stacks_start;

    setup_cpulocals();

    of_scan_fdt(fdt_scan_hart, NULL, dtb);
}

void smp_boot_ap(void)
{
    __cpu_ready = smp_processor_id();
    printk("smp: CPU %d is up\r\n", smp_processor_id());

    init_trap();
    local_irq_enable();

    hostif_init_cpu();

    while (!smp_commenced)
        ;

    while (1)
        wait_for_interrupt();
}

void smp_commence(void)
{
    __asm__ __volatile__("fence rw, rw" : : : "memory");
    smp_commenced = 1;
}

void software_interrupt(void)
{
    csr_clear(sip, SIE_SSIE);

    process_worker_queue();
}
