#ifndef _PROTO_H_
#define _PROTO_H_

#include "proc.h"
#include "types.h"

#include <stddef.h>
#include <stdint.h>

/* directy_tty.c */
void disp_char(const char c);
void direct_put_str(const char* str);
int printk(const char* fmt, ...);
void panic(const char* fmt, ...);

/* memory.c */
void init_memory(void* dtb);
void* alloc_page(unsigned long* phys_addr);
void* vmalloc_pages(size_t nr_pages, unsigned long* phys_addr);
int vmfree(void* ptr, unsigned long len);
void copy_from_user(void* dst, const void* src, size_t len);

/* vm.c */
void vm_map(struct proc* p, unsigned long phys_addr, void* vir_addr,
            void* vir_end);
void vm_mapkernel(struct proc* p);
void* vm_mapio(unsigned long phys_addr, size_t size);

/* proc.c */
void init_proc();
struct proc* pick_proc();
void switch_to_user();

/* exc.c */
void init_trap();

/* trap.S */
void switch_context(struct proc* prev, struct proc* next);
void restore_user_context();

void switch_address_space(struct proc* p);

/* clock.c */
void init_timer(void* dtb);
uint64_t read_cycles();
void restart_local_timer();
void timer_interrupt();
void stop_context(struct proc* p);
time_ns_t current_time_ns(void);
void setup_timer_oneshot(time_ns_t time);

/* alloc.c */
void mem_init(unsigned long mem_start, unsigned long free_mem_size);
unsigned long alloc_pages(size_t nr_pages);
int free_mem(unsigned long base, unsigned long len);

/* slab.c */
void slabs_init();
void* slaballoc(size_t bytes);
void slabfree(void* mem, size_t bytes);
#define SLABALLOC(p)               \
    do {                           \
        p = slaballoc(sizeof(*p)); \
    } while (0)
#define SLABFREE(p)              \
    do {                         \
        slabfree(p, sizeof(*p)); \
        p = NULL;                \
    } while (0)

/* blk.c */
int init_blkdev();
int blk_rdwt(int write, unsigned int block_num, size_t count, uint8_t* buf);

/* irq.c */
void init_irq(void* dtb);
void init_irq_cpu(int cpu);
void irq_mask(int hwirq);
void irq_unmask(int hwirq);
void put_irq_handler(int irq, int (*handler)(int, void*), void* data);

/* smp.c */
void init_smp(unsigned int bsp_hart, void* dtb);
void smp_commence(void);
void software_interrupt(void);
void smp_notify(unsigned int cpu);
int riscv_of_parent_hartid(const void* blob, unsigned long offset);

/* vsock.c */
int init_vsock(void);
void virtio_vsock_tx_thread(void);
void virtio_vsock_set_recv_callback(void (*callback)(uint32_t, uint32_t,
                                                     const char*, size_t));
int virtio_vsock_connect(uint32_t dst_cid, uint32_t dst_port);
int virtio_vsock_send(uint32_t dst_cid, uint32_t dst_port, const char* buf,
                      size_t len);

/* ivshmem.c */
int init_ivshmem(void);
void ivshmem_copy_from(void* dst, shmem_addr_t src, size_t len);
void ivshmem_copy_to(shmem_addr_t dst, void* src, size_t len);

static inline void wait_for_interrupt(void) { __asm__ __volatile__("wfi"); }

/* lib/rand.c */
void init_genrand(unsigned long s);
unsigned long genrand_int32(void);
long genrand_int31(void);

#endif
