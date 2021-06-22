#include "const.h"
#include "global.h"
#include "irq.h"
#include "pci.h"
#include "proto.h"
#include "smp.h"
#include "virtio.h"
#include "vm.h"

#include "ssd/hostif.h"
#include "ssd/ssd.h"

#include <string.h>

void kernel_main(unsigned int hart_id, void* dtb_phys)
{
    void* dtb = __va(dtb_phys);
    struct ssd_config config;

    init_memory(dtb);
    init_smp(hart_id, dtb);
    init_timer(dtb);
    init_irq(dtb);
    init_virtio_mmio(dtb);
    init_pci_host(dtb);

    init_trap();
    /* init_proc(); */

    init_irq_cpu(smp_processor_id());
    local_irq_enable();

    init_ivshmem();

    init_vsock();

    ssd_init_config_default(&config);

    config.flash_config.technology = FT_MLC;
    config.flash_config.page_read_latency_lsb = 75000;
    config.flash_config.page_read_latency_csb = 75000;
    config.flash_config.page_read_latency_msb = 75000;
    config.flash_config.page_program_latency_lsb = 750000;
    config.flash_config.page_program_latency_csb = 750000;
    config.flash_config.page_program_latency_msb = 750000;
    config.flash_config.block_erase_latency = 3800000;

    config.flash_config.nr_dies_per_chip = 2;
    config.flash_config.nr_planes_per_die = 2;
    config.flash_config.nr_blocks_per_plane = 2048;
    config.flash_config.nr_pages_per_block = 256;
    config.flash_config.page_capacity = 8192;

    config.cache_mode = CM_WRITE_CACHE;

    ssd_init(&config);

    hostif_init_cpu();

    virtio_vsock_connect(VSOCK_HOST_CID, VSOCK_HOST_PORT);

    /* init_blkdev(); */

    /* blk_rdwt(0, 0, 1, buf); */
    /* blk_rdwt(0, 0, 1, buf); */
    /* blk_rdwt(0, 0, 1, buf); */

    /* printk("%d\n", sizeof(struct reg_context)); */

    smp_commence();

    while (1)
        wait_for_interrupt();

    /* unreachable */
    return;
}
