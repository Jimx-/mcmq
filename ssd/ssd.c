#include "ssd.h"
#include "byteorder.h"
#include "const.h"
#include "hostif.h"
#include "proto.h"
#include "smp.h"

#include "proto/ssd_config.pb-c.h"

#include <string.h>

static void* pb_alloc(void* opaque, size_t size)
{
    void* ptr;

    size = roundup(size, 4);
    ptr = slaballoc(size + sizeof(uint32_t));

    if (!ptr) {
        size = roundup(size, PG_SIZE);
        ptr = vmalloc_pages(size >> PG_SHIFT, NULL);
        size |= 1;
    }

    *(uint32_t*)ptr = (uint32_t)size;
    return ptr + sizeof(uint32_t);
}

static void pb_free(void* opaque, void* ptr)
{
    void* p = ptr - sizeof(uint32_t);
    uint32_t size = *(uint32_t*)p;

    if (size & 1)
        vmfree(p, size & ~1);
    else
        slabfree(p, size);
}

static ProtobufCAllocator pb_allocator = {
    .alloc = pb_alloc,
    .free = pb_free,
    .allocator_data = NULL,
};

void ssd_init_config_default(struct ssd_config* config)
{
    memset(config, 0, sizeof(*config));

    config->seed = 123;
    config->cache_mode = CM_NO_CACHE;
    config->mapping_table_capacity = 2 << 20;
    config->data_cache_capacity = 512 << 20;
    config->gc_threshold = 20;
    config->gc_hard_threshold = 200;
    config->block_selection_policy = BSP_GREEDY;
    config->channel_count = 8;
    config->nr_chips_per_channel = 4;
    config->channel_transfer_rate = 300;
    config->channel_width = 1;
}

static void init_config_from_pb(struct ssd_config* config,
                                Mcmq__SsdConfig* pb_config)
{
    struct flash_config* flash_config = &config->flash_config;
    Mcmq__FlashConfig* flash_config_pb = pb_config->flash_config;

    switch (flash_config_pb->technology) {
    case MCMQ__FLASH_TECHNOLOGY__FT_SLC:
        flash_config->technology = FT_SLC;
    case MCMQ__FLASH_TECHNOLOGY__FT_MLC:
        flash_config->technology = FT_MLC;
    case MCMQ__FLASH_TECHNOLOGY__FT_TLC:
        flash_config->technology = FT_TLC;
    default:
        break;
    }

    flash_config->page_read_latency_lsb =
        flash_config_pb->page_read_latency_lsb;
    flash_config->page_read_latency_csb =
        flash_config_pb->page_read_latency_csb;
    flash_config->page_read_latency_msb =
        flash_config_pb->page_read_latency_msb;
    flash_config->page_program_latency_lsb =
        flash_config_pb->page_program_latency_lsb;
    flash_config->page_program_latency_csb =
        flash_config_pb->page_program_latency_csb;
    flash_config->page_program_latency_msb =
        flash_config_pb->page_program_latency_msb;
    flash_config->block_erase_latency = flash_config_pb->block_erase_latency;

    flash_config->nr_dies_per_chip = flash_config_pb->nr_dies_per_chip;
    flash_config->nr_planes_per_die = flash_config_pb->nr_planes_per_die;
    flash_config->nr_blocks_per_plane = flash_config_pb->nr_blocks_per_plane;
    flash_config->nr_pages_per_block = flash_config_pb->nr_pages_per_block;
    flash_config->page_capacity = flash_config_pb->page_capacity;

    switch (pb_config->cache_mode) {
    case MCMQ__CACHE_MODE__CM_NO_CACHE:
        config->cache_mode = CM_NO_CACHE;
        break;
    case MCMQ__CACHE_MODE__CM_WRITE_CACHE:
        config->cache_mode = CM_WRITE_CACHE;
        break;
    default:
        break;
    }

    switch (pb_config->block_selection_policy) {
    case MCMQ__BLOCK_SELECTION_POLICY__BSP_GREEDY:
        config->block_selection_policy = BSP_GREEDY;
        break;
    default:
        break;
    }

    config->seed = pb_config->seed;
    config->mapping_table_capacity = pb_config->mapping_table_capacity;
    config->data_cache_capacity = pb_config->data_cache_capacity;
    config->gc_threshold = pb_config->gc_threshold;
    config->gc_hard_threshold = pb_config->gc_hard_threshold;
    config->channel_count = pb_config->channel_count;
    config->nr_chips_per_channel = pb_config->nr_chips_per_channel;
    config->channel_transfer_rate = pb_config->channel_transfer_rate;
    config->channel_width = pb_config->channel_width;
}

static void ssd_init_config(struct ssd_config* config)
{
    int i, j;
    time_ns_t read_latencies[3], write_latencies[3];

    printk("\r\nSSD config:\r\n");
    ssd_dump_config(config);

    init_genrand(config->seed);

    memset(read_latencies, 0, sizeof(read_latencies));
    memset(write_latencies, 0, sizeof(write_latencies));

    read_latencies[0] = config->flash_config.page_read_latency_lsb;
    read_latencies[1] = config->flash_config.page_read_latency_csb;
    read_latencies[2] = config->flash_config.page_read_latency_msb;
    write_latencies[0] = config->flash_config.page_program_latency_lsb;
    write_latencies[1] = config->flash_config.page_program_latency_csb;
    write_latencies[2] = config->flash_config.page_program_latency_msb;

    hostif_init(config->flash_config.page_capacity >> SECTOR_SHIFT);

    nvm_ctlr_init(config->channel_count, config->nr_chips_per_channel,
                  config->flash_config.nr_dies_per_chip,
                  config->flash_config.nr_planes_per_die,
                  config->flash_config.nr_blocks_per_plane,
                  config->flash_config.nr_pages_per_block);
    for (i = 0; i < config->channel_count; i++) {
        nvm_ctlr_init_channel(
            i, config->channel_width,
            (time_ns_t)(1000 / config->channel_transfer_rate * 2),
            (time_ns_t)(1000 / config->channel_transfer_rate * 2));

        for (j = 0; j < config->nr_chips_per_channel; j++) {
            nvm_ctlr_init_chip(i, j, read_latencies, write_latencies,
                               config->flash_config.block_erase_latency);
        }
    }

    dc_init(config->cache_mode,
            config->data_cache_capacity / config->flash_config.page_capacity);

    bm_init(config->channel_count, config->nr_chips_per_channel,
            config->flash_config.nr_dies_per_chip,
            config->flash_config.nr_planes_per_die,
            config->flash_config.nr_blocks_per_plane,
            config->flash_config.nr_pages_per_block,
            config->flash_config.page_capacity >> SECTOR_SHIFT,
            config->block_selection_policy, config->gc_threshold,
            config->gc_hard_threshold);

    amu_init(config->mapping_table_capacity, config->channel_count,
             config->nr_chips_per_channel,
             config->flash_config.nr_dies_per_chip,
             config->flash_config.nr_planes_per_die,
             config->flash_config.nr_blocks_per_plane,
             config->flash_config.nr_pages_per_block,
             config->flash_config.page_capacity >> SECTOR_SHIFT);

    tsu_init(config->channel_count, config->nr_chips_per_channel,
             config->flash_config.nr_dies_per_chip,
             config->flash_config.nr_planes_per_die);
}

static void ssd_config_recv_callback(uint32_t src_cid, uint32_t src_port,
                                     const char* buf, size_t len)
{
    Mcmq__SsdConfig* pb_config;
    struct ssd_config config;
    uint16_t msg_len;

    msg_len = *(const uint16_t*)buf;
    msg_len = be16_to_cpup(&msg_len);

    pb_config =
        mcmq__ssd_config__unpack(&pb_allocator, msg_len - 2, (uint8_t*)&buf[2]);
    init_config_from_pb(&config, pb_config);
    mcmq__ssd_config__free_unpacked(pb_config, &pb_allocator);

    ssd_init_config(&config);

    hostif_send_ready();
}

void ssd_init(void)
{
    virtio_vsock_set_recv_callback(ssd_config_recv_callback);
}

void ssd_timer_interrupt(void)
{
    unsigned int self = smp_processor_id();

    if (self == THREAD_TSU) nvm_ctlr_timer_interrupt();
}

void ssd_dump_config(struct ssd_config* config)
{
    printk("==============================\r\n");
    printk("Seed: %d\r\n", config->seed);

    printk("Cache mode: ");
    switch (config->cache_mode) {
    case CM_NO_CACHE:
        printk("NO");
        break;
    case CM_WRITE_CACHE:
        printk("WRITE");
        break;
    }
    printk("\r\n");

    printk("Mapping table capacity: %d\r\n", config->mapping_table_capacity);
    printk("Data cache capacity: %d\r\n", config->data_cache_capacity);
    printk("GC threshold (normal/hard): %d/%d\r\n", config->gc_threshold,
           config->gc_hard_threshold);

    printk("Block selection policy: ");
    switch (config->block_selection_policy) {
    case BSP_GREEDY:
        printk("GREEDY");
        break;
    }
    printk("\r\n");

    printk("Channel count: %d\r\n", config->channel_count);
    printk("#Chips per channel: %d\r\n", config->nr_chips_per_channel);
    printk("Channel transfer rate: %d\r\n", config->channel_transfer_rate);
    printk("Channel width: %d\r\n", config->channel_width);

    printk("Flash config:\r\n");

    printk("Technology: ");
    switch (config->flash_config.technology) {
    case FT_SLC:
        printk("SLC");
        break;
    case FT_MLC:
        printk("MLC");
        break;
    case FT_TLC:
        printk("TLC");
        break;
    }
    printk("\r\n");

    printk("  Read latency (LSB/CSB/MSB): %d/%d/%d\r\n",
           config->flash_config.page_read_latency_lsb,
           config->flash_config.page_read_latency_csb,
           config->flash_config.page_read_latency_msb);
    printk("  Program latency (LSB/CSB/MSB): %d/%d/%d\r\n",
           config->flash_config.page_program_latency_lsb,
           config->flash_config.page_program_latency_csb,
           config->flash_config.page_program_latency_msb);
    printk("  Erase latency: %d\r\n", config->flash_config.block_erase_latency);

    printk("  #Dies per chip: %d\r\n", config->flash_config.nr_dies_per_chip);
    printk("  #Planes per die: %d\r\n", config->flash_config.nr_planes_per_die);
    printk("  #Blocks per plane: %d\r\n",
           config->flash_config.nr_blocks_per_plane);
    printk("  #Pages per block: %d\r\n",
           config->flash_config.nr_pages_per_block);
    printk("  Page capacity: 0x%x\r\n", config->flash_config.page_capacity);

    printk("==============================\r\n");
}
