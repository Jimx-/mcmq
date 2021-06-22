#include "ssd.h"
#include "hostif.h"
#include "smp.h"

#include <string.h>

void ssd_init_config_default(struct ssd_config* config)
{
    memset(config, 0, sizeof(*config));

    config->cache_mode = CM_NO_CACHE;
    config->mapping_table_capacity = 2 << 20;
    config->data_cache_capacity = 512 << 20;
    config->channel_count = 8;
    config->nr_chips_per_channel = 4;
    config->channel_transfer_rate = 300;
    config->channel_width = 1;
}

void ssd_init(struct ssd_config* config)
{
    int i, j;
    time_ns_t read_latencies[3], write_latencies[3];

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
                  config->flash_config.nr_planes_per_die);
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
            config->flash_config.nr_pages_per_block);

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

void ssd_timer_interrupt(void)
{
    unsigned int self = smp_processor_id();

    if (self == THREAD_TSU) nvm_ctlr_timer_interrupt();
}
