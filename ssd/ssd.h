#ifndef _SSD_SSD_H_
#define _SSD_SSD_H_

#include "flash.h"

#include "list.h"
#include "types.h"
#include <stddef.h>
#include <stdint.h>

typedef uint64_t lha_t; /* logical host address */
typedef uint64_t pda_t; /* physical device address */

#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9

#define THREAD_TSU 1
#define THREAD_WORKER_START 2

struct user_request {
    int do_write;
    uint16_t command_id;
    uint16_t qid;
    lha_t start_lba;
    unsigned int sector_count;

    struct list_head txn_list;
};

enum cache_mode {
    CM_NO_CACHE,
    CM_WRITE_CACHE,
};

struct ssd_config {
    size_t mapping_table_capacity;
    unsigned int channel_count;
    unsigned int nr_chips_per_channel;
    unsigned int channel_transfer_rate;
    unsigned int channel_width;
    struct flash_config flash_config;
};

/* ssd.c */
void ssd_init(struct ssd_config* config);
void ssd_init_config_default(struct ssd_config* config);

/* worker.c */
void init_ssd_worker(void);
void notify_worker(int worker);
int enqueue_user_request(int worker, struct user_request* req);
void process_worker_queue(void);
void release_user_request(struct user_request* req);
int submit_transaction(struct flash_transaction* txn);
int notify_transaction_complete(struct flash_transaction* txn);

/* data_cache.c */
void dc_handle_user_request(struct user_request* req);
void dc_transaction_complete(struct flash_transaction* txn);

/* amu.c */
void amu_init(size_t mt_capacity, unsigned int nr_channels,
              unsigned int nr_chips_per_channel, unsigned int nr_dies_per_chip,
              unsigned int nr_planes_per_die, unsigned int nr_blocks_per_plane,
              unsigned int nr_pages_per_block, unsigned int sectors_in_page);
void amu_dispatch(struct user_request* req);
void amu_notify_txn_complete(struct flash_transaction* txn);

/* block_manager.c */
void bm_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
             unsigned int nr_dies_per_chip, unsigned int nr_planes_per_die,
             unsigned int nr_blocks_per_plane, unsigned int nr_pages_per_block);
void bm_alloc_page(struct flash_address* addr, int for_gc);

/* tsu.c */
void tsu_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
              unsigned int nr_dies_per_chip, unsigned int nr_planes_per_die);
void tsu_kick(void);
void tsu_process_transaction(struct flash_transaction* txn);
void tsu_flush_queues(void);
void tsu_notify_channel_idle(unsigned int channel);
void tsu_notify_chip_idle(unsigned int channel, unsigned int chip);

/* nvm_ctlr.c */
void nvm_ctlr_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
                   unsigned int nr_dies_per_chip,
                   unsigned int nr_planes_per_die);
void nvm_ctlr_init_channel(unsigned int channel_id, unsigned int channel_width,
                           time_ns_t t_RC, time_ns_t t_DSC);
void nvm_ctlr_init_chip(unsigned int channel_id, unsigned int chip_id,
                        time_ns_t* read_latencies, time_ns_t* program_latencies,
                        time_ns_t erase_latency);
void nvm_ctlr_dispatch(struct list_head* txn_list);
enum bus_status nvm_ctlr_get_channel_status(unsigned int channel);
enum chip_status nvm_ctlr_get_chip_status(unsigned int channel,
                                          unsigned int chip);
void nvm_ctlr_timer_interrupt(void);

#endif
