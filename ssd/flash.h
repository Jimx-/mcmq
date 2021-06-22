#ifndef _SSD_FLASH_H_
#define _SSD_FLASH_H_

#include "list.h"
#include "types.h"
#include <stdint.h>

typedef uint64_t lpa_t;
typedef uint64_t ppa_t;
typedef uint64_t page_bitmap_t;

#define NO_LPA UINT64_MAX
#define NO_PPA UINT64_MAX

struct flash_address {
    unsigned int channel_id;
    unsigned int chip_id;
    unsigned int die_id;
    unsigned int plane_id;
    unsigned int block_id;
    unsigned int page_id;
};

enum txn_type {
    TXN_UNKNOWN,
    TXN_READ,
    TXN_WRITE,
    TXN_ERASE,
};

enum txn_source {
    TS_USER_IO,
    TS_MAPPING,
    TS_GC,
};

struct user_request;

struct flash_transaction {
    struct list_head list;
    struct list_head queue;
    struct list_head waiting_list;
    struct user_request* req;
    enum txn_type type;
    enum txn_source source;
    int worker;

    lpa_t lpa;
    ppa_t ppa;
    struct flash_address addr;
    unsigned long length;
    page_bitmap_t bitmap;
    int ppa_ready;
    void* opaque;

    struct flash_transaction* related_read;
    struct flash_transaction* related_write;
};

enum flash_technology {
    FT_SLC,
    FT_MLC,
    FT_TLC,
};

struct flash_config {
    enum flash_technology technology;

    time_ns_t page_read_latency_lsb;
    time_ns_t page_read_latency_csb;
    time_ns_t page_read_latency_msb;
    time_ns_t page_program_latency_lsb;
    time_ns_t page_program_latency_csb;
    time_ns_t page_program_latency_msb;
    time_ns_t block_erase_latency;

    unsigned int nr_dies_per_chip;
    unsigned int nr_planes_per_die;
    unsigned int nr_blocks_per_plane;
    unsigned int nr_pages_per_block;
    unsigned int page_capacity;
};

enum bus_status {
    BUS_IDLE,
    BUS_BUSY,
};

enum chip_status {
    CS_IDLE,
    CS_CMD_DATA_IN,
    CS_WAIT_FOR_DATA_OUT,
    CS_DATA_OUT,
    CS_READING,
    CS_WRITING,
    CS_ERASING,
};

enum flash_command_code {
    CMD_READ = 0x0030,
    CMD_READ_PAGE = 0x0030,
    CMD_READ_PAGE_MULTIPLANE = 0x0032,
    CMD_PROGRAM = 0x8000,
    CMD_PROGRAM_PAGE = 0x8010,
    CMD_PROGRAM_PAGE_MULTIPLANE = 0x8011,
    CMD_ERASE = 0x6000,
    CMD_ERASE_BLOCK = 0x60d0,
    CMD_ERASE_BLOCK_MULTIPLANE = 0x60d1,
};

struct flash_command {
    enum flash_command_code cmd_code;
    unsigned int nr_addrs;
    struct flash_address addr;
};

#endif
