#include "const.h"
#include "flash.h"
#include "proto.h"
#include "ssd.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct nvm_ctlr_stats {
    size_t read_cmds;
    size_t multiplane_read_cmds;
    size_t program_cmds;
    size_t multiplane_program_cmds;
    size_t erase_cmds;
    size_t multiplane_erase_cmds;
};

static struct nvm_ctlr_stats stats;

struct channel_data {
    unsigned int channel_id;
    enum bus_status status;
    unsigned int channel_width;
    time_ns_t t_RC;
    time_ns_t t_DSC;

    struct list_head waiting_read_xfer;
};

struct page {
    struct page_metadata metadata;
};

struct block_data {
    struct page* pages;
};

struct plane_data {
    struct block_data* blocks;
};

struct die_data {
    struct list_head list;
    struct list_head active_txns;
    time_ns_t data_transfer_time;

    struct plane_data* planes;

    struct flash_command cmd_buf;
    struct flash_command* active_cmd;
    struct flash_command* current_cmd;
    time_ns_t cmd_finish_time;

    struct flash_transaction* active_xfer;
    time_ns_t xfer_complete_time;

    time_ns_t exec_start_time;
};

struct chip_data {
    unsigned int chip_id;
    struct channel_data* channel;
    enum flash_technology technology;
    time_ns_t read_latencies[3];
    time_ns_t program_latencies[3];
    time_ns_t erase_latency;

    enum chip_status status;
    struct die_data* dies;
    unsigned int active_dies;

    struct list_head cmd_xfer_queue;
    struct die_data* current_xfer;
    time_ns_t xfer_complete_time;
    unsigned int nr_waiting_read_xfers;

    time_ns_t last_xfer_start;
    time_ns_t exec_start_time;

    time_ns_t total_xfer_time;
    time_ns_t total_exec_time;
    time_ns_t total_overlapped_time;
};

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die, blocks_per_plane, pages_per_block;

static struct chip_data** chip_data;
static struct channel_data* channel_data;

static void complete_chip_transfer(struct chip_data* chip);

static inline time_ns_t
nvddr2_data_in_transfer_time(struct channel_data* channel, size_t size)
{
    return (size / channel->channel_width / 2) * channel->t_RC;
}

static inline time_ns_t
nvddr2_data_out_transfer_time(struct channel_data* channel, size_t size)
{
    return (size / channel->channel_width / 2) * channel->t_DSC;
}

static inline void get_metadata(struct flash_address* addr,
                                struct page_metadata* metadata)
{
    *metadata = chip_data[addr->chip_id]
                    ->dies[addr->die_id]
                    .planes[addr->plane_id]
                    .blocks[addr->block_id]
                    .pages[addr->page_id]
                    .metadata;
}

void nvm_ctlr_get_metadata(struct flash_address* addr,
                           struct page_metadata* metadata)
{
    get_metadata(addr, metadata);
}

static inline void set_metadata(struct flash_address* addr,
                                struct page_metadata* metadata)
{
    chip_data[addr->chip_id]
        ->dies[addr->die_id]
        .planes[addr->plane_id]
        .blocks[addr->block_id]
        .pages[addr->page_id]
        .metadata = *metadata;
}

static inline get_command_latency(struct chip_data* chip,
                                  enum flash_command_code cmd_code,
                                  unsigned int page_id)
{
    int latency_type = 0;

    switch (chip->technology) {
    case FT_MLC:
        latency_type = page_id & 1;
        break;
    case FT_TLC:
        latency_type = (page_id <= 5)
                           ? 0
                           : ((page_id <= 7) ? 1 : (((page_id - 8) >> 1) % 3));
        break;
    default:
        break;
    }

    switch (cmd_code) {
    case CMD_READ_PAGE:
    case CMD_READ_PAGE_MULTIPLANE:
        return chip->read_latencies[latency_type];
        break;
    case CMD_PROGRAM_PAGE:
    case CMD_PROGRAM_PAGE_MULTIPLANE:
        return chip->program_latencies[latency_type];
        break;
    case CMD_ERASE_BLOCK:
    case CMD_ERASE_BLOCK_MULTIPLANE:
        return chip->erase_latency;
        break;
    default:
        assert(FALSE);
        break;
    }
}

static void init_page(struct page* page) { page->metadata.lpa = NO_LPA; }

static void init_block(struct block_data* block)
{
    /* int i; */

    /* for (i = 0; i < pages_per_block; i++) */
    /*     init_page(&block->pages[i]); */
}

static void init_plane(struct plane_data* plane)
{
    int i;

    for (i = 0; i < blocks_per_plane; i++)
        init_block(&plane->blocks[i]);
}

static void init_die(struct die_data* die)
{
    int i;

    INIT_LIST_HEAD(&die->active_txns);

    die->exec_start_time = INVALID_TIME;

    for (i = 0; i < planes_per_die; i++)
        init_plane(&die->planes[i]);
}

static void set_channel_status(struct channel_data* channel,
                               enum bus_status status)
{
    channel->status = status;
}

static void set_chip_status(struct chip_data* chip, enum chip_status status)
{
    chip->status = status;
}

static void init_chip(struct chip_data* chip)
{
    int i;

    INIT_LIST_HEAD(&chip->cmd_xfer_queue);
    set_chip_status(chip, CS_IDLE);

    chip->last_xfer_start = INVALID_TIME;
    chip->exec_start_time = INVALID_TIME;

    for (i = 0; i < dies_per_chip; i++)
        init_die(&chip->dies[i]);
}

static void alloc_controller(void)
{
    size_t nr_ptrs, nr_chips, nr_dies, nr_planes, nr_blocks, nr_pages,
        alloc_size;
    void* buf;
    void** cur_ptr;
    size_t offset;
    struct chip_data* cur_chip;
    struct die_data* cur_die;
    struct plane_data* cur_plane;
    struct block_data* cur_block;
    struct page* cur_page;
    int i, j, k, l, m;

    nr_chips = channel_count * chips_per_channel;
    nr_dies = nr_chips * dies_per_chip;
    nr_planes = nr_dies * planes_per_die;
    nr_blocks = nr_planes * blocks_per_plane;
    nr_pages = nr_blocks * pages_per_block;
    nr_ptrs = channel_count;

    alloc_size = nr_ptrs * sizeof(void*) + nr_chips * sizeof(struct chip_data) +
                 nr_dies * sizeof(struct die_data) +
                 channel_count * sizeof(struct channel_data) +
                 nr_planes * sizeof(struct plane_data) +
                 nr_blocks * sizeof(struct block_data) +
                 nr_pages * sizeof(struct page);
    alloc_size = roundup(alloc_size, PG_SIZE);

    buf = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);
    assert(buf);

    cur_ptr = (void**)buf;
    offset = nr_ptrs * sizeof(void*);

    cur_chip = (struct chip_data*)(buf + offset);
    offset += nr_chips * sizeof(struct chip_data);

    cur_die = (struct die_data*)(buf + offset);
    offset += nr_dies * sizeof(struct die_data);

    channel_data = (struct channel_data*)(buf + offset);
    offset += channel_count * sizeof(struct channel_data);

    cur_plane = (struct plane_data*)(buf + offset);
    offset += nr_planes * sizeof(struct plane_data);

    cur_block = (struct block_data*)(buf + offset);
    offset += nr_blocks * sizeof(struct block_data);

    cur_page = (struct page*)(buf + offset);

    chip_data = (struct chip_data**)cur_ptr;
    cur_ptr += channel_count;

    for (i = 0; i < channel_count; i++) {
        struct channel_data* channel = &channel_data[i];
        memset(channel, 0, sizeof(*channel));
        chip_data[i] = cur_chip;
        cur_chip += chips_per_channel;
        channel->channel_id = i;
        channel->status = BUS_IDLE;

        for (j = 0; j < chips_per_channel; j++) {
            struct chip_data* chip = &chip_data[i][j];
            memset(chip, 0, sizeof(*chip));
            chip->chip_id = j;
            chip->channel = channel;
            chip->dies = cur_die;
            cur_die += dies_per_chip;

            for (k = 0; k < dies_per_chip; k++) {
                struct die_data* die = &chip->dies[k];
                memset(die, 0, sizeof(*die));
                die->planes = cur_plane;
                cur_plane += planes_per_die;

                for (l = 0; l < planes_per_die; l++) {
                    struct plane_data* plane = &die->planes[l];
                    plane->blocks = cur_block;
                    cur_block += blocks_per_plane;

                    for (m = 0; m < blocks_per_plane; m++) {
                        struct block_data* block = &plane->blocks[m];
                        block->pages = cur_page;
                        cur_page += pages_per_block;
                    }
                }
            }

            init_chip(chip);
        }
    }
}

enum bus_status nvm_ctlr_get_channel_status(unsigned int channel)
{
    return channel_data[channel].status;
}

enum chip_status nvm_ctlr_get_chip_status(unsigned int channel,
                                          unsigned int chip)
{
    assert(channel < channel_count && chip < chips_per_channel);
    return chip_data[channel][chip].status;
}

int nvm_ctlr_is_die_busy(unsigned int channel, unsigned int chip,
                         unsigned int die)
{
    assert(channel < channel_count && chip < chips_per_channel &&
           die < dies_per_chip);
    return chip_data[channel][chip].dies[die].active_cmd != NULL;
}

static void rearm_timer(void)
{
    int i, j, k;
    time_ns_t min_time = UINT64_MAX;

    for (i = 0; i < channel_count; i++) {
        for (j = 0; j < chips_per_channel; j++) {
            struct chip_data* chip = &chip_data[i][j];

            if (chip->current_xfer) {
                if (min_time > chip->xfer_complete_time) {
                    min_time = chip->xfer_complete_time;
                }
            }

            for (k = 0; k < dies_per_chip; k++) {
                struct die_data* die = &chip->dies[k];

                if (die->current_cmd) {
                    if (min_time > die->cmd_finish_time) {
                        min_time = die->cmd_finish_time;
                    }
                }

                if (die->active_xfer) {
                    if (min_time > die->xfer_complete_time) {
                        min_time = die->xfer_complete_time;
                    }
                }
            }
        }
    }

    if (min_time != UINT64_MAX) {
        setup_timer_oneshot(min_time);
    }
}

static int start_cmd_data_transfer(struct chip_data* chip)
{
    struct die_data* die;
    time_ns_t now;

    /* if (chip->status != CS_IDLE) return FALSE; */
    assert(!chip->current_xfer);

    if (list_empty(&chip->cmd_xfer_queue)) return FALSE;

    die = list_entry(chip->cmd_xfer_queue.next, struct die_data, list);
    list_del(&die->list);

    now = current_time_ns();
    set_chip_status(chip, CS_CMD_DATA_IN);
    chip->current_xfer = die;
    chip->last_xfer_start = now;
    chip->xfer_complete_time = now + die->data_transfer_time;

    if (!die->data_transfer_time) complete_chip_transfer(chip);

    return TRUE;
}

static int start_data_out_transfer(struct channel_data* channel)
{
    struct flash_transaction* txn = NULL;
    struct chip_data* chip;
    struct die_data* die;
    time_ns_t now;

    if (channel->status != BUS_IDLE) return FALSE;

    if (!list_empty(&channel->waiting_read_xfer))
        txn = list_entry(channel->waiting_read_xfer.next,
                         struct flash_transaction, waiting_list);

    if (!txn) return FALSE;

    list_del(&txn->waiting_list);

    chip = &chip_data[channel->channel_id][txn->addr.chip_id];
    die = &chip->dies[txn->addr.die_id];
    assert(!die->active_xfer);

    now = current_time_ns();
    set_chip_status(chip, CS_DATA_OUT);
    die->active_xfer = txn;
    chip->last_xfer_start = now;
    die->xfer_complete_time =
        now + nvddr2_data_out_transfer_time(channel, txn->length);
    set_channel_status(channel, BUS_BUSY);

    return TRUE;
}

static int start_die_command(struct chip_data* chip, struct flash_command* cmd)
{
    time_ns_t now;
    struct die_data* die = &chip->dies[cmd->addrs[0].die_id];

    if (cmd->nr_addrs > 1)
        assert(cmd->cmd_code != CMD_READ_PAGE &&
               cmd->cmd_code != CMD_PROGRAM_PAGE &&
               cmd->cmd_code != CMD_ERASE_BLOCK);

    now = current_time_ns();
    die->exec_start_time = now;
    die->cmd_finish_time =
        now + get_command_latency(chip, cmd->cmd_code, cmd->addrs[0].page_id);
    die->current_cmd = cmd;

    if (!chip->active_dies) chip->exec_start_time = now;
    chip->active_dies++;

    return TRUE;
}

static void dispatch_read(struct channel_data* channel, struct chip_data* chip,
                          struct die_data* die)
{
    /* Ignore command read latency. */
    die->data_transfer_time = 0;
    list_add_tail(&die->list, &chip->cmd_xfer_queue);

    start_cmd_data_transfer(chip);
}

static void dispatch_write(struct channel_data* channel, struct chip_data* chip,
                           struct die_data* die)
{
    struct flash_transaction* txn;
    time_ns_t transfer_time = 0;

    list_for_each_entry(txn, &die->active_txns, queue)
    {
        transfer_time += nvddr2_data_in_transfer_time(channel, txn->length);
    }

    die->data_transfer_time = transfer_time;
    list_add_tail(&die->list, &chip->cmd_xfer_queue);

    start_cmd_data_transfer(chip);
}

static void dispatch_erase(struct channel_data* channel, struct chip_data* chip,
                           struct die_data* die)
{
    /* Ignore command read latency. */
    die->data_transfer_time = 0;
    list_add_tail(&die->list, &chip->cmd_xfer_queue);

    start_cmd_data_transfer(chip);
}

void nvm_ctlr_dispatch(struct list_head* txn_list)
{
    struct flash_transaction* head;
    struct flash_transaction* txn;
    struct channel_data* channel;
    struct chip_data* chip;
    struct die_data* die;
    unsigned int txn_count = 0;

    if (list_empty(txn_list)) return;

    head = list_entry(txn_list->next, struct flash_transaction, queue);
    channel = &channel_data[head->addr.channel_id];
    chip = &chip_data[head->addr.channel_id][head->addr.chip_id];
    die = &chip->dies[head->addr.die_id];

    assert(!die->active_cmd);

    assert(channel->status == BUS_IDLE || chip->current_xfer);

    die->active_cmd = &die->cmd_buf;
    list_for_each_entry(txn, txn_list, queue)
    {
        assert(txn_count < MAX_CMD_ADDRS);

        struct flash_address* addr = &die->active_cmd->addrs[txn_count];
        struct page_metadata* metadata =
            &die->active_cmd->metadata[txn_count++];
        *addr = txn->addr;
        metadata->lpa = txn->lpa;

        txn->dispatch_time = current_time_ns();
    }

    die->active_cmd->nr_addrs = txn_count;

    list_splice_init(txn_list, &die->active_txns);

    set_channel_status(channel, BUS_BUSY);

    switch (head->type) {
    case TXN_READ:
        if (txn_count == 1) {
            stats.read_cmds++;
            die->active_cmd->cmd_code = CMD_READ_PAGE;
        } else {
            stats.multiplane_read_cmds++;
            die->active_cmd->cmd_code = CMD_READ_PAGE_MULTIPLANE;
        }

        dispatch_read(channel, chip, die);
        break;
    case TXN_WRITE:
        if (txn_count == 1) {
            stats.program_cmds++;
            die->active_cmd->cmd_code = CMD_PROGRAM_PAGE;
        } else {
            stats.multiplane_program_cmds++;
            die->active_cmd->cmd_code = CMD_PROGRAM_PAGE_MULTIPLANE;
        }

        dispatch_write(channel, chip, die);
        break;
    case TXN_ERASE:
        if (txn_count == 1) {
            stats.erase_cmds++;
            die->active_cmd->cmd_code = CMD_ERASE_BLOCK;
        } else {
            stats.multiplane_erase_cmds++;
            die->active_cmd->cmd_code = CMD_ERASE_BLOCK_MULTIPLANE;
        }

        dispatch_erase(channel, chip, die);
        break;
    }

    rearm_timer();
}

static void complete_chip_transfer(struct chip_data* chip)
{
    struct die_data* die = chip->current_xfer;
    struct flash_transaction *txn,
        *head =
            list_entry(die->active_txns.next, struct flash_transaction, queue);
    struct channel_data* channel = &channel_data[head->addr.channel_id];
    time_ns_t xfer_time;

    assert(!list_empty(&die->active_txns));

    xfer_time = current_time_ns() - chip->last_xfer_start;
    chip->last_xfer_start = INVALID_TIME;
    chip->total_xfer_time += xfer_time;
    if (chip->active_dies) chip->total_overlapped_time += xfer_time;

    list_for_each_entry(txn, &die->active_txns, queue)
    {
        txn->total_xfer_time += xfer_time;
    }

    chip->current_xfer = NULL;

    start_die_command(chip, die->active_cmd);

    if (!list_empty(&chip->cmd_xfer_queue)) {
        start_cmd_data_transfer(chip);
        return;
    }

    switch (head->type) {
    case TXN_READ:
        set_chip_status(chip, CS_READING);
        break;
    case TXN_WRITE:
        set_chip_status(chip, CS_WRITING);
        break;
    case TXN_ERASE:
        set_chip_status(chip, CS_ERASING);
        break;
    }

    set_channel_status(channel, BUS_IDLE);
    tsu_notify_channel_idle(channel->channel_id);
}

static void complete_die_command(struct chip_data* chip, struct die_data* die)
{
    struct flash_command* cmd = die->current_cmd;
    struct flash_transaction *txn, *tmp;
    time_ns_t now, exec_time;
    int i;

    now = current_time_ns();

    chip->active_dies--;
    if (!chip->active_dies) {
        chip->total_exec_time += now - chip->exec_start_time;
        if (chip->last_xfer_start != INVALID_TIME)
            chip->total_overlapped_time += now - chip->last_xfer_start;
        chip->exec_start_time = INVALID_TIME;
    }

    exec_time = now - die->exec_start_time;
    die->exec_start_time = INVALID_TIME;

    die->current_cmd = NULL;
    die->cmd_finish_time = UINT64_MAX;

    switch (cmd->cmd_code) {
    case CMD_READ_PAGE:
    case CMD_READ_PAGE_MULTIPLANE:
        for (i = 0; i < cmd->nr_addrs; i++)
            get_metadata(&cmd->addrs[i], &cmd->metadata[i]);

        if (!chip->active_dies) set_chip_status(chip, CS_WAIT_FOR_DATA_OUT);

        list_for_each_entry(txn, &die->active_txns, queue)
        {
            txn->total_exec_time += exec_time;
            chip->nr_waiting_read_xfers++;
            list_add(&txn->waiting_list, &chip->channel->waiting_read_xfer);
        }

        start_data_out_transfer(chip->channel);
        break;
    case CMD_PROGRAM_PAGE:
    case CMD_PROGRAM_PAGE_MULTIPLANE:
        for (i = 0; i < cmd->nr_addrs; i++)
            set_metadata(&cmd->addrs[i], &cmd->metadata[i]);

        list_for_each_entry_safe(txn, tmp, &die->active_txns, queue)
        {
            /* In notify_transaction_complete(), the thread that produced this
               txn gets immediately notified and it may release txn before we
               continue to the next txn in the list so list_for_each_entry_safe
               is needed. */
            txn->total_exec_time += exec_time;
            notify_transaction_complete(txn);
        }
        INIT_LIST_HEAD(&die->active_txns);
        die->active_cmd = NULL;

        if (!chip->active_dies) set_chip_status(chip, CS_IDLE);
        break;
    case CMD_ERASE_BLOCK:
    case CMD_ERASE_BLOCK_MULTIPLANE:
        list_for_each_entry_safe(txn, tmp, &die->active_txns, queue)
        {
            txn->total_exec_time += exec_time;
            notify_transaction_complete(txn);
        }

        INIT_LIST_HEAD(&die->active_txns);
        die->active_cmd = NULL;

        if (!chip->active_dies) set_chip_status(chip, CS_IDLE);
        break;
    }

    if (chip->channel->status == BUS_IDLE)
        tsu_notify_channel_idle(chip->channel->channel_id);
    if (chip->status == CS_IDLE)
        tsu_notify_chip_idle(chip->channel->channel_id, chip->chip_id);
}

static void complete_data_out_transfer(struct chip_data* chip,
                                       struct die_data* die)
{
    struct flash_transaction* txn = die->active_xfer;
    struct flash_command* cmd = die->active_cmd;
    time_ns_t xfer_time;
    int i;

    xfer_time = current_time_ns() - chip->last_xfer_start;
    chip->last_xfer_start = INVALID_TIME;
    chip->total_xfer_time += xfer_time;
    if (chip->active_dies) chip->total_overlapped_time += xfer_time;
    txn->total_xfer_time += xfer_time;

    die->active_xfer = NULL;
    die->xfer_complete_time = UINT64_MAX;

    for (i = 0; i < cmd->nr_addrs; i++) {
        if (cmd->addrs[i].plane_id == txn->addr.plane_id)
            txn->lpa = cmd->metadata[i].lpa;
    }

    list_del(&txn->queue);
    notify_transaction_complete(txn);

    if (list_empty(&die->active_txns)) {
        die->active_cmd = NULL;
    }

    if (!chip->active_dies) {
        if (!--chip->nr_waiting_read_xfers) {
            set_chip_status(chip, CS_IDLE);
        } else {
            set_chip_status(chip, CS_WAIT_FOR_DATA_OUT);
        }
    }

    set_channel_status(chip->channel, BUS_IDLE);
    tsu_notify_channel_idle(chip->channel->channel_id);
}

static void check_completion(void)
{
    int i, j, k;

    time_ns_t now = current_time_ns();

    for (i = 0; i < channel_count; i++) {
        for (j = 0; j < chips_per_channel; j++) {
            struct chip_data* chip = &chip_data[i][j];

            if (chip->current_xfer && now >= chip->xfer_complete_time)
                complete_chip_transfer(chip);

            for (k = 0; k < dies_per_chip; k++) {
                struct die_data* die = &chip->dies[k];

                if (die->current_cmd && now >= die->cmd_finish_time) {
                    complete_die_command(chip, die);
                }

                if (die->active_xfer && now >= die->xfer_complete_time) {
                    complete_data_out_transfer(chip, die);
                }
            }
        }
    }

    for (i = 0; i < channel_count; i++) {
        struct channel_data* channel = &channel_data[i];

        start_data_out_transfer(channel);
        if (channel->status == BUS_IDLE) tsu_notify_channel_idle(i);
    }
}

void nvm_ctlr_init_channel(unsigned int channel_id, unsigned int channel_width,
                           time_ns_t t_RC, time_ns_t t_DSC)
{
    struct channel_data* channel = &channel_data[channel_id];

    INIT_LIST_HEAD(&channel->waiting_read_xfer);
    channel->channel_width = channel_width;
    channel->t_RC = t_RC;
    channel->t_DSC = t_DSC;
}

void nvm_ctlr_init_chip(unsigned int channel_id, unsigned int chip_id,
                        time_ns_t* read_latencies, time_ns_t* program_latencies,
                        time_ns_t erase_latency)
{
    struct chip_data* chip = &chip_data[channel_id][chip_id];

    memcpy(chip->read_latencies, read_latencies, sizeof(chip->read_latencies));
    memcpy(chip->program_latencies, program_latencies,
           sizeof(chip->program_latencies));
    chip->erase_latency = erase_latency;
}

void nvm_ctlr_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
                   unsigned int nr_dies_per_chip,
                   unsigned int nr_planes_per_die,
                   unsigned int nr_blocks_per_plane,
                   unsigned int nr_pages_per_block)
{
    channel_count = nr_channels;
    chips_per_channel = nr_chips_per_channel;
    dies_per_chip = nr_dies_per_chip;
    planes_per_die = nr_planes_per_die;
    blocks_per_plane = nr_blocks_per_plane;
    pages_per_block = nr_pages_per_block;

    alloc_controller();
}

void nvm_ctlr_timer_interrupt(void)
{
    check_completion();
    rearm_timer();
}

void nvm_ctlr_report_result(Mcmq__SimResult* result)
{
    int i;
    struct Mcmq__NvmControllerStats* nvm_ctlr_stats =
        malloc(sizeof(Mcmq__NvmControllerStats));

    mcmq__nvm_controller_stats__init(nvm_ctlr_stats);
    result->nvm_controller_stats = nvm_ctlr_stats;

    nvm_ctlr_stats->n_chip_stats = channel_count * chips_per_channel;
    nvm_ctlr_stats->chip_stats =
        calloc(channel_count * chips_per_channel, sizeof(Mcmq__ChipStats*));

    for (i = 0; i < channel_count * chips_per_channel; i++) {
        struct chip_data* chip =
            &chip_data[i / chips_per_channel][i % chips_per_channel];
        struct Mcmq__ChipStats* chip_stats = malloc(sizeof(Mcmq__ChipStats));

        nvm_ctlr_stats->chip_stats[i] = chip_stats;
        mcmq__chip_stats__init(chip_stats);

        chip_stats->channel_id = chip->channel->channel_id;
        chip_stats->chip_id = chip->chip_id;
        chip_stats->total_transfer_time = chip->total_xfer_time / 1000;
        chip_stats->total_execution_time = chip->total_exec_time / 1000;
    }

    nvm_ctlr_stats->read_command_count = stats.read_cmds;
    nvm_ctlr_stats->multiplane_read_command_count = stats.multiplane_read_cmds;
    nvm_ctlr_stats->program_command_count = stats.program_cmds;
    nvm_ctlr_stats->multiplane_program_command_count =
        stats.multiplane_program_cmds;
    nvm_ctlr_stats->erase_command_count = stats.erase_cmds;
    nvm_ctlr_stats->multiplane_erase_command_count =
        stats.multiplane_erase_cmds;
}
