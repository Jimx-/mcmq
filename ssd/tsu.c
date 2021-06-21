#include "const.h"
#include "proto.h"
#include "spinlock.h"

#include "ssd.h"

#include <assert.h>
#include <string.h>

struct txn_queues {
    struct list_head read_queue;
    struct list_head write_queue;
    struct list_head gc_read_queue;
    struct list_head gc_write_queue;
    struct list_head gc_erase_queue;
    spinlock_t lock;
};

static struct txn_queues** chip_queues;
static unsigned int* channel_rr_index;

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die;

void tsu_kick(void) { notify_worker(THREAD_TSU); }

void tsu_process_transaction(struct flash_transaction* txn)
{
    struct txn_queues* chip =
        &chip_queues[txn->addr.channel_id][txn->addr.chip_id];
    struct list_head* queue;

    switch (txn->type) {
    case TXN_READ:
        switch (txn->source) {
        case TS_USER_IO:
            queue = &chip->read_queue;
            break;
        case TS_GC:
            queue = &chip->gc_read_queue;
            break;
        }
        break;
    case TXN_WRITE:
        switch (txn->source) {
        case TS_USER_IO:
            queue = &chip->write_queue;
            break;
        case TS_GC:
            queue = &chip->gc_write_queue;
            break;
        }
        break;
    case TXN_ERASE:
        queue = &chip->gc_erase_queue;
        break;
    }

    spin_lock(&chip->lock);
    list_add_tail(&txn->queue, queue);
    spin_unlock(&chip->lock);
}

void alloc_queues(void)
{
    size_t nr_ptrs, nr_chips, alloc_size;
    void* buf;
    void** cur_ptr;
    struct txn_queues* cur_queues;
    int i, j;

    nr_chips = channel_count * chips_per_channel;
    nr_ptrs = channel_count;

    alloc_size = nr_ptrs * sizeof(void*) +
                 nr_chips * sizeof(struct txn_queues) +
                 channel_count * sizeof(unsigned int);
    alloc_size = roundup(alloc_size, PG_SIZE);

    buf = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);
    assert(buf);

    cur_ptr = (void**)buf;
    cur_queues = (struct txn_queues*)(buf + nr_ptrs * sizeof(void*));
    channel_rr_index = (unsigned int*)(buf + nr_ptrs * sizeof(void*) +
                                       nr_chips * sizeof(struct txn_queues));

    chip_queues = (struct txn_queues**)cur_ptr;
    cur_ptr += channel_count;

    for (i = 0; i < channel_count; i++) {
        chip_queues[i] = cur_queues;
        cur_queues += chips_per_channel;

        for (j = 0; j < chips_per_channel; j++) {
            struct txn_queues* qs = &chip_queues[i][j];
            INIT_LIST_HEAD(&qs->read_queue);
            INIT_LIST_HEAD(&qs->write_queue);
            INIT_LIST_HEAD(&qs->gc_read_queue);
            INIT_LIST_HEAD(&qs->gc_write_queue);
            INIT_LIST_HEAD(&qs->gc_erase_queue);
            spin_lock_init(&qs->lock);
        }
    }

    memset(channel_rr_index, 0, channel_count * sizeof(unsigned int));
}

static int transaction_ready(struct flash_transaction* txn) { return TRUE; }

static void dispatch_queue_request(struct list_head* q_prim,
                                   struct list_head* q_sec, enum txn_type type)
{
    struct flash_transaction* head =
        list_entry(q_prim->next, struct flash_transaction, queue);
    unsigned int die_id = head->addr.die_id;
    unsigned int page_id = head->addr.page_id;
    struct list_head dispatch_list;

    struct flash_transaction *txn, *tmp;
    uint64_t plane_bitmap = 0;
    int found = 0;

    INIT_LIST_HEAD(&dispatch_list);

    list_for_each_entry_safe(txn, tmp, q_prim, queue)
    {
        if (transaction_ready(txn) && txn->addr.die_id == die_id &&
            !(plane_bitmap & (1 << txn->addr.plane_id)) &&
            (!plane_bitmap || txn->addr.page_id == page_id)) {
            found++;
            plane_bitmap |= 1 << txn->addr.plane_id;
            list_del(&txn->queue);
            list_add_tail(&txn->queue, &dispatch_list);
        }
    }

    if (q_sec && found < planes_per_die) {
        list_for_each_entry_safe(txn, tmp, q_sec, queue)
        {
            if (transaction_ready(txn) && txn->addr.die_id == die_id &&
                !(plane_bitmap & (1 << txn->addr.plane_id)) &&
                (!plane_bitmap || txn->addr.page_id == page_id)) {
                plane_bitmap |= 1 << txn->addr.plane_id;
                list_del(&txn->queue);
                list_add_tail(&txn->queue, &dispatch_list);
            }
        }
    }

    nvm_ctlr_dispatch(&dispatch_list);
}

static int dispatch_read_request(unsigned int channel, unsigned int chip)
{
    struct list_head *q_prim = NULL, *q_sec = NULL;
    struct txn_queues* queues = &chip_queues[channel][chip];

    if (!list_empty(&queues->read_queue)) {
        q_prim = &queues->read_queue;
        if (!list_empty(&queues->gc_read_queue)) {
            q_sec = &queues->gc_read_queue;
        }
    } else if (!list_empty(&queues->write_queue))
        return FALSE;
    else if (!list_empty(&queues->gc_read_queue))
        q_prim = &queues->gc_read_queue;
    else
        return FALSE;

    if (nvm_ctlr_get_chip_status(channel, chip) != CS_IDLE) return FALSE;

    dispatch_queue_request(q_prim, q_sec, TXN_READ);
    return TRUE;
}

static int dispatch_write_request(unsigned int channel, unsigned int chip)
{
    struct list_head *q_prim = NULL, *q_sec = NULL;
    struct txn_queues* queues = &chip_queues[channel][chip];

    if (!list_empty(&queues->write_queue)) {
        q_prim = &queues->write_queue;
        if (!list_empty(&queues->gc_write_queue)) {
            q_sec = &queues->gc_write_queue;
        }
    } else if (!list_empty(&queues->gc_write_queue))
        q_prim = &queues->gc_write_queue;
    else
        return FALSE;

    if (nvm_ctlr_get_chip_status(channel, chip) != CS_IDLE) return FALSE;

    dispatch_queue_request(q_prim, q_sec, TXN_WRITE);
    return TRUE;
}

static int dispatch_erase_request(unsigned int channel, unsigned int chip)
{
    struct txn_queues* queues = &chip_queues[channel][chip];
    struct list_head* q_prim = &queues->gc_erase_queue;

    if (nvm_ctlr_get_chip_status(channel, chip) != CS_IDLE) return FALSE;

    if (list_empty(q_prim)) return FALSE;

    dispatch_queue_request(q_prim, NULL, TXN_ERASE);
    return TRUE;
}

static void dispatch_request(unsigned int channel, unsigned int chip)
{
    if (dispatch_read_request(channel, chip)) return;
    if (dispatch_write_request(channel, chip)) return;
    dispatch_erase_request(channel, chip);
}

static void tsu_flush_channel(unsigned int channel)
{
    int i;
    for (i = 0; i < chips_per_channel; i++) {
        unsigned int chip_id = channel_rr_index[channel];
        dispatch_request(channel, chip_id);
        channel_rr_index[channel] =
            (channel_rr_index[channel] + 1) % chips_per_channel;

        if (nvm_ctlr_get_channel_status(channel) != BUS_IDLE) break;
    }
}

void tsu_flush_queues(void)
{
    int i;

    for (i = 0; i < channel_count; i++) {
        if (nvm_ctlr_get_channel_status(i) != BUS_IDLE) continue;

        tsu_flush_channel(i);
    }
}

void tsu_notify_channel_idle(unsigned int channel)
{
    tsu_flush_channel(channel);
}

void tsu_notify_chip_idle(unsigned int channel, unsigned int chip)
{
    if (nvm_ctlr_get_channel_status(channel) != BUS_IDLE) return;
    dispatch_request(channel, chip);
}

void tsu_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
              unsigned int nr_dies_per_chip, unsigned int nr_planes_per_die)
{
    channel_count = nr_channels;
    chips_per_channel = nr_chips_per_channel;
    dies_per_chip = nr_dies_per_chip;
    planes_per_die = nr_planes_per_die;

    alloc_queues();
}
