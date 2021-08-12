#include "const.h"
#include "proto.h"
#include "spinlock.h"
#include "ssd.h"

#include "proto/sim_result.pb-c.h"

#include "hdrhistogram/hdr_histogram.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static struct tsu_stats {
    uint64_t enqueued_read_txns;
    uint64_t enqueued_write_txns;
    uint64_t enqueued_erase_txns;

    struct hdr_histogram* read_waiting_time_hist;
    struct hdr_histogram* write_waiting_time_hist;
    struct hdr_histogram* erase_waiting_time_hist;
} stats;

struct txn_queues {
    struct list_head read_queue;
    struct list_head write_queue;
    struct list_head mapping_read_queue;
    struct list_head mapping_write_queue;
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
    uint64_t* counter;

    switch (txn->type) {
    case TXN_READ:
        switch (txn->source) {
        case TS_USER_IO:
            queue = &chip->read_queue;
            break;
        case TS_MAPPING:
            queue = &chip->mapping_read_queue;
            break;
        case TS_GC:
            queue = &chip->gc_read_queue;
            break;
        }
        counter = &stats.enqueued_read_txns;
        break;
    case TXN_WRITE:
        switch (txn->source) {
        case TS_USER_IO:
            queue = &chip->write_queue;
            break;
        case TS_MAPPING:
            queue = &chip->mapping_write_queue;
            break;
        case TS_GC:
            queue = &chip->gc_write_queue;
            break;
        }
        counter = &stats.enqueued_write_txns;
        break;
    case TXN_ERASE:
        queue = &chip->gc_erase_queue;
        counter = &stats.enqueued_erase_txns;
        break;
    }

    txn->enqueue_time = current_time_ns();
    (*counter)++;

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
            INIT_LIST_HEAD(&qs->mapping_read_queue);
            INIT_LIST_HEAD(&qs->mapping_write_queue);
            INIT_LIST_HEAD(&qs->gc_read_queue);
            INIT_LIST_HEAD(&qs->gc_write_queue);
            INIT_LIST_HEAD(&qs->gc_erase_queue);
            spin_lock_init(&qs->lock);
        }
    }

    memset(channel_rr_index, 0, channel_count * sizeof(unsigned int));
}

static int transaction_ready(struct flash_transaction* txn)
{
    switch (txn->type) {
    case TXN_WRITE:
        return !txn->related_read;
    default:
        return TRUE;
    }
}

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

    if (!list_empty(&dispatch_list)) nvm_ctlr_dispatch(&dispatch_list);
}

static int dispatch_read_request(unsigned int channel, unsigned int chip)
{
    struct list_head *q_prim = NULL, *q_sec = NULL;
    struct txn_queues* queues = &chip_queues[channel][chip];

    if (!list_empty(&queues->mapping_read_queue)) {
        /* Prioritize read txns for mapping entries. */
        q_prim = &queues->mapping_read_queue;

        if (!list_empty(&queues->read_queue))
            q_sec = &queues->read_queue;
        else if (!list_empty(&queues->gc_read_queue))
            q_sec = &queues->gc_read_queue;
    } else {
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
    }

    if (nvm_ctlr_get_chip_status(channel, chip) != CS_IDLE) return FALSE;

    dispatch_queue_request(q_prim, q_sec, TXN_READ);
    return TRUE;
}

static int dispatch_write_request(unsigned int channel, unsigned int chip)
{
    struct list_head *q_prim = NULL, *q_sec = NULL;
    struct txn_queues* queues = &chip_queues[channel][chip];

    if (!list_empty(&queues->mapping_write_queue)) {
        /* Prioritize write txns for mapping entries. */
        q_prim = &queues->mapping_write_queue;

        if (!list_empty(&queues->write_queue))
            q_sec = &queues->write_queue;
        else if (!list_empty(&queues->gc_write_queue))
            q_sec = &queues->gc_write_queue;
    } else {
        if (!list_empty(&queues->write_queue)) {
            q_prim = &queues->write_queue;
            if (!list_empty(&queues->gc_write_queue)) {
                q_sec = &queues->gc_write_queue;
            }
        } else if (!list_empty(&queues->gc_write_queue))
            q_prim = &queues->gc_write_queue;
        else
            return FALSE;
    }

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

    hdr_init(1, UINT64_C(2000000), 1, &stats.read_waiting_time_hist);
    hdr_init(1, UINT64_C(2000000), 1, &stats.write_waiting_time_hist);
    hdr_init(1, UINT64_C(2000000), 1, &stats.erase_waiting_time_hist);
}

void tsu_transaction_complete(struct flash_transaction* txn)
{
    time_ns_t delta = txn->dispatch_time - txn->enqueue_time;
    struct hdr_histogram* hist;

    switch (txn->type) {
    case TXN_READ:
        hist = stats.read_waiting_time_hist;
        break;
    case TXN_WRITE:
        hist = stats.write_waiting_time_hist;
        break;
    case TXN_ERASE:
        hist = stats.erase_waiting_time_hist;
        break;
    }

    hdr_record_value(hist, delta / 1000);
}

void tsu_report_result(Mcmq__SimResult* result)
{
    static const int ticks_per_half_distance = 5;
    struct Mcmq__TSUStats* tsu_stats = malloc(sizeof(Mcmq__TSUStats));

    mcmq__tsustats__init(tsu_stats);
    result->tsu_stats = tsu_stats;

#define SET_LATENCY_HISTOGRAM(name)                                         \
    do {                                                                    \
        struct hdr_iter iter;                                               \
        struct hdr_iter_percentiles* percentiles;                           \
        int j, count = 0;                                                   \
        tsu_stats->name##_waiting_time_mean =                               \
            hdr_mean(stats.name##_waiting_time_hist);                       \
        tsu_stats->name##_waiting_time_stddev =                             \
            hdr_stddev(stats.name##_waiting_time_hist);                     \
        tsu_stats->max_##name##_waiting_time =                              \
            hdr_max(stats.name##_waiting_time_hist);                        \
        hdr_iter_percentile_init(&iter, stats.name##_waiting_time_hist,     \
                                 ticks_per_half_distance);                  \
        while (hdr_iter_next(&iter)) {                                      \
            count++;                                                        \
        }                                                                   \
        tsu_stats->n_##name##_waiting_time_histogram = count;               \
        if (count) {                                                        \
            tsu_stats->name##_waiting_time_histogram =                      \
                calloc(count, sizeof(Mcmq__HistogramEntry*));               \
            j = 0;                                                          \
            hdr_iter_percentile_init(&iter, stats.name##_waiting_time_hist, \
                                     ticks_per_half_distance);              \
            while (hdr_iter_next(&iter) && j < count) {                     \
                struct Mcmq__HistogramEntry* entry =                        \
                    malloc(sizeof(Mcmq__HistogramEntry));                   \
                percentiles = &iter.specifics.percentiles;                  \
                mcmq__histogram_entry__init(entry);                         \
                tsu_stats->name##_waiting_time_histogram[j] = entry;        \
                entry->value = iter.highest_equivalent_value;               \
                entry->percentile = percentiles->percentile;                \
                entry->total_count = iter.cumulative_count;                 \
                j++;                                                        \
            }                                                               \
        }                                                                   \
    } while (0)

    SET_LATENCY_HISTOGRAM(read);
    SET_LATENCY_HISTOGRAM(write);
    SET_LATENCY_HISTOGRAM(erase);

    tsu_stats->enqueued_read_transactions = stats.enqueued_read_txns;
    tsu_stats->enqueued_write_transactions = stats.enqueued_write_txns;
    tsu_stats->enqueued_erase_transactions = stats.enqueued_erase_txns;
}
