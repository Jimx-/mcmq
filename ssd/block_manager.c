#include "bitmap.h"
#include "const.h"
#include "proto.h"
#include "spinlock.h"

#include "ssd.h"

#include <assert.h>
#include <string.h>

struct bm_stats {
    size_t total_gc_executions;
    size_t total_page_movements;
};

static struct bm_stats stats;

struct block_data {
    struct list_head list;
    unsigned short block_id;
    unsigned int nr_invalid_pages;
    unsigned short page_write_index;
    unsigned int nr_ongoing_reads;
    unsigned int nr_ongoing_programs;
    int has_ongoing_gc;
    int has_mapping;
    struct flash_transaction* erase_txn;
    bitchunk_t invalidate_page_bitmap[0];
};

struct plane_allocator {
    struct block_data* blocks;
    struct list_head free_list;
    unsigned int free_list_size;
    struct block_data* data_wf;
    struct block_data* gc_wf;
    struct block_data* mapping_wf;
    spinlock_t lock;
};

static struct plane_allocator**** planes;

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die, blocks_per_plane, pages_per_block;
static unsigned int sectors_per_page;
static unsigned int block_pool_gc_threshold, block_pool_gc_hard_threshold;
static size_t block_data_alloc_size;
static enum block_selection_policy gc_block_selection_policy;

static void submit_gc_transactions(struct block_data* block,
                                   struct flash_address* addr);

static struct block_data* get_block_data(struct plane_allocator* plane,
                                         unsigned int block_id)
{
    return (struct block_data*)((uintptr_t)plane->blocks +
                                block_id * block_data_alloc_size);
}

#define GEN_NOTIFY_FUNC(type, event, op)                                  \
    static void bm_##type##_##event##_locked(struct flash_address* addr)  \
    {                                                                     \
        struct plane_allocator* plane =                                   \
            &planes[addr->channel_id][addr->chip_id][addr->die_id]        \
                   [addr->plane_id];                                      \
        struct block_data* block = get_block_data(plane, addr->block_id); \
        block->nr_ongoing_##type##s op;                                   \
    }                                                                     \
    void bm_##type##_##event(struct flash_address* addr)                  \
    {                                                                     \
        struct plane_allocator* plane =                                   \
            &planes[addr->channel_id][addr->chip_id][addr->die_id]        \
                   [addr->plane_id];                                      \
        spin_lock(&plane->lock);                                          \
        bm_##type##_##event##_locked(addr);                               \
        spin_unlock(&plane->lock);                                        \
    }

GEN_NOTIFY_FUNC(read, issued, ++)
GEN_NOTIFY_FUNC(read, completed, --)
GEN_NOTIFY_FUNC(program, issued, ++)
GEN_NOTIFY_FUNC(program, completed, --)

static struct block_data* get_free_block(struct plane_allocator* plane,
                                         int for_mapping)
{
    struct block_data* block;

    if (list_empty(&plane->free_list)) return NULL;

    block = list_entry(plane->free_list.next, struct block_data, list);
    list_del(&block->list);
    plane->free_list_size--;
    block->has_mapping = for_mapping;

    return block;
}

static void erase_block(struct block_data* block)
{
    block->page_write_index = 0;
    block->has_mapping = FALSE;
    memset(block->invalidate_page_bitmap, 0,
           BITCHUNKS(pages_per_block) * sizeof(bitchunk_t));
    block->erase_txn = NULL;
}

static void init_plane(struct plane_allocator* plane)
{
    int i;

    INIT_LIST_HEAD(&plane->free_list);

    for (i = 0; i < blocks_per_plane; i++) {
        struct block_data* block = get_block_data(plane, i);

        memset(block, 0, block_data_alloc_size);
        block->block_id = i;

        list_add(&block->list, &plane->free_list);
        plane->free_list_size++;
    }

    plane->data_wf = get_free_block(plane, FALSE);
    plane->gc_wf = get_free_block(plane, FALSE);
    plane->mapping_wf = get_free_block(plane, TRUE);

    spin_lock_init(&plane->lock);
}

static void alloc_planes(void)
{
    size_t nr_ptrs, nr_planes, nr_blocks, alloc_size;
    void* buf;
    void** cur_ptr;
    struct plane_allocator* cur_plane;
    struct block_data* cur_block;
    int i, j, k, l;

    nr_planes =
        channel_count * chips_per_channel * dies_per_chip * planes_per_die;

    nr_blocks = nr_planes * blocks_per_plane;

    nr_ptrs = channel_count + channel_count * chips_per_channel +
              channel_count * chips_per_channel * dies_per_chip;

    alloc_size = nr_ptrs * sizeof(void*) +
                 nr_planes * sizeof(struct plane_allocator) +
                 nr_blocks * block_data_alloc_size;
    alloc_size = roundup(alloc_size, PG_SIZE);

    buf = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);
    assert(buf);

    cur_ptr = (void**)buf;
    cur_plane = (struct plane_allocator*)(buf + nr_ptrs * sizeof(void*));
    cur_block =
        (struct block_data*)(buf + nr_ptrs * sizeof(void*) +
                             nr_planes * sizeof(struct plane_allocator));

    planes = (struct plane_allocator****)cur_ptr;
    cur_ptr += channel_count;

    for (i = 0; i < channel_count; i++) {
        planes[i] = (struct plane_allocator***)cur_ptr;
        cur_ptr += chips_per_channel;

        for (j = 0; j < chips_per_channel; j++) {
            planes[i][j] = (struct plane_allocator**)cur_ptr;
            cur_ptr += dies_per_chip;

            for (k = 0; k < dies_per_chip; k++) {
                planes[i][j][k] = cur_plane;
                cur_plane += planes_per_die;

                for (l = 0; l < planes_per_die; l++) {
                    memset(&planes[i][j][k][l], 0,
                           sizeof(struct plane_allocator));

                    planes[i][j][k][l].blocks = cur_block;
                    cur_block = (struct block_data*)((uintptr_t)cur_block +
                                                     block_data_alloc_size *
                                                         blocks_per_plane);

                    init_plane(&planes[i][j][k][l]);
                }
            }
        }
    }
}

static int is_block_safe_for_gc(struct plane_allocator* plane,
                                unsigned int block_id)
{
    struct block_data* block = get_block_data(plane, block_id);

    if (block == plane->data_wf || block == plane->gc_wf) return FALSE;

    if (block->nr_ongoing_programs) return FALSE;

    return !block->has_ongoing_gc;
}

static int can_start_gc(struct flash_address* addr)
{
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    struct block_data* block = get_block_data(plane, addr->block_id);

    return block->nr_ongoing_reads + block->nr_ongoing_programs == 0;
}

static void lock_block_pages(struct block_data* block,
                             struct flash_address* addr)
{
    int i;
    struct flash_address page_addr = *addr;

    for (i = 0; i < block->page_write_index; i++) {
        if (!GET_BIT(block->invalidate_page_bitmap, i)) {
            lpa_t lpa;
            struct page_metadata metadata;

            page_addr.page_id = i;
            nvm_ctlr_get_metadata(&page_addr, &metadata);
            lpa = metadata.lpa;

            amu_lock_lpa(lpa, block->has_mapping);
        }
    }
}

void gc_check(unsigned free_block_pool_size, struct flash_address* addr)
{
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    unsigned int candidate_block_id;
    struct block_data* candidate_block;
    struct flash_address candidate_addr;
    int i;

    if (free_block_pool_size > block_pool_gc_threshold) return;

    switch (gc_block_selection_policy) {
    case BSP_GREEDY:
        candidate_block_id = 0;
        candidate_block = get_block_data(plane, candidate_block_id);

        for (i = 1; i < blocks_per_plane; i++) {
            struct block_data* cur_block = get_block_data(plane, i);

            if (cur_block->nr_invalid_pages >
                    candidate_block->nr_invalid_pages &&
                cur_block->page_write_index == pages_per_block &&
                is_block_safe_for_gc(plane, i)) {
                candidate_block_id = i;
                candidate_block = cur_block;
            }
        }
        break;
    }

    if (!candidate_block->page_write_index ||
        !candidate_block->nr_invalid_pages)
        return;

    candidate_addr = *addr;
    candidate_addr.block_id = candidate_block_id;
    candidate_block->has_ongoing_gc = TRUE;

    lock_block_pages(candidate_block, &candidate_addr);

    if (can_start_gc(&candidate_addr)) {
        submit_gc_transactions(candidate_block, &candidate_addr);
    }
}

void bm_alloc_page(struct flash_address* addr, int for_gc, int for_mapping)
{
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    struct block_data* block;

    spin_lock(&plane->lock);

    block = for_mapping ? plane->mapping_wf
                        : (for_gc ? plane->gc_wf : plane->data_wf);
    addr->block_id = block->block_id;
    addr->page_id = block->page_write_index++;
    bm_program_issued_locked(addr);

    if (block->page_write_index == pages_per_block) {
        block = get_free_block(plane, for_mapping);

        if (for_mapping)
            plane->mapping_wf = block;
        else if (for_gc)
            plane->gc_wf = block;
        else
            plane->data_wf = block;

        if (!for_gc) gc_check(plane->free_list_size, addr);
    }

    spin_unlock(&plane->lock);
}

void bm_invalidate_page(struct flash_address* addr)
{
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    struct block_data* block = get_block_data(plane, addr->block_id);

    spin_lock(&plane->lock);

    block->nr_invalid_pages++;
    SET_BIT(block->invalidate_page_bitmap, addr->page_id);

    spin_unlock(&plane->lock);
}

void bm_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
             unsigned int nr_dies_per_chip, unsigned int nr_planes_per_die,
             unsigned int nr_blocks_per_plane, unsigned int nr_pages_per_block,
             unsigned int sectors_in_page,
             enum block_selection_policy block_selection_policy,
             unsigned int gc_threshold, unsigned int gc_hard_threshold)
{
    channel_count = nr_channels;
    chips_per_channel = nr_chips_per_channel;
    dies_per_chip = nr_dies_per_chip;
    planes_per_die = nr_planes_per_die;
    blocks_per_plane = nr_blocks_per_plane;
    pages_per_block = nr_pages_per_block;
    sectors_per_page = sectors_in_page;

    block_data_alloc_size = sizeof(struct block_data) +
                            sizeof(bitchunk_t) * BITCHUNKS(pages_per_block);

    alloc_planes();

    gc_block_selection_policy = block_selection_policy;

    block_pool_gc_threshold = nr_blocks_per_plane / gc_threshold;
    block_pool_gc_hard_threshold = nr_blocks_per_plane / gc_hard_threshold;

    if (block_pool_gc_threshold < 1) block_pool_gc_threshold = 1;
    if (block_pool_gc_hard_threshold < 1) block_pool_gc_hard_threshold = 1;
}

static void submit_gc_transactions(struct block_data* block,
                                   struct flash_address* addr)
{
    struct flash_transaction *erase_tx, *read_tx, *write_tx;

    stats.total_gc_executions++;

    SLABALLOC(erase_tx);
    assert(erase_tx);

    memset(erase_tx, 0, sizeof(*erase_tx));
    INIT_LIST_HEAD(&erase_tx->page_movement_list);
    erase_tx->type = TXN_ERASE;
    erase_tx->source = TS_GC;
    erase_tx->worker = worker_self();
    erase_tx->lpa = NO_LPA;
    erase_tx->ppa = NO_PPA;
    erase_tx->length = 0;
    erase_tx->addr = *addr;

    if (block->page_write_index - block->nr_invalid_pages) {
        int i;
        for (i = 0; i < block->page_write_index; i++) {
            if (!GET_BIT(block->invalidate_page_bitmap, i)) {
                stats.total_page_movements++;

                addr->page_id = i;

                SLABALLOC(read_tx);
                assert(read_tx);
                SLABALLOC(write_tx);
                assert(write_tx);

                memset(read_tx, 0, sizeof(*read_tx));
                read_tx->type = TXN_READ;
                read_tx->source = TS_GC;
                read_tx->worker = worker_self();
                read_tx->lpa = NO_LPA;
                read_tx->ppa = address_to_ppa(addr);
                read_tx->length = sectors_per_page << SECTOR_SHIFT;
                read_tx->addr = *addr;

                memset(write_tx, 0, sizeof(*write_tx));
                write_tx->type = TXN_WRITE;
                write_tx->source = TS_GC;
                write_tx->worker = worker_self();
                write_tx->lpa = NO_LPA;
                write_tx->ppa = address_to_ppa(addr);
                write_tx->length = sectors_per_page << SECTOR_SHIFT;
                write_tx->bitmap = UINT64_MAX;
                write_tx->opaque = (void*)block->has_mapping;

                read_tx->related_write = write_tx;
                write_tx->related_read = read_tx;
                write_tx->related_erase = erase_tx;

                list_add(&write_tx->list, &erase_tx->page_movement_list);

                submit_transaction(read_tx);
            }
        }

        block->erase_txn = erase_tx;

        tsu_kick();
    }
}

static void bm_handle_user_transaction(struct flash_transaction* txn)
{
    struct flash_address* addr = &txn->addr;
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    struct block_data* block = get_block_data(plane, addr->block_id);

    assert(txn->type == TXN_READ || txn->type == TXN_WRITE);

    spin_lock(&plane->lock);

    switch (txn->type) {
    case TXN_READ:
        bm_read_completed_locked(&txn->addr);
        break;
    case TXN_WRITE:
        bm_program_completed_locked(&txn->addr);
        break;
    default:
        break;
    }

    if (block->has_ongoing_gc && can_start_gc(&txn->addr)) {
        submit_gc_transactions(block, &txn->addr);
    }

    spin_unlock(&plane->lock);
}

static void bm_handle_gc_transaction(struct flash_transaction* txn)
{
    struct flash_transaction* write_tx;
    struct plane_allocator* plane;
    struct block_data* block;
    struct flash_address* addr = &txn->addr;

    switch (txn->type) {
    case TXN_READ:
        write_tx = txn->related_write;
        assert(write_tx);

        write_tx->lpa = txn->lpa;
        write_tx->related_read = NULL;

        amu_alloc_page_gc(write_tx, write_tx->opaque != NULL);

        submit_transaction(write_tx);
        tsu_kick();
        break;

    case TXN_WRITE:
        amu_unlock_lpa(txn->lpa, txn->opaque != NULL);

        list_del(&txn->list);

        if (list_empty(&txn->related_erase->page_movement_list)) {
            submit_transaction(txn->related_erase);
            tsu_kick();
        }
        break;
    case TXN_ERASE:
        plane = &planes[addr->channel_id][addr->chip_id][addr->die_id]
                       [addr->plane_id];
        block = get_block_data(plane, addr->block_id);

        spin_lock(&plane->lock);
        erase_block(block);
        list_add(&block->list, &plane->free_list);
        plane->free_list_size++;
        block->has_ongoing_gc = FALSE;
        spin_unlock(&plane->lock);
        break;
    }
}

void bm_transaction_complete(struct flash_transaction* txn)
{
    switch (txn->source) {
    case TS_USER_IO:
    case TS_MAPPING:
        bm_handle_user_transaction(txn);
        break;
    case TS_GC:
        bm_handle_gc_transaction(txn);
        break;
    }
}
