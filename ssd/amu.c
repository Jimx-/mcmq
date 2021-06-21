#include "avl.h"
#include "const.h"
#include "flash.h"
#include "list.h"
#include "proto.h"
#include "spinlock.h"
#include "ssd.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

struct amu_stats {
    size_t total_mt_queries;
    size_t total_mt_queries_read;
    size_t total_mt_queries_write;
    size_t total_mt_hits;
    size_t total_mt_hits_read;
    size_t total_mt_hits_write;
    size_t total_mt_miss;
    size_t total_mt_miss_read;
    size_t total_mt_miss_write;
};

static struct amu_stats stats;

enum mapping_entry_status {
    MES_FREE,
    MES_WAITING,
    MES_VALID,
};

struct mapping_entry {
    lpa_t lpa;
    ppa_t ppa;
    enum mapping_entry_status status;
    int dirty;
    page_bitmap_t bitmap;
    struct avl_node avl;
    struct list_head lru;
};

struct mapping_table {
    size_t capacity;
    struct avl_root root;
    struct list_head lru_list;
};

struct gtd_entry {
    ppa_t mppn;
    uint64_t timestamp;
};

struct am_domain {
    struct mapping_table table;
    struct gtd_entry* gtd;
    size_t translation_entries_per_page;
    spinlock_t lock;
};

static struct am_domain g_domain;

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die, blocks_per_plane, pages_per_block;
static unsigned int pages_per_plane, pages_per_die, pages_per_chip,
    pages_per_channel;
static unsigned int sectors_per_page;

static inline struct am_domain* domain_get(struct flash_transaction* txn)
{
    return &g_domain;
}

static inline lpa_t get_mvpn(struct am_domain* domain, lpa_t lpa)
{
    return lpa / domain->translation_entries_per_page;
}

static inline void ppa_to_address(ppa_t ppa, struct flash_address* addr)
{
#define XLATE_PPA(ppa, name)                      \
    do {                                          \
        addr->name##_id = ppa / pages_per_##name; \
        ppa = ppa % pages_per_##name;             \
    } while (0)
    XLATE_PPA(ppa, channel);
    XLATE_PPA(ppa, chip);
    XLATE_PPA(ppa, die);
    XLATE_PPA(ppa, plane);
    XLATE_PPA(ppa, block);
    addr->page_id = ppa;
#undef XLATE_PPA
}

static inline ppa_t address_to_ppa(struct flash_address* addr)
{
    return pages_per_chip *
               (chips_per_channel * addr->channel_id + addr->chip_id) +
           pages_per_die * addr->die_id + pages_per_plane * addr->plane_id +
           pages_per_block * addr->block_id + addr->page_id;
}

static int mt_key_node_comp(void* key, struct avl_node* node)
{
    struct mapping_entry* r1 = (struct mapping_entry*)key;
    struct mapping_entry* r2 = avl_entry(node, struct mapping_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static int mt_node_node_comp(struct avl_node* node1, struct avl_node* node2)
{
    struct mapping_entry* r1 = avl_entry(node1, struct mapping_entry, avl);
    struct mapping_entry* r2 = avl_entry(node2, struct mapping_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static void mt_init(struct mapping_table* mt, size_t capacity)
{
    mt->capacity = capacity;
    INIT_LIST_HEAD(&mt->lru_list);
    INIT_AVL_ROOT(&mt->root, mt_key_node_comp, mt_node_node_comp);
}

static struct mapping_entry* mt_find(struct mapping_table* mt, lpa_t lpa)
{
    struct avl_node* node = mt->root.node;
    struct mapping_entry* entry = NULL;

    while (node) {
        entry = avl_entry(node, struct mapping_entry, avl);

        if (entry->lpa == lpa) {
            return entry;
        } else if (lpa < entry->lpa)
            node = node->left;
        else if (lpa > entry->lpa)
            node = node->right;
    }

    return NULL;
}

static void mt_touch_lru(struct mapping_table* mt, struct mapping_entry* entry)
{
    list_del(&entry->lru);
    list_add(&entry->lru, &mt->lru_list);
}

static int mt_reserve_slot(struct mapping_table* mt, lpa_t lpa)
{
    struct mapping_entry* entry;

    entry = mt_find(mt, lpa);
    if (entry) return EEXIST;

    SLABALLOC(entry);
    if (!entry) return ENOMEM;

    memset(entry, 0, sizeof(*entry));
    entry->status = MES_WAITING;
    entry->lpa = lpa;
    entry->ppa = NO_PPA;
    avl_insert(&entry->avl, &mt->root);
    list_add(&entry->lru, &mt->lru_list);

    return 0;
}

static int mt_update_mapping(struct mapping_table* mt, lpa_t lpa, ppa_t ppa,
                             page_bitmap_t bitmap, int first, int set_bitmap)
{
    struct mapping_entry* entry;

    entry = mt_find(mt, lpa);
    if (!entry) return ESRCH;

    entry->status = MES_VALID;
    entry->ppa = ppa;
    entry->dirty = !first;

    if (set_bitmap)
        entry->bitmap = bitmap;
    else
        entry->bitmap |= bitmap;

    return 0;
}

static inline int mapping_entry_exists(struct am_domain* domain, lpa_t lpa)
{
    return mt_find(&domain->table, lpa) != NULL;
}

static ppa_t get_ppa(struct am_domain* domain, lpa_t lpa)
{
    struct mapping_entry* entry;

    entry = mt_find(&domain->table, lpa);
    if (!entry) return NO_PPA;

    assert(entry->status == MES_VALID);

    mt_touch_lru(&domain->table, entry);
    return entry->ppa;
}

static void assign_plane(struct flash_transaction* txn)
{
    struct flash_address* addr = &txn->addr;

    addr->channel_id = 0;
    addr->chip_id = 0;
    addr->die_id = 0;
    addr->plane_id = 0;
}

static void alloc_page_for_write(struct flash_transaction* txn, int for_gc)
{
    struct am_domain* domain = domain_get(txn);

    bm_alloc_page(&txn->addr, for_gc);
    txn->ppa = address_to_ppa(&txn->addr);
    mt_update_mapping(&domain->table, txn->lpa, txn->ppa, txn->bitmap, FALSE,
                      FALSE);
}

static int translate_lpa(struct am_domain* domain,
                         struct flash_transaction* txn)
{

    if (txn->type == TXN_READ) {
        ppa_t ppa = get_ppa(domain, txn->lpa);

        if (ppa == NO_PPA) {
            assign_plane(txn);
            alloc_page_for_write(txn, FALSE);
        } else {
            txn->ppa = ppa;
            ppa_to_address(txn->ppa, &txn->addr);
        }
        txn->ppa_ready = TRUE;

        return TRUE;
    } else {
        assign_plane(txn);
        alloc_page_for_write(txn, FALSE);
        txn->ppa_ready = TRUE;

        return TRUE;
    }

    return FALSE;
}

static int request_mapping_entry(struct flash_transaction* txn)
{
    struct am_domain* domain = domain_get(txn);
    lpa_t lpa = txn->lpa;
    lpa_t mvpn = get_mvpn(domain, lpa);

    if (domain->gtd[mvpn].mppn == NO_PPA) {
        mt_reserve_slot(&domain->table, lpa);
        mt_update_mapping(&domain->table, lpa, NO_PPA, 0, TRUE, TRUE);

        return TRUE;
    }

    return FALSE;
}

static void translate_transaction(struct flash_transaction* txn)
{
    struct am_domain* domain = domain_get(txn);

    spin_lock(&domain->lock);
    stats.total_mt_queries++;

    if (mapping_entry_exists(domain, txn->lpa)) {
        stats.total_mt_hits++;

        if (txn->type == TXN_READ) {
            stats.total_mt_queries_read++;
            stats.total_mt_hits_read++;
        } else {
            stats.total_mt_queries_write++;
            stats.total_mt_hits_write++;
        }

        if (translate_lpa(domain, txn))
            ;
    } else {
        stats.total_mt_miss++;

        if (request_mapping_entry(txn)) {
            if (txn->type == TXN_READ) {
                stats.total_mt_queries_read++;
                stats.total_mt_miss_read++;
            } else {
                stats.total_mt_queries_write++;
                stats.total_mt_miss_write++;
            }

            if (translate_lpa(domain, txn))
                ;
        }
    }

    spin_unlock(&domain->lock);
}

static void domain_init(struct am_domain* domain, size_t capacity,
                        size_t translation_entries_per_page,
                        lha_t total_logical_sectors)
{
    size_t total_logical_pages = total_logical_sectors / sectors_per_page;
    size_t total_translation_pages =
        (total_logical_pages + translation_entries_per_page - 1) /
        translation_entries_per_page;
    size_t alloc_size;
    int i;

    mt_init(&domain->table, capacity);
    spin_lock_init(&domain->lock);

    domain->translation_entries_per_page = translation_entries_per_page;

    alloc_size = total_translation_pages * sizeof(struct gtd_entry);
    alloc_size = roundup(alloc_size, PG_SIZE);
    domain->gtd = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);

    for (i = 0; i < total_translation_pages; i++) {
        domain->gtd[i].mppn = NO_PPA;
        domain->gtd[i].timestamp = 0;
    }
}

void amu_init(size_t mt_capacity, unsigned int nr_channels,
              unsigned int nr_chips_per_channel, unsigned int nr_dies_per_chip,
              unsigned int nr_planes_per_die, unsigned int nr_blocks_per_plane,
              unsigned int nr_pages_per_block, unsigned int sectors_in_page)
{
    channel_count = nr_channels;
    chips_per_channel = nr_chips_per_channel;
    dies_per_chip = nr_dies_per_chip;
    planes_per_die = nr_planes_per_die;
    blocks_per_plane = nr_blocks_per_plane;
    pages_per_block = nr_pages_per_block;

    pages_per_plane = pages_per_block * blocks_per_plane;
    pages_per_die = pages_per_plane * planes_per_die;
    pages_per_chip = pages_per_die * dies_per_chip;
    pages_per_channel = pages_per_chip * chips_per_channel;

    sectors_per_page = sectors_in_page;

    domain_init(&g_domain, mt_capacity, (sectors_per_page * SECTOR_SIZE) >> 2,
                pages_per_channel * sectors_per_page);
}

void amu_dispatch(struct user_request* req)
{
    struct flash_transaction* txn;

    list_for_each_entry(txn, &req->txn_list, list)
    {
        translate_transaction(txn);
    }

    if (!list_empty(&req->txn_list)) {
        list_for_each_entry(txn, &req->txn_list, list)
        {
            if (txn->ppa_ready) {
                submit_transaction(txn);
            }
        }

        tsu_kick();
    }
}

void amu_notify_txn_complete(struct flash_transaction* txn) {}
