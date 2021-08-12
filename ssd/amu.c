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
    size_t total_flash_reads_for_mapping;
    size_t total_flash_writes_for_mapping;
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
    size_t size;
    struct avl_root root;
    struct list_head lru_list;
};

struct lock_entry {
    lpa_t lpa;
    struct avl_node avl;
};

struct lock_table {
    spinlock_t lock;
    struct avl_root root;
};

/* Global translation directory entry. */
struct gtd_entry {
    ppa_t mppn;
    uint64_t timestamp;
};

/* Global mapping table entry. */
struct gmt_entry {
    ppa_t ppa;
    page_bitmap_t bitmap;
    uint64_t timestamp;
};

struct am_domain {
    unsigned int nsid;
    enum plane_allocate_scheme plane_allocate_scheme;
    struct mapping_table table;
    struct gtd_entry* gtd;
    struct gmt_entry* gmt;
    size_t translation_entries_per_page;
    unsigned int gtd_entry_size;
    struct list_head unsuccessful_txns;
    struct list_head waiting_read_txns;
    struct list_head waiting_write_txns;
    spinlock_t lock;

    struct lock_table lpa_lock_table;
    struct lock_table mvpn_lock_table;

    struct list_head locked_user_txns;
    struct list_head locked_mapping_txns;
};

static struct am_domain* domains;

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die, blocks_per_plane, pages_per_block;
static unsigned int pages_per_plane, pages_per_die, pages_per_chip,
    pages_per_channel;
static unsigned int sectors_per_page;

static unsigned int namespace_count;
static unsigned int** channel_ids;
static unsigned int* channel_id_count;
static unsigned int** chip_ids;
static unsigned int* chip_id_count;
static unsigned int** die_ids;
static unsigned int* die_id_count;
static unsigned int** plane_ids;
static unsigned int* plane_id_count;

static inline struct am_domain* domain_get(struct flash_transaction* txn)
{
    assert(txn->nsid > 0 && txn->nsid <= namespace_count);
    return &domains[txn->nsid - 1];
}

static inline lpa_t get_mvpn(struct am_domain* domain, lpa_t lpa)
{
    return lpa / domain->translation_entries_per_page;
}

static inline lpa_t mvpn_start_lpa(struct am_domain* domain, lpa_t mvpn)
{
    return mvpn * domain->translation_entries_per_page;
}
static inline lpa_t mvpn_end_lpa(struct am_domain* domain, lpa_t mvpn)
{
    return mvpn_start_lpa(domain, mvpn + 1);
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

ppa_t address_to_ppa(struct flash_address* addr)
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

static void mt_avl_start_iter(struct mapping_table* mt, struct avl_iter* iter,
                              void* key, int flags)
{
    avl_start_iter(&mt->root, iter, key, flags);
}
static struct mapping_entry* mt_avl_get_iter(struct avl_iter* iter)
{
    struct avl_node* node = avl_get_iter(iter);
    if (!node) return NULL;
    return avl_entry(node, struct mapping_entry, avl);
}
static inline void mt_avl_inc_iter(struct avl_iter* iter)
{
    avl_inc_iter(iter);
}
static inline void mt_avl_dec_iter(struct avl_iter* iter)
{
    avl_dec_iter(iter);
}

static void mt_init(struct mapping_table* mt, size_t capacity)
{
    mt->capacity = capacity;
    mt->size = 0;
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

static inline void mt_add_entry(struct mapping_table* mt,
                                struct mapping_entry* entry)
{
    avl_insert(&entry->avl, &mt->root);
    list_add(&entry->lru, &mt->lru_list);
    mt->size++;
}

static int mt_reserve_slot(struct mapping_table* mt, lpa_t lpa)
{
    struct mapping_entry* entry;

    entry = mt_find(mt, lpa);
    if (entry) return EEXIST;

    if (mt->size >= mt->capacity) return ENOSPC;

    SLABALLOC(entry);
    if (!entry) return ENOMEM;

    memset(entry, 0, sizeof(*entry));
    entry->status = MES_WAITING;
    entry->lpa = lpa;
    entry->ppa = NO_PPA;
    mt_add_entry(mt, entry);

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

static struct mapping_entry* mt_evict_entry(struct mapping_table* mt)
{
    struct mapping_entry* entry;

    assert(!list_empty(&mt->lru_list));
    entry = list_entry(mt->lru_list.prev, struct mapping_entry, lru);

    list_del(&entry->lru);
    avl_erase(&entry->avl, &mt->root);
    mt->size--;

    return entry;
}

static int lt_key_node_comp(void* key, struct avl_node* node)
{
    struct lock_entry* r1 = (struct lock_entry*)key;
    struct lock_entry* r2 = avl_entry(node, struct lock_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static int lt_node_node_comp(struct avl_node* node1, struct avl_node* node2)
{
    struct lock_entry* r1 = avl_entry(node1, struct lock_entry, avl);
    struct lock_entry* r2 = avl_entry(node2, struct lock_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static void lt_init(struct lock_table* lt)
{
    spin_lock_init(&lt->lock);
    INIT_AVL_ROOT(&lt->root, lt_key_node_comp, lt_node_node_comp);
}

static struct lock_entry* lt_find(struct lock_table* lt, lpa_t lpa)
{
    struct avl_node* node = lt->root.node;
    struct lock_entry* entry = NULL;

    while (node) {
        entry = avl_entry(node, struct lock_entry, avl);

        if (entry->lpa == lpa) {
            return entry;
        } else if (lpa < entry->lpa)
            node = node->left;
        else if (lpa > entry->lpa)
            node = node->right;
    }

    return NULL;
}

static inline int is_lpa_locked_for_gc(struct am_domain* domain, lpa_t lpa)
{
    return lt_find(&domain->lpa_lock_table, lpa) != NULL;
}

static inline int is_mvpn_locked_for_gc(struct am_domain* domain, lpa_t mvpn)
{
    return lt_find(&domain->mvpn_lock_table, mvpn) != NULL;
}

static inline int mapping_entry_exists(struct am_domain* domain, lpa_t lpa)
{
    return mt_find(&domain->table, lpa) != NULL;
}

static inline int mapping_entry_reserved(struct am_domain* domain, lpa_t lpa)
{
    struct mapping_entry* entry = mt_find(&domain->table, lpa);
    return entry && entry->status == MES_WAITING;
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

static inline void queue_locked_user_transaction(struct am_domain* domain,
                                                 struct flash_transaction* txn)
{
    list_add(&txn->waiting_list, &domain->locked_user_txns);
}

static inline void
queue_locked_mapping_transaction(struct am_domain* domain,
                                 struct flash_transaction* txn)
{
    list_add(&txn->waiting_list, &domain->locked_user_txns);
}

static void assign_plane(struct flash_transaction* txn)
{
    struct am_domain* domain = domain_get(txn);
    struct flash_address* addr = &txn->addr;
    lpa_t lpa = txn->lpa;
    int nsid = txn->nsid - 1;
    unsigned int* channel_id = channel_ids[nsid];
    unsigned int* chip_id = chip_ids[nsid];
    unsigned int* die_id = die_ids[nsid];
    unsigned int* plane_id = plane_ids[nsid];
    unsigned int channel_count = channel_id_count[nsid];
    unsigned int chip_count = chip_id_count[nsid];
    unsigned int die_count = die_id_count[nsid];
    unsigned int plane_count = plane_id_count[nsid];

    assert(txn->nsid > 0 && txn->nsid <= namespace_count);

#define ASSIGN_PHYS_ADDR(lpa, name)                        \
    do {                                                   \
        addr->name##_id = name##_id[(lpa) % name##_count]; \
        (lpa) = (lpa) / name##_count;                      \
    } while (0)

#define ASSIGN_PLANE(lpa, first, second, third, fourth) \
    do {                                                \
        ASSIGN_PHYS_ADDR(lpa, first);                   \
        ASSIGN_PHYS_ADDR(lpa, second);                  \
        ASSIGN_PHYS_ADDR(lpa, third);                   \
        ASSIGN_PHYS_ADDR(lpa, fourth);                  \
    } while (0)

    switch (domain->plane_allocate_scheme) {
    case PAS_CWDP:
        ASSIGN_PLANE(lpa, channel, chip, die, plane);
        break;
    case PAS_CWPD:
        ASSIGN_PLANE(lpa, channel, chip, plane, die);
        break;
    case PAS_CDWP:
        ASSIGN_PLANE(lpa, channel, die, chip, plane);
        break;
    case PAS_CDPW:
        ASSIGN_PLANE(lpa, channel, die, plane, chip);
        break;
    case PAS_CPWD:
        ASSIGN_PLANE(lpa, channel, plane, chip, die);
        break;
    case PAS_CPDW:
        ASSIGN_PLANE(lpa, channel, plane, die, chip);
        break;
    case PAS_WCDP:
        ASSIGN_PLANE(lpa, chip, channel, die, plane);
        break;
    case PAS_WCPD:
        ASSIGN_PLANE(lpa, chip, channel, plane, die);
        break;
    case PAS_WDCP:
        ASSIGN_PLANE(lpa, chip, die, channel, plane);
        break;
    case PAS_WDPC:
        ASSIGN_PLANE(lpa, chip, die, plane, channel);
        break;
    case PAS_WPCD:
        ASSIGN_PLANE(lpa, chip, plane, channel, die);
        break;
    case PAS_WPDC:
        ASSIGN_PLANE(lpa, chip, plane, die, channel);
        break;
    case PAS_DCWP:
        ASSIGN_PLANE(lpa, die, channel, chip, plane);
        break;
    case PAS_DCPW:
        ASSIGN_PLANE(lpa, die, channel, plane, chip);
        break;
    case PAS_DWCP:
        ASSIGN_PLANE(lpa, die, chip, channel, plane);
        break;
    case PAS_DWPC:
        ASSIGN_PLANE(lpa, die, chip, plane, channel);
        break;
    case PAS_DPCW:
        ASSIGN_PLANE(lpa, die, plane, channel, chip);
        break;
    case PAS_DPWC:
        ASSIGN_PLANE(lpa, die, plane, chip, channel);
        break;
    case PAS_PCWD:
        ASSIGN_PLANE(lpa, plane, channel, chip, die);
        break;
    case PAS_PCDW:
        ASSIGN_PLANE(lpa, plane, channel, die, chip);
        break;
    case PAS_PWCD:
        ASSIGN_PLANE(lpa, plane, chip, channel, die);
        break;
    case PAS_PWDC:
        ASSIGN_PLANE(lpa, plane, chip, die, channel);
        break;
    case PAS_PDCW:
        ASSIGN_PLANE(lpa, plane, die, channel, chip);
        break;
    case PAS_PDWC:
        ASSIGN_PLANE(lpa, plane, die, chip, channel);
        break;
    }
#undef ASSIGN_PLANE
#undef ASSIGN_PHYS_ADDR
}

static void alloc_page_for_write(struct flash_transaction* txn, int for_gc)
{
    struct am_domain* domain = domain_get(txn);
    struct mapping_entry* entry = mt_find(&domain->table, txn->lpa);
    assert(entry);

    if (entry->ppa != NO_PPA) {
        struct flash_address addr;

        if (!for_gc) {
            page_bitmap_t bitmap = entry->bitmap & txn->bitmap;
            if (bitmap != entry->bitmap) {
                /* Update read required. */
                struct flash_transaction* read_tx;
                page_bitmap_t read_bitmap = bitmap ^ entry->bitmap;
                int count;

                count = __builtin_popcountl(read_bitmap);

                SLABALLOC(read_tx);
                assert(read_tx);

                memset(read_tx, 0, sizeof(*read_tx));
                read_tx->req = txn->req;
                read_tx->type = TXN_READ;
                read_tx->source = txn->source;
                read_tx->worker = txn->worker;
                read_tx->nsid = txn->nsid;
                read_tx->lpa = txn->lpa;
                read_tx->ppa = entry->ppa;
                read_tx->length = count << SECTOR_SHIFT;
                read_tx->bitmap = read_bitmap;
                read_tx->opaque = txn->opaque;
                read_tx->related_write = txn;
                INIT_LIST_HEAD(&read_tx->list);
                ppa_to_address(entry->ppa, &read_tx->addr);
                bm_read_issued(&read_tx->addr);

                txn->related_read = read_tx;
            }
        }

        ppa_to_address(entry->ppa, &addr);
        bm_invalidate_page(&addr);
    }

    bm_alloc_page(txn->nsid, &txn->addr, for_gc, FALSE);
    txn->ppa = address_to_ppa(&txn->addr);
    mt_update_mapping(&domain->table, txn->lpa, txn->ppa, txn->bitmap, FALSE,
                      FALSE);
}

static void alloc_page_for_mapping(struct flash_transaction* txn, lpa_t mvpn,
                                   int for_gc)
{
    struct am_domain* domain = domain_get(txn);
    struct gtd_entry* gtd = &domain->gtd[mvpn];
    ppa_t mppn = gtd->mppn;

    if (mppn != NO_PPA) {
        struct flash_address addr;
        ppa_to_address(mppn, &addr);
        bm_invalidate_page(&addr);
    }

    bm_alloc_page(txn->nsid, &txn->addr, for_gc, TRUE);
    txn->ppa = address_to_ppa(&txn->addr);
    gtd->mppn = txn->ppa;
    gtd->timestamp = current_time_ns();
}

void amu_alloc_page_gc(struct flash_transaction* txn, int is_mapping)
{
    struct am_domain* domain = domain_get(txn);

    spin_lock(&domain->lock);

    if (is_mapping) {
        alloc_page_for_mapping(txn, txn->lpa, TRUE);
    } else {
        alloc_page_for_write(txn, TRUE);
    }
    txn->ppa_ready = TRUE;

    spin_unlock(&domain->lock);
}

static void submit_mapping_read(struct am_domain* domain, lpa_t lpa)
{
    lpa_t mvpn = get_mvpn(domain, lpa);
    ppa_t mppn;
    struct flash_transaction* read_tx;

    mppn = domain->gtd[mvpn].mppn;

    SLABALLOC(read_tx);
    assert(read_tx);

    memset(read_tx, 0, sizeof(*read_tx));
    read_tx->type = TXN_READ;
    read_tx->source = TS_MAPPING;
    read_tx->worker = worker_self();
    read_tx->nsid = domain->nsid;
    read_tx->lpa = mvpn;
    read_tx->ppa = mppn;
    read_tx->length = sectors_per_page << SECTOR_SHIFT;
    read_tx->bitmap = (1 << sectors_per_page) - 1;
    read_tx->opaque = (void*)mvpn;

    if (is_mvpn_locked_for_gc(domain, mvpn)) {
        queue_locked_mapping_transaction(domain, read_tx);
        return;
    }

    ppa_to_address(mppn, &read_tx->addr);
    bm_read_issued(&read_tx->addr);

    submit_transaction(read_tx);
    stats.total_flash_reads_for_mapping++;

    tsu_kick();
}

static void submit_mapping_writeback(struct am_domain* domain, lpa_t lpa)
{
    lpa_t mvpn = get_mvpn(domain, lpa);
    lpa_t start_lpa = mvpn_start_lpa(domain, mvpn);
    lpa_t end_lpa = mvpn_end_lpa(domain, mvpn);
    struct mapping_entry start_key, *entry;
    struct avl_iter iter;
    page_bitmap_t read_bitmap = 0;
    size_t read_size = 0;
    struct flash_transaction *read_tx = NULL, *write_tx;
    ppa_t mppn;
    int locked = is_mvpn_locked_for_gc(domain, mvpn);

    start_key.lpa = start_lpa;
    mt_avl_start_iter(&domain->table, &iter, &start_key, AVL_GREATER_EQUAL);
    for (entry = mt_avl_get_iter(&iter); entry && entry->lpa < end_lpa;) {
        if (entry->dirty) {
            domain->gmt[entry->lpa].ppa = entry->ppa;
            entry->dirty = FALSE;
        } else {
            page_bitmap_t bit =
                1 << (((entry->lpa - start_lpa) * domain->gtd_entry_size) >>
                      SECTOR_SHIFT);
            if (!(read_bitmap & bit)) {
                read_bitmap |= bit;
                read_size += SECTOR_SIZE;
            }
        }

        mt_avl_inc_iter(&iter);
        entry = mt_avl_get_iter(&iter);
    }

    mppn = domain->gtd[mvpn].mppn;

    SLABALLOC(write_tx);
    assert(write_tx);
    memset(write_tx, 0, sizeof(*write_tx));
    write_tx->type = TXN_WRITE;
    write_tx->source = TS_MAPPING;
    write_tx->worker = worker_self();
    write_tx->nsid = domain->nsid;
    write_tx->lpa = mvpn;
    write_tx->ppa = NO_PPA;
    write_tx->length = sectors_per_page << SECTOR_SHIFT;
    write_tx->bitmap = (1 << sectors_per_page) - 1;

    if (locked) {
        queue_locked_mapping_transaction(domain, write_tx);
        return;
    } else {
        assign_plane(write_tx);
        alloc_page_for_mapping(write_tx, mvpn, FALSE);
        stats.total_flash_writes_for_mapping++;
    }

    if (mppn != NO_PPA && read_size) {
        SLABALLOC(read_tx);
        assert(read_tx);
        memset(read_tx, 0, sizeof(*read_tx));
        read_tx->type = TXN_READ;
        read_tx->source = TS_MAPPING;
        read_tx->worker = worker_self();
        read_tx->nsid = domain->nsid;
        read_tx->lpa = mvpn;
        read_tx->ppa = mppn;
        read_tx->length = read_size;
        read_tx->bitmap = read_bitmap;
        read_tx->opaque = (void*)mvpn;
        ppa_to_address(mppn, &read_tx->addr);
        bm_read_issued(&read_tx->addr);

        read_tx->related_write = write_tx;
        stats.total_flash_reads_for_mapping++;
    }

    write_tx->related_read = read_tx;

    if (read_tx) submit_transaction(read_tx);
    submit_transaction(write_tx);

    tsu_kick();
}

static int reserve_slot(struct am_domain* domain, lpa_t lpa)
{
    int retval = mt_reserve_slot(&domain->table, lpa);

    if (retval == ENOSPC) {
        struct mapping_entry* entry;

        entry = mt_evict_entry(&domain->table);
        if (entry->dirty) {
            struct gmt_entry* gmt = &domain->gmt[entry->lpa];
            gmt->ppa = entry->ppa;
            gmt->bitmap = entry->bitmap;
            gmt->timestamp = current_time_ns();
            submit_mapping_writeback(domain, entry->lpa);
        }

        memset(entry, 0, sizeof(*entry));
        entry->status = MES_WAITING;
        entry->lpa = lpa;
        entry->ppa = NO_PPA;
        mt_add_entry(&domain->table, entry);

        return 0;
    }

    return retval;
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
        bm_read_issued(&txn->addr);
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
    struct flash_transaction* tp;

    if (domain->gtd[mvpn].mppn == NO_PPA) {
        reserve_slot(domain, lpa);
        mt_update_mapping(&domain->table, lpa, NO_PPA, 0, TRUE, TRUE);

        return TRUE;
    }

    /* Check whether a read txn for the target MVPN is in flight. */
    list_for_each_entry(tp, &domain->waiting_read_txns, waiting_list)
    {
        if (get_mvpn(domain, tp->lpa) == mvpn) {
            if (!mapping_entry_reserved(domain, lpa)) reserve_slot(domain, lpa);

            return FALSE;
        }
    }
    list_for_each_entry(tp, &domain->waiting_write_txns, waiting_list)
    {
        if (get_mvpn(domain, tp->lpa) == mvpn) {
            if (!mapping_entry_reserved(domain, lpa)) reserve_slot(domain, lpa);

            return FALSE;
        }
    }

    /* Generate a read request for the MVPN. */
    reserve_slot(domain, lpa);
    submit_mapping_read(domain, lpa);

    return FALSE;
}

static void handle_unsuccessful_translation(struct am_domain* domain,
                                            struct flash_transaction* txn)
{
    list_add(&txn->waiting_list, &domain->unsuccessful_txns);
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

        if (!translate_lpa(domain, txn))
            handle_unsuccessful_translation(domain, txn);
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

            if (!translate_lpa(domain, txn))
                handle_unsuccessful_translation(domain, txn);
        } else {
            if (txn->type == TXN_READ) {
                list_add_tail(&txn->waiting_list, &domain->waiting_read_txns);
            } else {
                list_add_tail(&txn->waiting_list, &domain->waiting_write_txns);
            }
        }
    }

    spin_unlock(&domain->lock);
}

static void domain_init(struct am_domain* domain, unsigned int nsid,
                        size_t capacity, unsigned int gtd_entry_size,
                        size_t translation_entries_per_page,
                        lha_t total_logical_sectors,
                        enum plane_allocate_scheme scheme)
{
    size_t total_logical_pages = total_logical_sectors / sectors_per_page;
    size_t total_translation_pages =
        (total_logical_pages + translation_entries_per_page - 1) /
        translation_entries_per_page;
    size_t alloc_size;
    void* buf;
    int i;

    memset(domain, 0, sizeof(*domain));

    domain->nsid = nsid;
    domain->plane_allocate_scheme = scheme;

    mt_init(&domain->table, capacity);
    spin_lock_init(&domain->lock);
    INIT_LIST_HEAD(&domain->unsuccessful_txns);
    INIT_LIST_HEAD(&domain->waiting_read_txns);
    INIT_LIST_HEAD(&domain->waiting_write_txns);

    INIT_LIST_HEAD(&domain->locked_user_txns);
    INIT_LIST_HEAD(&domain->locked_mapping_txns);

    domain->translation_entries_per_page = translation_entries_per_page;
    domain->gtd_entry_size = gtd_entry_size;

    alloc_size = total_translation_pages * sizeof(struct gtd_entry) +
                 total_logical_pages * sizeof(struct gmt_entry);
    alloc_size = roundup(alloc_size, PG_SIZE);
    buf = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);
    domain->gtd = (struct gtd_entry*)buf;
    domain->gmt = (struct gmt_entry*)(buf + total_translation_pages *
                                                sizeof(struct gtd_entry));

    for (i = 0; i < total_translation_pages; i++) {
        domain->gtd[i].mppn = NO_PPA;
        domain->gtd[i].timestamp = 0;
    }

    for (i = 0; i < total_logical_pages; i++) {
        domain->gmt[i].ppa = NO_PPA;
        domain->gmt[i].timestamp = 0;
        domain->gmt[i].bitmap = 0;
    }

    lt_init(&domain->lpa_lock_table);
    lt_init(&domain->mvpn_lock_table);
}

void amu_init(size_t mt_capacity, unsigned int nr_channels,
              unsigned int nr_chips_per_channel, unsigned int nr_dies_per_chip,
              unsigned int nr_planes_per_die, unsigned int nr_blocks_per_plane,
              unsigned int nr_pages_per_block, unsigned int sectors_in_page,
              unsigned int nr_namespaces, unsigned int** channel_id_list,
              unsigned int* nr_channel_ids, unsigned int** chip_id_list,
              unsigned int* nr_chip_ids, unsigned int** die_id_list,
              unsigned int* nr_die_ids, unsigned int** plane_id_list,
              unsigned int* nr_plane_ids,
              enum plane_allocate_scheme* plane_allocate_schemes)
{
    int i;
    size_t alloc_size;

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

    namespace_count = nr_namespaces;
    channel_ids = channel_id_list;
    channel_id_count = nr_channel_ids;
    chip_ids = chip_id_list;
    chip_id_count = nr_chip_ids;
    die_ids = die_id_list;
    die_id_count = nr_die_ids;
    plane_ids = plane_id_list;
    plane_id_count = nr_plane_ids;

    alloc_size = namespace_count * sizeof(struct am_domain);
    alloc_size = roundup(alloc_size, PG_SIZE);
    domains = (struct am_domain*)vmalloc_pages(alloc_size >> PG_SHIFT, NULL);

    for (i = 0; i < namespace_count; i++)
        domain_init(&domains[i], i + 1, mt_capacity, 4,
                    (sectors_per_page * SECTOR_SIZE) >> 2,
                    pages_per_channel * sectors_per_page,
                    plane_allocate_schemes[i]);
}

void amu_dispatch(struct user_request* req)
{
    struct flash_transaction* txn;

    list_for_each_entry(txn, &req->txn_list, list)
    {
        struct am_domain* domain = domain_get(txn);
        if (is_lpa_locked_for_gc(domain, txn->lpa))
            queue_locked_user_transaction(domain, txn);
        else
            translate_transaction(txn);
    }

    if (!list_empty(&req->txn_list)) {
        list_for_each_entry(txn, &req->txn_list, list)
        {
            if (txn->ppa_ready) {
                submit_transaction(txn);

                if (txn->related_read) submit_transaction(txn->related_read);
            }
        }

        tsu_kick();
    }
}

void amu_transaction_complete(struct flash_transaction* txn)
{
    struct am_domain* domain = domain_get(txn);

    if (txn->type == TXN_READ) {
        struct flash_transaction *tp, *tmp;
        lpa_t mvpn = (lpa_t)txn->opaque;
        struct list_head restart_txns;
        lpa_t lpa;

        spin_lock(&domain->lock);

        INIT_LIST_HEAD(&restart_txns);

        if (txn->related_write) {
            txn->related_write->related_read = NULL;
        }

        list_for_each_entry_safe(tp, tmp, &domain->waiting_read_txns,
                                 waiting_list)
        {
            if (get_mvpn(domain, tp->lpa) == mvpn) {
                list_del(&tp->waiting_list);
                lpa = tp->lpa;

                if (mapping_entry_reserved(domain, lpa)) {
                    struct gmt_entry* gmt = &domain->gmt[lpa];

                    mt_update_mapping(&domain->table, lpa, gmt->ppa,
                                      gmt->bitmap, TRUE, TRUE);
                }

                list_add_tail(&tp->waiting_list, &restart_txns);
            }
        }

        list_for_each_entry_safe(tp, tmp, &domain->waiting_write_txns,
                                 waiting_list)
        {
            if (get_mvpn(domain, tp->lpa) == mvpn) {
                list_del(&tp->waiting_list);
                lpa = tp->lpa;

                if (mapping_entry_reserved(domain, lpa)) {
                    struct gmt_entry* gmt = &domain->gmt[lpa];

                    mt_update_mapping(&domain->table, lpa, gmt->ppa,
                                      gmt->bitmap, TRUE, TRUE);
                }

                list_add_tail(&tp->waiting_list, &restart_txns);
            }
        }

        list_for_each_entry(tp, &restart_txns, waiting_list)
        {
            if (translate_lpa(domain, tp))
                submit_transaction(tp);
            else
                handle_unsuccessful_translation(domain, tp);
        }

        spin_unlock(&domain->lock);

        tsu_kick();
    }
}

void amu_lock_lpa(unsigned int nsid, lpa_t lpa, int is_mapping)
{
    assert(nsid > 0 && nsid <= namespace_count);
    struct am_domain* domain = &domains[nsid - 1];
    struct lock_table* table;
    struct lock_entry* entry;

    SLABALLOC(entry);
    assert(entry);

    entry->lpa = lpa;
    if (is_mapping) {
        table = &domain->mvpn_lock_table;
    } else {
        table = &domain->lpa_lock_table;
    }

    spin_lock(&table->lock);
    avl_insert(&entry->avl, &table->root);
    spin_unlock(&table->lock);
}

static void restart_locked_user_transactions(struct am_domain* domain,
                                             lpa_t lpa)
{
    struct flash_transaction *txn, *tmp;

    list_for_each_entry_safe(txn, tmp, &domain->locked_user_txns, waiting_list)
    {
        if (txn->lpa == lpa) {
            list_del(&txn->waiting_list);
            notify_transaction_complete(txn);
        }
    }
}

static void restart_locked_mapping_transactions(struct am_domain* domain,
                                                lpa_t mvpn)
{
    struct flash_transaction *txn, *tmp;

    list_for_each_entry_safe(txn, tmp, &domain->locked_mapping_txns,
                             waiting_list)
    {
        if (txn->lpa == mvpn) {
            list_del(&txn->waiting_list);
            notify_transaction_complete(txn);
        }
    }
}

void amu_unlock_lpa(unsigned int nsid, lpa_t lpa, int is_mapping)
{
    assert(nsid > 0 && nsid <= namespace_count);
    struct am_domain* domain = &domains[nsid - 1];
    struct lock_table* table;
    struct lock_entry* entry;

    spin_lock(&domain->lock);

    if (is_mapping) {
        table = &domain->mvpn_lock_table;
    } else {
        table = &domain->lpa_lock_table;
    }

    spin_lock(&table->lock);
    entry = lt_find(table, lpa);
    assert(entry);
    avl_erase(&entry->avl, &table->root);
    SLABFREE(entry);
    spin_unlock(&table->lock);

    if (is_mapping) {
        restart_locked_mapping_transactions(domain, lpa);
    } else {
        restart_locked_user_transactions(domain, lpa);
    }

    spin_unlock(&domain->lock);
}
