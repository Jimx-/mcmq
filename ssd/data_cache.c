#include "avl.h"
#include "const.h"
#include "hostif.h"
#include "proto.h"
#include "spinlock.h"
#include "ssd.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

enum cache_entry_status {
    CES_EMPTY,
    CES_CLEAN,
    CES_DIRTY,
};

struct cache_entry {
    lpa_t lpa;
    unsigned int nsid;
    page_bitmap_t bitmap;
    enum cache_entry_status status;
    struct avl_node avl;
    struct list_head lru;
};

static enum cache_mode cache_mode = CM_NO_CACHE;

struct data_cache {
    size_t capacity_pages;
    size_t nr_pages;
    unsigned int nsid;
    struct avl_root root;
    struct list_head lru_list;
    spinlock_t lock;
};

static unsigned int namespace_count;
static struct data_cache* caches;

static inline struct data_cache*
get_cache_for_txn(struct flash_transaction* txn)
{
    assert(txn->nsid > 0 && txn->nsid <= namespace_count);
    return &caches[txn->nsid - 1];
}

static inline int is_user_request_complete(struct user_request* req)
{
    return list_empty(&req->txn_list);
}

static void complete_user_request(struct user_request* req)
{
    nvme_complete_request(req);
}

static int cache_key_node_comp(void* key, struct avl_node* node)
{
    struct cache_entry* r1 = (struct cache_entry*)key;
    struct cache_entry* r2 = avl_entry(node, struct cache_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static int cache_node_node_comp(struct avl_node* node1, struct avl_node* node2)
{
    struct cache_entry* r1 = avl_entry(node1, struct cache_entry, avl);
    struct cache_entry* r2 = avl_entry(node2, struct cache_entry, avl);

    if (r1->lpa < r2->lpa)
        return -1;
    else if (r1->lpa > r2->lpa)
        return 1;
    return 0;
}

static void cache_init(struct data_cache* cache, unsigned int nsid,
                       size_t capacity_pages)
{
    cache->capacity_pages = capacity_pages;
    cache->nr_pages = 0;
    cache->nsid = nsid;
    spin_lock_init(&cache->lock);
    INIT_LIST_HEAD(&cache->lru_list);
    INIT_AVL_ROOT(&cache->root, cache_key_node_comp, cache_node_node_comp);
}

static struct cache_entry* cache_find(struct data_cache* cache, lpa_t lpa)
{
    struct avl_node* node = cache->root.node;
    struct cache_entry* entry = NULL;

    while (node) {
        entry = avl_entry(node, struct cache_entry, avl);

        if (entry->lpa == lpa) {
            return entry;
        } else if (lpa < entry->lpa)
            node = node->left;
        else if (lpa > entry->lpa)
            node = node->right;
    }

    return NULL;
}

static void cache_touch_lru(struct data_cache* cache, struct cache_entry* entry)
{
    list_del(&entry->lru);
    list_add(&entry->lru, &cache->lru_list);
}

static struct cache_entry* cache_get(struct data_cache* cache, lpa_t lpa)
{
    struct cache_entry* entry = cache_find(cache, lpa);
    if (!entry) return NULL;

    cache_touch_lru(cache, entry);
    return entry;
}

static inline void cache_add_entry(struct data_cache* cache,
                                   struct cache_entry* entry)
{
    avl_insert(&entry->avl, &cache->root);
    list_add(&entry->lru, &cache->lru_list);
    cache->nr_pages++;
}

static int cache_add(struct data_cache* cache, lpa_t lpa, page_bitmap_t bitmap)
{
    struct cache_entry* entry;

    if (cache->nr_pages >= cache->capacity_pages) return ENOSPC;

    SLABALLOC(entry);
    if (!entry) return ENOMEM;

    memset(entry, 0, sizeof(*entry));
    entry->lpa = lpa;
    entry->bitmap = bitmap;
    entry->status = CES_DIRTY;
    cache_add_entry(cache, entry);

    return 0;
}

static struct cache_entry* cache_evict_entry(struct data_cache* cache)
{
    struct cache_entry* entry;

    assert(!list_empty(&cache->lru_list));
    entry = list_entry(cache->lru_list.prev, struct cache_entry, lru);

    list_del(&entry->lru);
    avl_erase(&entry->avl, &cache->root);
    cache->nr_pages--;

    return entry;
}

static void handle_cached_read(struct user_request* req)
{
    struct flash_transaction *txn, *tmp;

    list_for_each_entry_safe(txn, tmp, &req->txn_list, list)
    {
        struct data_cache* cache = get_cache_for_txn(txn);
        spin_lock(&cache->lock);

        struct cache_entry* slot = cache_get(cache, txn->lpa);
        page_bitmap_t avail_sectors;

        if (!slot) goto unlock;

        avail_sectors = slot->bitmap & txn->bitmap;

        if (avail_sectors == txn->bitmap) {
            list_del(&txn->list);
            SLABFREE(txn);
        } else if (avail_sectors != 0) {
            int count = __builtin_popcountl(avail_sectors);

            txn->bitmap &= ~avail_sectors;
            txn->length -= count << SECTOR_SHIFT;
        }
    unlock:
        spin_unlock(&cache->lock);
    }
}

void write_to_buffers(struct user_request* req)
{
    struct flash_transaction *txn, *tmp;
    struct user_request writeback_req;

    INIT_LIST_HEAD(&writeback_req.txn_list);

    list_for_each_entry_safe(txn, tmp, &req->txn_list, list)
    {
        struct data_cache* cache = get_cache_for_txn(txn);
        spin_lock(&cache->lock);

        struct cache_entry* entry = cache_find(cache, txn->lpa);
        int retval;

        if (entry) {
            entry->bitmap |= txn->bitmap;
        } else {
            retval = cache_add(cache, txn->lpa, txn->bitmap);

            if (retval) {
                if (retval == ENOSPC) {
                    entry = cache_evict_entry(cache);

                    if (entry->status == CES_DIRTY) {
                        struct flash_transaction* wb_txn;

                        int count = __builtin_popcountl(entry->bitmap);

                        SLABALLOC(wb_txn);

                        if (!wb_txn) {
                            spin_unlock(&cache->lock);
                            break;
                        }

                        memset(wb_txn, 0, sizeof(*wb_txn));
                        wb_txn->type = TXN_WRITE;
                        wb_txn->source = TS_USER_IO;
                        wb_txn->worker = worker_self();
                        wb_txn->nsid = cache->nsid;
                        wb_txn->lpa = entry->lpa;
                        wb_txn->ppa = NO_PPA;
                        wb_txn->length = count << SECTOR_SHIFT;
                        wb_txn->bitmap = entry->bitmap;
                        list_add_tail(&wb_txn->list, &writeback_req.txn_list);
                    }

                    memset(entry, 0, sizeof(*entry));
                    entry->status = CES_DIRTY;
                    entry->lpa = txn->lpa;
                    entry->bitmap = txn->bitmap;
                    cache_add_entry(cache, entry);
                } else {
                    spin_unlock(&cache->lock);
                    break;
                }
            }
        }

        list_del(&txn->list);
        SLABFREE(txn);

        spin_unlock(&cache->lock);
    }

    if (!list_empty(&writeback_req.txn_list)) amu_dispatch(&writeback_req);
}

void dc_handle_user_request(struct user_request* req)
{
    if (list_empty(&req->txn_list)) complete_user_request(req);

    switch (cache_mode) {
    case CM_NO_CACHE:
        amu_dispatch(req);
        break;
    case CM_WRITE_CACHE:
        if (req->do_write) {
            /* Write request. */
            write_to_buffers(req);
        } else {
            /* Read request. */
            handle_cached_read(req);
        }

        if (list_empty(&req->txn_list))
            complete_user_request(req);
        else
            amu_dispatch(req);

        break;
    }
}

void dc_transaction_complete(struct flash_transaction* txn)
{
    if (!txn->req) return;

    if (!(txn->type == TXN_WRITE && cache_mode == CM_WRITE_CACHE)) {
        if (txn->type == TXN_READ && txn->related_write) {
            txn->related_write->related_read = NULL;
            tsu_kick();
        }

        list_del(&txn->list);
        if (is_user_request_complete(txn->req)) complete_user_request(txn->req);
    }
}

void dc_init(enum cache_mode mode, size_t capacity_pages,
             unsigned int nr_namespaces)
{
    int i;
    size_t alloc_size;

    cache_mode = mode;
    namespace_count = nr_namespaces;

    alloc_size = namespace_count * sizeof(struct data_cache);
    alloc_size = roundup(alloc_size, PG_SIZE);
    caches = (struct data_cache*)vmalloc_pages(alloc_size >> PG_SHIFT, NULL);

    for (i = 0; i < namespace_count; i++)
        cache_init(&caches[i], i + 1, capacity_pages / namespace_count);
}
