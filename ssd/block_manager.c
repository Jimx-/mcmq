#include "const.h"
#include "proto.h"
#include "spinlock.h"

#include "ssd.h"

#include <assert.h>

struct block_data {
    struct list_head list;
    unsigned short block_id;
    unsigned short page_write_index;
};

struct plane_allocator {
    struct block_data* blocks;
    struct list_head free_list;
    struct block_data* data_wf;
    struct block_data* gc_wf;
    spinlock_t lock;
};

static struct plane_allocator**** planes;

static unsigned int channel_count, chips_per_channel, dies_per_chip,
    planes_per_die, blocks_per_plane, pages_per_block;

static struct block_data* get_free_block(struct plane_allocator* plane)
{
    struct block_data* block;

    if (list_empty(&plane->free_list)) return NULL;

    block = list_entry(plane->free_list.next, struct block_data, list);
    list_del(&block->list);

    return block;
}

static void init_plane(struct plane_allocator* plane)
{
    int i;

    INIT_LIST_HEAD(&plane->free_list);

    for (i = 0; i < blocks_per_plane; i++) {
        struct block_data* block = &plane->blocks[i];

        block->block_id = i;
        block->page_write_index = 0;

        list_add(&block->list, &plane->free_list);
    }

    plane->data_wf = get_free_block(plane);
    plane->gc_wf = get_free_block(plane);

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
                 nr_blocks * sizeof(struct block_data);
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
                    planes[i][j][k][l].blocks = cur_block;
                    cur_block += blocks_per_plane;

                    init_plane(&planes[i][j][k][l]);
                }
            }
        }
    }
}

void bm_alloc_page(struct flash_address* addr, int for_gc)
{
    struct plane_allocator* plane =
        &planes[addr->channel_id][addr->chip_id][addr->die_id][addr->plane_id];
    struct block_data* block;

    spin_lock(&plane->lock);

    block = for_gc ? plane->gc_wf : plane->data_wf;
    addr->block_id = block->block_id;
    addr->page_id = block->page_write_index++;

    if (block->page_write_index == pages_per_block) {
        block = get_free_block(plane);

        if (for_gc)
            plane->gc_wf = block;
        else
            plane->data_wf = block;
    }

    spin_unlock(&plane->lock);
}

void bm_invalidate_page(struct flash_address* addr) {}

void bm_init(unsigned int nr_channels, unsigned int nr_chips_per_channel,
             unsigned int nr_dies_per_chip, unsigned int nr_planes_per_die,
             unsigned int nr_blocks_per_plane, unsigned int nr_pages_per_block)
{
    channel_count = nr_channels;
    chips_per_channel = nr_chips_per_channel;
    dies_per_chip = nr_dies_per_chip;
    planes_per_die = nr_planes_per_die;
    blocks_per_plane = nr_blocks_per_plane;
    pages_per_block = nr_pages_per_block;

    alloc_planes();
}
