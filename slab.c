#include "bitmap.h"
#include "const.h"
#include "global.h"
#include "list.h"
#include "proto.h"
#include "spinlock.h"
#include "vm.h"

#include <string.h>

#define OBJ_ALIGN 4

#define SLABSIZE 200
#define MINSIZE 8
#define MAXSIZE ((SLABSIZE - 1 + MINSIZE) / OBJ_ALIGN * OBJ_ALIGN)

struct slabdata;

struct slabheader {
    struct list_head list;
    bitchunk_t used_mask[BITCHUNKS(PG_SIZE / MINSIZE)];
    unsigned short freeguess;
    unsigned short used;
    unsigned long phys;
    struct slabdata* data;
};

#define DATABYTES (PG_SIZE - sizeof(struct slabheader))

struct slabdata {
    unsigned char data[DATABYTES];
    struct slabheader header;
};

struct slab {
    struct list_head list;
    spinlock_t lock;
};

static struct slab slabs[SLABSIZE];

#define SLAB_INDEX(bytes) (roundup(bytes, OBJ_ALIGN) - (MINSIZE / OBJ_ALIGN))

void slabs_init()
{
    int i;
    for (i = 0; i < SLABSIZE; i++) {
        spin_lock_init(&slabs[i].lock);
        INIT_LIST_HEAD(&slabs[i].list);
    }
}

static struct slabdata* alloc_slabdata()
{
    unsigned long phys = alloc_pages(1);
    struct slabdata* sd = (struct slabdata*)__va(phys);
    if (!sd) return NULL;

    memset(&sd->header.used_mask, 0, sizeof(sd->header.used_mask));
    sd->header.used = 0;
    sd->header.freeguess = 0;
    INIT_LIST_HEAD(&(sd->header.list));
    sd->header.phys = phys;
    sd->header.data = sd;

    return sd;
}

void* slaballoc(size_t bytes)
{
    if (bytes > MAXSIZE || bytes < MINSIZE) {
        /* printk("mm: slaballoc: invalid size(%d bytes)\n", bytes); */
        return NULL;
    }

    struct slab* slab = &slabs[SLAB_INDEX(bytes)];
    struct slabdata* sd = NULL;
    struct slabheader* header;
    void* ptr = NULL;

    bytes = roundup(bytes, OBJ_ALIGN);

    spin_lock(&slab->lock);

    if (list_empty(&slab->list)) {
        sd = alloc_slabdata();
        if (!sd) goto out;

        list_add(&sd->header.list, &slab->list);
    }

    int i;
    int max_objs = DATABYTES / bytes;
    list_for_each_entry(header, &slab->list, list)
    {
        if (header->used == max_objs) continue;

        for (i = header->freeguess; i < max_objs; i++) {
            if (!GET_BIT(header->used_mask, i)) {
                sd = header->data;
                SET_BIT(header->used_mask, i);
                header->freeguess = i + 1;
                header->used++;

                ptr = (void*)&sd->data[i * bytes];
                goto out;
            }
        }

        for (i = 0; i < header->freeguess; i++) {
            if (!GET_BIT(header->used_mask, i)) {
                sd = header->data;
                SET_BIT(header->used_mask, i);
                header->freeguess = i + 1;
                header->used++;

                ptr = (void*)&sd->data[i * bytes];
                goto out;
            }
        }
    }

    sd = alloc_slabdata();
    if (!sd) goto out;

    header = &sd->header;
    list_add(&header->list, &slab->list);

    for (i = 0; i < max_objs; i++) {
        if (!GET_BIT(header->used_mask, i)) {
            SET_BIT(header->used_mask, i);
            header->freeguess = i + 1;
            header->used++;

            ptr = (void*)&sd->data[i * bytes];
            goto out;
        }
    }

out:
    spin_unlock(&slab->lock);
    return ptr;
}

void slabfree(void* mem, size_t bytes)
{
    if (bytes > MAXSIZE || bytes < MINSIZE) {
        return;
    }

    struct slab* slab = &slabs[SLAB_INDEX(bytes)];
    struct slabdata* sd;
    struct slabheader* header;

    spin_lock(&slab->lock);

    bytes = roundup(bytes, OBJ_ALIGN);

    if (list_empty(&slab->list)) goto out;

    list_for_each_entry(header, &slab->list, list)
    {
        if (header->used == 0) continue;
        sd = header->data;

        if ((mem >= (void*)&sd->data) && (mem < (void*)&sd->data + DATABYTES)) {
            int i = (mem - (void*)&sd->data) / bytes;
            UNSET_BIT(header->used_mask, i);
            header->used--;
            header->freeguess = i;
            goto out;
        }
    }

out:
    spin_unlock(&slab->lock);
}
