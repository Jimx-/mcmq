#include "const.h"
#include "proto.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void* malloc(size_t size)
{
    void* ptr;

    size = roundup(size, 4);
    ptr = slaballoc(size + sizeof(uint32_t));

    if (!ptr) {
        size = roundup(size, PG_SIZE);
        ptr = vmalloc_pages(size >> PG_SHIFT, NULL);
        assert(ptr);
        size |= 1;
    }

    *(uint32_t*)ptr = (uint32_t)size;
    return ptr + sizeof(uint32_t);
}

void* calloc(size_t num, size_t size)
{
    size_t alloc_size = num * size;
    void* ptr = malloc(alloc_size);

    if (!ptr) return NULL;

    memset(ptr, 0, alloc_size);
    return ptr;
}

void free(void* ptr)
{
    void* p = ptr - sizeof(uint32_t);
    uint32_t size = *(uint32_t*)p;

    if (size & 1)
        vmfree(p, size & ~1);
    else
        slabfree(p, size);
}
