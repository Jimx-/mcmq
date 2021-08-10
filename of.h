#ifndef _OF_H_
#define _OF_H_

#include <stdint.h>

typedef uint32_t phandle_t;

extern void* fdt_root;

#define MAX_PHANDLE_ARGS 16
struct of_phandle_args {
    unsigned long offset;
    int args_count;
    uint32_t args[MAX_PHANDLE_ARGS];
};

struct of_phandle_iterator {
    const char* cells_name;
    int cell_count;
    const void* blob;
    unsigned long parent_offset;

    const uint32_t* list_end;
    const uint32_t* phandle_end;

    const uint32_t* cur;
    uint32_t cur_count;
    phandle_t phandle;
    unsigned long offset;
};

int of_phandle_iterator_init(struct of_phandle_iterator* it, const void* blob,
                             unsigned long offset, const char* list_name,
                             const char* cells_name, int cell_count);
int of_phandle_iterator_next(struct of_phandle_iterator* it);

#define of_for_each_phandle(it, err, blob, off, ln, cn, cc)               \
    for (of_phandle_iterator_init((it), (blob), (off), (ln), (cn), (cc)), \
         err = of_phandle_iterator_next(it);                              \
         err == 0; err = of_phandle_iterator_next(it))

int of_irq_count(const void* blob, unsigned long offset);
int of_irq_parse_one(const void* blob, unsigned long offset, int index,
                     struct of_phandle_args* out_irq);

#endif
