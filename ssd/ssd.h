#ifndef _SSD_SSD_H_
#define _SSD_SSD_H_

#include <stdint.h>

typedef uint64_t lha_t; /* logical host address */
typedef uint64_t pda_t; /* physical device address */

/* worker.c */
void init_ssd_worker(void);
void notify_worker(int worker);
int enqueue_rw_command(int worker, int do_write, uint64_t slba,
                       uint64_t length);
void process_worker_queue(void);

#endif
