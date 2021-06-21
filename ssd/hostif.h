#ifndef _SSD_HOSTIF_H_
#define _SSD_HOSTIF_H_

#include "ssd.h"

#include <stddef.h>
#include <stdint.h>

/* hostif.c */
void hostif_init(unsigned int sectors_per_page);
void hostif_init_cpu(void);
int hostif_complete_host_read(uint32_t id, const char* buf, size_t len);
int hostif_send_irq(uint16_t vector);

/* hostif_nvme.c */
void hostif_nvme_init(unsigned int sectors_per_page);
void nvme_process_read_message(uint64_t addr, uint32_t id);
void nvme_process_write_message(uint64_t addr, const char* buf, size_t len);
void nvme_complete_request(struct user_request* req);

#endif
