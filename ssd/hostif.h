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
int hostif_send_ready(void);
void hostif_report_result(Mcmq__SimResult* result);

/* hostif_nvme.c */
void hostif_nvme_init(unsigned int sectors_per_page);
void nvme_process_read_message(uint64_t addr, uint32_t id);
void nvme_process_write_message(uint64_t addr, const char* buf, size_t len);
void nvme_complete_request(struct user_request* req);
void nvme_report_result(Mcmq__SimResult* result);

#endif
