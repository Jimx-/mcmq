#ifndef _SSD_HOSTIF_H_
#define _SSD_HOSTIF_H_

#include <stddef.h>
#include <stdint.h>

/* hostif.c */
void hostif_init(void);
int hostif_complete_host_read(uint32_t id, const char* buf, size_t len);
int hostif_send_irq(uint16_t vector);

/* hostif_nvme.c */
void hostif_nvme_init(void);
void nvme_process_read_message(uint64_t addr, uint32_t id);
void nvme_process_write_message(uint64_t addr, const char* buf, size_t len);

#endif
