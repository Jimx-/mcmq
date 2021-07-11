#include "hostif.h"
#include "byteorder.h"
#include "const.h"
#include "proto.h"
#include "ringbuf.h"
#include "ssd.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Message types. */
#define MT_READ 1
#define MT_WRITE 2
#define MT_READ_COMP 3
#define MT_IRQ 4
#define MT_READY 5
#define MT_REPORT 6
#define MT_RESULT 7

#define MESSAGE_RINGBUF_DEFAULT_CAPACITY (PG_SIZE * 4 - 1)

static ringbuf_t pcie_message_ringbuf;

static int hostif_send_report(const char* buf, size_t len);

static void handle_report_message(void)
{
    Mcmq__SimResult result;
    size_t packed_size;
    char* buf;
    size_t alloc_size;

    mcmq__sim_result__init(&result);
    ssd_report_result(&result);
    packed_size = mcmq__sim_result__get_packed_size(&result);

    alloc_size = roundup(packed_size, PG_SIZE);
    buf = vmalloc_pages(alloc_size >> PG_SHIFT, NULL);
    assert(buf);

    mcmq__sim_result__pack(&result, (uint8_t*)buf);
    hostif_send_report(buf, packed_size);
}

static void consume_pcie_messsage(const char* buf, size_t len)
{
    uint16_t type;
    uint64_t addr;
    uint32_t id;

    assert(len >= 10);
    type = be16_to_cpup((uint16_t*)buf);
    addr = ((unsigned long)be32_to_cpup((uint32_t*)&buf[2]) << 32) |
           be32_to_cpup((uint32_t*)&buf[6]);

    switch (type) {
    case MT_READ:
        id = *(uint32_t*)&buf[10];
        nvme_process_read_message(addr, id);
        break;
    case MT_WRITE:
        nvme_process_write_message(addr, &buf[10], len - 10);
        break;
    case MT_REPORT:
        handle_report_message();
        break;
    default:
        break;
    }
}

static void process_message_ringbuf(void)
{
    uint16_t msg_len;
    char msg_buf[512];

    for (;;) {
        /* No message. */
        if (ringbuf_bytes_used(pcie_message_ringbuf) < sizeof(uint16_t)) return;

        ringbuf_memcpy_from(&msg_len, pcie_message_ringbuf, sizeof(msg_len));
        msg_len = be16_to_cpup(&msg_len);

        assert(ringbuf_bytes_used(pcie_message_ringbuf) >= msg_len);
        assert(msg_len < sizeof(msg_buf));

        ringbuf_memcpy_from(msg_buf, pcie_message_ringbuf, msg_len);

        consume_pcie_messsage(msg_buf, msg_len);
    }
}

static void hostif_process_pcie_message(uint32_t src_cid, uint32_t src_port,
                                        const char* buf, size_t len)
{
    ringbuf_memcpy_into(pcie_message_ringbuf, buf, len);

    process_message_ringbuf();
}

int hostif_complete_host_read(uint32_t id, const char* buf, size_t len)
{
    char msg[1024];
    size_t msg_len = 2 + 4 + len;

    assert(msg_len + 2 <= sizeof(msg));

    *(uint16_t*)&msg[0] = __builtin_bswap16(msg_len);
    *(uint16_t*)&msg[2] = __builtin_bswap16((uint16_t)MT_READ_COMP);
    *(uint32_t*)&msg[4] = id;
    memcpy(&msg[8], buf, len);

    virtio_vsock_send(VSOCK_HOST_CID, VSOCK_HOST_PORT, msg, 2 + msg_len);

    return 0;
}

int hostif_send_irq(uint16_t vector)
{
    char msg[1024];
    size_t msg_len = 2 + 2;

    assert(msg_len + 2 <= sizeof(msg));

    *(uint16_t*)&msg[0] = __builtin_bswap16(msg_len);
    *(uint16_t*)&msg[2] = __builtin_bswap16((uint16_t)MT_IRQ);
    *(uint16_t*)&msg[4] = __builtin_bswap16(vector);

    virtio_vsock_send(VSOCK_HOST_CID, VSOCK_HOST_PORT, msg, 2 + msg_len);

    return 0;
}

int hostif_send_ready(void)
{
    char msg[1024];
    size_t msg_len = 2;

    assert(msg_len + 2 <= sizeof(msg));

    *(uint16_t*)&msg[0] = __builtin_bswap16(msg_len);
    *(uint16_t*)&msg[2] = __builtin_bswap16((uint16_t)MT_READY);

    virtio_vsock_send(VSOCK_HOST_CID, VSOCK_HOST_PORT, msg, 2 + msg_len);

    return 0;
}

static int hostif_send_report(const char* buf, size_t len)
{
    char* msg;
    int first = TRUE;

    msg = vmalloc_pages(1, NULL);
    assert(msg);

    while (len > 0) {
        size_t header_len = first ? 6 : 4;
        size_t buf_len = PG_SIZE - header_len;
        if (buf_len > len) buf_len = len;

        *(uint16_t*)&msg[0] =
            __builtin_bswap16((uint16_t)header_len + buf_len - 2);
        *(uint16_t*)&msg[2] = __builtin_bswap16((uint16_t)MT_RESULT);

        if (first) {
            *(uint16_t*)&msg[4] = __builtin_bswap16((uint16_t)len);
        }

        memcpy(&msg[header_len], buf, buf_len);

        buf += buf_len;
        len -= buf_len;

        virtio_vsock_send(VSOCK_HOST_CID, VSOCK_HOST_PORT, msg,
                          header_len + buf_len);

        first = FALSE;
    }

    vmfree(msg, PG_SIZE);

    return 0;
}

void hostif_init(unsigned int sectors_per_page)
{
    pcie_message_ringbuf = ringbuf_new(MESSAGE_RINGBUF_DEFAULT_CAPACITY);

    hostif_nvme_init(sectors_per_page);

    virtio_vsock_set_recv_callback(hostif_process_pcie_message);
}

void hostif_init_cpu(void) { init_ssd_worker(); }

void hostif_report_result(Mcmq__SimResult* result)
{
    nvme_report_result(result);
}
