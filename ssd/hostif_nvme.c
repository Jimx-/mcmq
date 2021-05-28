#include "config.h"
#include "hostif.h"
#include "nvme.h"
#include "ssd.h"

#include <assert.h>

#define CAP_DSTRD 0
#define CAP_MPSMIN 0
#define CAP_MPSMAX 0
#define CAP_MQES 1024

/* Controller Configuration */
static uint8_t cc_en;
static uint8_t cc_iosqes;
static uint8_t cc_iocqes;
static uint8_t cc_mps;

#define INVALID_QID ((uint16_t)-1)

struct nvme_queue {
    uint16_t qid;

    uint16_t sq_depth;
    uint16_t cq_depth;
    uint64_t sq_dma_addr;
    uint64_t cq_dma_addr;

    uint16_t sq_head;
    uint16_t sq_tail;
    uint16_t cq_head;
    uint16_t cq_tail;
    uint8_t cq_phase;

    uint16_t cq_vector;
};

static struct nvme_queue nvme_queues[1 + CONFIG_NVME_IO_QUEUE_MAX];

static inline int nvmeq_worker(int qid) { return qid; }

void hostif_nvme_init(void)
{
    int i;
    for (i = 0; i <= CONFIG_NVME_IO_QUEUE_MAX; i++)
        nvme_queues[i].qid = INVALID_QID;

    nvme_queues[0].cq_vector = 0;
}

static void init_nvme_queue(struct nvme_queue* nvmeq, unsigned int qid)
{
    nvmeq->qid = qid;
    nvmeq->sq_head = 0;
    nvmeq->sq_tail = 0;
    nvmeq->cq_head = 0;
    nvmeq->cq_tail = 0;
    nvmeq->cq_phase = 1;
}

static int post_cqe(struct nvme_queue* nvmeq, int status, uint16_t command_id,
                    union nvme_result* result)
{
    struct nvme_completion cqe;

    cqe.status = (status << 1) | (nvmeq->cq_phase & 1);
    cqe.command_id = command_id;
    cqe.sq_id = nvmeq->qid;
    cqe.sq_head = nvmeq->sq_head;
    cqe.result = *result;

    ivshmem_copy_to(nvmeq->cq_dma_addr + (nvmeq->cq_tail << cc_iocqes), &cqe,
                    sizeof(cqe));

    if (++nvmeq->cq_tail == nvmeq->cq_depth) {
        nvmeq->cq_tail = 0;
        nvmeq->cq_phase ^= 1;
    }
}

static int process_set_features_command(struct nvme_features* cmd,
                                        union nvme_result* result)
{
    int status = NVME_SC_SUCCESS;

    switch (cmd->fid) {
    case NVME_FEAT_NUM_QUEUES:
        result->u32 = CONFIG_NVME_IO_QUEUE_MAX - 1;
        result->u32 |= result->u32 << 16;
        break;
    default:
        status = NVME_SC_FEATURE_NOT_SAVEABLE;
        break;
    }

    return status;
}

static int process_create_cq_command(struct nvme_create_cq* cmd,
                                     union nvme_result* result)
{
    uint16_t qid = cmd->cqid;
    struct nvme_queue* nvmeq;

    /* Invalid queue identifier. */
    if (qid == 0 || qid > CONFIG_NVME_IO_QUEUE_MAX) return NVME_SC_QID_INVALID;

    nvmeq = &nvme_queues[qid];

    nvmeq->cq_depth = cmd->qsize;
    nvmeq->cq_dma_addr = cmd->prp1;
    nvmeq->cq_vector = cmd->irq_vector;

    return 0;
}

static int process_create_sq_command(struct nvme_create_sq* cmd,
                                     union nvme_result* result)
{
    uint16_t qid = cmd->sqid;
    struct nvme_queue* nvmeq;

    /* Invalid queue identifier. */
    if (qid == 0 || qid > CONFIG_NVME_IO_QUEUE_MAX) return NVME_SC_QID_INVALID;
    /* Invalid CQ identifier. */
    if (qid != cmd->cqid) return NVME_SC_CQ_INVALID;

    nvmeq = &nvme_queues[qid];

    /* CQ not created. */
    if (!nvmeq->cq_depth) return NVME_SC_CQ_INVALID;

    nvmeq->sq_depth = cmd->qsize;
    nvmeq->sq_dma_addr = cmd->prp1;

    init_nvme_queue(nvmeq, qid);

    return 0;
}

static void process_admin_command(struct nvme_command* cmd)
{
    int status;
    union nvme_result result = {0};

    switch (cmd->common.opcode) {
    case nvme_admin_set_features:
        status = process_set_features_command(&cmd->features, &result);
        break;
    case nvme_admin_create_cq:
        status = process_create_cq_command(&cmd->create_cq, &result);
        break;
    case nvme_admin_create_sq:
        status = process_create_sq_command(&cmd->create_sq, &result);
        break;
    default:
        status = NVME_SC_INVALID_OPCODE;
        break;
    }

    post_cqe(&nvme_queues[0], status, cmd->common.command_id, &result);
}

static void process_io_command(struct nvme_queue* nvmeq,
                               struct nvme_command* cmd)
{
    int do_write = cmd->rw.opcode == nvme_cmd_write;
    uint64_t slba = cmd->rw.slba;
    uint64_t length = cmd->rw.length;

    enqueue_rw_command(nvmeq_worker(nvmeq->qid), do_write, slba, length);
}

static void fetch_next_request(struct nvme_queue* nvmeq)
{
    struct nvme_command cmd;

    ivshmem_copy_from(&cmd, nvmeq->sq_dma_addr + (nvmeq->sq_head << cc_iosqes),
                      sizeof(cmd));

    if (nvmeq->qid == 0)
        process_admin_command(&cmd);
    else
        process_io_command(nvmeq, &cmd);
}

void nvme_process_read_message(uint64_t addr, uint32_t id)
{
#define USE_U32(val)           \
    do {                       \
        u32 = (uint32_t)(val); \
        buf = &u32;            \
        len = sizeof(u32);     \
    } while (0)

#define USE_U64(val)           \
    do {                       \
        u64 = (uint64_t)(val); \
        buf = &u64;            \
        len = sizeof(u64);     \
    } while (0)

    void* buf = NULL;
    size_t len = 0;
    uint32_t u32;
    uint64_t u64;

    switch (addr) {
    case NVME_REG_CAP:
        USE_U64((CAP_MQES - 1) | ((uint64_t)CAP_DSTRD << 32) |
                ((uint64_t)CAP_MPSMIN << 48) | ((uint64_t)CAP_MPSMAX << 52));
        break;
    case NVME_REG_CSTS:
        USE_U32((cc_en ? NVME_CSTS_RDY : 0));
        break;
    }

    hostif_complete_host_read(id, buf, len);
}

static void update_cq_head_doorbell(unsigned int qid, uint32_t val)
{
    struct nvme_queue* nvmeq;

    if (qid > CONFIG_NVME_IO_QUEUE_MAX) return;

    nvmeq = &nvme_queues[qid];
    if (nvmeq->qid == INVALID_QID) return;

    nvmeq->cq_head = val;
}

static void update_sq_tail_doorbell(unsigned int qid, uint32_t val)
{
    struct nvme_queue* nvmeq;

    if (qid > CONFIG_NVME_IO_QUEUE_MAX) return;

    nvmeq = &nvme_queues[qid];
    if (nvmeq->qid == INVALID_QID) return;

    nvmeq->sq_tail = val;

    while (nvmeq->sq_head != nvmeq->sq_tail) {
        fetch_next_request(nvmeq);

        nvmeq->sq_head++;
        if (nvmeq->sq_head == nvmeq->sq_depth) nvmeq->sq_head = 0;
    }

    if (qid == 0 && nvmeq->cq_head != nvmeq->cq_tail)
        hostif_send_irq(nvmeq->cq_vector);

    if (qid) notify_worker(nvmeq_worker(qid));
}

void nvme_process_write_message(uint64_t addr, const char* buf, size_t len)
{
    uint32_t u32;

    switch (addr) {
    case NVME_REG_CC:
        assert(len == 4);
        u32 = *(uint32_t*)buf;
        cc_en = !!(u32 & NVME_CC_ENABLE);
        cc_iocqes = (u32 >> NVME_CC_IOCQES_SHIFT) & 0xf;
        cc_iosqes = (u32 >> NVME_CC_IOSQES_SHIFT) & 0xf;
        cc_mps = (u32 >> NVME_CC_MPS_SHIFT) & 0xf;
        break;
    case NVME_REG_AQA:
        /* Admin submission queue attribute. */
        assert(len == 4);
        u32 = *(uint32_t*)buf;
        nvme_queues[0].sq_depth = (u32 & 0xfff) + 1;
        nvme_queues[0].cq_depth = ((u32 >> 16) & 0xfff) + 1;
        init_nvme_queue(&nvme_queues[0], 0);
        break;
    case NVME_REG_ASQ:
        /* Admin submission queue base address. */
        assert(len == 8);
        nvme_queues[0].sq_dma_addr = *(uint64_t*)buf;
        init_nvme_queue(&nvme_queues[0], 0);
        break;
    case NVME_REG_ACQ:
        /* Admin completion queue base address. */
        assert(len == 8);
        nvme_queues[0].cq_dma_addr = *(uint64_t*)buf;
        init_nvme_queue(&nvme_queues[0], 0);
        break;
    default:
        assert(len == 4);
        u32 = *(uint32_t*)buf;

        if (addr >= NVME_REG_DBS) {
            uint64_t offset = addr - NVME_REG_DBS;

            if (offset & ((1 << (CAP_DSTRD + 3)) - 1)) {
                update_cq_head_doorbell(offset >> (CAP_DSTRD + 3), u32);
            } else {
                update_sq_tail_doorbell(offset >> (CAP_DSTRD + 3), u32);
            }
        }
        break;
    }
}
