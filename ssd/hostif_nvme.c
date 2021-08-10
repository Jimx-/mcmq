#include "config.h"
#include "hostif.h"
#include "nvme.h"
#include "proto.h"
#include "ssd.h"

#include "proto/sim_result.pb-c.h"

#include "hdrhistogram/hdr_histogram.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define CAP_DSTRD 0
#define CAP_MPSMIN 0
#define CAP_MPSMAX 0
#define CAP_MQES 1024

static unsigned int sectors_per_page;

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

    uint64_t read_request_count;
    uint64_t write_request_count;

    struct hdr_histogram* read_latency_hist;
    struct hdr_histogram* write_latency_hist;
};

static struct nvme_queue nvme_queues[1 + CONFIG_NVME_IO_QUEUE_MAX];
static unsigned int io_queue_count;

static inline int nvmeq_worker(int qid)
{
    static const int worker_max = CONFIG_SMP_MAX_CPUS - THREAD_WORKER_START;
    return THREAD_WORKER_START + (qid - 1) % worker_max;
}

void hostif_nvme_init(unsigned int sectors_in_page)
{
    int i;
    for (i = 0; i <= CONFIG_NVME_IO_QUEUE_MAX; i++)
        nvme_queues[i].qid = INVALID_QID;

    nvme_queues[0].cq_vector = 0;

    sectors_per_page = sectors_in_page;
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

    memset(&cqe, 0, sizeof(cqe));
    cqe.status = (status << 1) | (nvmeq->cq_phase & 1);
    cqe.command_id = command_id;
    cqe.sq_id = nvmeq->qid;
    cqe.sq_head = nvmeq->sq_head;
    if (result) cqe.result = *result;

    ivshmem_copy_to(nvmeq->cq_dma_addr + (nvmeq->cq_tail << cc_iocqes), &cqe,
                    sizeof(cqe));

    if (++nvmeq->cq_tail == nvmeq->cq_depth) {
        nvmeq->cq_tail = 0;
        nvmeq->cq_phase ^= 1;
    }

    return 0;
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

    nvmeq->cq_depth = cmd->qsize + 1;
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

    nvmeq->sq_depth = cmd->qsize + 1;
    nvmeq->sq_dma_addr = cmd->prp1;

    init_nvme_queue(nvmeq, qid);
    io_queue_count++;

    hdr_init(1, UINT64_C(2000000), 1, &nvmeq->read_latency_hist);
    hdr_init(1, UINT64_C(2000000), 1, &nvmeq->write_latency_hist);

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

static void segment_user_request(struct user_request* req, int worker)
{
    unsigned count = 0;
    lha_t slba = req->start_lba;

    while (count < req->sector_count) {
        struct flash_transaction* txn;
        unsigned int txn_size = sectors_per_page - slba % sectors_per_page;
        lpa_t lpa = slba / sectors_per_page;
        page_bitmap_t bitmap;

        if (count + txn_size > req->sector_count)
            txn_size = req->sector_count - count;

        SLABALLOC(txn);
        memset(txn, 0, sizeof(*txn));

        bitmap = ~(~0ULL << txn_size);
        bitmap <<= (slba % sectors_per_page);

        txn->req = req;
        txn->type = req->do_write ? TXN_WRITE : TXN_READ;
        txn->source = TS_USER_IO;
        txn->worker = worker;
        txn->nsid = req->nsid;
        txn->lpa = lpa;
        txn->ppa = NO_PPA;
        txn->length = txn_size << SECTOR_SHIFT;
        txn->bitmap = bitmap;
        list_add_tail(&txn->list, &req->txn_list);

        slba += txn_size;
        count += txn_size;
    }
}

static void process_io_command(struct nvme_queue* nvmeq,
                               struct nvme_command* cmd)
{
    struct user_request* req;

    SLABALLOC(req);
    memset(req, 0, sizeof(*req));

    if (cmd->rw.nsid == 0) {
        req->status = NVME_SC_INVALID_NS;
        nvme_complete_request(req);
    }

    req->do_write = cmd->rw.opcode == nvme_cmd_write;
    req->command_id = cmd->rw.command_id;
    req->qid = nvmeq->qid;
    req->nsid = cmd->rw.nsid;
    req->start_lba = cmd->rw.slba;
    req->sector_count = cmd->rw.length + 1;
    req->start_timestamp = current_time_ns();
    INIT_LIST_HEAD(&req->txn_list);

    if (req->do_write)
        nvmeq->write_request_count++;
    else
        nvmeq->read_request_count++;

    segment_user_request(req, nvmeq_worker(nvmeq->qid));
    enqueue_user_request(nvmeq_worker(nvmeq->qid), req);
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

void nvme_complete_request(struct user_request* req)
{
    struct nvme_queue* nvmeq;
    time_ns_t end_timestamp, latency;

    end_timestamp = current_time_ns();
    latency = end_timestamp - req->start_timestamp;

    nvmeq = &nvme_queues[req->qid];

    if (req->do_write)
        hdr_record_value(nvmeq->write_latency_hist, latency / 1000);
    else
        hdr_record_value(nvmeq->read_latency_hist, latency / 1000);

    post_cqe(nvmeq, req->status, req->command_id, NULL);
    release_user_request(req);

    hostif_send_irq(nvmeq->cq_vector);
}

void nvme_report_result(Mcmq__SimResult* result)
{
    int i;
    static const int ticks_per_half_distance = 5;

    result->n_host_queue_stats = io_queue_count;
    result->host_queue_stats =
        calloc(io_queue_count, sizeof(Mcmq__HostQueueStats*));

    for (i = 0; i < io_queue_count; i++) {
        struct nvme_queue* nvmeq = &nvme_queues[i + 1];
        struct Mcmq__HostQueueStats* queue_stats =
            malloc(sizeof(Mcmq__HostQueueStats));

        result->host_queue_stats[i] = queue_stats;
        mcmq__host_queue_stats__init(queue_stats);

        queue_stats->queue_id = nvmeq->qid;

        queue_stats->read_request_count = nvmeq->read_request_count;
        queue_stats->write_request_count = nvmeq->write_request_count;

#define SET_LATENCY_HISTOGRAM(name)                                        \
    do {                                                                   \
        struct hdr_iter iter;                                              \
        struct hdr_iter_percentiles* percentiles;                          \
        int j, count = 0;                                                  \
        queue_stats->name##_request_turnaround_time_mean =                 \
            hdr_mean(nvmeq->name##_latency_hist);                          \
        queue_stats->name##_request_turnaround_time_stddev =               \
            hdr_stddev(nvmeq->name##_latency_hist);                        \
        queue_stats->max_##name##_request_turnaround_time =                \
            hdr_max(nvmeq->name##_latency_hist);                           \
        hdr_iter_percentile_init(&iter, nvmeq->name##_latency_hist,        \
                                 ticks_per_half_distance);                 \
        while (hdr_iter_next(&iter)) {                                     \
            count++;                                                       \
        }                                                                  \
        queue_stats->n_##name##_request_turnaround_time_histogram = count; \
        if (count) {                                                       \
            queue_stats->name##_request_turnaround_time_histogram =        \
                calloc(count, sizeof(Mcmq__HistogramEntry*));              \
            j = 0;                                                         \
            hdr_iter_percentile_init(&iter, nvmeq->name##_latency_hist,    \
                                     ticks_per_half_distance);             \
            while (hdr_iter_next(&iter) && j < count) {                    \
                struct Mcmq__HistogramEntry* entry =                       \
                    malloc(sizeof(Mcmq__HistogramEntry));                  \
                percentiles = &iter.specifics.percentiles;                 \
                mcmq__histogram_entry__init(entry);                        \
                queue_stats->name##_request_turnaround_time_histogram[j] = \
                    entry;                                                 \
                entry->value = iter.highest_equivalent_value;              \
                entry->percentile = percentiles->percentile;               \
                entry->total_count = iter.cumulative_count;                \
                j++;                                                       \
            }                                                              \
        }                                                                  \
    } while (0)

        SET_LATENCY_HISTOGRAM(read);
        SET_LATENCY_HISTOGRAM(write);
    }
}
