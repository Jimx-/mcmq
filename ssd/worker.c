#include "list.h"
#include "proto.h"
#include "smp.h"
#include "spinlock.h"
#include "ssd.h"

#include <errno.h>
#include <string.h>

enum {
    EVENT_USER_REQUEST = 1,
    EVENT_FLASH_TRANSACTION = 2,
    EVENT_TRANSACTION_COMPLETE = 3,
};

struct event {
    struct list_head list;
    int type;
    union {
        struct user_request* request;
        struct flash_transaction* txn;
    };
};

static DEFINE_CPULOCAL(spinlock_t, event_queue_lock);
static DEFINE_CPULOCAL(struct list_head, event_queue);

void init_ssd_worker(void)
{
    spin_lock_init(get_cpulocal_var_ptr(event_queue_lock));
    INIT_LIST_HEAD(get_cpulocal_var_ptr(event_queue));
}

unsigned int worker_self(void) { return smp_processor_id(); }

void notify_worker(int worker)
{
    if (worker != worker_self()) smp_notify(worker);
}

void release_user_request(struct user_request* req)
{
    struct flash_transaction *txn, *tmp;
    list_for_each_entry_safe(txn, tmp, &req->txn_list, list) { SLABFREE(txn); }
    SLABFREE(req);
}

int enqueue_user_request(int worker, struct user_request* req)
{
    struct event* event;
    assert(worker < CONFIG_SMP_MAX_CPUS);

    SLABALLOC(event);
    if (!event) return ENOMEM;

    memset(event, 0, sizeof(*event));
    event->type = EVENT_USER_REQUEST;
    event->request = req;

    spin_lock(get_cpu_var_ptr(worker, event_queue_lock));
    list_add_tail(&event->list, get_cpu_var_ptr(worker, event_queue));
    spin_unlock(get_cpu_var_ptr(worker, event_queue_lock));

    return 0;
}

int submit_transaction(struct flash_transaction* txn)
{
    struct event* event;

    SLABALLOC(event);
    if (!event) return ENOMEM;

    memset(event, 0, sizeof(*event));
    event->type = EVENT_FLASH_TRANSACTION;
    event->txn = txn;

    spin_lock(get_cpu_var_ptr(THREAD_TSU, event_queue_lock));
    list_add_tail(&event->list, get_cpu_var_ptr(THREAD_TSU, event_queue));
    spin_unlock(get_cpu_var_ptr(THREAD_TSU, event_queue_lock));

    return 0;
}

int notify_transaction_complete(struct flash_transaction* txn)
{
    struct event* event;
    int worker = txn->worker;

    SLABALLOC(event);
    if (!event) return ENOMEM;

    memset(event, 0, sizeof(*event));
    event->type = EVENT_TRANSACTION_COMPLETE;
    event->txn = txn;

    spin_lock(get_cpu_var_ptr(worker, event_queue_lock));
    list_add_tail(&event->list, get_cpu_var_ptr(worker, event_queue));
    spin_unlock(get_cpu_var_ptr(worker, event_queue_lock));

    notify_worker(worker);

    return 0;
}

static int dequeue_event(struct event* event)
{
    int found = 0;
    struct list_head* queue = get_cpulocal_var_ptr(event_queue);
    struct event* head;

    spin_lock(get_cpulocal_var_ptr(event_queue_lock));

    if (list_empty(queue)) goto out;

    found = 1;
    head = list_entry(queue->next, struct event, list);
    list_del(&head->list);

    memcpy(event, head, sizeof(*event));
    INIT_LIST_HEAD(&event->list);

    SLABFREE(head);

out:
    spin_unlock(get_cpulocal_var_ptr(event_queue_lock));
    return found;
}

static void process_user_request(struct user_request* req)
{
    dc_handle_user_request(req);
}

void process_worker_queue(void)
{
    struct event event;
    unsigned int self = smp_processor_id();

    while (dequeue_event(&event)) {

        if (self == THREAD_TSU) {
            switch (event.type) {
            case EVENT_FLASH_TRANSACTION:
                tsu_process_transaction(event.txn);
                break;
            }
        } else {
            switch (event.type) {
            case EVENT_USER_REQUEST:
                process_user_request(event.request);
                break;
            case EVENT_TRANSACTION_COMPLETE:
                /* printk( */
                /*     "Flash %s transaction complete source=%s, lpa=%d, " */
                /*     "channel=%d, chip=%d, die=%d, plane=%d, block=%d, " */
                /*     "page=%d\r\n", */
                /*     event.txn->type == TXN_READ */
                /*         ? "read" */
                /*         : (event.txn->type == TXN_WRITE ? "write" : "erase"),
                 */
                /*     event.txn->source == TS_USER_IO */
                /*         ? "user" */
                /*         : (event.txn->source == TS_MAPPING ? "mapping" :
                 * "gc"), */
                /*     event.txn->lpa, event.txn->addr.channel_id, */
                /*     event.txn->addr.chip_id, event.txn->addr.die_id, */
                /*     event.txn->addr.plane_id, event.txn->addr.block_id, */
                /*     event.txn->addr.page_id); */

                switch (event.txn->source) {
                case TS_USER_IO:
                    dc_transaction_complete(event.txn);
                    break;
                case TS_MAPPING:
                    amu_transaction_complete(event.txn);
                    break;
                }

                bm_transaction_complete(event.txn);
                tsu_transaction_complete(event.txn);

                SLABFREE(event.txn);
                break;
            }
        }
    }

    if (self == THREAD_TSU) tsu_flush_queues();
}

void ssd_worker_thread(void)
{
    unsigned int self = smp_processor_id();

    if (self == THREAD_VSOCK_TX) {
        virtio_vsock_tx_thread();
    } else {
        while (1)
            wait_for_interrupt();
    }
}
