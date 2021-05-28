#include "list.h"
#include "proto.h"
#include "smp.h"
#include "spinlock.h"

#include <errno.h>
#include <string.h>

enum {
    EVENT_RW_COMMAND = 1,
};

struct rw_command_event {
    int do_write;
    uint64_t slba;
    uint64_t length;
};

struct event {
    struct list_head list;
    int type;
    union {
        struct rw_command_event rw;
    };
};

static DEFINE_CPULOCAL(spinlock_t, event_queue_lock);
static DEFINE_CPULOCAL(struct list_head, event_queue);

void init_ssd_worker(void)
{
    spin_lock_init(get_cpulocal_var_ptr(event_queue_lock));
    INIT_LIST_HEAD(get_cpulocal_var_ptr(event_queue));
}

void notify_worker(int worker) { smp_notify(worker); }

int enqueue_rw_command(int worker, int do_write, uint64_t slba, uint64_t length)
{
    struct event* event;

    SLABALLOC(event);
    if (!event) return ENOMEM;

    memset(event, 0, sizeof(*event));
    event->type = EVENT_RW_COMMAND;
    event->rw.do_write = do_write;
    event->rw.slba = slba;
    event->rw.length = length;

    spin_lock(get_cpu_var_ptr(worker, event_queue_lock));
    list_add_tail(&event->list, get_cpu_var_ptr(worker, event_queue));
    spin_unlock(get_cpu_var_ptr(worker, event_queue_lock));

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

void process_worker_queue(void)
{
    struct event event;

    while (dequeue_event(&event)) {
        printk("get event %d\r\n", event.type);
    }
}
