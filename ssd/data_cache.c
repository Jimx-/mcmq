#include "hostif.h"
#include "ssd.h"

static enum cache_mode cache_mode = CM_NO_CACHE;

static inline int is_user_request_complete(struct user_request* req)
{
    return list_empty(&req->txn_list);
}

void dc_handle_user_request(struct user_request* req)
{
    switch (cache_mode) {
    case CM_NO_CACHE:
        amu_dispatch(req);
        break;
    case CM_WRITE_CACHE:
        if (req->do_write) {
            /* Write request. */
        } else {
            /* Read request. */
        }
        break;
    }
}

static void complete_user_request(struct user_request* req)
{
    nvme_complete_request(req);
}

void dc_transaction_complete(struct flash_transaction* txn)
{
    switch (txn->type) {
    case TXN_READ:
        break;
    case TXN_WRITE:
        switch (cache_mode) {
        case CM_NO_CACHE:
            list_del(&txn->list);
            if (is_user_request_complete(txn->req))
                complete_user_request(txn->req);
            break;
        case CM_WRITE_CACHE:
            break;
        }
        break;
    }
}
