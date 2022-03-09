#include "pci.h"
#include "proto.h"

#include <errno.h>
#include <string.h>

#define IVSHMEM_VENDOR_ID 0x1af4
#define IVSHMEM_DEVICE_ID 0x1110

static void* shmem_base;

int init_ivshmem(void)
{
    unsigned long base;
    size_t size;
    int iof, retval;

    struct pcidev* pdev = pci_get_device(IVSHMEM_VENDOR_ID, IVSHMEM_DEVICE_ID);
    if (!pdev) {
        printk("Inter-VM shared memory device not found.\r\n");
        return ENXIO;
    }

    retval = pci_get_bar(pdev, PCI_BAR + 8, &base, &size, &iof);
    if (retval) return retval;

    shmem_base = vm_mapio(base, size);

    printk("ivshmem: base %p, size %d MB\r\n", shmem_base, size >> 20);

    return 0;
}

void ivshmem_copy_from(void* dst, shmem_addr_t src, size_t len)
{
    if (len == 4)
        *(uint32_t*)dst = *(uint32_t*)(shmem_base + src);
    else
        memcpy(dst, shmem_base + src, len);
}

void ivshmem_copy_to(shmem_addr_t dst, void* src, size_t len)
{
    memcpy(shmem_base + dst, src, len);
}
