#include "const.h"
#include "errno.h"
#include "fdt.h"
#include "global.h"
#include "proto.h"

#include "pci.h"

#include <errno.h>

#define NR_PCIBUS 1
#define NR_PCIDEV 32

static struct pcibus pcibus[NR_PCIBUS];
static int nr_pcibus = 0;

static struct pcidev pcidev[NR_PCIDEV];
static int nr_pcidev = 0;

#define BUS_SHIFT 20
#define DEVFN_SHIFT (BUS_SHIFT - 8)

static void pci_probe_bus(struct pcibus* bus);
static void record_bars(struct pcidev* dev, int last_reg);

static int fdt_scan_pci_host(void* blob, unsigned long offset, const char* name,
                             int depth, void* arg)
{
    const char* type = fdt_getprop(blob, offset, "device_type", NULL);
    struct pcibus* bus = &pcibus[nr_pcibus];
    const uint32_t *reg, *ranges, *ranges_lim;
    int len;
    uint64_t base, size;
    uint16_t did, vid;

    if (!type || strcmp(type, "pci") != 0) return 0;

    reg = fdt_getprop(blob, offset, "reg", &len);
    if (!reg) return 0;

    base = of_read_number(reg, dt_root_addr_cells);
    reg += dt_root_addr_cells;
    size = of_read_number(reg, dt_root_size_cells);
    reg += dt_root_size_cells;

    printk("pci: ECAM: [mem 0x%lx-0x%lx]\r\n", base, base + size - 1);

    ranges = fdt_getprop(blob, offset, "ranges", &len);
    if (!ranges) return 0;
    ranges_lim = (uint32_t*)((char*)ranges + len);

    bus->nr_resources = 0;
    while (ranges < ranges_lim) {
        unsigned long child_addr_hi, child_addr;
        unsigned long parent_addr;
        size_t range_size;
        const char* range_type;
        int flags;

        child_addr_hi = of_read_number(ranges, 1);
        child_addr = of_read_number(ranges + 1, 2);
        ranges += 3;
        parent_addr = of_read_number(ranges, dt_root_addr_cells);
        ranges += dt_root_addr_cells;
        range_size = of_read_number(ranges, dt_root_size_cells);
        ranges += dt_root_size_cells;

        switch ((child_addr_hi >> 24) & 3) {
        case 1:
            range_type = "IO";
            flags = PCI_RESOURCE_IO;
            break;
        case 2:
            range_type = "MEM";
            flags = PCI_RESOURCE_MEM;
            break;
        default:
            return 0;
        }

        bus->resources[bus->nr_resources].flags = flags;
        bus->resources[bus->nr_resources].cpu_addr = parent_addr;
        bus->resources[bus->nr_resources].pci_addr = child_addr;
        bus->resources[bus->nr_resources].size = range_size;
        bus->resources[bus->nr_resources].alloc_offset = 0;
        bus->nr_resources++;

        printk("pci:  %6s %012lx..%012lx -> %012lx\r\n", range_type,
               parent_addr, parent_addr + range_size - 1, child_addr);
    }

    bus->busnr = 0;

    bus->reg_base = base;
    bus->reg_size = size;

    bus->win = vm_mapio(bus->reg_base, bus->reg_size);

    pci_bus_read_config_word(bus, 0, PCI_VID, &vid);
    pci_bus_read_config_word(bus, 0, PCI_DID, &did);

    if (vid == 0xffff && did == 0xffff) return 0;

    pci_probe_bus(bus);

    nr_pcibus++;
    return nr_pcibus >= NR_PCIBUS;
}

void init_pci_host(void* dtb) { of_scan_fdt(fdt_scan_pci_host, NULL, dtb); }

static void pci_probe_bus(struct pcibus* bus)
{
    int i, func;
    for (i = 0; i < 32; i++) {
        for (func = 0; func < 8; func++) {
            struct pcidev* dev = &pcidev[nr_pcidev];
            unsigned int devfn = (i << 3) | func;
            uint16_t did, vid;
            uint8_t baseclass, subclass, infclass;
            uint8_t headt;

            pci_bus_read_config_word(bus, devfn, PCI_VID, &vid);
            pci_bus_read_config_word(bus, devfn, PCI_DID, &did);

            dev->bus = bus;
            dev->busnr = bus->busnr;
            dev->dev = i;
            dev->func = func;
            dev->devfn = devfn;

            if (vid == 0xffff) {
                if (func == 0) break;

                continue;
            }

            nr_pcidev++;

            pci_bus_read_config_byte(bus, devfn, PCI_HEADT, &headt);
            pci_bus_read_config_byte(bus, devfn, PCI_BCR, &baseclass);
            pci_bus_read_config_byte(bus, devfn, PCI_SCR, &subclass);
            pci_bus_read_config_byte(bus, devfn, PCI_PIFR, &infclass);

            dev->vid = vid;
            dev->did = did;
            dev->baseclass = baseclass;
            dev->subclass = subclass;
            dev->infclass = infclass;
            dev->headt = headt;

            printk("pci %d.%02x.%x: (0x%04x:0x%04x) Unknown device\r\n",
                   dev->busnr, dev->dev, dev->func, dev->vid, dev->did);

            switch (headt) {
            case PHT_NORMAL:
                record_bars(dev, PCI_BAR_6);
                break;
            }
        }
    }
}

static int allocate_bar(struct pcibus* bus, int flags, size_t size,
                        unsigned long* pci_base, unsigned long* host_base)
{
    int i;

    for (i = 0; i < bus->nr_resources; i++) {
        if (bus->resources[i].flags == flags) {
            unsigned long offset = bus->resources[i].alloc_offset;

            offset = (offset + size - 1) & ~(size - 1);
            if (offset + size > bus->resources[i].size) continue;

            bus->resources[i].alloc_offset = offset + size;

            *pci_base = bus->resources[i].pci_addr + offset;
            *host_base = bus->resources[i].cpu_addr + offset;

            return 0;
        }
    }

    return ENOMEM;
}

static int record_bar(struct pcidev* dev, int bar_nr, int last)
{
    int reg, width, nr_bars, type;
    uint32_t bar, bar2, mask, mask2;
    unsigned long base;
    size_t size;
    int flags;

    width = 1;
    reg = PCI_BAR + bar_nr * 4;

    pci_bus_read_config_dword(dev->bus, dev->devfn, reg, &bar);

    type = (bar & PCI_BAR_TYPE);

    switch (type) {
    case PCI_TYPE_32:
    case PCI_TYPE_32_1M:
        base = bar & PCI_BAR_MEM_MASK;

        pci_bus_write_config_dword(dev->bus, dev->devfn, reg, 0xffffffff);
        pci_bus_read_config_dword(dev->bus, dev->devfn, reg, &mask);
        pci_bus_write_config_dword(dev->bus, dev->devfn, reg, bar);

        mask &= PCI_BAR_MEM_MASK;
        if (!mask) return width;

        size = (~mask & 0xffff) + 1;

        flags = PCI_RESOURCE_MEM;

        break;

    case PCI_TYPE_64:
        if (last) {
            return width;
        }

        width++;

        pci_bus_read_config_dword(dev->bus, dev->devfn, reg + 4, &bar2);
        base = ((unsigned long)bar2 << 32) | (bar & PCI_BAR_MEM_MASK);

        pci_bus_write_config_dword(dev->bus, dev->devfn, reg, 0xffffffff);
        pci_bus_write_config_dword(dev->bus, dev->devfn, reg + 4, 0xffffffff);
        pci_bus_read_config_dword(dev->bus, dev->devfn, reg, &mask);
        pci_bus_read_config_dword(dev->bus, dev->devfn, reg + 4, &mask2);
        pci_bus_write_config_dword(dev->bus, dev->devfn, reg, bar);
        pci_bus_write_config_dword(dev->bus, dev->devfn, reg + 4, bar2);

        size = ((unsigned long)mask2 << 32) | (mask & PCI_BAR_MEM_MASK);
        size = ~size + 1;

        flags = PCI_RESOURCE_MEM;

        break;

    default:
        return width;
    }

    nr_bars = dev->nr_bars++;
    dev->bars[nr_bars].base = base;
    dev->bars[nr_bars].size = size;
    dev->bars[nr_bars].nr = bar_nr;
    dev->bars[nr_bars].flags = flags;

    if (!base) {
        unsigned long pci_base, host_base;
        uint16_t cmd;

        allocate_bar(dev->bus, flags, size, &pci_base, &host_base);
        pci_bus_write_config_dword(dev->bus, dev->devfn, reg,
                                   (uint32_t)pci_base);
        if (width > 1)
            pci_bus_write_config_dword(dev->bus, dev->devfn, reg + 4,
                                       (uint32_t)(pci_base >> 32));

        pci_bus_read_config_word(dev->bus, dev->devfn, PCI_CR, &cmd);
        if (flags == PCI_RESOURCE_IO)
            cmd |= PCI_CR_IO_EN;
        else if (flags == PCI_RESOURCE_MEM)
            cmd |= PCI_CR_MEM_EN;
        pci_bus_write_config_word(dev->bus, dev->devfn, PCI_CR, cmd);

        dev->bars[nr_bars].base = host_base;
    }

    return width;
}

static void record_bars(struct pcidev* dev, int last_reg)
{
    int i, reg, width;

    for (i = 0, reg = PCI_BAR; reg <= last_reg; i += width, reg += 4 * width) {
        width = record_bar(dev, i, reg == last_reg);
    }
}

int pci_generic_config_read(struct pcibus* bus, unsigned int devfn, int where,
                            int size, uint32_t* val)
{
    int busnr = bus->busnr;
    void* base = bus->win + (busnr << BUS_SHIFT);
    void* addr = base + (devfn << DEVFN_SHIFT) + where;

    if (size == 1)
        *val = (uint32_t) * (volatile uint8_t*)addr;
    else if (size == 2)
        *val = (uint32_t) * (volatile uint16_t*)addr;
    else
        *val = *(volatile uint32_t*)addr;

    return 0;
}

int pci_generic_config_write(struct pcibus* bus, unsigned int devfn, int where,
                             int size, uint32_t val)
{
    int busnr = bus->busnr;
    void* base = bus->win + (busnr << BUS_SHIFT);
    void* addr = base + (devfn << DEVFN_SHIFT) + where;

    if (size == 1)
        *(volatile uint8_t*)addr = (uint8_t)val;
    else if (size == 2)
        *(volatile uint16_t*)addr = (uint16_t)val;
    else
        *(volatile uint32_t*)addr = val;

    return 0;
}

#define PCI_OP_READ(size, type, len)                                       \
    int pci_bus_read_config_##size(struct pcibus* bus, unsigned int devfn, \
                                   int pos, type* value)                   \
    {                                                                      \
        int res;                                                           \
        uint32_t data = 0;                                                 \
        res = pci_generic_config_read(bus, devfn, pos, len, &data);        \
        *value = (type)data;                                               \
        return res;                                                        \
    }

#define PCI_OP_WRITE(size, type, len)                                       \
    int pci_bus_write_config_##size(struct pcibus* bus, unsigned int devfn, \
                                    int pos, type value)                    \
    {                                                                       \
        int res;                                                            \
        res = pci_generic_config_write(bus, devfn, pos, len, value);        \
        return res;                                                         \
    }

PCI_OP_READ(byte, uint8_t, 1)
PCI_OP_READ(word, uint16_t, 2)
PCI_OP_READ(dword, uint32_t, 4)
PCI_OP_WRITE(byte, uint8_t, 1)
PCI_OP_WRITE(word, uint16_t, 2)
PCI_OP_WRITE(dword, uint32_t, 4)

struct pcidev* pci_get_device(uint16_t vid, uint16_t did)
{
    struct pcidev* dev;

    for (dev = pcidev; dev < pcidev + nr_pcidev; dev++) {
        if (dev->vid == vid && dev->did == did) return dev;
    }

    return NULL;
}
