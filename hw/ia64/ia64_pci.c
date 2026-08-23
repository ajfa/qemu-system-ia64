/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Minimal IA-64 PCI host bridge.
 * Provides a single root PCI bus with MMIO and I/O windows.
 */

#include "qemu/osdep.h"
#include "hw/ia64/ia64_pci.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pci_bus.h"
#include "system/address-spaces.h"
#include "hw/core/irq.h"
#include "qom/object.h"

OBJECT_DECLARE_SIMPLE_TYPE(IA64PCIState, IA64_PCI_HOST_BRIDGE)

struct IA64PCIState {
    PCIHostState parent_obj;

    MemoryRegion pci_mmio;
    MemoryRegion pci_mmio_window;
    MemoryRegion pci_io;
    MemoryRegion pci_io_sparse;
    MemoryRegion pci_config;
    AddressSpace pci_io_as;
    qemu_irq irq[IA64_PCI_INTX_LINES];
};

static hwaddr ia64_pci_sparse_io_port(hwaddr encoded)
{
    hwaddr group = encoded >> 12;
    hwaddr low = encoded & 0xfff;

    /*
     * Linux marks the legacy IA-64 I/O space sparse and encodes port p as:
     *
     *     ((p >> 2) << 12) | (p & 0xfff)
     *
     * The firmware historically used dense addresses in the same window for
     * early ATA/PS2 access, so keep invalid sparse encodings as dense fallbacks.
     */
    if ((group & 0x3ff) == (low >> 2)) {
        return (group << 2) | (low & 3);
    }
    return encoded;
}

static hwaddr ia64_pci_dense_io_addr(hwaddr port)
{
    return IA64_PCI_IO_BASE + port;
}

static uint64_t ia64_pci_sparse_io_read(void *opaque, hwaddr addr,
                                        unsigned size)
{
    IA64PCIState *s = opaque;
    hwaddr port = ia64_pci_sparse_io_port(addr + IA64_PCI_IO_SPARSE_SKIP);
    hwaddr dense = ia64_pci_dense_io_addr(port);

    if (port >= IA64_PCI_IO_SIZE || port + size > IA64_PCI_IO_SIZE) {
        return ~0ULL;
    }

    switch (size) {
    case 1:
        return address_space_ldub(&s->pci_io_as, dense,
                                  MEMTXATTRS_UNSPECIFIED, NULL);
    case 2:
        return address_space_lduw_le(&s->pci_io_as, dense,
                                     MEMTXATTRS_UNSPECIFIED, NULL);
    case 4:
        return address_space_ldl_le(&s->pci_io_as, dense,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
    default:
        return ~0ULL;
    }
}

static void ia64_pci_sparse_io_write(void *opaque, hwaddr addr, uint64_t data,
                                     unsigned size)
{
    IA64PCIState *s = opaque;
    hwaddr port = ia64_pci_sparse_io_port(addr + IA64_PCI_IO_SPARSE_SKIP);
    hwaddr dense = ia64_pci_dense_io_addr(port);

    if (port >= IA64_PCI_IO_SIZE || port + size > IA64_PCI_IO_SIZE) {
        return;
    }

    switch (size) {
    case 1:
        address_space_stb(&s->pci_io_as, dense, data,
                          MEMTXATTRS_UNSPECIFIED, NULL);
        break;
    case 2:
        address_space_stw_le(&s->pci_io_as, dense, data,
                             MEMTXATTRS_UNSPECIFIED, NULL);
        break;
    case 4:
        address_space_stl_le(&s->pci_io_as, dense, data,
                             MEMTXATTRS_UNSPECIFIED, NULL);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ia64_pci_sparse_io_ops = {
    .read = ia64_pci_sparse_io_read,
    .write = ia64_pci_sparse_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static PCIDevice *ia64_pci_config_device(IA64PCIState *s, hwaddr addr,
                                         uint32_t *reg)
{
    PCIHostState *phb = PCI_HOST_BRIDGE(s);
    uint8_t bus = extract64(addr, 20, 8);
    uint8_t slot = extract64(addr, 15, 5);
    uint8_t func = extract64(addr, 12, 3);

    *reg = addr & 0xfff;
    return pci_find_device(phb->bus, bus, PCI_DEVFN(slot, func));
}

static uint64_t ia64_pci_config_read(void *opaque, hwaddr addr, unsigned size)
{
    IA64PCIState *s = opaque;
    PCIDevice *pci_dev;
    uint32_t reg;

    if (addr >= IA64_PCI_CONFIG_SIZE || size > 4 ||
        addr + size > IA64_PCI_CONFIG_SIZE) {
        return ~0ULL;
    }

    pci_dev = ia64_pci_config_device(s, addr, &reg);
    if (pci_dev == NULL) {
        return ~0ULL;
    }

    return pci_host_config_read_common(pci_dev, reg,
                                       pci_config_size(pci_dev), size);
}

static void ia64_pci_config_write(void *opaque, hwaddr addr, uint64_t val,
                                  unsigned size)
{
    IA64PCIState *s = opaque;
    PCIDevice *pci_dev;
    uint32_t reg;

    if (addr >= IA64_PCI_CONFIG_SIZE || size > 4 ||
        addr + size > IA64_PCI_CONFIG_SIZE) {
        return;
    }

    pci_dev = ia64_pci_config_device(s, addr, &reg);
    if (pci_dev == NULL) {
        return;
    }

    pci_host_config_write_common(pci_dev, reg, pci_config_size(pci_dev),
                                 val, size);
}

static const MemoryRegionOps ia64_pci_config_ops = {
    .read = ia64_pci_config_read,
    .write = ia64_pci_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static int ia64_pci_route_intx_output(uint8_t devfn, int irq_num)
{
    return (PCI_SLOT(devfn) + irq_num) % IA64_PCI_INTX_LINES;
}

int ia64_pci_route_intx_gsi(uint8_t devfn, int irq_num)
{
    return IA64_PCI_INTX_GSI_BASE + ia64_pci_route_intx_output(devfn, irq_num);
}

static int ia64_pci_map_irq(PCIDevice *d, int irq_num)
{
    return ia64_pci_route_intx_output(d->devfn, irq_num);
}

static void ia64_pci_set_irq(void *opaque, int irq_num, int level)
{
    IA64PCIState *s = opaque;

    if (irq_num < IA64_PCI_INTX_LINES) {
        qemu_set_irq(s->irq[irq_num], level);
    }
}

static void ia64_pci_realize(DeviceState *dev, Error **errp)
{
    IA64PCIState *s = IA64_PCI_HOST_BRIDGE(dev);
    PCIHostState *phb = PCI_HOST_BRIDGE(dev);

    /*
     * PCI BAR values on this platform are identity-mapped CPU physical
     * addresses.  Keep the PCI bus address space large enough to contain the
     * advertised low MMIO window at its bus address, then expose only that
     * window into system memory.
     */
    memory_region_init(&s->pci_mmio, OBJECT(dev), "pci-mmio",
                       IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE);
    memory_region_init_alias(&s->pci_mmio_window, OBJECT(dev),
                             "pci-mmio-window", &s->pci_mmio,
                             IA64_PCI_MMIO_BASE, IA64_PCI_MMIO_SIZE);
    /*
     * IA-64 sparse I/O uses a 24-bit port offset within each io_space slot.
     * Linux constructs CPU virtual addresses that can reach beyond 64 KiB
     * even for ordinary byte/word port accesses, so the legacy PCI I/O window
     * must cover the full 16 MiB aperture.
     */
    memory_region_init(&s->pci_io, OBJECT(dev), "pci-io",
                       IA64_PCI_IO_SIZE);
    address_space_init(&s->pci_io_as, &s->pci_io, "ia64-pci-io");
    memory_region_init_io(&s->pci_io_sparse, OBJECT(dev),
                          &ia64_pci_sparse_io_ops, s, "pci-io-sparse",
                          IA64_PCI_IO_SPARSE_SIZE -
                          IA64_PCI_IO_SPARSE_SKIP);
    memory_region_init_io(&s->pci_config, OBJECT(dev),
                          &ia64_pci_config_ops, s, "ia64-pci-config",
                          IA64_PCI_CONFIG_SIZE);

    qdev_init_gpio_out(dev, s->irq, IA64_PCI_INTX_LINES);

    phb->bus = pci_register_root_bus(dev, "pci",
                                     ia64_pci_set_irq, ia64_pci_map_irq, s,
                                     &s->pci_mmio, &s->pci_io,
                                     PCI_DEVFN(0, 0), 4, TYPE_PCI_BUS);

    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_PCI_MMIO_BASE,
                                        &s->pci_mmio_window, 1);
    memory_region_add_subregion(get_system_memory(), IA64_PCI_IO_BASE,
                                &s->pci_io);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_PCI_IO_BASE +
                                        IA64_PCI_IO_SPARSE_SKIP,
                                        &s->pci_io_sparse, 1);
    memory_region_add_subregion(get_system_memory(), IA64_PCI_CONFIG_BASE,
                                &s->pci_config);
}

static void ia64_pci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = ia64_pci_realize;
}

static const TypeInfo ia64_pci_info = {
    .name          = TYPE_IA64_PCI_HOST_BRIDGE,
    .parent        = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(IA64PCIState),
    .class_init    = ia64_pci_class_init,
};

static void ia64_pci_register_types(void)
{
    type_register_static(&ia64_pci_info);
}
type_init(ia64_pci_register_types)
