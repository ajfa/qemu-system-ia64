/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Intel 460GX GXB AGP host bridge + GART, minimal model.
 *
 * Models just enough of the 460GX "expander/graphics bridge" (chipset device
 * 14h) for Linux's i460-agp driver to bind and for an AGP master (the ATI
 * Rage 128) to DMA through the graphics aperture into DRAM above 4 GiB, which a
 * 32-bit PCI master cannot reach on its own.  Per the 460GX SSDM (248704-001,
 * ch. 7) the GART is not an in-DRAM table with a base pointer: it is on-chip
 * SRAM the OS programs through a fixed physical MMIO window at 0xFE200000, with
 * no TLB and no flush register.  A GATT entry translates a 4 KiB aperture page
 * to a 36-bit physical page.
 *
 * Contract taken from Linux 2.6.8 drivers/char/agp/i460-agp.c:
 *   - binds to class host-bridge, 8086:84ea, and requires a PCI AGP capability;
 *   - APBASE (BAR0, 64-bit) is the aperture base; GXBCTL[0xa0] bit1 must read 0
 *     (4 KiB pages); AGPSIZ[0xa2] bits[2:0] select the size (1 = 256 MiB);
 *   - GATT entry = 0x03000000 | (paddr[35:12]); bit24 valid, bit25 coherent.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/ia64/ia64_agp.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "system/address-spaces.h"
#include "qemu/log.h"
#include "qapi/error.h"

/* Fixed physical window through which the OS reads/writes the GART SRAM. */
#define I460_GART_WINDOW_BASE   0x00000000fe200000ULL

/* Config-space registers the i460-agp driver touches. */
#define I460_GXBCTL             0xa0    /* 8-bit: bit1 = 4 MiB page select */
#define I460_AGPSIZ             0xa2    /* 8-bit: [2:0] size, bit3/4 flags   */

#define I460_GXBCTL_4M_PS       0x02

/* GATT entry bits. */
#define I460_GATT_VALID         (1u << 24)
#define I460_GATT_COHERENT      (1u << 25)
#define I460_GATT_PFN_MASK      0x00ffffffu     /* phys[35:12] */

/*
 * 256 MiB aperture (AGPSIZ size_value 1), 4 KiB pages => 65536 GATT entries
 * (256 KiB of SRAM).  Placed high in the DMA address space, clear of any DRAM
 * (max modelled guest RAM is a few GiB), so an out-of-aperture DMA still passes
 * straight through to system memory.
 */
#define I460_APERTURE_SIZE      (256 * MiB)
#define I460_GATT_ENTRIES       (I460_APERTURE_SIZE / (4 * KiB))
#define I460_APERTURE_BASE      0x0000000400000000ULL   /* 16 GiB */

static IA64AGPState *ia64_agp_from_iommu(IOMMUMemoryRegion *iommu)
{
    return container_of(iommu, IA64AGPState, iommu);
}

/*
 * Aperture DMA -> DRAM.  Addresses outside [apbase, apbase+size) pass through
 * untranslated (ordinary 32-bit-reachable DMA); addresses inside walk the GATT
 * SRAM to a 36-bit physical page.
 */
static IOMMUTLBEntry ia64_agp_translate(IOMMUMemoryRegion *iommu, hwaddr addr,
                                        IOMMUAccessFlags flag, int iommu_idx)
{
    IA64AGPState *s = ia64_agp_from_iommu(iommu);
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr & ~(hwaddr)0xfff,
        .translated_addr = addr & ~(hwaddr)0xfff,
        .addr_mask = 0xfff,
        .perm = IOMMU_RW,
    };
    uint64_t apbase = s->aperture_base;
    uint32_t entry;
    unsigned index;

    if (!s->aperture_enabled || addr < apbase ||
        addr >= apbase + I460_APERTURE_SIZE) {
        /* Not the graphics aperture: identity map into system memory. */
        return ret;
    }

    index = (addr - apbase) >> 12;
    entry = s->gatt[index];
    if (!(entry & I460_GATT_VALID)) {
        ret.perm = IOMMU_NONE;
        return ret;
    }
    ret.translated_addr = ((hwaddr)(entry & I460_GATT_PFN_MASK) << 12) |
                          (addr & 0xfff);
    return ret;
}

/* GART SRAM programming window (0xFE200000): 32-bit little-endian words. */
static uint64_t ia64_agp_gart_read(void *opaque, hwaddr addr, unsigned size)
{
    IA64AGPState *s = opaque;
    unsigned index = addr >> 2;

    if (index >= I460_GATT_ENTRIES) {
        return 0;
    }
    return s->gatt[index];
}

static void ia64_agp_gart_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size)
{
    IA64AGPState *s = opaque;
    unsigned index = addr >> 2;

    if (index >= I460_GATT_ENTRIES) {
        return;
    }
    /*
     * HW regenerates parity (bit 26); keep it out of the stored value.  There
     * is no GART TLB (SSDM 7.1.1.2): emulated-master DMA re-walks the SRAM on
     * every access via ia64_agp_translate(), so a fresh entry is live at once
     * with no invalidation needed.
     */
    s->gatt[index] = (uint32_t)val & ~(1u << 26);
}

static const MemoryRegionOps ia64_agp_gart_ops = {
    .read = ia64_agp_gart_read,
    .write = ia64_agp_gart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Every device on the bus DMAs through the GART address space. */
static AddressSpace *ia64_agp_dma_as(PCIBus *bus, void *opaque, int devfn)
{
    IA64AGPState *s = opaque;

    return &s->dma_as;
}

static const PCIIOMMUOps ia64_agp_iommu_ops = {
    .get_address_space = ia64_agp_dma_as,
};

static void ia64_agp_config_write(PCIDevice *dev, uint32_t addr,
                                  uint32_t val, int len)
{
    IA64AGPState *s = IA64_AGP(dev);

    pci_default_write_config(dev, addr, val, len);

    /* Track the aperture base/enable straight from the BAR the driver reads. */
    s->aperture_base = pci_get_bar_addr(dev, 0);
    s->aperture_enabled = (pci_get_word(dev->config + PCI_COMMAND) &
                           PCI_COMMAND_MEMORY) &&
                          s->aperture_base != PCI_BAR_UNMAPPED &&
                          s->aperture_base != 0;
}

static void ia64_agp_realize(PCIDevice *dev, Error **errp)
{
    IA64AGPState *s = IA64_AGP(dev);
    uint8_t *c = dev->config;

    /* Host-bridge class so i460-agp's pci_device_id table matches. */
    pci_config_set_prog_interface(c, 0);

    /* i460-agp reads GXBCTL bit1 (must be 0 = 4 KiB pages) and AGPSIZ[2:0]. */
    c[I460_GXBCTL] = 0x00;
    c[I460_AGPSIZ] = 0x01;                    /* size_value 1 = 256 MiB */
    dev->wmask[I460_GXBCTL] = 0x05;           /* driver writes OOG|BWC only */
    dev->wmask[I460_AGPSIZ] = 0x07;           /* size_value RMW, keep [7:3] */

    /* Mandatory: an AGP capability, or the driver returns -ENODEV. */
    if (pci_add_capability(dev, PCI_CAP_ID_AGP, 0, 8, errp) < 0) {
        return;
    }
    /* Advertise AGP 2.0, 1x/2x/4x so agp_generic_enable negotiates a rate. */
    pci_set_long(c + pci_find_capability(dev, PCI_CAP_ID_AGP) + PCI_AGP_STATUS,
                 0x1f000207);

    /* The graphics aperture BAR (64-bit; CPU never touches it, DMA-only). */
    memory_region_init(&s->aperture, OBJECT(s), "ia64-agp-aperture",
                       I460_APERTURE_SIZE);
    pci_register_bar(dev, 0,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64 |
                     PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &s->aperture);

    /* GART SRAM, exposed to the CPU at the fixed 0xFE200000 window. */
    s->gatt = g_new0(uint32_t, I460_GATT_ENTRIES);
    memory_region_init_io(&s->gart_window, OBJECT(s), &ia64_agp_gart_ops, s,
                          "ia64-agp-gart", I460_GATT_ENTRIES * sizeof(uint32_t));
    memory_region_add_subregion(get_system_memory(), I460_GART_WINDOW_BASE,
                                &s->gart_window);

    /* Per-bus DMA translation: aperture -> GATT -> DRAM, else passthrough. */
    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_IA64_AGP_IOMMU_MEMORY_REGION, OBJECT(s),
                             "ia64-agp-dma", UINT64_MAX);
    address_space_init(&s->dma_as, MEMORY_REGION(&s->iommu), "ia64-agp-dma");
    pci_setup_iommu(pci_get_bus(dev), &ia64_agp_iommu_ops, s);
}

static void ia64_agp_reset(DeviceState *dev)
{
    IA64AGPState *s = IA64_AGP(dev);

    memset(s->gatt, 0, I460_GATT_ENTRIES * sizeof(uint32_t));
    s->aperture_base = 0;
    s->aperture_enabled = false;
}

static void ia64_agp_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = ia64_agp_realize;
    k->config_write = ia64_agp_config_write;
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = 0x84ea;              /* PCI_DEVICE_ID_INTEL_84460GX */
    k->class_id = PCI_CLASS_BRIDGE_HOST;
    dc->desc = "Intel 460GX GXB AGP bridge";
    device_class_set_legacy_reset(dc, ia64_agp_reset);
    /* Chipset device, not user-pluggable. */
    dc->user_creatable = false;
}

static const TypeInfo ia64_agp_info = {
    .name          = TYPE_IA64_AGP,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(IA64AGPState),
    .class_init    = ia64_agp_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void ia64_agp_iommu_class_init(ObjectClass *klass, const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = ia64_agp_translate;
}

static const TypeInfo ia64_agp_iommu_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_IA64_AGP_IOMMU_MEMORY_REGION,
    .class_init = ia64_agp_iommu_class_init,
};

static void ia64_agp_register_types(void)
{
    type_register_static(&ia64_agp_info);
    type_register_static(&ia64_agp_iommu_info);
}

type_init(ia64_agp_register_types)
