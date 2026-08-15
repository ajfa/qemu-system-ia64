/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Intel 460GX GXB AGP host bridge + GART.
 */

#ifndef HW_IA64_AGP_H
#define HW_IA64_AGP_H

#include "hw/pci/pci_device.h"
#include "system/memory.h"
#include "qom/object.h"

#define TYPE_IA64_AGP "ia64-agp-gxb"
OBJECT_DECLARE_SIMPLE_TYPE(IA64AGPState, IA64_AGP)

#define TYPE_IA64_AGP_IOMMU_MEMORY_REGION "ia64-agp-iommu-memory-region"

struct IA64AGPState {
    PCIDevice parent_obj;

    MemoryRegion gart_window;    /* GART SRAM window at 0xFE200000           */
    IOMMUMemoryRegion iommu;     /* per-bus DMA translation                  */
    AddressSpace dma_as;

    uint32_t *gatt;              /* GART SRAM, one 32-bit entry per 4 KiB    */
    uint64_t aperture_base;      /* current aperture base (from BAPBASE)     */
    bool aperture_enabled;

    /*
     * Devfn of the single AGP graphics master whose DMA the GART translates.
     * On the real 460GX the GART sits only on the GXB's AGP port; other PCI
     * masters do not traverse it.  Set by the machine; -1 leaves every master
     * on a plain identity pass-through.
     */
    int32_t agp_master_devfn;
};

#endif /* HW_IA64_AGP_H */
