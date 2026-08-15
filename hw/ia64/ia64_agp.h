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

    MemoryRegion aperture;       /* BAR0: the graphics aperture (DMA-only)   */
    MemoryRegion gart_window;    /* GART SRAM window at 0xFE200000           */
    IOMMUMemoryRegion iommu;     /* per-bus DMA translation                  */
    AddressSpace dma_as;

    uint32_t *gatt;              /* GART SRAM, one 32-bit entry per 4 KiB    */
    uint64_t aperture_base;      /* current APBASE (from BAR0)               */
    bool aperture_enabled;
};

#endif /* HW_IA64_AGP_H */
