/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * HP zx1 LBA (Local Bus Adapter) AGP capability block for the zx1 machine.
 */

#ifndef HW_IA64_LBA_H
#define HW_IA64_LBA_H

#include "hw/core/qdev.h"
#include "system/memory.h"
#include "qom/object.h"

#define TYPE_IA64_LBA "ia64-zx1-lba"
OBJECT_DECLARE_SIMPLE_TYPE(IA64LBAState, IA64_LBA)

struct IA64LBAState {
    DeviceState parent_obj;

    MemoryRegion csr;              /* config block, mapped at csr_base */
    uint64_t csr_base;             /* fixed chipset MMIO base (IA64_LBA_CSR_BASE) */
    uint32_t agp_command;          /* AGP command register (0x68), r/w */
};

#endif /* HW_IA64_LBA_H */
