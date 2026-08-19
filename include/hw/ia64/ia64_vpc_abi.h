/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 virtual PC ABI shared by QEMU and its freestanding firmware.
 *
 * This header must remain usable with -nostdinc.  Do not include QEMU or
 * hosted C library headers here; use compiler built-in types only.
 */

#ifndef HW_IA64_VPC_ABI_H
#define HW_IA64_VPC_ABI_H

#define IA64_FW_HANDOFF_ADDR          0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC         0x4d41523436414951ULL /* "QIA64RAM" */
#define IA64_FW_HANDOFF_VERSION       10ULL

#define IA64_FW_CONSOLE_SERIAL        0ULL
#define IA64_FW_CONSOLE_VGA           1ULL
#define IA64_FW_DEBUG_PORT_PRESENT    1ULL

#define IA64_VPC_MAX_CPUS             8U

/*
 * CPU-private physical memory used before and after ExitBootServices().
 *
 * Real IA-64 firmware keeps low DRAM contiguous from 1 MiB up to the PCI/MMIO
 * aperture and carves its own SAL/boot scratch from the TOP of installed RAM
 * (460GX SDV: "allocate PAL/SAL memory near top of RAM"; E8870 SR870BH2: a
 * SAL data block at negative offsets from a RAM-top base holding the BSP
 * backing store and MP buffers - plans/sdv-i2000-firmware-reference.md 6.1,
 * plans/sr870bh2-firmware-reference.md 6.2).  The fork does the same: the
 * 2 MiB CPU-assist region (per-CPU SAL re-entry slots, debug contexts and
 * stacks, initial RSE backing stores, and the boot memory stacks) sits at
 * [low_ram_end - 2 MiB, low_ram_end), where low_ram_end is installed RAM
 * clamped to the PCI aperture and rounded down to IA64_FW_LOW_RAM_ALIGN.
 * Low DRAM below it stays conventional (the firmware's efi_init_memory_map
 * keeps only the loader-contract boundaries described there), so OS loaders
 * that map their working set with large translation registers (Server 2003
 * SP1 setupldr: 64 MiB pages at [64 MiB, 192 MiB)) are satisfied.
 *
 * The minimum machine has 128 MiB of low RAM, where this layout coincides
 * exactly with the historical fixed [126 MiB, 128 MiB) region.
 *
 * entry.S cannot include this header (it is assembled without the C
 * preprocessor); it re-derives the region from the handoff block with the
 * same constants (see the .equ literals there), and its AP stack stride
 * shift must match IA64_FW_CPU_STACK_SIZE.
 */
#define IA64_FW_LOW_RAM_MIN            0x0000000008000000ULL
#define IA64_FW_LOW_RAM_ALIGN          0x0000000000002000ULL
#define IA64_FW_CPU_ASSIST_SIZE        0x0000000000200000ULL

/* Offsets inside the CPU-assist region. */
#define IA64_FW_SAL_RUNTIME_OFFSET     0x0000000000000000ULL
#define IA64_FW_SAL_RUNTIME_SLOT_SIZE  0x0000000000008000ULL
#define IA64_FW_SAL_RUNTIME_END_OFFSET \
    (IA64_FW_SAL_RUNTIME_OFFSET + \
     IA64_VPC_MAX_CPUS * IA64_FW_SAL_RUNTIME_SLOT_SIZE)

#define IA64_FW_DEBUG_CONTEXT_OFFSET   0x0000000000040000ULL
#define IA64_FW_DEBUG_CONTEXT_STRIDE   0x0000000000000800ULL
#define IA64_FW_DEBUG_CONTEXT_SIZE     1192U
#define IA64_FW_DEBUG_CONTEXT_END_OFFSET \
    (IA64_FW_DEBUG_CONTEXT_OFFSET + \
     IA64_VPC_MAX_CPUS * IA64_FW_DEBUG_CONTEXT_STRIDE)

#define IA64_FW_DEBUG_STACK_OFFSET     0x0000000000080000ULL
#define IA64_FW_DEBUG_STACK_SIZE       0x0000000000008000ULL
#define IA64_FW_DEBUG_STACK_END_OFFSET \
    (IA64_FW_DEBUG_STACK_OFFSET + \
     IA64_VPC_MAX_CPUS * IA64_FW_DEBUG_STACK_SIZE)

#define IA64_FW_EARLY_RSE_OFFSET       0x00000000000c0000ULL
#define IA64_FW_EARLY_RSE_SIZE         0x0000000000008000ULL
#define IA64_FW_EARLY_RSE_END_OFFSET \
    (IA64_FW_EARLY_RSE_OFFSET + \
     IA64_VPC_MAX_CPUS * IA64_FW_EARLY_RSE_SIZE)

#define IA64_FW_CPU_STACK_SIZE         0x0000000000020000ULL
#define IA64_FW_BOOT_STACK_SIZE \
    (IA64_VPC_MAX_CPUS * IA64_FW_CPU_STACK_SIZE)
/* The boot memory stacks occupy the top of the region, ending at low_ram_end. */
#define IA64_FW_BOOT_STACK_OFFSET \
    (IA64_FW_CPU_ASSIST_SIZE - IA64_FW_BOOT_STACK_SIZE)

/* low_ram_end for an installed RAM size, as both QEMU and the firmware see it. */
#define IA64_FW_LOW_RAM_END(ram_size) \
    ((((ram_size) < IA64_PCI_MMIO_BASE ? (ram_size) : IA64_PCI_MMIO_BASE)) & \
     ~(IA64_FW_LOW_RAM_ALIGN - 1ULL))
#define IA64_FW_CPU_ASSIST_BASE_FOR(ram_size) \
    (IA64_FW_LOW_RAM_END(ram_size) - IA64_FW_CPU_ASSIST_SIZE)

#define IA64_UART_BASE                0x00000047f0000000ULL
#define IA64_DEBUG_UART_BASE          0x00000047f0001000ULL
#define IA64_UART_MMIO_SIZE           0x0000000000002000ULL

/*
 * The PCI/MMIO aperture sits just below the fixed chipset/SAPIC/firmware
 * region [0xFE000000, 4 GiB), mirroring real 460GX hardware, which keeps a
 * single MMIO gap at the top of the 32-bit space so DRAM stays contiguous up
 * to it and any displaced RAM is remapped above 4 GiB (see
 * plans/sdv-i2000-firmware-reference.md 7.1).
 */
#define IA64_PCI_MMIO_BASE            0x00000000ee000000ULL
#define IA64_PCI_MMIO_SIZE            0x0000000010000000ULL

typedef struct __attribute__((packed)) IA64VpcHandoff {
    unsigned long long Magic;
    unsigned long long Version;
    unsigned long long RamSize;
    unsigned long long ConsolePolicy;
    unsigned long long IdeDmaEnabled;
    unsigned long long DebugPortFlags;
    unsigned long long DebugPortBase;
    unsigned long long I8042Enabled;
    unsigned long long ProcessorCount;
    unsigned long long NvramPersistent;
    unsigned long long SocketCount;
    unsigned long long CoresPerSocket;
    unsigned long long ThreadsPerCore;
} IA64VpcHandoff;

#endif /* HW_IA64_VPC_ABI_H */
