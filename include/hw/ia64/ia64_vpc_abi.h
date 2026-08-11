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
 * The minimum machine has 128 MiB of low RAM.  Keep the upper 2 MiB of that
 * minimum configuration reserved so every supported CPU has independent SAL,
 * debug, initial RSE, and bootstrap memory-stack storage.  The ordinary EFI
 * stack pool remains relative to the installed low-RAM end; at the minimum
 * RAM size it coincides with the fixed bootstrap-stack subrange below.
 *
 * entry.S cannot include this header (it is assembled without the C
 * preprocessor); its SAL_RUNTIME_AREA_TOP and FW_AP_BOOTSTRAP_STACK_TOP
 * .equ literals must match IA64_FW_SAL_RUNTIME_END and
 * IA64_FW_BOOTSTRAP_STACK_TOP, and its AP stack stride shift must match
 * IA64_FW_CPU_STACK_SIZE.
 */
#define IA64_FW_CPU_ASSIST_BASE        0x0000000007e00000ULL
#define IA64_FW_CPU_ASSIST_END         0x0000000008000000ULL

#define IA64_FW_SAL_RUNTIME_BASE       0x0000000007e00000ULL
#define IA64_FW_SAL_RUNTIME_SLOT_SIZE  0x0000000000008000ULL
#define IA64_FW_SAL_RUNTIME_END \
    (IA64_FW_SAL_RUNTIME_BASE + \
     IA64_VPC_MAX_CPUS * IA64_FW_SAL_RUNTIME_SLOT_SIZE)

#define IA64_FW_DEBUG_CONTEXT_BASE     0x0000000007e40000ULL
#define IA64_FW_DEBUG_CONTEXT_STRIDE   0x0000000000000800ULL
#define IA64_FW_DEBUG_CONTEXT_SIZE     1192U
#define IA64_FW_DEBUG_CONTEXT_END \
    (IA64_FW_DEBUG_CONTEXT_BASE + \
     IA64_VPC_MAX_CPUS * IA64_FW_DEBUG_CONTEXT_STRIDE)

#define IA64_FW_DEBUG_STACK_BASE       0x0000000007e80000ULL
#define IA64_FW_DEBUG_STACK_SIZE       0x0000000000008000ULL
#define IA64_FW_DEBUG_STACK_END \
    (IA64_FW_DEBUG_STACK_BASE + \
     IA64_VPC_MAX_CPUS * IA64_FW_DEBUG_STACK_SIZE)

#define IA64_FW_EARLY_RSE_BASE         0x0000000007ec0000ULL
#define IA64_FW_EARLY_RSE_SIZE         0x0000000000008000ULL
#define IA64_FW_EARLY_RSE_END \
    (IA64_FW_EARLY_RSE_BASE + \
     IA64_VPC_MAX_CPUS * IA64_FW_EARLY_RSE_SIZE)

#define IA64_FW_BOOTSTRAP_STACK_TOP    0x0000000008000000ULL
#define IA64_FW_CPU_STACK_SIZE         0x0000000000020000ULL
#define IA64_FW_BOOT_STACK_SIZE \
    (IA64_VPC_MAX_CPUS * IA64_FW_CPU_STACK_SIZE)
#define IA64_FW_FIXED_STACK_BASE \
    (IA64_FW_BOOTSTRAP_STACK_TOP - IA64_FW_BOOT_STACK_SIZE)

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
