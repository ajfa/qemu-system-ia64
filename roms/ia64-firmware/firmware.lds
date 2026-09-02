/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IA-64 EFI firmware linker script. Linked at the machine-model load address. */

ENTRY(_start)

SECTIONS
{
    /*
     * 3 MiB, not 1 MiB.  AIX 5L/IA-64's BOOTIA64.EFI has its relocations
     * stripped and is linked at a fixed ImageBase of 0x1ff000, so EFI
     * LoadImage() can only place it if [0x1ff000, 0x254000) is conventional
     * memory.  Linked at 1 MiB this firmware spans [0x100000, 0x2fe000) and
     * swallows that window, and the AIX loader cannot be loaded at all.
     * Must match IA64_FW_BASE (hw/ia64/ia64_vpc.c) and
     * IA64_FW_IDENTITY_BASE (target/ia64/cpu.h).
     */
    . = 0x300000;

    .text.boot : {
        *(.text._start)
        *(.text.pal_proc_entry)
        *(.text.start_after_pal)
        *(.text.start_secondary)
        *(.text.fw_pal_halt_light)
    }

    . = ALIGN(0x2000);
    __runtime_code_start = .;

    /*
     * The SAL runtime stub trio leads the runtime code region: Windows
     * Server 2003's HAL requires the SST SalProc address to fall inside an
     * EfiRuntimeServicesCode descriptor.  The machine recognises the stubs
     * by fixed physical address (IA64_FW_SAL_RUNTIME_ENTRY_PA et al.), so
     * pin the region base.
     */
    .text.sal_runtime : {
        *(.text.sal_runtime)
    }

    .text : {
        *(.text*)
        *(.plt*)
    }

    . = ALIGN(0x2000);
    __runtime_data_start = .;

    . = ALIGN(16);

    .rodata : {
        *(.rodata*)
    }

    . = ALIGN(16);

    .opd : {
        *(.opd)
    }

    . = ALIGN(16);

    .IA_64.unwind_info : {
        *(.IA_64.unwind_info*)
    }

    . = ALIGN(16);

    .IA_64.unwind : {
        *(.IA_64.unwind*)
    }

    .data : {
        *(.data*)
    }

    . = ALIGN(16);

    .got : {
        __gp_start = .;
        *(.got*)
    }

    . = ALIGN(16);

    .bss : {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    }

    _end = .;
}

/* The machine hardcodes the SAL runtime stub addresses (target/ia64/cpu.h). */
ASSERT(sal_runtime_entry == 0x302000,
       "sal_runtime_entry must sit at IA64_FW_SAL_RUNTIME_ENTRY_PA (0x302000)")
ASSERT(sal_runtime_return == 0x302020,
       "sal_runtime_return must sit at IA64_FW_SAL_RUNTIME_RETURN_PA (0x302020)")
ASSERT(sal_dispatch_block == 0x302040,
       "sal_dispatch_block must sit at IA64_FW_SAL_DISPATCH_BLOCK_PA (0x302040)")
