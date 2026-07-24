/* SPDX-License-Identifier: GPL-2.0-or-later */
/* IA-64 EFI firmware linker script. Linked at the machine-model load address. */

ENTRY(_start)

SECTIONS
{
    . = 0x100000;

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
ASSERT(sal_runtime_entry == 0x102000,
       "sal_runtime_entry must sit at IA64_FW_SAL_RUNTIME_ENTRY_PA (0x102000)")
ASSERT(sal_runtime_return == 0x102020,
       "sal_runtime_return must sit at IA64_FW_SAL_RUNTIME_RETURN_PA (0x102020)")
ASSERT(sal_dispatch_block == 0x102040,
       "sal_dispatch_block must sit at IA64_FW_SAL_DISPATCH_BLOCK_PA (0x102040)")
