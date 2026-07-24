/* Reuse QEMU's block memory-access support for IA-32 x87 state. */

#include "helper-compat.h"
#include "ia32/ia32.h"
#define X86_CPU_ARCH_ENV(env) ((CPUIA64State *)(env))
#define X86_ACCESS_ADDRESS(env, addr) ((uint32_t)(addr))
#define X86_ACCESS_CHECK_ALIGNMENT(env, addr, size, ra) \
    ia64_ia32_check_block_alignment(env, addr, size, ra)
#define X86_ACCESS_RECORD(env, addr, size, access)                     \
    ia64_ia32_record_data_access(                                     \
        (CPUIA64State *)(env), (uint32_t)(addr), (size),              \
        (access) == MMU_DATA_STORE ? IA64_IA32_SEG_ACCESS_WRITE :     \
                                     IA64_IA32_SEG_ACCESS_READ)
#include "target/i386/tcg/access.c"
