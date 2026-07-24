/* Reuse QEMU's x87, MMX and SSE helper implementation for IA-32 mode. */

#include "helper-compat.h"
#define X86_CPU_ARCH_ENV(env) ((CPUIA64State *)(env))
#define X86_MASKMOV_ACCESS(env, addr, ra)                              \
    ia64_ia32_check_segment_access(                                   \
        (env), (uint32_t)(addr), R_DS, 1,                             \
        IA64_IA32_SEG_ACCESS_WRITE, (ra))
#define X86_FPU_ALWAYS_NE 1
#define X86_MXCSR_VALID_MASK 0x0000ffbfU
#include "ia32/ia32.h"
#include "target/i386/tcg/fpu_helper.c"
