/*
 * IA-32 execution-engine compatibility definitions.
 *
 * The IA-64 application architecture contains an IA-32 register view.  Keep
 * QEMU's x86 TCG backing state as an implementation detail so that the
 * existing decoder and helpers can be used without making an X86CPU a second
 * QEMU CPU object.  The generic structure tags in target/i386/cpu.h are
 * renamed while importing the x86 definitions; the real IA-64 CPUArchState
 * and ArchCPU are declared later by target/ia64/cpu.h.
 */

#ifndef TARGET_IA64_IA32_COMPAT_H
#define TARGET_IA64_IA32_COMPAT_H

#undef CPU_RESOLVING_TYPE
#undef MMU_PHYS_IDX
#define CPUArchState IA64X86State
#define ArchCPU IA64X86CPU
#include "target/i386/cpu.h"
#undef ArchCPU
#undef CPUArchState

/* Do not let the imported target's generic aliases escape into IA-64. */
#undef CPU_RESOLVING_TYPE
#define CPU_RESOLVING_TYPE TYPE_IA64_CPU
#undef TARGET_DEFAULT_CPU_TYPE
#undef MMU_PHYS_IDX
#define MMU_PHYS_IDX 0
#undef CC_DST
#undef CC_SRC
#undef CC_SRC2
#undef CC_OP

#endif /* TARGET_IA64_IA32_COMPAT_H */
