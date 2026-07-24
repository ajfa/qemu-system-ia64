/* Reuse QEMU's real/protected-mode x86 segmentation helpers. */

#include "helper-compat.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "target/i386/tcg/helper-tcg.h"
#include "target/i386/tcg/seg_helper.h"
#include "ia32/ia32.h"

/*
 * The x86 helpers normally select one of x86's private MMU indices.  IA-32
 * execution on Itanium uses the IA-64 translation and protection machinery,
 * so every descriptor and stack access must instead use the current IA-64
 * data MMU index.  The backing x86 view is at offset zero in CPUIA64State.
 */
#define IA32_ARCH_ENV(env) ((CPUIA64State *)(env))
#define IA32_MMU_IDX(env) \
    cpu_mmu_index(env_cpu(IA32_ARCH_ENV(env)), false)

static void ia32_stack_access_prepare(CPUX86State *xenv, vaddr addr,
                                      unsigned size, MMUAccessType type,
                                      uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);
    unsigned access = type == MMU_DATA_STORE ?
                      IA64_IA32_SEG_ACCESS_WRITE :
                      IA64_IA32_SEG_ACCESS_READ;

    /* Translation and protection faults have priority over alignment. */
    ia64_ia32_probe_access(env, addr, size, type, IA32_MMU_IDX(xenv),
                           retaddr);
    ia64_ia32_record_data_access(env, addr, size, access);
    ia64_ia32_check_block_alignment(xenv, addr, size, retaddr);
}

static uint16_t ia32_stack_lduw(CPUX86State *xenv, vaddr addr,
                                uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 2, MMU_DATA_LOAD, retaddr);
    return cpu_lduw_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr,
                                 IA32_MMU_IDX(xenv), retaddr);
}

static uint32_t ia32_stack_ldl(CPUX86State *xenv, vaddr addr,
                               uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 4, MMU_DATA_LOAD, retaddr);
    return cpu_ldl_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr,
                                IA32_MMU_IDX(xenv), retaddr);
}

static G_GNUC_UNUSED uint64_t ia32_stack_ldq(CPUX86State *xenv, vaddr addr,
                                              uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 8, MMU_DATA_LOAD, retaddr);
    return cpu_ldq_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr,
                                IA32_MMU_IDX(xenv), retaddr);
}

static void ia32_stack_stw(CPUX86State *xenv, vaddr addr, uint16_t value,
                           uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 2, MMU_DATA_STORE, retaddr);
    cpu_stw_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr, value,
                         IA32_MMU_IDX(xenv), retaddr);
}

static void ia32_stack_stl(CPUX86State *xenv, vaddr addr, uint32_t value,
                           uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 4, MMU_DATA_STORE, retaddr);
    cpu_stl_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr, value,
                         IA32_MMU_IDX(xenv), retaddr);
}

static G_GNUC_UNUSED void ia32_stack_stq(CPUX86State *xenv, vaddr addr,
                                         uint64_t value, uintptr_t retaddr)
{
    addr = (uint32_t)addr;
    ia32_stack_access_prepare(xenv, addr, 8, MMU_DATA_STORE, retaddr);
    cpu_stq_le_mmuidx_ra(IA32_ARCH_ENV(xenv), addr, value,
                         IA32_MMU_IDX(xenv), retaddr);
}

static void ia32_supervisor_access_prepare(CPUX86State *xenv, vaddr addr,
                                           unsigned size,
                                           MMUAccessType type,
                                           uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);
    unsigned access = type == MMU_DATA_STORE ?
                      IA64_IA32_SEG_ACCESS_WRITE :
                      IA64_IA32_SEG_ACCESS_READ;

    /* GDT/LDT/TSS accesses ignore EFLAGS.AC, but not PSR.ac. */
    ia64_ia32_probe_access(env, addr, size, type, IA32_MMU_IDX(xenv),
                           retaddr);
    ia64_ia32_record_data_access(env, addr, size, access);
    ia64_ia32_check_psr_alignment(xenv, addr, size, retaddr);
}

static void ia32_system_descriptor_check(CPUX86State *xenv,
                                         const SegmentCache *dt,
                                         uint16_t selector,
                                         uintptr_t retaddr)
{
    /* IA-64 adds run-time integrity checks to GDT/LDT references. */
    if ((dt->flags & (DESC_S_MASK | DESC_P_MASK)) != DESC_P_MASK) {
        raise_exception_err_ra(xenv, EXCP0D_GPF, selector & 0xfffc,
                               retaddr);
    }
}

static uint16_t ia32_supervisor_lduw(CPUX86State *xenv, vaddr addr,
                                     uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 2, MMU_DATA_LOAD, retaddr);
    return cpu_lduw_le_mmuidx_ra(env, addr, IA32_MMU_IDX(xenv), retaddr);
}

static uint32_t ia32_supervisor_ldl(CPUX86State *xenv, vaddr addr,
                                    uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 4, MMU_DATA_LOAD, retaddr);
    return cpu_ldl_le_mmuidx_ra(env, addr, IA32_MMU_IDX(xenv), retaddr);
}

static G_GNUC_UNUSED uint64_t ia32_supervisor_ldq(CPUX86State *xenv,
                                                   vaddr addr,
                                                   uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 8, MMU_DATA_LOAD, retaddr);
    return cpu_ldq_le_mmuidx_ra(env, addr, IA32_MMU_IDX(xenv), retaddr);
}

static G_GNUC_UNUSED void ia32_supervisor_stw(CPUX86State *xenv,
                                               vaddr addr, uint16_t value,
                                               uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 2, MMU_DATA_STORE, retaddr);
    cpu_stw_le_mmuidx_ra(env, addr, value, IA32_MMU_IDX(xenv), retaddr);
}

static void ia32_supervisor_stl(CPUX86State *xenv, vaddr addr,
                                uint32_t value, uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 4, MMU_DATA_STORE, retaddr);
    cpu_stl_le_mmuidx_ra(env, addr, value, IA32_MMU_IDX(xenv), retaddr);
}

static G_GNUC_UNUSED void ia32_supervisor_stq(CPUX86State *xenv,
                                               vaddr addr, uint64_t value,
                                               uintptr_t retaddr)
{
    CPUIA64State *env = IA32_ARCH_ENV(xenv);

    addr = (uint32_t)addr;
    ia32_supervisor_access_prepare(xenv, addr, 8, MMU_DATA_STORE, retaddr);
    cpu_stq_le_mmuidx_ra(env, addr, value, IA32_MMU_IDX(xenv), retaddr);
}

#undef cpu_lduw_kernel_ra
#undef cpu_ldl_kernel_ra
#undef cpu_ldq_kernel_ra
#undef cpu_stw_kernel_ra
#undef cpu_stl_kernel_ra
#undef cpu_stq_kernel_ra
#define cpu_lduw_kernel_ra(env, addr, ra) \
    ia32_supervisor_lduw((env), (addr), (ra))
#define cpu_ldl_kernel_ra(env, addr, ra) \
    ia32_supervisor_ldl((env), (addr), (ra))
#define cpu_ldq_kernel_ra(env, addr, ra) \
    ia32_supervisor_ldq((env), (addr), (ra))
#define cpu_stw_kernel_ra(env, addr, val, ra) \
    ia32_supervisor_stw((env), (addr), (val), (ra))
#define cpu_stl_kernel_ra(env, addr, val, ra) \
    ia32_supervisor_stl((env), (addr), (val), (ra))
#define cpu_stq_kernel_ra(env, addr, val, ra) \
    ia32_supervisor_stq((env), (addr), (val), (ra))

#define cpu_stw_le_mmuidx_ra(env, addr, val, idx, ra) \
    ia32_stack_stw((env), (addr), (val), (ra))
#define cpu_stl_le_mmuidx_ra(env, addr, val, idx, ra) \
    ia32_stack_stl((env), (addr), (val), (ra))
#define cpu_stq_le_mmuidx_ra(env, addr, val, idx, ra) \
    ia32_stack_stq((env), (addr), (val), (ra))
#define cpu_lduw_le_mmuidx_ra(env, addr, idx, ra) \
    ia32_stack_lduw((env), (addr), (ra))
#define cpu_ldl_le_mmuidx_ra(env, addr, idx, ra) \
    ia32_stack_ldl((env), (addr), (ra))
#define cpu_ldq_le_mmuidx_ra(env, addr, idx, ra) \
    ia32_stack_ldq((env), (addr), (ra))

#define cpu_lduw_le_data_ra(env, addr, ra) \
    ia32_stack_lduw((env), (addr), (ra))
#define cpu_ldl_le_data_ra(env, addr, ra) \
    ia32_stack_ldl((env), (addr), (ra))
#define probe_access(env, addr, size, type, idx, ra) \
    ia64_ia32_probe_access(IA32_ARCH_ENV(env), addr, size, type, \
                           IA32_MMU_IDX(env), ra)

/* Only CPUState identity is used by paths shared with ordinary x86 helpers. */
#define env_cpu(env) env_cpu(IA32_ARCH_ENV(env))
#define env_archcpu(env) ((X86CPU *)env_archcpu(IA32_ARCH_ENV(env)))
#define X86_IA32_GATE_INTERCEPT(env, selector, e1, e2, ident, next, ra) \
    ia64_ia32_gate_intercept((env), (selector), (e1), (e2),            \
                             (ident), (next), (ra))
#define X86_IA32_SYSTEM_DESCRIPTOR_CHECK(env, dt, selector, ra) \
    ia32_system_descriptor_check((env), (dt), (selector), (ra))
#define cpu_x86_load_seg_cache(env, seg, selector, base, limit, flags) \
    ia64_ia32_load_seg_cache((env), (seg), (selector), (base),         \
                             (limit), (flags))

#include "target/i386/tcg/seg_helper.c"
