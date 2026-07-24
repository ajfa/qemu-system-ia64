/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TCG softmmu implementation of the IA-64 execution access boundary
 * (subset used by the IA-32 execution engine).
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec-access.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "exec/tlb-flags.h"

bool ia64_exec_probe_writeback(CPUIA64State *env, uint64_t addr,
                               int size, MMUAccessType access_type,
                               uintptr_t ra)
{
    CPUState *cs = env_cpu(env);
    int mmu_idx = cpu_mmu_index(cs, false);
    bool writeback = true;

    while (size > 0) {
        CPUTLBEntryFull *full;
        void *host;
        int page_offset = addr & ((1u << TARGET_PAGE_BITS) - 1);
        int page_left = (1u << TARGET_PAGE_BITS) - page_offset;
        int chunk = MIN(size, page_left);
        int flags = probe_access_full(env, addr, chunk, access_type,
                                      mmu_idx, false, &host, &full, ra);

        if (flags & TLB_WATCHPOINT) {
            cpu_check_watchpoint(cs, addr, chunk, full->attrs,
                                 BP_MEM_ACCESS, ra);
        }
        writeback &= full->extra.ia64.memory_attribute == IA64_PTE_MA_WB;
        addr += chunk;
        if (env->psr & IA64_PSR_IS) {
            addr = (uint32_t)addr;
        }
        size -= chunk;
    }
    return writeback;
}
