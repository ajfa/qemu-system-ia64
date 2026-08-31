/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 interruption tracing for -d ia64_fault.
 *
 * Kept out of arch/ deliberately: reading the guest's debug-print buffer
 * needs the memory-access APIs that architectural code must stay clear of.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "debug.h"
#include "exec/cpu-common.h"
#include "exec/target_page.h"
#include "system/memory.h"
#include "system/address-spaces.h"

/*
 * The fault classes that indicate broken guest code or an emulation bug.
 * Routine memory-management traffic (TLB/VHPT/paging/dirty/access/key),
 * external interrupts and lazy-FP switches are deliberately excluded so the
 * log stays small over a full OS boot (~16 KB across XP text setup).
 */
static const uint64_t ia64_trace_fault_classes =
    (1ULL << IA64_EXCP_BREAK) |
    (1ULL << IA64_EXCP_ILLEGAL) |
    (1ULL << IA64_EXCP_RESERVED_TEMPLATE) |
    (1ULL << IA64_EXCP_GENERAL) |
    (1ULL << IA64_EXCP_NAT_CONSUMPTION) |
    (1ULL << IA64_EXCP_UNALIGNED) |
    (1ULL << IA64_EXCP_UNIMPL_DATA_ADDR) |
    (1ULL << IA64_EXCP_UNIMPL_INST_ADDR) |
    (1ULL << IA64_EXCP_PRIVILEGED_OP) |
    (1ULL << IA64_EXCP_PRIVILEGED_REG) |
    (1ULL << IA64_EXCP_RESERVED_REG_FIELD) |
    (1ULL << IA64_EXCP_DISABLED_ISA_TRANSITION) |
    (1ULL << IA64_EXCP_UNSUPPORTED_DATA_REFERENCE) |
    (1ULL << IA64_EXCP_IA32_EXCEPTION) |
    (1ULL << IA64_EXCP_IA32_INTERCEPT) |
    (1ULL << IA64_EXCP_IA32_INTERRUPT);

/*
 * User-mode data faults that turn into a c0000005 access violation (a wild or
 * unmapped pointer): DTLB/alt-DTLB/data-access/NaT/key faults and general
 * exceptions taken at cpl 3.  Demand paging (page not present) is excluded.
 */
static const uint64_t ia64_trace_user_data_faults =
    (1ULL << IA64_EXCP_DTLB_FAULT) |
    (1ULL << IA64_EXCP_ALT_DTLB) |
    (1ULL << IA64_EXCP_DATA_ACCESS) |
    (1ULL << IA64_EXCP_GENERAL) |
    (1ULL << IA64_EXCP_NAT_CONSUMPTION) |
    (1ULL << IA64_EXCP_DATA_KEY_MISS) |
    (1ULL << IA64_EXCP_KEY_PERMISSION);

/*
 * Read the guest buffer behind an NT debug-print break.  The address is a
 * virtual one that may not be in the TLB (the debug page walker is TLB-only),
 * so translate it page by page with a full VHPT walk and fall back to the
 * TLB-based debug read, which covers a different subset of the mappings.
 */
static uint32_t ia64_trace_read_guest(CPUIA64State *env, uint64_t va,
                                      uint8_t *buf, uint32_t len)
{
    CPUState *cs = env_cpu(env);
    uint32_t got = 0;

    while (got < len) {
        uint64_t page_off = (va + got) & (TARGET_PAGE_SIZE - 1);
        uint32_t chunk = MIN(len - got,
                             TARGET_PAGE_SIZE - (uint32_t)page_off);
        uint64_t pa;

        if (!ia64_translate_data_access(env, va + got, false, &pa) ||
            address_space_read(&address_space_memory, pa,
                               MEMTXATTRS_UNSPECIFIED,
                               buf + got, chunk) != MEMTX_OK) {
            if (cpu_memory_rw_debug(cs, va + got, buf + got, chunk, false)) {
                break;
            }
        }
        got += chunk;
    }
    return got;
}

/*
 * NT's DebugPrint (break 0x80014) and DebugPrompt (break 0x80015, how a
 * checked-build RtlAssert reports a failed assertion) both pass the output
 * buffer address in t0/GR2 and its length in t1/GR3 (WSRV03
 * base/ntos/rtl/ia64/debugstb.s + regia64.h).  Surfacing the text turns an
 * anonymous crash-and-reboot into a readable error record.
 */
static void ia64_trace_debug_print(CPUIA64State *env)
{
    uint8_t buf[512];
    uint8_t out[sizeof(buf)];
    uint32_t len = env->gr[IA64_GR_NT_DEBUG_LENGTH] & 0xffff;
    uint64_t va = env->gr[IA64_GR_NT_DEBUG_BUFFER];
    uint32_t got;
    uint32_t n = 0;
    uint32_t i;

    len = MIN(len, (uint32_t)sizeof(buf) - 1);
    got = ia64_trace_read_guest(env, va, buf, len);
    if (got == 0) {
        return;
    }

    /*
     * Assertion text spans several lines and may carry embedded NULs, so
     * flatten the whole buffer onto one log line instead of printing it as a
     * C string.
     */
    for (i = 0; i < got; i++) {
        uint8_t c = buf[i];

        if (c == '\n' || c == '\r' || c == '\t' || c == 0) {
            c = ' ';
        } else if (c < 0x20 || c >= 0x7f) {
            c = '.';
        }
        if (c == ' ' && (n == 0 || out[n - 1] == ' ')) {
            continue;
        }
        out[n++] = c;
    }
    while (n > 0 && out[n - 1] == ' ') {
        n--;
    }
    out[n] = 0;
    qemu_log("IA64-%s %s\n",
             env->cr_iim == IA64_NT_BREAK_DEBUG_PROMPT ? "DBGPROMPT"
                                                       : "DBGPRINT",
             out);
}

void ia64_trace_interruption(CPUIA64State *env, uint32_t excp,
                             uint64_t vector, bool collect)
{
    unsigned fault_cpl;

    if (!qemu_loglevel_mask(CPU_LOG_IA64_FAULT) || excp >= 64) {
        return;
    }

    fault_cpl = ia64_psr_cpl(collect ? env->cr_ipsr : env->psr);

    if (fault_cpl == 3 && ((ia64_trace_user_data_faults >> excp) & 1)) {
        /*
         * Dedupe per (faulting IP, faulting page) so a hot address that
         * re-faults on every access (a spurious TLB/VHPT miss) collapses to
         * one line instead of thousands, while distinct first-touch faults
         * still each appear.  ps (from ITIR) and the VHPT hash address
         * distinguish a large-page or walker miss from ordinary demand
         * paging.  is=1 marks an IA-32-mode access.
         */
        static uint64_t seen[2048];
        unsigned ps = (env->cr_itir >> IA64_ITIR_PS_SHIFT) & 0x3f;
        uint64_t page = env->cr_ifa & ~((1ULL << (ps < 12 ? 12 : ps)) - 1);
        uint64_t key = env->cr_iip ^ (page << 1);
        unsigned h = (key >> 4) & (ARRAY_SIZE(seen) - 1);

        if (seen[h] != key) {
            seen[h] = key;
            qemu_log("IA64-AV excp=%u vector=0x%04" PRIx64 " is=%u"
                     " iip=0x%016" PRIx64 " ifa=0x%016" PRIx64
                     " ps=%u iha=0x%016" PRIx64 " isr=0x%016" PRIx64 "\n",
                     excp, vector, (env->psr & IA64_PSR_IS) ? 1u : 0u,
                     env->cr_iip, env->cr_ifa,
                     (unsigned)((env->cr_itir >> IA64_ITIR_PS_SHIFT) & 0x3f),
                     env->cr_iha, env->cr_isr);
        }
    }

    if ((ia64_trace_fault_classes >> excp) & 1) {
        /*
         * Bound the log for a fault that repeats, with two complementary
         * folds.  First, an unbroken run of the identical fault is collapsed
         * to one line plus a "repeated N times" count when the run ends, so a
         * wedged guest or the firmware's break.m 0x12345 debug probe stays
         * measurable rather than emitting millions of lines that fill the host
         * disk.  Second, a per-(iip,iim,excp) seen[] table then folds a fault
         * site that recurs *interleaved* with others - e.g. Linux's per-syscall
         * break 0x100000, which is never consecutive and so slips past the run
         * fold on its own.  Every distinct fault site is still reported on its
         * first occurrence.
         */
        static uint64_t last_key;
        static uint64_t run_length;
        static uint64_t seen[2048];
        uint64_t key = env->cr_iip ^ (env->cr_iim << 1) ^
                       ((uint64_t)excp << 56);
        unsigned h = (key >> 4) & (ARRAY_SIZE(seen) - 1);

        if (key == last_key) {
            run_length++;
            return;
        }
        if (run_length) {
            qemu_log("IA64-FAULT ... repeated %" PRIu64 " more times\n",
                     run_length);
            run_length = 0;
        }
        last_key = key;
        if (seen[h] == key) {
            return;
        }
        seen[h] = key;

        qemu_log("IA64-FAULT excp=%u vector=0x%04" PRIx64
                 " cpl=%u iip=0x%016" PRIx64 " iipa=0x%016" PRIx64
                 " ifa=0x%016" PRIx64 " iim=0x%016" PRIx64
                 " isr=0x%016" PRIx64 " ipsr=0x%016" PRIx64 "\n",
                 excp, vector, fault_cpl,
                 env->cr_iip, env->cr_iipa, env->cr_ifa,
                 env->cr_iim, env->cr_isr, env->cr_ipsr);

        if (excp == IA64_EXCP_BREAK &&
            (env->cr_iim == IA64_NT_BREAK_DEBUG_PRINT ||
             env->cr_iim == IA64_NT_BREAK_DEBUG_PROMPT)) {
            ia64_trace_debug_print(env);
        }
    }
}
