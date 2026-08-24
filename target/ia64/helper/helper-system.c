/* IA-64 TCG helper ABI adapters for system-register operations. */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "arch/arch.h"
#include "arch/system.h"

/*
 * Full-speed IP trace (debug facility).  When the environment variable
 * IA64_IPTRACE lists bundle IPs (comma-separated hex), the translator plants
 * a call to this helper on those bundles; it logs the IP and a general
 * register slice under -d int.  This is the way to observe deep firmware
 * boot states that the gdbstub cannot reach in reasonable time (a software
 * or hardware breakpoint slows the boot to POST 0x98 past several minutes).
 * Zero overhead when IA64_IPTRACE is unset.  Note bundle IPs are 16-byte
 * aligned; an objdump slot label like ...c9c is slot 2 of bundle ...c90.
 */
void helper_ia64_ip_trace(CPUIA64State *env)
{
    g_autoptr(GString) s = g_string_new(NULL);
    unsigned r;

    g_string_append_printf(s, "ia64-IPTRACE ip=%016" PRIx64 " b0=%016" PRIx64,
                           env->ip, env->br[IA64_BR_RETURN_LINK]);
    /* Return values (r8-r11), status/index (r28-r31), first stacked
     * registers (r32-r43) - the slice needed to follow firmware call
     * results and frame arguments. */
    for (r = 8; r <= 11; r++) {
        g_string_append_printf(s, " r%u=%016" PRIx64, r, env->gr[r]);
    }
    for (r = 28; r <= 43; r++) {
        g_string_append_printf(s, " r%u=%016" PRIx64, r, env->gr[r]);
    }
    qemu_log_mask(CPU_LOG_INT, "%s\n", s->str);
}

/*
 * Full-speed IA-32 IP trace (debug facility).  When IA32_IPTRACE=<hex> names an
 * x86 linear IP, the translator plants a call to this helper on every x86
 * instruction (X86_GEN_INSN_START); it keeps a ring of the most recent x86 IPs
 * and, the first time the trigger IP executes, dumps that history plus the x86
 * register file under -d int.  This is how to recover the control-flow path the
 * IA-32 engine took to reach an unexpected x86 address (for example the SDV
 * "Emult" BIOS falling into its guard HLT), which the fault-only trace
 * (-d ia32_fault) cannot show.  Zero overhead when IA32_IPTRACE is unset (the
 * helper is not planted).
 */
void helper_ia32_ip_trace(CPUIA64State *env)
{
    static uint32_t ring[1024];
    static unsigned pos;
    static uint32_t trigger;
    static bool trigger_read;
    static bool dumped;
    static unsigned post;      /* IA32_IPTRACE_POST: log this many IPs after hit */
    static bool post_read;
    static unsigned post_max;
    uint32_t ip = (uint32_t)env->ip;

    if (!trigger_read) {
        const char *e = getenv("IA32_IPTRACE");

        trigger = e ? (uint32_t)strtoul(e, NULL, 16) : 0;
        trigger_read = true;
    }
    if (!post_read) {
        const char *e = getenv("IA32_IPTRACE_POST");

        post_max = e ? (unsigned)strtoul(e, NULL, 0) : 0;
        post_read = true;
    }
    ring[pos++ & (ARRAY_SIZE(ring) - 1)] = ip;
    if (trigger && ip == trigger && !dumped) {
        g_autoptr(GString) s = g_string_new(NULL);
        unsigned n = pos < ARRAY_SIZE(ring) ? pos : ARRAY_SIZE(ring);
        unsigned i;

        dumped = true;
        post = post_max;
        g_string_append_printf(s,
            "ia32-IPTRACE hit ip=%08x eip=%08x cs.sel=%04x cs.base=%08x "
            "eax=%08x ecx=%08x edx=%08x ebx=%08x "
            "esp=%08x ebp=%08x esi=%08x edi=%08x; preceding %u x86 IPs:",
            ip, (uint32_t)env->ia32.eip,
            (unsigned)env->ia32.segs[R_CS].selector,
            (uint32_t)env->ia32.segs[R_CS].base,
            (uint32_t)env->ia32.regs[0], (uint32_t)env->ia32.regs[1],
            (uint32_t)env->ia32.regs[2], (uint32_t)env->ia32.regs[3],
            (uint32_t)env->ia32.regs[4], (uint32_t)env->ia32.regs[5],
            (uint32_t)env->ia32.regs[6], (uint32_t)env->ia32.regs[7], n);
        for (i = 0; i < n; i++) {
            unsigned idx = (pos - n + i) & (ARRAY_SIZE(ring) - 1);

            g_string_append_printf(s, "%s%08x",
                                   (i % 8) ? " " : "\n  ", ring[idx]);
        }
        qemu_log_mask(CPU_LOG_INT, "%s\n", s->str);
    } else if (dumped && post > 0) {
        post--;
        qemu_log_mask(CPU_LOG_INT,
            "ia32-IPTRACE post ip=%08x eip=%08x cs.base=%08x esp=%08x\n",
            ip, (uint32_t)env->ia32.eip,
            (uint32_t)env->ia32.segs[R_CS].base,
            (uint32_t)env->ia32.regs[4]);
    }
}

uint64_t helper_read_pr(CPUIA64State *env)
{
    return ia64_system_read_pr(env);
}

void helper_epc(CPUIA64State *env, uint64_t fault_ip, uint64_t raw,
                uint32_t fault_slot)
{
    ia64_system_epc(env, fault_ip, raw, fault_slot);
}

void helper_write_pr(CPUIA64State *env, uint64_t value, uint64_t mask)
{
    ia64_system_write_pr(env, value, mask);
}

uint64_t helper_read_ar(CPUIA64State *env, uint32_t ar_num)
{
    return ia64_system_read_ar(env, ar_num);
}

void helper_validate_ar_access(CPUIA64State *env, uint64_t value,
                               uint32_t ar_num, uint32_t write,
                               uint64_t fault_ip, uint64_t raw,
                               uint32_t slot)
{
    ia64_system_validate_ar_access(env, value, ar_num, write,
                                   fault_ip, raw, slot);
}

void helper_write_ar(CPUIA64State *env, uint32_t ar_num, uint64_t value)
{
    ia64_system_write_ar(env, ar_num, value);
}

uint64_t helper_read_cr(CPUIA64State *env, uint32_t cr_num)
{
    return ia64_system_read_cr(env, cr_num);
}

void helper_write_cr(CPUIA64State *env, uint32_t cr_num, uint64_t value)
{
    ia64_write_cr(env, cr_num, value);
}

uint64_t helper_validate_cr_access(CPUIA64State *env, uint64_t value,
                                   uint32_t cr_num, uint32_t write,
                                   uint64_t fault_ip, uint64_t raw,
                                   uint32_t slot)
{
    return ia64_system_validate_cr_access(env, value, cr_num, write,
                                          fault_ip, raw, slot);
}

uint64_t helper_read_cpuid(CPUIA64State *env, uint64_t index)
{
    return ia64_system_read_cpuid(env, index);
}

uint64_t helper_read_dahr_indexed(CPUIA64State *env, uint64_t index)
{
    return ia64_system_read_dahr_indexed(env, index);
}

uint64_t helper_read_msr(CPUIA64State *env, uint64_t index)
{
    return ia64_system_read_msr(env, index);
}

void helper_write_msr(CPUIA64State *env, uint64_t index, uint64_t value)
{
    ia64_system_write_msr(env, index, value);
}

uint64_t helper_read_dbr(CPUIA64State *env, uint32_t index)
{
    return ia64_system_read_dbr(env, index);
}

void helper_write_dbr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    ia64_system_write_dbr(env, index, value);
}

uint64_t helper_read_ibr(CPUIA64State *env, uint32_t index)
{
    return ia64_system_read_ibr(env, index);
}

void helper_write_ibr(CPUIA64State *env, uint32_t index, uint64_t value)
{
    ia64_system_write_ibr(env, index, value);
}

uint64_t helper_read_pmc(CPUIA64State *env, uint32_t index)
{
    return ia64_system_read_pmc(env, index);
}

void helper_write_pmc(CPUIA64State *env, uint32_t index, uint64_t value)
{
    ia64_system_write_pmc(env, index, value);
}

uint64_t helper_read_pmc_indexed(CPUIA64State *env, uint64_t index)
{
    return ia64_system_read_pmc_indexed(env, index);
}

void helper_write_pmc_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    ia64_system_write_pmc_indexed(env, index, value);
}

uint64_t helper_read_pmd(CPUIA64State *env, uint32_t index)
{
    return ia64_system_read_pmd(env, index);
}

uint64_t helper_read_pmd_checked(CPUIA64State *env, uint64_t index,
                                 uint64_t fault_ip, uint64_t raw,
                                 uint32_t slot)
{
    return ia64_system_read_pmd_checked(env, index, fault_ip, raw, slot);
}

void helper_write_pmd(CPUIA64State *env, uint32_t index, uint64_t value)
{
    ia64_system_write_pmd(env, index, value);
}

uint64_t helper_read_pmd_indexed(CPUIA64State *env, uint64_t index)
{
    return ia64_system_read_pmd_indexed(env, index);
}

void helper_write_pmd_indexed(CPUIA64State *env, uint64_t index,
                              uint64_t value)
{
    ia64_system_write_pmd_indexed(env, index, value);
}

void helper_st_spill_unat(CPUIA64State *env, uint32_t reg, uint64_t addr)
{
    ia64_system_st_spill_unat(env, reg, addr);
}

void helper_clear_psr_fault_suppression(CPUIA64State *env)
{
    ia64_system_clear_psr_fault_suppression(env);
}

void helper_set_psr_bn(CPUIA64State *env, uint32_t bank1)
{
    ia64_system_set_psr_bn(env, bank1);
}

void helper_ssm(CPUIA64State *env, uint64_t imm)
{
    ia64_system_ssm(env, imm);
}

void helper_rsm(CPUIA64State *env, uint64_t imm)
{
    ia64_system_rsm(env, imm);
}

uint64_t helper_mov_psrgr_read(CPUIA64State *env, uint32_t unused)
{
    return ia64_system_mov_psrgr_read(env, unused);
}

void helper_mov_psr_write(CPUIA64State *env, uint64_t value, uint32_t unused)
{
    ia64_system_mov_psr_write(env, value, unused);
}

uint64_t helper_mov_rrgr_read(CPUIA64State *env, uint64_t rr_addr)
{
    return ia64_system_mov_rrgr_read(env, rr_addr);
}

uint64_t helper_validate_rr_value(CPUIA64State *env, uint64_t value,
                                  uint64_t fault_ip, uint64_t raw,
                                  uint32_t slot)
{
    return ia64_system_validate_rr_value(env, value, fault_ip, raw, slot);
}

void helper_mov_grrr_write(CPUIA64State *env, uint64_t rr_addr,
                           uint64_t value)
{
    ia64_system_mov_grrr_write(env, rr_addr, value);
}

uint64_t helper_mov_pkrgr_read(CPUIA64State *env, uint32_t pkr_num)
{
    return ia64_system_mov_pkrgr_read(env, pkr_num);
}

uint64_t helper_mov_pkrgr_indexed_read(CPUIA64State *env, uint64_t pkr_num)
{
    return ia64_system_mov_pkrgr_indexed_read(env, pkr_num);
}

void helper_mov_grpkr_write(CPUIA64State *env, uint32_t pkr_num,
                            uint64_t value)
{
    ia64_system_mov_grpkr_write(env, pkr_num, value);
}

void helper_mov_grpkr_indexed_write(CPUIA64State *env, uint64_t pkr_num,
                                    uint64_t value)
{
    ia64_system_mov_grpkr_indexed_write(env, pkr_num, value);
}
