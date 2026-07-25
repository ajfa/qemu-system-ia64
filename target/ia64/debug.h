/* IA-64 debugger and state-dump integration. */

#ifndef TARGET_IA64_DEBUG_H
#define TARGET_IA64_DEBUG_H

#include "cpu.h"

#define IA64_GDB_NUM_CORE_REGS 462
#define IA64_STATE_SCHEMA_VERSION 1

/* NT debug-service break immediates (WSRV03 base/ntos/rtl/ia64). */
#define IA64_NT_BREAK_DEBUG_PRINT  0x80014ULL
#define IA64_NT_BREAK_DEBUG_PROMPT 0x80015ULL

void ia64_trace_interruption(CPUIA64State *env, uint32_t excp,
                             uint64_t vector, bool collect);
void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags);
int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *buf, int reg);
int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *buf, int reg);

#endif /* TARGET_IA64_DEBUG_H */
