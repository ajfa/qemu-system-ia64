/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 execution-engine access boundary (subset used by the IA-32
 * execution engine).
 */
#ifndef TARGET_IA64_EXEC_ACCESS_H
#define TARGET_IA64_EXEC_ACCESS_H

#include "cpu.h"
#include "exec/mmu-access-type.h"

bool ia64_exec_probe_writeback(CPUIA64State *env, uint64_t addr,
                               int size, MMUAccessType access_type,
                               uintptr_t ra);

#endif /* TARGET_IA64_EXEC_ACCESS_H */
