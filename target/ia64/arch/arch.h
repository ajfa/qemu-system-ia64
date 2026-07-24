/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Shim exposing the handful of IA-64 architecture entry points that the
 * ported IA-32 execution engine calls.  (On the upstream refactored tree
 * these live in a split arch/ subsystem; this fork keeps them in
 * op_helper.c / cpu.h.)
 */
#ifndef TARGET_IA64_ARCH_ARCH_H
#define TARGET_IA64_ARCH_ARCH_H

#include "cpu.h"

void ia64_gr_nat_set(CPUIA64State *env, uint32_t reg, bool nat);
bool ia64_data_address_to_phys(CPUIA64State *env, uint64_t va,
                               uint64_t *pa);
G_NORETURN void ia64_raise_disabled_isa_transition(CPUIA64State *env,
                                                   uint64_t fault_ip,
                                                   uint32_t fault_slot);
G_NORETURN void ia64_raise_exception(CPUIA64State *env, uint32_t exception,
                                     uint64_t fault_ip, uint64_t fault_imm,
                                     uint32_t fault_slot);

#endif /* TARGET_IA64_ARCH_ARCH_H */
