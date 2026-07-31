/*
 * IA-64 TCG helper ABI adapters for packed integer operations.
 *
 * All of these are pure value functions (TCG_CALL_NO_RWG_SE): they take
 * operand values and return the result; the translator writes the
 * destination register through the normal GR path, which is what makes an
 * r0 destination a no-op instead of a write to the r0 global.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "arch/simd-ops.h"

uint64_t helper_simd_pavg(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_pavg_value(op_sel, a, b);
}

uint64_t helper_simd_pcmp(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_pcmp_value(op_sel, a, b);
}

uint64_t helper_simd_pminmax(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_pminmax_value(op_sel, a, b);
}

uint64_t helper_simd_pmpy(uint32_t op_sel, uint64_t a, uint64_t b,
                          uint32_t shift)
{
    return ia64_simd_pmpy_value(op_sel, a, b, shift);
}

uint64_t helper_simd_psad1(uint64_t a, uint64_t b)
{
    return ia64_simd_psad1_value(a, b);
}

uint64_t helper_simd_mux(uint32_t op_sel, uint64_t value, uint32_t imm)
{
    return ia64_simd_mux_value(op_sel, value, imm);
}

uint64_t helper_simd_mix(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_mix_value(op_sel, a, b);
}

uint64_t helper_simd_unpack(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_unpack_value(op_sel, a, b);
}

uint64_t helper_simd_pack(uint32_t op_sel, uint64_t a, uint64_t b)
{
    return ia64_simd_pack_value(op_sel, a, b);
}

uint64_t helper_simd_czx(uint32_t op_sel, uint64_t value)
{
    return ia64_simd_czx_value(op_sel, value);
}

uint64_t helper_simd_sum(uint64_t a, uint64_t b)
{
    return ia64_simd_sum_value(a, b);
}
