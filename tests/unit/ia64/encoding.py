#!/usr/bin/env python3
#
# IA-64 instruction encoders and architectural microprogram registry.
# Injects hand-encoded bundles with the generic loader and verifies state.

import re

from .runner import (Completion, ExpectedExit, MicroProgram, encode_bundles,
                     run_expected_exit, run_guest_panic_stop, run_microprogram)
from .fpmodel import (BINARY32_EDGE_VECTORS, BINARY64_EDGE_VECTORS,
                      binary32_to_spill, binary64_to_spill,
                      deterministic_words, fnorm_setf_sig,
                      spill_to_binary32, spill_to_binary64)
from .state import ExpectedBits, ExpectedFP, StateExpectation

IA64_EXCP_NONE = 0
IA64_EXCP_BREAK = 1
IA64_EXCP_ILLEGAL = 2
IA64_EXCP_RESERVED_TEMPLATE = 3
IA64_EXCP_ALT_DTLB = 8
IA64_EXCP_NAT_CONSUMPTION = 12
IA64_EXCP_UNALIGNED = 14
IA64_EXCP_PAGE_NOT_PRESENT = 15
IA64_EXCP_DATA_DIRTY = 17
IA64_EXCP_INST_ACCESS_BIT = 18
IA64_EXCP_DATA_ACCESS_BIT = 19
IA64_EXCP_INST_KEY_MISS = 20
IA64_EXCP_DATA_KEY_MISS = 21
IA64_EXCP_KEY_PERMISSION = 22
IA64_EXCP_UNIMPL_DATA_ADDR = 23
IA64_EXCP_UNIMPL_INST_ADDR = 24
IA64_EXCP_PRIVILEGED_OP = 25
IA64_EXCP_PRIVILEGED_REG = 26
IA64_EXCP_RESERVED_REG_FIELD = 27
IA64_EXCP_DISABLED_ISA_TRANSITION = 30
IA64_EXCP_DISABLED_FP = 31
IA64_EXCP_UNSUPPORTED_DATA_REFERENCE = 32
IA64_EXCP_VIRTUALIZATION = 33
IA64_ISR_X = 1 << 32
IA64_ISR_W = 1 << 33
IA64_ISR_R = 1 << 34
IA64_ISR_NA = 1 << 35
IA64_ISR_CODE_REG_NAT = 0x10
UINT64_MAX = (1 << 64) - 1
DEFAULT_FPSR = 0x0009804c0270033f
FPSR_SF0_SHIFT = 6
FPSR_SF1_SHIFT = 19
FPSR_SF2_SHIFT = 32
FPSR_SF_FLAGS_SHIFT = 7
FPSR_SF_D_FLAG = 0x02
FPSR_SF_TD = 0x40
FPSR_SF_RESERVED_PC1 = 0x04
IA64_ISR_SP = 1 << 36
IA64_ISR_RS = 1 << 37
IA64_ISR_IR = 1 << 38
IA64_ISR_NI = 1 << 39
IA64_ISR_EI_SHIFT = 41
IA64_ISR_ED = 1 << 43
IA64_DCR_PP = 1 << 0
IA64_DCR_BE = 1 << 1
IA64_DCR_DM = 1 << 8
IA64_DCR_DK = 1 << 10
IA64_DCR_DX = 1 << 11
IA64_DCR_DA = 1 << 13
IA64_PSR_BE = 1 << 1
IA64_PSR_UP = 1 << 2
IA64_PSR_AC = 1 << 3
IA64_PSR_MFL = 1 << 4
IA64_PSR_MFH = 1 << 5
IA64_PSR_IC = 1 << 13
IA64_PSR_I = 1 << 14
IA64_PSR_PK = 1 << 15
IA64_PSR_DT = 1 << 17
IA64_PSR_DFL = 1 << 18
IA64_PSR_DFH = 1 << 19
IA64_PSR_SP = 1 << 20
IA64_PSR_PP = 1 << 21
IA64_PSR_DI = 1 << 22
IA64_PSR_SI = 1 << 23
IA64_PSR_RT = 1 << 27
IA64_PSR_CPL3 = 3 << 32
IA64_PSR_IS = 1 << 34
IA64_PSR_MC = 1 << 35
IA64_PSR_IT = 1 << 36
IA64_PSR_ED = 1 << 43
IA64_PSR_BN = 1 << 44
IA64_PSR_VM = 1 << 46
IA64_PHYS_UC_BIT = 1 << 63
IA64_FW_IDENTITY_BASE = 0x100000
IA64_CR_ITM = 1
IA64_CR_SAPIC_IVR = 65
IA64_CR_SAPIC_TPR = 66
IA64_CR_SAPIC_EOI = 67
IA64_CR_SAPIC_IRR3 = 71
IA64_CR_ITV = 72
IA64_TPR_MMI = 1 << 16
IA64_VECTOR_MASKED = 1 << 16
IA64_RSC_PL3 = 3 << 2
IA64_RSC_BE = 1 << 4
IA64_BREAK_VECTOR = 0x2c00
IA64_DTLB_VECTOR = 0x0800
IA64_ALT_DTLB_VECTOR = 0x1000
IA64_DATA_NESTED_TLB_VECTOR = 0x1400
IA64_INST_KEY_MISS_VECTOR = 0x1800
IA64_DATA_KEY_MISS_VECTOR = 0x1c00
IA64_DATA_DIRTY_VECTOR = 0x2000
IA64_INST_ACCESS_BIT_VECTOR = 0x2400
IA64_DATA_ACCESS_BIT_VECTOR = 0x2800
IA64_PAGE_NOT_PRESENT_VECTOR = 0x5000
IA64_KEY_PERMISSION_VECTOR = 0x5100
IA64_INST_ACCESS_VECTOR = 0x5200
IA64_DATA_ACCESS_VECTOR = 0x5300
IA64_GENERAL_VECTOR = 0x5400
IA64_DISABLED_FP_VECTOR = 0x5500
IA64_NAT_CONSUMPTION_VECTOR = 0x5600
IA64_UNALIGNED_VECTOR = 0x5a00
IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR = 0x5b00
IA64_FP_FAULT_VECTOR = 0x5c00
IA64_FP_TRAP_VECTOR = 0x5d00
IA64_LOWER_PRIV_TRANSFER_VECTOR = 0x5e00
IA64_VIRTUALIZATION_VECTOR = 0x6100
IA64_GENEX_UNIMPL_DATA_ADDR = 43
IA64_GENEX_UNIMPL_INST_ADDR = 69
IA64_PKR_COUNT = 16
IA64_PKR_VALID = 1 << 0
IA64_PKR_WD = 1 << 1
IA64_PKR_RD = 1 << 2
IA64_PKR_XD = 1 << 3
# Per translation-register bank.  Both supported CPU models implement 64.
IA64_TR_COUNT = 64
IA64_TLB_MAX = 128
IA64_REGION_BITS = 3
IA64_IMPL_PA_BITS = 50
IA64_IMPL_VA_MSB = 60
IA64_IMPL_VA_BITS = IA64_IMPL_VA_MSB + 1 + IA64_REGION_BITS
IA64_PAL_IMPL_VA_MSB = IA64_IMPL_VA_MSB
LONG_VHPT_RID1_TAG = 1 << (IA64_IMPL_VA_MSB + 1 - 12)
LONG_VHPT_RID2_TAG = 2 << (IA64_IMPL_VA_MSB + 1 - 12)
LONG_VHPT_RID2_TAG_BYTE_SWAPPED = int.from_bytes(
    LONG_VHPT_RID2_TAG.to_bytes(8, "little"), "big")
IA64_FIRMWARE_IVT_BASE = 0x10000
PAL_PROC_ENTRY = 0x100060

PAL_CACHE_FLUSH = 0x0001
PAL_CACHE_INFO = 0x0002
PAL_CACHE_INIT = 0x0003
PAL_CACHE_SUMMARY = 0x0004
PAL_MEM_ATTRIB = 0x0005
PAL_PTCE_INFO = 0x0006
PAL_VM_INFO = 0x0007
PAL_VM_SUMMARY = 0x0008
PAL_BUS_GET_FEATURES = 0x0009
PAL_BUS_SET_FEATURES = 0x000A
PAL_DEBUG_INFO = 0x000B
PAL_FIXED_ADDR = 0x000C
PAL_FREQ_BASE = 0x000D
PAL_FREQ_RATIOS = 0x000E
PAL_PERF_MON_INFO = 0x000F
PAL_PLATFORM_ADDR = 0x0010
PAL_PROC_GET_FEATURES = 0x0011
PAL_PROC_SET_FEATURES = 0x0012
PAL_RSE_INFO = 0x0013
PAL_VERSION = 0x0014
PAL_MC_CLEAR_LOG = 0x0015
PAL_MC_DRAIN = 0x0016
PAL_MC_EXPECTED = 0x0017
PAL_MC_DYNAMIC_STATE = 0x0018
PAL_MC_ERROR_INFO = 0x0019
PAL_MC_RESUME = 0x001A
PAL_MC_REGISTER_MEM = 0x001B
PAL_HALT = 0x001C
PAL_HALT_LIGHT = 0x001D
PAL_COPY_INFO = 0x001E
PAL_CACHE_LINE_INIT = 0x001F
PAL_PMI_ENTRYPOINT = 0x0020
PAL_VM_PAGE_SIZE = 0x0022
PAL_MEM_FOR_TEST = 0x0025
PAL_CACHE_PROT_INFO = 0x0026
PAL_REGISTER_INFO = 0x0027
PAL_PREFETCH_VIS = 0x0029
PAL_LOGICAL_TO_PHYSICAL = 0x002A
PAL_CACHE_SHARED_INFO = 0x002B
PAL_COPY_PAL = 0x0100
PAL_HALT_INFO = 0x0101
PAL_TEST_PROC = 0x0102
PAL_VM_TR_READ = 0x0105
PAL_BRAND_INFO = 0x0112

PAL_VERSION_VALUE = ((2 << 40) | (0x23 << 32) | (1 << 24) |
                     (2 << 8) | 0x23)
PAL_INSERTABLE_PAGE_SIZE_MASK = ((1 << 12) | (1 << 13) | (1 << 14) |
                                 (1 << 16) | (1 << 18) | (1 << 20) |
                                 (1 << 22) | (1 << 24) | (1 << 26) |
                                 (1 << 28) | (1 << 30))
PAL_PURGE_PAGE_SIZE_MASK = PAL_INSERTABLE_PAGE_SIZE_MASK | (1 << 32)
PAL_VM_SUMMARY_INFO_1 = (1 | (IA64_IMPL_PA_BITS << 1) | (24 << 8) |
                         ((IA64_PKR_COUNT - 1) << 16) |
                         (8 << 24) | ((IA64_TR_COUNT - 1) << 32) |
                         ((IA64_TR_COUNT - 1) << 40) | (4 << 48) |
                         (2 << 56))
PAL_VM_SUMMARY_INFO_2 = IA64_PAL_IMPL_VA_MSB | (24 << 8)
# Merced reports 8 ITR / 48 DTR (248701-002 sec 2.5.6); only the max_itr/max_dtr
# fields (bits 32:39 and 40:47) differ from the default summary word.
IA64_MERCED_ITR_COUNT = 8
IA64_MERCED_DTR_COUNT = 48
PAL_VM_SUMMARY_INFO_1_MERCED = (1 | (IA64_IMPL_PA_BITS << 1) | (24 << 8) |
                                ((IA64_PKR_COUNT - 1) << 16) |
                                (8 << 24) |
                                ((IA64_MERCED_ITR_COUNT - 1) << 32) |
                                ((IA64_MERCED_DTR_COUNT - 1) << 40) |
                                (4 << 48) | (2 << 56))
PAL_RATIO_16_1 = (16 << 32) | 1
PAL_RATIO_16_3 = (16 << 32) | 3
PAL_RATIO_4_1 = (4 << 32) | 1
PAL_RATIO_4_3 = (4 << 32) | 3
PAL_RATIO_8_1 = (8 << 32) | 1
PAL_RATIO_2_1 = (2 << 32) | 1
PAL_MEM_ATTRIB_WB_UC = (1 << 0) | (1 << 4)
PAL_CACHE_INFO_L0_I_1 = ((4 << 8) | (6 << 16) |
                         (6 << 24) | (0xff << 32) | (1 << 40))
PAL_CACHE_INFO_L0_D_1 = ((4 << 8) | (6 << 16) |
                         (6 << 24) | (1 << 32) | (1 << 40))
PAL_CACHE_INFO_L0_2 = 16384 | (6 << 32) | (12 << 40) | (49 << 48)
PAL_CACHE_INFO_L1_I_1 = ((8 << 8) | (7 << 16) | (7 << 24) |
                         (0xff << 32) | (7 << 40))
PAL_CACHE_INFO_L1_I_2 = (1048576 | (7 << 32) | (17 << 40) | (49 << 48))
PAL_CACHE_INFO_L1_D_1 = ((1 << 1) | (8 << 8) | (7 << 16) |
                         (7 << 24) | (1 << 32) | (5 << 40))
PAL_CACHE_INFO_L1_D_2 = (262144 | (7 << 32) | (15 << 40) | (49 << 48))
PAL_CACHE_INFO_L2_U_1 = (1 | (1 << 1) | (12 << 8) | (7 << 16) |
                         (7 << 24) | (1 << 32) | (14 << 40))
PAL_CACHE_INFO_L2_U_2 = (12 * 1024 * 1024 | (7 << 32) | (20 << 40) |
                         (49 << 48))
PAL_VM_INFO_L0 = 1 | (32 << 8) | (32 << 16)
PAL_VM_INFO_L1 = (1 | (128 << 8) | (128 << 16) |
                  (1 << 32) | (1 << 34))
PAL_CACHE_PROT_DATA_NONE = 64
PAL_CACHE_PROT_TAG_NONE_L0 = (1 << 30) | (12 << 8) | (49 << 14)
PAL_PLATFORM_INTERRUPT_BLOCK = 0
PAL_PLATFORM_IO_BLOCK = 1
PAL_INTERRUPT_BLOCK_DEFAULT = 0xfee00000
PAL_IO_BLOCK_DEFAULT = 0x80000c000000
PAL_TR_VALID_ALL = 0xf
PAL_TR_TEST_PTE = 0x4009661
PAL_TR_TEST_ITIR = 12 << 2
PAL_TR_TEST_IFA = 0x8001
PAL_VIRTUAL_CODE_BASE = 0xe0000000d0000000
PAL_VIRTUAL_CODE_PA = 0x04000000
PAL_VIRTUAL_CODE_ENTRY = PAL_VIRTUAL_CODE_BASE + 0x200
PAL_VIRTUAL_CODE_ENTRY_PA = PAL_VIRTUAL_CODE_PA + 0x200
PAL_VIRTUAL_PROC_BASE = 0xe0000000e0000000
PAL_VIRTUAL_PROC_ENTRY = PAL_VIRTUAL_PROC_BASE + 0x60
PAL_VIRTUAL_ITIR = 14 << 2
PAL_VIRTUAL_RR = (1 << 8) | PAL_VIRTUAL_ITIR
PAL_VIRTUAL_CODE_PTE = 0x0010000004000661
PAL_VIRTUAL_PROC_PTE = 0x0010000000100661
PAL_VIRTUAL_PSR = (1 << 13) | (1 << 36)
PAL_COPY_BUFFER_SIZE = 0x1000
PAL_COPY_BUFFER_ALIGN = 0x1000
PAL_COPY_TARGET = 0x4000
PAL_AR_IMPLEMENTED_LOW = 0x000011117f2f00ff
PAL_AR_IMPLEMENTED_HIGH = 0x7
PAL_CR_IMPLEMENTED_LOW = 0x0000000003fb0107
PAL_CR_IMPLEMENTED_HIGH = 0x307ff
PAL_CR_READ_SIDE_EFFECT_HIGH = 0x2
PAL_PERF_BUFFER = 0x3000
PAL_HALT_INFO_BUFFER = 0x3800
PAL_BRAND_BUFFER = 0x3900
PAL_HALT_LIGHT_INFO = ((1 << 61) | (1 << 60) | (1000 << 32) |
                       (1 << 16) | 1)
PAL_HALT_STATE1_INFO = ((1 << 60) | (1000 << 32) | (1 << 16) | 1)
PAL_SELF_TEST_STATE_TESTED = 1 << 2
IA64_ITC_TICKS_PER_MILLISECOND = 200000

def bitfield(value, low, width):
    return (value & ((1 << width) - 1)) << low

def op(major):
    return bitfield(major, 37, 4)

def nop_m():
    return bitfield(1, 27, 4)

def break_m(imm=0, qp=0):
    return (
        bitfield(imm & 0xfffff, 6, 20)
        | bitfield((imm >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def illegal_m():
    return (
        nop_m() & ~((1 << 41) - 1)
        | bitfield(0xf, 37, 4)
        | bitfield(0x3f, 27, 6)
        | bitfield(0x3f, 30, 6)
    )

def adds(r1, imm, r3, qp=0):
    encoded = imm & 0x3fff
    return (
        op(8)
        | bitfield(2, 34, 2)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield((encoded >> 7) & 0x3f, 27, 6)
        | bitfield((encoded >> 13) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def addl(r1, imm, r3, qp=0):
    if not 0 <= r3 < 4:
        raise ValueError("addl base must be a static general register r0-r3")
    encoded = imm & 0x3FFFFF
    return (
        op(9)
        | bitfield((encoded >> 21) & 1, 36, 1)
        | bitfield((encoded >> 7) & 0x1FF, 27, 9)
        | bitfield((encoded >> 16) & 0x1F, 22, 5)
        | bitfield(r3, 20, 2)
        | bitfield(encoded & 0x7F, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def alu_reg(x4, x2b, r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(x4, 29, 4)
        | bitfield(x2b, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def add(r1, r2, r3, qp=0):
    return alu_reg(0x0, 0x0, r1, r2, r3, qp)

def add_one(r1, r2, r3, qp=0):
    return alu_reg(0x0, 0x1, r1, r2, r3, qp)

def sub_reg(r1, r2, r3, qp=0):
    return alu_reg(0x1, 0x1, r1, r2, r3, qp)

def or_reg(r1, r2, r3, qp=0):
    return alu_reg(0x3, 0x2, r1, r2, r3, qp)

def movl_mlx(r1, imm64, qp=0):
    imm64 &= 0xffffffffffffffff
    imm7b = imm64 & 0x7f
    imm9d = (imm64 >> 7) & 0x1ff
    imm5c = (imm64 >> 16) & 0x1f
    ic = (imm64 >> 21) & 1
    imm41 = (imm64 >> 22) & 0x1ffffffffff
    i = (imm64 >> 63) & 1
    l_slot = imm41
    x_slot = (
        op(6)
        | bitfield(i, 36, 1)
        | bitfield(imm9d, 27, 9)
        | bitfield(imm5c, 22, 5)
        | bitfield(ic, 21, 1)
        | bitfield(imm7b, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )
    return (0x04, nop_m(), l_slot, x_slot)

def break_x_mlx(imm62, qp=0):
    imm62 &= (1 << 62) - 1
    imm21 = imm62 & 0x1fffff
    l_slot = imm62 >> 21
    x_slot = (
        bitfield(imm21 & 0xfffff, 6, 20)
        | bitfield((imm21 >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )
    return (0x04, nop_m(), l_slot, x_slot)

def nop_x_mlx(imm62, qp=0):
    imm62 &= (1 << 62) - 1
    imm21 = imm62 & 0x1fffff
    l_slot = imm62 >> 21
    x_slot = (
        bitfield(1, 27, 6)
        | bitfield(imm21 & 0xfffff, 6, 20)
        | bitfield((imm21 >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )
    return (0x04, nop_m(), l_slot, x_slot)

def hint_x_mlx(imm62, qp=0):
    imm62 &= (1 << 62) - 1
    imm21 = imm62 & 0x1fffff
    l_slot = imm62 >> 21
    x_slot = (
        bitfield(1, 27, 6)
        | bitfield(1, 26, 1)
        | bitfield(imm21 & 0xfffff, 6, 20)
        | bitfield((imm21 >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )
    return (0x04, nop_m(), l_slot, x_slot)

def nop_i():
    return bitfield(1, 27, 6)

def nop_b():
    return op(2)

def nop_x(qp=0):
    return bitfield(1, 27, 6) | bitfield(qp, 0, 6)

def break_b():
    return 0

def break_f(imm=0, qp=0):
    return (
        bitfield(imm & 0xfffff, 6, 20)
        | bitfield((imm >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def nop_f(imm=0, qp=0):
    return (
        bitfield(1, 27, 6)
        | bitfield(imm & 0xfffff, 6, 20)
        | bitfield((imm >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def clrrrb_b(qp=0, ignored=0):
    return EndGroupInsn(
        0x20000000 | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6))

def clrrrb_pr_b(qp=0, ignored=0):
    return EndGroupInsn(
        0x28000000 | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6))

def pal_break(qp=0):
    return break_m(0x100000, qp)

def pal_call_program(index, args=()):
    program = [
        (0x10, 0x00, nop_m(), addl(28, index, 0), nop_i()),
    ]
    addr = 0x20
    for reg, value in args:
        signed_value = value if value < (1 << 63) else value - (1 << 64)
        if -(1 << 21) <= signed_value < (1 << 21):
            program.append((addr, 0x00, nop_m(), addl(reg, value, 0),
                            nop_i()))
        else:
            program.append((addr, *movl_mlx(reg, value)))
        addr += 0x10
    program += [
        (addr, 0x10, nop_m(), nop_i(), br_call(0, addr, PAL_PROC_ENTRY)),
        (addr + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(addr + 0x10, addr + 0x10)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ]
    return program

def pal_stacked_call_program(index, args=()):
    values = [0, 0, 0]
    for arg, value in enumerate(args[:3]):
        values[arg] = value

    return [
        (0x10, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
        (0x20, *movl_mlx(28, index)),
        (0x30, *movl_mlx(32, index)),
        (0x40, *movl_mlx(33, values[0])),
        (0x50, *movl_mlx(34, values[1])),
        (0x60, *movl_mlx(35, values[2])),
        (0x70, 0x10, nop_m(), nop_i(), br_call(0, 0x70, PAL_PROC_ENTRY)),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x80)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ]

def br_call(b1, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(5)
        | bitfield(b1, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_call_indirect(b1, b2, wh=1, many=False, clear=False, ignored=0, bit36=0,
                     qp=0):
    return (
        op(1)
        | bitfield(b1, 6, 3)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(b2, 13, 3)
        | bitfield(ignored, 16, 16)
        | bitfield(wh, 32, 3)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(bit36, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_indirect(b2, btype=0, wh=0, many=False, clear=False, bit36=0, qp=0):
    return (
        bitfield(0x20, 27, 6)
        | bitfield(b2, 13, 3)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(btype, 6, 3)
        | bitfield(wh, 33, 2)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(bit36, 36, 1)
        | bitfield(qp, 0, 6)
    )

def ip_relative_branch_btype(btype, source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(btype, 6, 3)
        | bitfield(qp, 0, 6)
    )

def mov_br_gr(b1, r2, qp=0):
    return (
        bitfield(b1, 6, 3)
        | bitfield(r2, 13, 7)
        | bitfield(7, 33, 3)
        | bitfield(qp, 0, 6)
    )

def br_ret(b2, qp=0):
    return bitfield(0x21, 27, 6) | bitfield(4, 6, 3) | bitfield(b2, 13, 3) | bitfield(qp, 0, 6)

def rfi_b(qp=0):
    return EndGroupInsn(
        bitfield(0x08, 27, 6) | bitfield(qp, 0, 6))

def rfi_to_gr(address, psr_reg, target_reg):
    """Install a full PSR and resume at the IIP held in target_reg."""
    return [
        (address, 0x09, mov_m_gr_cr(psr_reg, 16),
         mov_m_gr_cr(target_reg, 19), nop_i()),
        (address + 0x10, 0x11, nop_m(), nop_i(), rfi_b()),
    ]

def epc_b(qp=0, ignored=0):
    return bitfield(0x10, 27, 6) | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6)

def mov_ar(r1, ar_num, qp=0):
    return (op(1) | bitfield(0x2a, 27, 6)
            | bitfield(ar_num, 20, 7) | bitfield(r1, 13, 7)
            | bitfield(qp, 0, 6))

class MUnitAlloc(int):
    pass


class IUnitInsn(int):
    pass


class StartGroupInsn(int):
    pass


class EndGroupInsn(int):
    pass


def alloc(r1, sof, sol, sor, rrb, qp=0):
    return MUnitAlloc(alloc_m(r1, sof, sol, sor, rrb, qp))

def alloc_m(r1, sof, sol, sor, rrb, qp=0, ignored31=0, ignored36=0):
    return (
        op(1)
        | bitfield(6, 33, 3)
        | bitfield(sof & 0x7f, 13, 7)
        | bitfield(sol & 0x7f, 20, 7)
        | bitfield(sor & 0x0f, 27, 4)
        | bitfield(ignored31, 31, 1)
        | bitfield(rrb & 0x01, 32, 1)
        | bitfield(ignored36, 36, 1)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mov_ar_lc(r1, qp=0):
    return bitfield(0x32, 27, 6) | bitfield(65, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_i_ar_gr(r1, ar_num, qp=0):
    return bitfield(0x32, 27, 6) | bitfield(ar_num, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_lc_gr(r2, qp=0):
    return bitfield(0x2a, 27, 6) | bitfield(65, 20, 7) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def mov_lc_imm(imm, qp=0):
    encoded = imm & 0xff
    return (
        bitfield(0x0a, 27, 6)
        | bitfield(65, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(encoded >> 7, 36, 1)
        | bitfield(qp, 0, 6)
    )

def mov_pr_rot_imm(value, qp=0):
    encoded = (value >> 16) & 0x0fffffff
    return (
        bitfield(1, 34, 2)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield((encoded >> 7) & 0x7f, 13, 7)
        | bitfield((encoded >> 14) & 0x0f, 20, 4)
        | bitfield((encoded >> 18) & 0xff, 24, 8)
        | bitfield((encoded >> 26) & 1, 32, 1)
        | bitfield((encoded >> 27) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def mov_m_imm_ar(ar_num, imm, qp=0):
    encoded = imm & 0xff
    if ar_num in (64, 65, 66):
        return IUnitInsn(
            bitfield(0x0a, 27, 6)
            | bitfield(ar_num, 20, 7)
            | bitfield(encoded & 0x7f, 13, 7)
            | bitfield(encoded >> 7, 36, 1)
            | bitfield(qp, 0, 6)
        )
    return (
        bitfield(0x28, 27, 6)
        | bitfield(ar_num, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(encoded >> 7, 36, 1)
        | bitfield(qp, 0, 6)
    )

def mov_i_imm_ar(ar_num, imm, qp=0):
    encoded = imm & 0xff
    return (
        bitfield(0x0a, 27, 6)
        | bitfield(ar_num, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(encoded >> 7, 36, 1)
        | bitfield(qp, 0, 6)
    )

def mov_m_gr_ar(r2, ar_num, qp=0):
    if ar_num in (64, 65, 66):
        return IUnitInsn(
            bitfield(0x2a, 27, 6)
            | bitfield(ar_num, 20, 7)
            | bitfield(r2, 13, 7)
            | bitfield(qp, 0, 6)
        )
    return op(1) | bitfield(0x2a, 27, 6) | bitfield(ar_num, 20, 7) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def mov_m_ar_gr(r1, ar_num, qp=0):
    if ar_num in (64, 65, 66):
        return IUnitInsn(
            bitfield(0x32, 27, 6)
            | bitfield(ar_num, 20, 7)
            | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6)
        )
    return op(1) | bitfield(0x22, 27, 6) | bitfield(ar_num, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_m_psr_gr(r1, qp=0):
    return op(1) | bitfield(0x25, 27, 6) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_m_gr_psrl(r2, qp=0):
    return op(1) | bitfield(0x2d, 27, 6) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def mov_m_psr_um_gr(r1, qp=0):
    return op(1) | bitfield(0x21, 27, 6) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_m_gr_psr_um(r2, qp=0):
    return op(1) | bitfield(0x29, 27, 6) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def mov_gr_psr_full(r1, qp=0):
    return (
        op(1)
        | bitfield(0x2d, 27, 6)
        | bitfield(r1, 13, 7)
        | bitfield(qp, 0, 6)
    )

def mov_m_cr_gr(r1, cr_num, qp=0):
    return op(1) | bitfield(0x24, 27, 6) | bitfield(cr_num, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_m_gr_cr(r2, cr_num, qp=0):
    return op(1) | bitfield(0x2c, 27, 6) | bitfield(cr_num, 20, 7) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def mov_dbr_indexed_read(r1, index_reg, bit36=0, qp=0):
    return op(1) | bitfield(bit36, 36, 1) | bitfield(0x11, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_dbr_indexed_write(index_reg, value_reg, qp=0):
    return op(1) | bitfield(0x01, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(value_reg, 13, 7) | bitfield(qp, 0, 6)

def mov_ibr_indexed_read(r1, index_reg, bit36=0, qp=0):
    return op(1) | bitfield(bit36, 36, 1) | bitfield(0x12, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def mov_ibr_indexed_write(index_reg, value_reg, qp=0):
    return op(1) | bitfield(0x02, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(value_reg, 13, 7) | bitfield(qp, 0, 6)

def mov_pkr_indexed(index_reg, value_reg, qp=0, bit36=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x03, 27, 6)
        | bitfield(index_reg, 20, 7)
        | bitfield(value_reg, 13, 7)
        | bitfield(qp, 0, 6)
    )

def mov_pkr_indexed_read(r1, index_reg, bit36=0, qp=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x13, 27, 6)
        | bitfield(index_reg, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def load_mem(x6, r1, r3, qp=0):
    return op(4) | bitfield(x6, 30, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def load_mem_reg_postinc(x6, r1, r3, r2, qp=0):
    return (
        op(4)
        | bitfield(1, 36, 1)
        | bitfield(x6, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def load_mem_postinc(x6, r1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(x6, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld1(r1, r3, qp=0):
    return load_mem(0x00, r1, r3, qp)

def ld2(r1, r3, qp=0):
    return load_mem(0x01, r1, r3, qp)

def ld2_s(r1, r3, qp=0):
    return load_mem(0x05, r1, r3, qp)

def ld2_bias(r1, r3, qp=0):
    return load_mem(0x11, r1, r3, qp)

def ld4(r1, r3, qp=0):
    return load_mem(0x02, r1, r3, qp)

def ld4_postinc(r1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x02, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld8(r1, r3, qp=0):
    return load_mem(0x03, r1, r3, qp)

def ld16(r1, r3, qp=0):
    return (
        op(4)
        | bitfield(0x28, 30, 6)
        | bitfield(1, 27, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld16_acq(r1, r3, qp=0, hint=0):
    return (
        op(4)
        | bitfield(0x2c, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(1, 27, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld8_s(r1, r3, qp=0):
    return load_mem(0x07, r1, r3, qp)

def ld8_s_hint(r1, r3, hint, qp=0):
    return ld8_s(r1, r3, qp) | bitfield(hint, 28, 2)

def ld8_postinc(r1, r3, imm, hint=0, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x03, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld8_s_postinc(r1, r3, imm, hint=0, qp=0):
    return ld8_postinc(r1, r3, imm, hint, qp) | bitfield(0x07, 30, 6)

def ld2_c_clr_reg_update(r1, r3, r2, hint=0, qp=0):
    return (
        op(4)
        | bitfield(0x21, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld8_fill_postinc(r1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x1b, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldf8(f1, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(0x01, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldfs(f1, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(0x02, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldfd(f1, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(0x03, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldfps(f1, f2, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(0x02, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(1, 27, 1)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldfe(f1, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(hint, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldf8_s(f1, r3, hint=0, qp=0):
    return ldf8(f1, r3, hint, qp) | bitfield(0x05, 30, 6)

def ldf8_a(f1, r3, hint=0, qp=0):
    return ldf8(f1, r3, hint, qp) | bitfield(0x09, 30, 6)

def ldf8_sa(f1, r3, hint=0, qp=0):
    return ldf8(f1, r3, hint, qp) | bitfield(0x0d, 30, 6)

def ldf8_c_nc(f1, r3, hint=0, qp=0):
    return ldf8(f1, r3, hint, qp) | bitfield(0x25, 30, 6)

def ldfp8_postinc(f1, f2, r3, hint=0, qp=0):
    return (
        op(6)
        | bitfield(1, 36, 1)
        | bitfield(0x01, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(1, 27, 1)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ldf_fill_postinc(f1, r3, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(0x1b, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def store_mem(x6, r3, r2, qp=0):
    return op(4) | bitfield(x6, 30, 6) | bitfield(r3, 20, 7) | bitfield(r2, 13, 7) | bitfield(qp, 0, 6)

def st2(r3, r2, qp=0):
    return store_mem(0x31, r3, r2, qp)

def st4(r3, r2, qp=0):
    return store_mem(0x32, r3, r2, qp)

def st4_rel(r3, r2, qp=0):
    return store_mem(0x36, r3, r2, qp)

def store_mem_postinc(x6, r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(x6, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def st4_postinc(r3, r2, imm, qp=0):
    return store_mem_postinc(0x32, r3, r2, imm, qp)

def cmpxchg4(r1, r3, r2, qp=0):
    return (
        op(2)
        | bitfield(3, 29, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def cmpxchg_acq(size_log2, r1, r3, r2, qp=0, hint=0):
    return (
        op(4)
        | bitfield(1, 27, 1)
        | bitfield(hint, 28, 2)
        | bitfield(size_log2 & 1, 30, 1)
        | bitfield(size_log2 >> 1, 31, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def cmpxchg4_acq(r1, r3, r2, qp=0):
    return cmpxchg_acq(2, r1, r3, r2, qp)

def cmpxchg_rel(size_log2, r1, r3, r2, qp=0, hint=0):
    return cmpxchg_acq(size_log2, r1, r3, r2, qp, hint) | bitfield(1, 32, 1)

def cmp8xchg16_acq(r1, r3, r2, qp=0, hint=0):
    return (
        op(4)
        | bitfield(1, 27, 1)
        | bitfield(hint, 28, 2)
        | bitfield(0x20, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def cmp8xchg16_rel(r1, r3, r2, qp=0, hint=0):
    return cmp8xchg16_acq(r1, r3, r2, qp, hint) | bitfield(1, 32, 1)

def xchg(size_log2, r1, r3, r2, qp=0, hint=0):
    return (
        op(4)
        | bitfield(1, 27, 1)
        | bitfield(hint, 28, 2)
        | bitfield(size_log2 & 1, 30, 1)
        | bitfield(size_log2 >> 1, 31, 1)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def xchg4(r1, r3, r2, qp=0):
    return xchg(2, r1, r3, r2, qp)

def andcm_imm(r1, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(8)
        | bitfield(0xb, 29, 4)
        | bitfield(1, 27, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def st8(r3, r2, qp=0):
    return store_mem(0x33, r3, r2, qp)

def st8_postinc(r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x33, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def st8_rel(r3, r2, qp=0):
    return store_mem(0x37, r3, r2, qp)

def st16(r3, r2, x6=0x01, ignored=0, qp=0):
    return (
        op(4)
        | bitfield(6, 33, 3)
        | bitfield(x6, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(ignored, 6, 7)
        | bitfield(qp, 0, 6)
    )

def st8_spill_postinc(r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x3b, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def czx(opcode, r1, r3, qp=0):
    return bitfield(opcode, 27, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def czx1_l(r1, r3, qp=0):
    return czx(0x18, r1, r3, qp)

def czx1_r(r1, r3, qp=0):
    return czx(0x1c, r1, r3, qp)

def czx2_l(r1, r3, qp=0):
    return czx(0x19, r1, r3, qp)

def czx2_r(r1, r3, qp=0):
    return czx(0x1d, r1, r3, qp)

def mix(x6, x3, z, r1, r2, r3, qp=0, ignored=0):
    return (
        op(7)
        | bitfield(x6, 27, 6)
        | bitfield(ignored, 27, 1)
        | bitfield(x3, 33, 3)
        | bitfield(z, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mix4_r(r1, r2, r3, qp=0):
    return mix(0x10, 4, 1, r1, r2, r3, qp)

def mix4_l(r1, r2, r3, qp=0):
    return mix(0x14, 4, 1, r1, r2, r3, qp)

def mix2_r(r1, r2, r3, qp=0):
    return mix(0x10, 5, 0, r1, r2, r3, qp)

def mix2_l(r1, r2, r3, qp=0):
    return mix(0x14, 5, 0, r1, r2, r3, qp)

def mix1_r(r1, r2, r3, qp=0, ignored=0):
    return mix(0x10, 4, 0, r1, r2, r3, qp, ignored)

def mix1_l(r1, r2, r3, qp=0, ignored=0):
    return mix(0x14, 4, 0, r1, r2, r3, qp, ignored)

def unpack(size, low, r1, r2, r3, qp=0):
    fields = {
        1: (0, 0),
        2: (0, 1),
        4: (1, 0),
    }
    za, zb = fields[size]
    return (
        op(7)
        | bitfield(za, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(1, 30, 2)
        | bitfield(2 if low else 0, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def unpack2_l(r1, r2, r3, qp=0):
    return unpack(2, True, r1, r2, r3, qp)

def unpack1_h(r1, r2, r3, qp=0):
    return unpack(1, False, r1, r2, r3, qp)

def unpack1_l(r1, r2, r3, qp=0):
    return unpack(1, True, r1, r2, r3, qp)

def unpack2_h(r1, r2, r3, qp=0):
    return unpack(2, False, r1, r2, r3, qp)

def unpack4_h(r1, r2, r3, qp=0):
    return unpack(4, False, r1, r2, r3, qp)

def unpack4_l(r1, r2, r3, qp=0):
    return unpack(4, True, r1, r2, r3, qp)

def mov_rr_write(value_reg, addr_reg, qp=0, ignored36=0):
    return (op(1) | bitfield(ignored36, 36, 1) | bitfield(addr_reg, 20, 7)
            | bitfield(value_reg, 13, 7) | bitfield(qp, 0, 6))

def mov_rr_read(dest_reg, addr_reg, qp=0, ignored36=0):
    return (op(1) | bitfield(ignored36, 36, 1) | bitfield(0x10, 27, 6)
            | bitfield(addr_reg, 20, 7) | bitfield(dest_reg, 6, 7)
            | bitfield(qp, 0, 6))

def mov_cpuid(r1, index_reg, qp=0, bit36=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x17, 27, 6)
            | bitfield(index_reg, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def mov_dahr_read(r1, index_reg, qp=0, bit36=0, ignored=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x20, 27, 6)
            | bitfield(index_reg, 20, 7) | bitfield(ignored, 13, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))

def mov_msr_read(r1, index_reg, qp=0, bit36=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x16, 27, 6)
            | bitfield(index_reg, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def mov_msr_write(index_reg, value_reg, qp=0, bit36=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x06, 27, 6)
            | bitfield(index_reg, 20, 7) | bitfield(value_reg, 13, 7)
            | bitfield(qp, 0, 6))

def itr_i(index_reg, source_reg, qp=0):
    return op(1) | bitfield(0x0f, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(source_reg, 13, 7) | bitfield(qp, 0, 6)

def itr_d(index_reg, source_reg, bit36=0, qp=0):
    return op(1) | bitfield(bit36, 36, 1) | bitfield(0x0e, 27, 6) | bitfield(index_reg, 20, 7) | bitfield(source_reg, 13, 7) | bitfield(qp, 0, 6)

def itc_d(source_reg, qp=0):
    return EndGroupInsn(
        op(1) | bitfield(0x2e, 27, 6) | bitfield(source_reg, 13, 7)
        | bitfield(qp, 0, 6))

def itc_i(source_reg, qp=0):
    return EndGroupInsn(
        op(1) | bitfield(0x2f, 27, 6) | bitfield(source_reg, 13, 7)
        | bitfield(qp, 0, 6))

def ptc_l(addr_reg, size_reg, qp=0):
    return op(1) | bitfield(0x09, 27, 6) | bitfield(addr_reg, 20, 7) | bitfield(size_reg, 13, 7) | bitfield(qp, 0, 6)

def ptc_e(addr_reg, qp=0):
    return op(1) | bitfield(0x34, 27, 6) | bitfield(addr_reg, 20, 7) | bitfield(qp, 0, 6)

def ptr_op(x6, addr_reg, size_reg, qp=0, alt=False):
    prefix = op(1) if alt else 0
    return prefix | bitfield(x6, 27, 6) | bitfield(addr_reg, 20, 7) | bitfield(size_reg, 13, 7) | bitfield(qp, 0, 6)

def ptr_d(addr_reg, size_reg, qp=0):
    return ptr_op(0x0c, addr_reg, size_reg, qp, alt=True)

def ptr_i(addr_reg, size_reg, qp=0):
    return ptr_op(0x0d, addr_reg, size_reg, qp, alt=True)

def ptr_d_alt(addr_reg, size_reg, qp=0):
    return ptr_op(0x0c, addr_reg, size_reg, qp, alt=True)

def ptr_i_alt(addr_reg, size_reg, qp=0):
    return ptr_op(0x0d, addr_reg, size_reg, qp, alt=True)

def tpa(dest_reg, source_reg, qp=0, bit36=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x1e, 27, 6)
            | bitfield(source_reg, 20, 7) | bitfield(dest_reg, 6, 7)
            | bitfield(qp, 0, 6))

def tak(dest_reg, source_reg, qp=0, bit36=0, ignored=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x1f, 27, 6)
            | bitfield(source_reg, 20, 7) | bitfield(ignored, 13, 7)
            | bitfield(dest_reg, 6, 7) | bitfield(qp, 0, 6))

def thash(dest_reg, source_reg, qp=0, bit36=0, ignored=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x1a, 27, 6)
            | bitfield(source_reg, 20, 7) | bitfield(ignored, 13, 7)
            | bitfield(dest_reg, 6, 7) | bitfield(qp, 0, 6))

def ttag(dest_reg, source_reg, qp=0, bit36=0, ignored=0):
    return (op(1) | bitfield(bit36, 36, 1) | bitfield(0x1b, 27, 6)
            | bitfield(source_reg, 20, 7) | bitfield(ignored, 13, 7)
            | bitfield(dest_reg, 6, 7) | bitfield(qp, 0, 6))

def mov_b_gr(b1, r2, x6=0, qp=0):
    return bitfield(7, 33, 3) | bitfield(x6, 27, 6) | bitfield(r2, 13, 7) | bitfield(b1, 6, 3) | bitfield(qp, 0, 6)

def mov_gr_b(r1, b2, qp=0):
    return bitfield(0x31, 27, 6) | bitfield(b2, 13, 3) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def psr_mask_op(x6, mask, qp=0):
    return (
        bitfield(x6, 27, 6)
        | bitfield(mask & 0x7f, 6, 7)
        | bitfield((mask >> 7) & 0x7f, 13, 7)
        | bitfield((mask >> 14) & 0x7f, 20, 7)
        | bitfield((mask >> 21) & 0x3, 31, 2)
        | bitfield((mask >> 23) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def ssm(mask, qp=0):
    return psr_mask_op(0x06, mask, qp)

def rsm(mask, qp=0):
    return psr_mask_op(0x07, mask, qp)

def sum_um(mask, qp=0):
    return psr_mask_op(0x04, mask, qp)

def rum(mask, qp=0):
    return psr_mask_op(0x05, mask, qp)

def bsw0(qp=0):
    return EndGroupInsn(
        bitfield(0x0c, 27, 6) | bitfield(qp, 0, 6))

def bsw1(qp=0):
    return EndGroupInsn(
        bitfield(0x0d, 27, 6) | bitfield(qp, 0, 6))

def vmsw0(qp=0):
    return bitfield(0x18, 27, 6) | bitfield(qp, 0, 6)

def vmsw1(qp=0):
    return bitfield(0x19, 27, 6) | bitfield(qp, 0, 6)

def flushrs_enc(qp=0):
    return StartGroupInsn(
        bitfield(0x0c, 27, 6)
        | bitfield(qp, 0, 6)
    )

def loadrs_enc(qp=0):
    return StartGroupInsn(
        bitfield(0x0a, 27, 6)
        | bitfield(qp, 0, 6)
    )

def chk_s_target_bits(source, target):
    field = branch_target_field(source, target)
    return (
        bitfield(field & 0x7f, 6, 7)
        | bitfield((field >> 7) & 0x1fff, 20, 13)
        | bitfield((field >> 20) & 1, 36, 1)
    )

def chk_a_target_bits(source, target):
    field = branch_target_field(source, target)
    return (
        bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
    )

def chk_s_m(r2, source=0, target=0, qp=0):
    return (
        op(1)
        | bitfield(1, 33, 1)
        | chk_s_target_bits(source, target)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def chk_s_f(f2, source=0, target=0, qp=0):
    return (
        op(1)
        | bitfield(3, 33, 3)
        | chk_s_target_bits(source, target)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def chk_s_i(r2, source=0, target=0, qp=0):
    return (
        bitfield(1, 33, 1)
        | chk_s_target_bits(source, target)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def chk_a_nc_m(r1, source=0, target=0, qp=0):
    return (
        bitfield(4, 33, 3)
        | chk_a_target_bits(source, target)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def chk_a_nc_f(f1, source=0, target=0, qp=0):
    return (
        bitfield(6, 33, 3)
        | chk_a_target_bits(source, target)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def chk_a_clr_m(r2, source=0, target=0, qp=0):
    return (
        bitfield(1, 33, 1)
        | bitfield(2, 34, 2)
        | chk_a_target_bits(source, target)
        | bitfield(r2, 6, 7)
        | bitfield(qp, 0, 6)
    )

def invala(qp=0):
    return bitfield(0x10, 27, 6) | bitfield(qp, 0, 6)

def invala_e_gr(r1, qp=0):
    return (bitfield(0x12, 27, 6) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def invala_e_fp(f1, qp=0):
    return (bitfield(0x13, 27, 6) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))

def ld1_acq(r1, r3, qp=0):
    return op(4) | bitfield(0x14, 30, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def ld8_c_clr_acq(r1, r3, qp=0):
    return load_mem(0x2b, r1, r3, qp)

def ld8_a(r1, r3, qp=0):
    return op(4) | bitfield(2, 27, 2) | bitfield(0x0b, 30, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def ld8_sa(r1, r3, qp=0):
    return op(4) | bitfield(2, 27, 2) | bitfield(0x0f, 30, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def ld2_sa(r1, r3, qp=0):
    return (op(4) | bitfield(2, 27, 2) | bitfield(0x0d, 30, 6)
            | bitfield(r3, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def ld2_c_clr(r1, r3, qp=0):
    return load_mem(0x21, r1, r3, qp)

def ld4_a(r1, r3, qp=0):
    return (op(4) | bitfield(2, 27, 2) | bitfield(0x0a, 30, 6)
            | bitfield(r3, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def ld4_c_clr(r1, r3, qp=0):
    return (op(4) | bitfield(0x22, 30, 6)
            | bitfield(r3, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def ld4_c_nc(r1, r3, qp=0):
    return (op(4) | bitfield(0x26, 30, 6)
            | bitfield(r3, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def ld4_c_clr_acq(r1, r3, hint=0, qp=0):
    return (op(4) | bitfield(0x2a, 30, 6) | bitfield(hint, 28, 2)
            | bitfield(r3, 20, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))

def ld8_c_clr(r1, r3, qp=0):
    return (op(4) | bitfield(0x23, 30, 6) | bitfield(r3, 20, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))

def ld8_c_nc(r1, r3, qp=0):
    return (op(4) | bitfield(0x27, 30, 6) | bitfield(r3, 20, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))

def fetchadd4_acq(r1, r3, inc, qp=0, hint=0, ignored=0):
    inc3 = {16: 0, 8: 1, 4: 2, 1: 3, -16: 4, -8: 5, -4: 6, -1: 7}[inc]
    return (op(4) | bitfield(0x12, 30, 6) | bitfield(1, 27, 1)
            | bitfield(hint, 28, 2) | bitfield(ignored, 16, 4)
            | bitfield(inc3, 13, 3) | bitfield(r3, 20, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))

def fetchadd4_rel(r1, r3, inc, qp=0, hint=0, ignored=0):
    return fetchadd4_acq(r1, r3, inc, qp, hint, ignored) | bitfield(1, 32, 1)

def ld4_bias(r1, r3, qp=0):
    return op(4) | bitfield(0x12, 30, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def tnat_z(p1, p2, r2, qp=0):
    return (
        op(5)
        | bitfield(1, 13, 1)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(r2, 20, 7)
        | bitfield(qp, 0, 6)
    )

def tnat_z_unc(p1, p2, r2, qp=0):
    return tnat_z(p1, p2, r2, qp) | bitfield(1, 12, 1)

def tnat_nz_or(p1, p2, r2, qp=0):
    return (
        op(5)
        | bitfield(1, 12, 1)
        | bitfield(1, 13, 1)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(r2, 20, 7)
        | bitfield(qp, 0, 6)
    )

def tnat_nz_and(p1, p2, r2, ignored=0, qp=0):
    return (
        op(5)
        | bitfield(1, 12, 1)
        | bitfield(1, 13, 1)
        | bitfield(ignored, 14, 6)
        | bitfield(p1, 6, 6)
        | bitfield(p2, 27, 6)
        | bitfield(1, 36, 1)
        | bitfield(r2, 20, 7)
        | bitfield(qp, 0, 6)
    )

def ld1_postinc(r1, r3, imm, qp=0):
    return op(5) | bitfield(r3, 20, 7) | bitfield(imm, 13, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def ld1_reg_postinc(r1, r3, r2, qp=0):
    return (
        op(4)
        | bitfield(1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def ld1_sa_postinc(r1, r3, imm, qp=0):
    return (
        op(5)
        | bitfield(0x0c, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def st1_postinc(r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(5)
        | bitfield(0x30, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def stf_spill_postinc(r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(0x3b, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def stf8_postinc(r3, r2, imm, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(0x31, 30, 6)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )

def stf8(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x31, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def stfe(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x30, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def stfs(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x32, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def stfd(r3, f2, qp=0):
    return (
        op(6)
        | bitfield(0x33, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def getf_sig(r1, f2, qp=0, ignored=0):
    return (
        op(4)
        | bitfield(0xe1, 27, 9)
        | bitfield(ignored, 28, 2)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def getf_exp(r1, f2, qp=0, ignored=0):
    return (
        op(4)
        | bitfield(0xe9, 27, 9)
        | bitfield(ignored, 28, 2)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def getf_s(r1, f2, qp=0):
    return (
        op(4)
        | bitfield(0x1e, 30, 6)
        | bitfield(1, 27, 1)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def getf_d(r1, f2, qp=0):
    return (
        op(4)
        | bitfield(0x1f, 30, 6)
        | bitfield(1, 27, 1)
        | bitfield(f2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def setf_sig(f1, r2, ignored=0, qp=0):
    return (
        op(6)
        | bitfield(0xe1, 27, 9)
        | bitfield(ignored, 28, 2)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def setf_d(f1, r2, qp=0):
    return (
        op(6)
        | bitfield(0xf9, 27, 9)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def setf_s(f1, r2, qp=0):
    return (
        op(6)
        | bitfield(0xf1, 27, 9)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def probe_rw_fault(r3, imm2, qp=0):
    return (
        op(1)
        | bitfield(0x31, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm2, 13, 2)
        | bitfield(qp, 0, 6)
    )

def probe_r_fault(r3, imm2, qp=0):
    return (
        op(1)
        | bitfield(0x32, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm2, 13, 2)
        | bitfield(qp, 0, 6)
    )

def probe_w_fault(r3, imm2, qp=0):
    return (
        op(1)
        | bitfield(0x33, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm2, 13, 2)
        | bitfield(qp, 0, 6)
    )

def lfetch_fault(r3, qp=0):
    return lfetch(r3, 0x2e, qp)

def probe_r_fault_ignored(r3, imm2, ignored5=0, ignored7=0, bit36=0, qp=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x32, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(ignored5, 15, 5)
        | bitfield(imm2, 13, 2)
        | bitfield(ignored7, 6, 7)
        | bitfield(qp, 0, 6)
    )

def probe_r_imm(r1, r3, imm2, qp=0):
    return (
        op(1)
        | bitfield(0x18, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm2, 13, 2)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def probe_w_imm(r1, r3, imm2, qp=0):
    return (
        op(1)
        | bitfield(0x19, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm2, 13, 2)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def probe_r_reg(r1, r3, r2, qp=0):
    return (
        op(1)
        | bitfield(0x38, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def probe_w_reg(r1, r3, r2, qp=0):
    return (
        op(1)
        | bitfield(0x39, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fnorm(f1, f2, f3, qp=0, sf=1):
    return (
        op(8)
        | bitfield(sf, 34, 2)
        | bitfield(1, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmov(f1, f2, qp=0):
    # The assembler alias `mov f1=f2` is fmerge.s f1=f2,f2.
    return fmerge_s(f1, f2, f2, qp)

def fpabs(f1, f3, qp=0):
    return (
        op(1)
        | bitfield(0x10, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fpneg(f1, f3, qp=0):
    return (
        op(1)
        | bitfield(0x11, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f3, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fpnegabs(f1, f3, qp=0):
    return (
        op(1)
        | bitfield(0x11, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmerge_ns(f1, f2, f3, qp=0):
    return (
        op(0)
        | bitfield(0x11, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmerge_s(f1, f2, f3, qp=0):
    return (
        op(0)
        | bitfield(0x10, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmerge_se(f1, f2, f3, qp=0):
    return (
        op(0)
        | bitfield(0x12, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def _f8_scalar_form(form, f1, f2, f3, sf=0, qp=0, bit36=0):
    return (
        op(0)
        | bitfield(bit36, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(form, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmin(f1, f2, f3, sf=0, qp=0):
    return _f8_scalar_form(0x14, f1, f2, f3, sf, qp)

def fmax(f1, f2, f3, sf=0, qp=0):
    return _f8_scalar_form(0x15, f1, f2, f3, sf, qp)

def famin(f1, f2, f3, sf=0, qp=0):
    return _f8_scalar_form(0x16, f1, f2, f3, sf, qp)

def famax(f1, f2, f3, sf=0, qp=0, bit36=0):
    return _f8_scalar_form(0x17, f1, f2, f3, sf, qp, bit36)

def fpack(f1, f2, f3, qp=0):
    return (
        op(0)
        | bitfield(0x28, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def _f9_form(x6, f1, f2, f3, qp=0, ignored=0):
    return (
        op(0)
        | bitfield(ignored, 34, 3)
        | bitfield(x6, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fand(f1, f2, f3, qp=0):
    return _f9_form(0x2c, f1, f2, f3, qp)

def fandcm(f1, f2, f3, qp=0):
    return _f9_form(0x2d, f1, f2, f3, qp)

def for_(f1, f2, f3, qp=0):
    return _f9_form(0x2e, f1, f2, f3, qp)

def fxor(f1, f2, f3, qp=0):
    return _f9_form(0x2f, f1, f2, f3, qp)

def fswap(f1, f2, f3, qp=0):
    return _f9_form(0x34, f1, f2, f3, qp)

def fswap_nl(f1, f2, f3, qp=0):
    return _f9_form(0x35, f1, f2, f3, qp)

def fswap_nr(f1, f2, f3, qp=0):
    return _f9_form(0x36, f1, f2, f3, qp)

def fmix_lr(f1, f2, f3, qp=0):
    return _f9_form(0x39, f1, f2, f3, qp)

def fmix_r(f1, f2, f3, qp=0):
    return _f9_form(0x3a, f1, f2, f3, qp)

def fmix_l(f1, f2, f3, qp=0, ignored=0):
    return _f9_form(0x3b, f1, f2, f3, qp, ignored)

def fsxt_r(f1, f2, f3, qp=0):
    return _f9_form(0x3c, f1, f2, f3, qp)

def fsxt_l(f1, f2, f3, qp=0):
    return _f9_form(0x3d, f1, f2, f3, qp)

def fsetc(sf, amask, omask, qp=0):
    return (
        op(0)
        | bitfield(0x04, 27, 6)
        | bitfield(sf, 34, 2)
        | bitfield(omask, 20, 7)
        | bitfield(amask, 13, 7)
        | bitfield(qp, 0, 6)
    )

def fclrf(sf, qp=0):
    return (
        op(0)
        | bitfield(0x05, 27, 6)
        | bitfield(sf, 34, 2)
        | bitfield(qp, 0, 6)
    )

def fchkf(sf, source, target, qp=0, ignored26=0):
    field = branch_target_field(source, target)
    return (
        op(0)
        | bitfield(0x08, 27, 6)
        | bitfield(sf, 34, 2)
        | bitfield(field, 6, 20)
        | bitfield(ignored26, 26, 1)
        | bitfield(field >> 20, 36, 1)
        | bitfield(qp, 0, 6)
    )

def _fp_parallel_form(x6, f1, f2, f3, sf=0, qp=0):
    return (
        op(1)
        | bitfield(x6, 27, 6)
        | bitfield(sf, 34, 2)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fpmerge_s(f1, f2, f3, qp=0):
    return _fp_parallel_form(0x10, f1, f2, f3, 0, qp)

def fpmerge_ns(f1, f2, f3, qp=0):
    return _fp_parallel_form(0x11, f1, f2, f3, 0, qp)

def fpmerge_se(f1, f2, f3, qp=0):
    return _fp_parallel_form(0x12, f1, f2, f3, 0, qp)

def fpmin(f1, f2, f3, sf=0, qp=0):
    return _fp_parallel_form(0x14, f1, f2, f3, sf, qp)

def fpmax(f1, f2, f3, sf=0, qp=0):
    return _fp_parallel_form(0x15, f1, f2, f3, sf, qp)

def fpamin(f1, f2, f3, sf=0, qp=0):
    return _fp_parallel_form(0x16, f1, f2, f3, sf, qp)

def fpamax(f1, f2, f3, sf=0, qp=0):
    return _fp_parallel_form(0x17, f1, f2, f3, sf, qp)

def fpcmp(frel, f1, f2, f3, sf=0, qp=0):
    return _fp_parallel_form(0x30 + frel, f1, f2, f3, sf, qp)

def fpcvt_fx(f1, f2, sf=0, qp=0):
    return _fp_parallel_form(0x18, f1, f2, 0, sf, qp)

def fpcvt_fxu(f1, f2, sf=0, qp=0):
    return _fp_parallel_form(0x19, f1, f2, 0, sf, qp)

def fpcvt_fx_trunc(f1, f2, sf=0, qp=0):
    return _fp_parallel_form(0x1a, f1, f2, 0, sf, qp)

def fpcvt_fxu_trunc(f1, f2, sf=0, qp=0):
    return _fp_parallel_form(0x1b, f1, f2, 0, sf, qp)

def fpma(f1, f2, f3, f4, sf=0, qp=0):
    return (
        op(9)
        | bitfield(1, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fpms(f1, f2, f3, f4, sf=0, qp=0):
    return (
        op(0xb)
        | bitfield(1, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fpnma(f1, f2, f3, f4, sf=0, qp=0):
    return (
        op(0xd)
        | bitfield(1, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def frsqrta(f1, p2, f3, sf=1, qp=0):
    return (
        op(0)
        | bitfield(1, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fprsqrta(f1, p2, f3, sf=1, qp=0):
    return (
        op(1)
        | bitfield(1, 36, 1)
        | bitfield(sf, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def frcpa(f1, p2, f3, f4, sf=1, qp=0):
    return (
        op(0)
        | bitfield(sf, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(f4, 20, 7)
        | bitfield(f3, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fprcpa(f1, p2, f2, f3, sf=1, qp=0):
    return (
        op(1)
        | bitfield(sf, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fcvt_fx(f1, f2, unsigned=False, trunc=False, sf=1, qp=0):
    form = 0x18 | (1 if unsigned else 0) | (2 if trunc else 0)

    return (
        op(0)
        | bitfield(sf, 34, 2)
        | bitfield(form, 27, 6)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fcvt_fxu(f1, f2, trunc=True, sf=1, qp=0):
    return fcvt_fx(f1, f2, unsigned=True, trunc=trunc, sf=sf, qp=qp)

def fcvt_xf(f1, f2, qp=0):
    return (
        op(0)
        | bitfield(0x1c, 27, 6)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmpy_s1(f1, f3, f4, qp=0):
    return (
        op(8)
        | bitfield(1, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fmpy_s_s1(f1, f3, f4, qp=0):
    return fmpy_s1(f1, f3, f4, qp) | bitfield(1, 36, 1)

def fmpy_s0(f1, f3, f4, qp=0):
    return (
        op(8)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fma_s1(f1, f3, f4, f2, qp=0):
    return fmpy_s1(f1, f3, f4, qp) | bitfield(f2, 13, 7)

def fma_s0(f1, f3, f4, f2, qp=0):
    return fmpy_s0(f1, f3, f4, qp) | bitfield(f2, 13, 7)

def fma_s_s0(f1, f3, f4, f2, qp=0):
    return fma_s0(f1, f3, f4, f2, qp) | bitfield(1, 36, 1)

def fma_d_s0(f1, f3, f4, f2, qp=0):
    return (
        op(9)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fsub_d_s0(f1, f3, f2, qp=0):
    return (
        op(0xb)
        | bitfield(1, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fms_s3(f1, f3, f4, f2, qp=0):
    return (
        op(0xa)
        | bitfield(3, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fclass_m(p1, p2, f2, fclass9, unc=False, ignored=0, qp=0):
    return (
        op(5)
        | bitfield(ignored, 35, 2)
        | bitfield((fclass9 >> 2) & 0x7f, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(1 if unc else 0, 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(fclass9 & 3, 33, 2)
        | bitfield(p2, 27, 6)
        | bitfield(qp, 0, 6)
    )

def fcmp(p1, p2, f2, f3, rel=0, sf=0, unc=False, qp=0):
    return (
        op(4)
        | bitfield((rel >> 1) & 1, 33, 1)
        | bitfield(sf, 34, 2)
        | bitfield(rel & 1, 36, 1)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(1 if unc else 0, 12, 1)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def fnma_s1(f1, f3, f4, f2, qp=0):
    return (
        op(0xc)
        | bitfield(1, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def fnmpy_s_s1(f1, f3, f4, qp=0):
    return fnma_s1(f1, f3, f4, 0, qp) | bitfield(1, 36, 1)

def fnma_d_s1(f1, f3, f4, f2, qp=0):
    return fnma_s1(f1, f3, f4, f2, qp) | op(0xd)

def setf_exp(f1, r2, qp=0, ignored=0):
    return (
        op(6)
        | bitfield(0xe9, 27, 9)
        | bitfield(ignored, 28, 2)
        | bitfield(r2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def lfetch(r3, x6a=0x2c, qp=0):
    return op(6) | bitfield(x6a, 30, 6) | bitfield(r3, 20, 7) | bitfield(qp, 0, 6)

def hint_m(qp=0):
    return bitfield(1, 27, 6) | bitfield(64, 20, 7) | bitfield(qp, 0, 6)

def hint_i(qp=0):
    return bitfield(1, 27, 6) | bitfield(64, 20, 7) | bitfield(qp, 0, 6)

def mov_grpmc_indexed(r3, r2, qp=0, bit36=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x04, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def mov_pmcgr_indexed(r1, r3, qp=0, bit36=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x14, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mov_grpmd_indexed(r3, r2, qp=0, bit36=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x05, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def mov_pmdgr_indexed(r1, r3, qp=0, bit36=0):
    return (
        op(1)
        | bitfield(bit36, 36, 1)
        | bitfield(0x15, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def lfetch_reg_postinc(r3, r2, x6a=0x2c, hint=0, qp=0):
    return (
        op(6)
        | bitfield(1, 36, 1)
        | bitfield(x6a, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )

def lfetch_postinc(r3, imm, x6a=0x2c, hint=0, qp=0):
    encoded = imm & 0x1ff
    return (
        op(7)
        | bitfield(x6a, 30, 6)
        | bitfield(hint, 28, 2)
        | bitfield((encoded >> 7) & 1, 27, 1)
        | bitfield((encoded >> 8) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(qp, 0, 6)
    )

def popcnt(r1, r3, qp=0):
    return (
        op(7)
        | bitfield(0x12, 27, 6)
        | bitfield(3, 33, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def clz(r1, r3, qp=0):
    return (
        op(7)
        | bitfield(0x1a, 27, 6)
        | bitfield(3, 33, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pcmp(r1, r2, r3, size, gt=False, qp=0):
    fields = {
        1: (0, 0),
        2: (0, 1),
        4: (1, 0),
    }
    za, zb = fields[size]
    return (
        op(8)
        | bitfield(za, 36, 1)
        | bitfield(1, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(1, 32, 1)
        | bitfield(9, 29, 4)
        | bitfield(1 if gt else 0, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pcmp1_eq(r1, r2, r3, qp=0):
    return pcmp(r1, r2, r3, 1, False, qp)

def pavg(r1, r2, r3, size, raz=False, qp=0):
    fields = {
        1: (0, 0),
        2: (0, 1),
    }
    za, zb = fields[size]
    return (
        op(8)
        | bitfield(za, 36, 1)
        | bitfield(1, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(2, 29, 4)
        | bitfield(3 if raz else 2, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pavgsub(r1, r2, r3, size, qp=0):
    fields = {
        1: (0, 0),
        2: (0, 1),
    }
    za, zb = fields[size]
    return (
        op(8)
        | bitfield(za, 36, 1)
        | bitfield(1, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(3, 29, 4)
        | bitfield(2, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def i2_multimedia(za, zb, x2b, x2c, r1, r2, r3, qp=0):
    return (
        op(7)
        | bitfield(za, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(x2c, 30, 2)
        | bitfield(x2b, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pmin1_u(r1, r2, r3, qp=0):
    return i2_multimedia(0, 0, 1, 0, r1, r2, r3, qp)

def pmax1_u(r1, r2, r3, qp=0):
    return i2_multimedia(0, 0, 1, 1, r1, r2, r3, qp)

def pmin2(r1, r2, r3, qp=0):
    return i2_multimedia(0, 1, 3, 0, r1, r2, r3, qp)

def pmax2(r1, r2, r3, qp=0):
    return i2_multimedia(0, 1, 3, 1, r1, r2, r3, qp)

def pack2_uss(r1, r2, r3, qp=0):
    return i2_multimedia(0, 1, 0, 0, r1, r2, r3, qp)

def pack2_sss(r1, r2, r3, qp=0):
    return i2_multimedia(0, 1, 2, 0, r1, r2, r3, qp)

def pack4_sss(r1, r2, r3, qp=0):
    return i2_multimedia(1, 0, 2, 0, r1, r2, r3, qp)

def psad1(r1, r2, r3, qp=0):
    return i2_multimedia(0, 0, 3, 2, r1, r2, r3, qp)

def fc_i(r3, qp=0):
    return op(1) | bitfield(0x30, 27, 6) | bitfield(r3, 20, 7) | bitfield(qp, 0, 6)

def srlz_d(qp=0, ignored36=0):
    return bitfield(ignored36, 36, 1) | bitfield(0x30, 27, 6) | bitfield(qp, 0, 6)

def srlz_i(qp=0, ignored36=0):
    return bitfield(ignored36, 36, 1) | bitfield(0x31, 27, 6) | bitfield(qp, 0, 6)

def sync_i(qp=0, ignored36=0, ignored=0):
    return (bitfield(ignored36, 36, 1) | bitfield(0x33, 27, 6)
            | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6))

def fwb(qp=0, ignored36=0, ignored=0):
    return (bitfield(ignored36, 36, 1) | bitfield(0x20, 27, 6)
            | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6))

def mf(advanced=False, qp=0, ignored36=0, ignored=0):
    x6 = 0x23 if advanced else 0x22
    return (bitfield(ignored36, 36, 1) | bitfield(x6, 27, 6)
            | bitfield(ignored, 6, 21) | bitfield(qp, 0, 6))

def pmpy2(r1, r2, r3, right=False, ignored=0, qp=0):
    return (
        op(7)
        | bitfield((0x1a if right else 0x1e) | (ignored & 1), 27, 6)
        | bitfield(5, 33, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pmpyshr2(r1, r2, r3, shift, signed=False, qp=0):
    shift_codes = {
        0: 0x02,
        7: 0x0a,
        15: 0x12,
        16: 0x1a,
    }
    return (
        op(7)
        | bitfield(shift_codes[shift] + (4 if signed else 0), 27, 6)
        | bitfield(1, 33, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pshl(size, r1, value_reg, count_reg, ignored=0, qp=0):
    if size == 2:
        za = 0
        zb = 1
    elif size == 4:
        za = 1
        zb = 0
    else:
        raise ValueError("pshl supports 2- and 4-byte lanes")
    return (
        op(7)
        | bitfield(za, 36, 1)
        | bitfield(zb, 33, 1)
        | bitfield(0x08 | (ignored & 1), 27, 6)
        | bitfield(count_reg, 20, 7)
        | bitfield(value_reg, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pshl2(r1, value_reg, count_reg, ignored=0, qp=0):
    return pshl(2, r1, value_reg, count_reg, ignored, qp)

def pshl4(r1, value_reg, count_reg, ignored=0, qp=0):
    return pshl(4, r1, value_reg, count_reg, ignored, qp)

def pshl_fixed(size, r1, value_reg, count, qp=0):
    za, zb = {2: (0, 1), 4: (1, 0)}[size]
    return (
        op(7)
        | bitfield(za, 36, 1)
        | bitfield(3, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(1, 30, 2)
        | bitfield(1, 28, 2)
        | bitfield(31 - count, 20, 5)
        | bitfield(value_reg, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pshl2_fixed(r1, value_reg, count, qp=0):
    return pshl_fixed(2, r1, value_reg, count, qp)

def pshl4_fixed(r1, value_reg, count, qp=0):
    return pshl_fixed(4, r1, value_reg, count, qp)

def pshr(size, r1, r3, count_or_r2, unsigned=False, variable=False,
         ignored=0, qp=0):
    za, zb = {2: (0, 1), 4: (1, 0)}[size]
    x2a = 0 if variable else 1
    if variable:
        x2b = 0 if unsigned else 2
    else:
        x2b = 1 if unsigned else 3
    raw = (
        op(7)
        | bitfield(za, 36, 1)
        | bitfield(x2a, 34, 2)
        | bitfield(zb, 33, 1)
        | bitfield(x2b, 28, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )
    if variable:
        return raw | bitfield(count_or_r2, 13, 7)
    return (
        raw
        | bitfield(count_or_r2, 14, 5)
        | bitfield(ignored & 1, 13, 1)
        | bitfield((ignored >> 1) & 1, 19, 1)
        | bitfield((ignored >> 2) & 1, 27, 1)
    )

def pshr2(r1, r3, count_or_r2, unsigned=False, variable=False,
          ignored=0, qp=0):
    return pshr(2, r1, r3, count_or_r2, unsigned, variable, ignored, qp)

def pshr4(r1, r3, count_or_r2, unsigned=False, variable=False,
          ignored=0, qp=0):
    return pshr(4, r1, r3, count_or_r2, unsigned, variable, ignored, qp)

def shl_var(r1, value_reg, count_reg, ignored=0, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(8, 27, 6)
        | bitfield(ignored, 27, 1)
        | bitfield(count_reg, 20, 7)
        | bitfield(value_reg, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def shr_u_var(r1, value_reg, count_reg, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(0, 27, 6)
        | bitfield(value_reg, 20, 7)
        | bitfield(count_reg, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def shr_var(r1, value_reg, count_reg, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(4, 27, 6)
        | bitfield(value_reg, 20, 7)
        | bitfield(count_reg, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mpy4(r1, r2, r3, ignored=0, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(0x1a | (ignored & 1), 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mpyshl4(r1, r2, r3, ignored=0, qp=0):
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(0x1e | (ignored & 1), 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def cmp_lt_unc_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(0xc)
        | bitfield(1, 12, 1)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp4_lt_unc(p1, p2, r2, r3, qp=0):
    return (
        op(0xc)
        | bitfield(1, 12, 1)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ltu_unc(p1, p2, r2, r3, qp=0):
    return (
        op(0xd)
        | bitfield(1, 12, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp4_ltu_unc(p1, p2, r2, r3, qp=0):
    return cmp_ltu_unc(p1, p2, r2, r3, qp) | bitfield(1, 34, 2)

def cmp_ltu_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(0xd)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp4_ltu_imm(p1, p2, imm, r3, qp=0):
    return cmp_ltu_imm(p1, p2, imm, r3, qp) | bitfield(3, 34, 2)

def cmp4_ltu_unc_imm(p1, p2, imm, r3, qp=0):
    return cmp4_ltu_imm(p1, p2, imm, r3, qp) | bitfield(1, 12, 1)

def cmp4_eq_unc_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(3, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def tbit_z(p1, p2, r3, bit, qp=0):
    return (
        op(5)
        | bitfield(bit, 14, 6)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def tbit_z_unc(p1, p2, r3, bit, qp=0):
    return tbit_z(p1, p2, r3, bit, qp) | bitfield(1, 12, 1)

def tbit_z_and(p1, p2, r3, bit, qp=0):
    return tbit_z(p1, p2, r3, bit, qp) | bitfield(1, 36, 1)

def tbit_z_or(p1, p2, r3, bit, qp=0):
    return tbit_z(p1, p2, r3, bit, qp) | bitfield(1, 33, 1)

def _tf_form(p1, p2, feature, nz=False, update="normal", qp=0):
    imm5 = feature - 32
    value = (
        op(5)
        | bitfield(1, 13, 1)
        | bitfield(imm5, 14, 5)
        | bitfield(1, 19, 1)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )
    if nz:
        value |= bitfield(1, 12, 1)
    if update in ("and", "or_andcm"):
        value |= bitfield(1, 36, 1)
    if update in ("or", "or_andcm"):
        value |= bitfield(1, 33, 1)
    return value

def tf_z(p1, p2, feature, qp=0):
    return _tf_form(p1, p2, feature, qp=qp)

def tf_z_unc(p1, p2, feature, qp=0):
    return _tf_form(p1, p2, feature, nz=True, qp=qp)

def tf_nz_and(p1, p2, feature, qp=0):
    return _tf_form(p1, p2, feature, nz=True, update="and", qp=qp)

def tf_nz_or_andcm(p1, p2, feature, qp=0):
    return _tf_form(p1, p2, feature, nz=True, update="or_andcm", qp=qp)

def cmp4_eq_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(0xe)
        | bitfield(3, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_eq_imm(p1, p2, imm, r3, qp=0):
    return cmp4_eq_imm(p1, p2, imm, r3, qp) & ~bitfield(1, 34, 1)

def cmp_eq_and(p1, p2, r2, r3, qp=0):
    return (
        op(0xc)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ne_and(p1, p2, r2, r3, qp=0):
    return cmp_eq_and(p1, p2, r2, r3, qp) | bitfield(1, 12, 1)

def cmp4_eq_and(p1, p2, r2, r3, qp=0):
    return cmp_eq_and(p1, p2, r2, r3, qp) | bitfield(1, 34, 2)

def cmp_ge_and(p1, p2, r3, ignored=0, qp=0):
    return (
        op(0xc)
        | bitfield(1, 33, 1)
        | bitfield(1, 36, 1)
        | bitfield(ignored, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_gt_and(p1, p2, r3, ignored=0, qp=0):
    return (
        op(0xc)
        | bitfield(1, 36, 1)
        | bitfield(ignored, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_le_or(p1, p2, r3, ignored=0, qp=0):
    return (
        op(0xd)
        | bitfield(1, 12, 1)
        | bitfield(1, 36, 1)
        | bitfield(ignored, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ne_or_andcm(p1, p2, r2, r3, qp=0):
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ge_or(p1, p2, r3, qp=0):
    return (
        op(0xd)
        | bitfield(1, 33, 1)
        | bitfield(1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ge_or_issue_raw(p1, p2, r3, ignored, qp=0):
    return cmp_ge_or(p1, p2, r3, qp) | bitfield(ignored, 13, 7)

def cmp_ge_or_andcm_issue_raw(p1, p2, r3, ignored, qp=0):
    return (
        op(0xe)
        | bitfield(1, 33, 1)
        | bitfield(1, 36, 1)
        | bitfield(ignored, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_ne_or_andcm_imm(p1, p2, imm, r3, qp=0):
    encoded = imm & 0xff
    return (
        op(0xe)
        | bitfield(1, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def _cmp_update_imm(major, p1, p2, imm, r3, cmp4=False, ne=False, qp=0):
    encoded = imm & 0xff
    return (
        op(major)
        | bitfield(1 if ne else 0, 12, 1)
        | bitfield(1, 33, 1)
        | bitfield(3 if cmp4 else 2, 34, 2)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp_eq_and_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xc, p1, p2, imm, r3, qp=qp)

def cmp_ne_and_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xc, p1, p2, imm, r3, ne=True, qp=qp)

def cmp_eq_or_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xd, p1, p2, imm, r3, qp=qp)

def cmp_ne_or_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xd, p1, p2, imm, r3, ne=True, qp=qp)

def cmp4_eq_and_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xc, p1, p2, imm, r3, cmp4=True, qp=qp)

def cmp4_ne_and_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xc, p1, p2, imm, r3, cmp4=True, ne=True, qp=qp)

def cmp4_eq_or_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xd, p1, p2, imm, r3, cmp4=True, qp=qp)

def cmp4_ne_or_imm(p1, p2, imm, r3, qp=0):
    return _cmp_update_imm(0xd, p1, p2, imm, r3, cmp4=True, ne=True, qp=qp)

def cmp4_ne_or_andcm(p1, p2, r2, r3, qp=0):
    return cmp_ne_or_andcm(p1, p2, r2, r3, qp) | bitfield(1, 34, 2)

def cmp4_eq_or(p1, p2, r2, r3, qp=0):
    return (
        op(0xd)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def cmp4_ne_or(p1, p2, r2, r3, qp=0):
    return cmp4_eq_or(p1, p2, r2, r3, qp) | bitfield(1, 12, 1)

def cmp4_ge_or_andcm(p1, p2, r3, qp=0):
    return (
        op(0xe)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(p2, 27, 6)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )

def dep(r1, r2, r3, pos, length, qp=0):
    cpos = 63 - pos
    encoded_len = length - 1
    return (
        op(4)
        | bitfield(encoded_len & 0xf, 27, 4)
        | bitfield(cpos & 0x3, 31, 2)
        | bitfield((cpos >> 2) & 1, 33, 1)
        | bitfield((cpos >> 3) & 0x3, 34, 2)
        | bitfield((cpos >> 5) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def depz_reg(r1, r2, pos, length, qp=0):
    cpos = 63 - pos
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield(r2, 13, 7)
        | bitfield(cpos, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(qp, 0, 6)
    )

def depz_imm(r1, imm, pos, length, qp=0):
    imm8 = imm & 0xff
    cpos = 127 - pos
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield(imm8 & 0x7f, 13, 7)
        | bitfield(cpos, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield((imm8 >> 7) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def extr_u(r1, r3, pos, length, bit36=0, qp=0):
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield(pos << 1, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 34, 2)
        | bitfield(bit36, 36, 1)
        | bitfield(qp, 0, 6)
    )

def extr(r1, r3, pos, length, qp=0):
    return extr_u(r1, r3, pos, length, qp=qp) | bitfield(1, 13, 1)

def sxt1(r1, r3, qp=0):
    return bitfield(0x14, 27, 6) | bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)

def shr_u_imm(r1, r3, imm, qp=0):
    return (
        op(5)
        | bitfield(1, 34, 2)
        | bitfield(63 - imm, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(imm << 1, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def shrp_imm(r1, r2, r3, imm, qp=0, ignored=0):
    return (
        op(5)
        | bitfield(3, 34, 2)
        | bitfield(ignored, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(imm, 27, 6)
        | bitfield(qp, 0, 6)
    )

def reserved_a1_x4_5_x2b_1(r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(5, 29, 4)
        | bitfield(1, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mux1_rev(r1, r2, qp=0):
    return mux1(r1, r2, 0x0b, qp)

def mux1(r1, r2, mbtype4, qp=0):
    return (
        op(7)
        | bitfield(3, 34, 2)
        | bitfield(2, 30, 2)
        | bitfield(2, 28, 2)
        | bitfield(mbtype4 & 0xf, 20, 4)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mov_ip(r1, qp=0):
    return (
        bitfield(0x30, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def mov_gr_pr(r2, mask, qp=0):
    encoded = ((mask & 0x1fffe) >> 1)
    return (
        bitfield(3, 33, 3)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(r2, 13, 7)
        | bitfield((encoded >> 7) & 0xff, 24, 8)
        | bitfield((encoded >> 15) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def mov_pr_gr(r1, qp=0):
    return (
        bitfield(0x33, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def brp_loop_imp():
    return op(7) | bitfield(0x100, 27, 9) | bitfield(1, 6, 1) | 8

def brp_sptk():
    return 0xf1fcf84840

def mux2(r1, r2, mhtype8, qp=0):
    return (
        op(7)
        | bitfield(3, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(2, 30, 2)
        | bitfield(2, 28, 2)
        | bitfield(mhtype8 & 0xff, 20, 8)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def shladd(r1, r2, shift, r3, qp=0):
    return (
        op(8)
        | bitfield(4, 29, 4)
        | bitfield(shift - 1, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def shladdp4(r1, r2, shift, r3, qp=0):
    return (
        op(8)
        | bitfield(6, 29, 4)
        | bitfield(shift - 1, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def padd1(r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(1, 34, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def psub1_uuu(r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(1, 34, 2)
        | bitfield(1, 29, 4)
        | bitfield(2, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pshladd2(r1, r2, count, r3, qp=0):
    return (
        op(8)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(4, 29, 4)
        | bitfield(count - 1, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def pshradd2(r1, r2, count, r3, qp=0):
    return (
        op(8)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(6, 29, 4)
        | bitfield(count - 1, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def addp4(r1, r2, r3, qp=0):
    return (
        op(8)
        | bitfield(2, 29, 4)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def addp4_imm(r1, imm, r3, qp=0):
    encoded = imm & 0x3fff
    return (
        op(8)
        | bitfield(3, 34, 2)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield((encoded >> 7) & 0x3f, 27, 6)
        | bitfield((encoded >> 13) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def branch_target_field(source, target):
    delta = target - source
    if delta % 16 != 0:
        raise ValueError("branch target is not bundle aligned")
    return (delta // 16) & 0x1fffff

def long_branch_target_field(source, target):
    delta = target - source
    if delta % 16 != 0:
        raise ValueError("branch target is not bundle aligned")
    return (delta // 16) & ((1 << 60) - 1)

def br_cond(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_wexit(source, target, qp):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(2, 6, 3)
        | bitfield(qp, 0, 6)
    )

def br_wtop(source, target, qp):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(3, 6, 3)
        | bitfield(qp, 0, 6)
    )

def brl_call_mlx(b1, source, target, qp=0, ignored_l=0, template=0x05):
    field = long_branch_target_field(source, target)
    l_slot = (
        bitfield(ignored_l & 0x3, 0, 2)
        | bitfield((field >> 20) & ((1 << 39) - 1), 2, 39)
    )
    x_slot = (
        op(0xd)
        | bitfield((field >> 59) & 1, 36, 1)
        | bitfield(1, 33, 2)
        | bitfield(1, 12, 1)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield(b1, 6, 3)
        | bitfield(qp, 0, 6)
    )
    return (template, nop_m(), l_slot, x_slot)

def brl_cond_mlx(source, target, qp=0, many=False, wh=0, clear=False,
                 ignored_l=0, template=0x05):
    field = long_branch_target_field(source, target)
    l_slot = (
        bitfield(ignored_l & 0x3, 0, 2)
        | bitfield((field >> 20) & ((1 << 39) - 1), 2, 39)
    )
    x_slot = (
        op(0xc)
        | bitfield((field >> 59) & 1, 36, 1)
        | bitfield(1 if clear else 0, 35, 1)
        | bitfield(wh, 33, 2)
        | bitfield(1 if many else 0, 12, 1)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield(qp, 0, 6)
    )
    return (template, nop_m(), l_slot, x_slot)

def br_cloop(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(5, 6, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )

def br_ctop_many(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(1, 12, 1)
        | bitfield(7, 6, 3)
        | bitfield(qp, 0, 6)
    )

def br_ctop_few(source, target, qp=0):
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(7, 6, 3)
        | bitfield(qp, 0, 6)
    )

def cover_b(qp=0):
    return EndGroupInsn(0x10000000 | bitfield(qp, 0, 6))

def cover_b_ignored_fields(qp=0):
    return EndGroupInsn(
        cover_b(qp)
        | bitfield(1, 12, 1)
        | bitfield(6, 13, 7)
        | bitfield(79, 20, 7)
        | bitfield(1, 6, 3)
    )

def fselect(f1, f2, f3, f4, qp=0):
    return (
        op(0xe)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def xma_h(f1, f2, f3, f4, qp=0):
    return (
        op(0xe)
        | bitfield(1, 36, 1)
        | bitfield(3, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def xma_l(f1, f2, f3, f4, qp=0):
    return (
        op(0xe)
        | bitfield(1, 36, 1)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def xma_hu(f1, f2, f3, f4, qp=0):
    return (
        op(0xe)
        | bitfield(1, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f2, 13, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def xmpy_hu(f1, f3, f4, qp=0):
    return (
        op(0xe)
        | bitfield(1, 36, 1)
        | bitfield(2, 34, 2)
        | bitfield(f4, 27, 7)
        | bitfield(f3, 20, 7)
        | bitfield(f1, 6, 7)
        | bitfield(qp, 0, 6)
    )

def bundle_words(template, slot0, slot1, slot2):
    if isinstance(slot1, MUnitAlloc):
        slot0, slot1 = slot1, slot0
    if isinstance(slot2, StartGroupInsn) and \
            slot0 == nop_m() and slot1 == nop_i():
        slot0, slot2 = slot2, nop_i()
    if isinstance(slot0, IUnitInsn):
        if slot2 != nop_i():
            raise ValueError("cannot relocate I-unit instruction into full bundle")
        slot0, slot1, slot2 = nop_m(), slot0, slot1
    if isinstance(slot0, EndGroupInsn):
        stop_after_slot0 = {
            0x00: 0x02, 0x01: 0x03,
            0x08: 0x0a, 0x09: 0x0b,
        }
        if template not in stop_after_slot0:
            raise ValueError("template cannot stop after slot 0")
        template = stop_after_slot0[template]
    elif isinstance(slot1, EndGroupInsn):
        raise ValueError("template cannot stop after slot 1")
    elif isinstance(slot2, EndGroupInsn):
        template |= 1
    raw = template | (slot0 << 5) | (slot1 << 46) | (slot2 << 87)
    return raw & ((1 << 64) - 1), raw >> 64

def raw_bundle(address, low, high):
    raw = low | (high << 64)
    return (
        address,
        raw & 0x1f,
        (raw >> 5) & ((1 << 41) - 1),
        (raw >> 46) & ((1 << 41) - 1),
        (raw >> 87) & ((1 << 41) - 1),
    )

def normalized_bundles(bundles):
    bundles = list(bundles)
    for index, bundle in enumerate(bundles):
        address, template, slot0, slot1, slot2 = bundle
        starts_group = (
            isinstance(slot0, (MUnitAlloc, StartGroupInsn))
            or isinstance(slot1, MUnitAlloc)
            or isinstance(slot2, StartGroupInsn)
        )

        if starts_group and index > 0 and \
                bundles[index - 1][0] + 0x10 == address:
            previous = bundles[index - 1]
            bundles[index - 1] = (
                previous[0], previous[1] | 1,
                previous[2], previous[3], previous[4],
            )
    return bundles


def run_program(qemu, bundles, entry=0x10, alat="full",
                terminal_ip=None, expected=None, timeout=2.0,
                name="ia64-microprogram", poll_initial_s=0.001,
                poll_max_s=0.020, cpu=None, smp="1", memory=None):
    """Run until an explicit architectural terminal state."""
    expected = dict(expected or {})
    if terminal_ip is None:
        terminal_ip = expected.get("ip")
    elif "ip" not in expected:
        expected["ip"] = terminal_ip
    expectation = StateExpectation(expected)
    predicate = None
    if terminal_ip is None and expected:
        predicate = expectation.matches
    program = MicroProgram(
        name=name,
        bundles=encode_bundles(normalized_bundles(bundles), bundle_words),
        entry=entry,
        expected=expectation,
        completion=Completion(terminal_ip=terminal_ip, timeout_s=timeout,
                              poll_initial_s=poll_initial_s,
                              poll_max_s=poll_max_s,
                              predicate=predicate),
        machine_args=(() if alat is None else (f"alat={alat}",)),
        cpu=cpu,
        smp=smp,
        memory=memory,
    )
    return run_microprogram(qemu, program)


def run_program_expect_failure(qemu, bundles, entry=0x10, timeout=3,
                               cpu=None):
    program = MicroProgram(
        name="ia64-expected-qemu-failure",
        bundles=encode_bundles(normalized_bundles(bundles), bundle_words),
        entry=entry,
        expected=StateExpectation(),
        completion=Completion(terminal_ip=None, timeout_s=timeout),
        cpu=cpu,
        expected_exit=ExpectedExit(),
    )
    return run_expected_exit(qemu, program)


def run_program_expect_ia32_stop(qemu, bundles, entry=0x10, timeout=6,
                                 cpu=None):
    program = MicroProgram(
        name="ia64-expected-ia32-stop",
        bundles=encode_bundles(normalized_bundles(bundles), bundle_words),
        entry=entry,
        expected=StateExpectation(),
        completion=Completion(terminal_ip=None, timeout_s=timeout),
        cpu=cpu,
    )
    return run_guest_panic_stop(qemu, program)


def require_ia32_stop(name, bundles, entry=0x10, cpu=None):
    def tc(qemu):
        run_program_expect_ia32_stop(qemu, bundles, entry=entry, cpu=cpu)
    return tc


def require_qemu_failure(name, bundles, expected_substrings, entry=0x10,
                         cpu=None):
    def tc(qemu):
        output = run_program_expect_failure(qemu, bundles, entry=entry,
                                            cpu=cpu)
        missing = [s for s in expected_substrings if s not in output]
        if missing:
            raise RuntimeError(
                f"{name} failed: missing {missing!r}\n{output}")
    return tc


def parse_jit_stats(output):
    stats = {}
    for key in [
        "TB count",
        "TB flush count",
        "TB invalidate count",
        "TLB full flushes",
        "TLB partial flushes",
        "TLB elided flushes",
    ]:
        match = re.search(rf"^{re.escape(key)}\s+([0-9]+)",
                          output, re.MULTILINE)
        if match:
            stats[key] = int(match.group(1), 10)
    return stats


def run_program_jit(qemu, bundles, entry=0x10, terminal_ip=None):
    bundles = normalized_bundles(bundles)
    if terminal_ip is None:
        terminal_ip = bundles[-1][0]
    program = MicroProgram(
        name="ia64-jit-observation",
        bundles=encode_bundles(bundles, bundle_words),
        entry=entry,
        expected=StateExpectation({"ip": terminal_ip}),
        completion=Completion(terminal_ip=terminal_ip, timeout_s=3.0),
        machine_args=("alat=full",),
    )
    result = run_microprogram(qemu, program, extra_hmp=("info jit",))
    output = result.extra_hmp["info jit"]
    return parse_jit_stats(output), output


def require_registers(name, bundles, expected, entry=0x10, alat="full",
                      cpu=None, smp="1"):
    def tc(qemu):
        run_program(qemu, bundles, entry=entry, alat=alat,
                    expected=expected, name=name, cpu=cpu, smp=smp)
    return tc


IA64_EXCEPTION_VECTORS = {
    IA64_EXCP_ILLEGAL: IA64_GENERAL_VECTOR,
    IA64_EXCP_RESERVED_TEMPLATE: IA64_GENERAL_VECTOR,
    IA64_EXCP_NAT_CONSUMPTION: IA64_NAT_CONSUMPTION_VECTOR,
    IA64_EXCP_UNALIGNED: IA64_UNALIGNED_VECTOR,
    IA64_EXCP_UNIMPL_DATA_ADDR: IA64_GENERAL_VECTOR,
    IA64_EXCP_UNIMPL_INST_ADDR: IA64_LOWER_PRIV_TRANSFER_VECTOR,
    IA64_EXCP_PRIVILEGED_OP: IA64_GENERAL_VECTOR,
    IA64_EXCP_PRIVILEGED_REG: IA64_GENERAL_VECTOR,
    IA64_EXCP_RESERVED_REG_FIELD: IA64_GENERAL_VECTOR,
    IA64_EXCP_DISABLED_ISA_TRANSITION: IA64_GENERAL_VECTOR,
    IA64_EXCP_DISABLED_FP: IA64_DISABLED_FP_VECTOR,
    IA64_EXCP_UNSUPPORTED_DATA_REFERENCE:
        IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR,
    IA64_EXCP_VIRTUALIZATION: IA64_VIRTUALIZATION_VECTOR,
}


def require_exception(name, bundles, excp, fault_ip=None, fault_imm=None,
                      entry=0x10, cpu=None):
    def tc(qemu):
        vector = IA64_EXCEPTION_VECTORS.get(excp)
        if vector is None:
            expected = {"exception": excp, "fault_code": excp}
            if fault_ip is not None:
                expected["fault_ip"] = fault_ip
            if fault_imm is not None:
                expected["fault_imm"] = fault_imm
            # The faulting IP can also be the initial IP.  Complete on the
            # exception state so an early QMP stop cannot observe reset state.
            run_program(
                qemu, bundles, entry=entry, expected=expected, name=name,
                cpu=cpu)
            return

        setup = 0x100000
        occupied = {address for address, *_ in bundles}
        while setup in occupied or (setup + 0x10) in occupied:
            setup += 0x1000
        if vector in occupied or (vector + 0x10) in occupied:
            raise RuntimeError(
                f"{name} test bundle overlaps exception vector 0x{vector:x}")

        wrapped = list(bundles) + [
            (setup, *movl_mlx(2, 1 << 13)),
            (setup + 0x10, 0x10, mov_gr_psr_full(2), nop_i(),
             br_cond(setup + 0x10, entry)),
            (vector, 0x00, nop_m(), nop_i(), nop_i()),
            (vector + 0x10, 0x10, nop_m(), nop_i(),
             br_cond(vector + 0x10, vector + 0x10)),
        ]
        expected = {
            "ip": vector + 0x10,
            "exception": IA64_EXCP_NONE,
            "fault_code": excp,
        }
        if fault_ip is not None:
            expected["fault_ip"] = fault_ip
        if fault_imm is not None:
            expected["fault_imm"] = fault_imm
        run_program(qemu, wrapped, entry=setup, expected=expected, name=name,
                    cpu=cpu)
    return tc


def require_uncollected_reserved_field(name, bundles, fault_ip, fault_imm,
                                       entry=0x10):
    return require_registers(name, bundles, {
        "ip": fault_ip,
        "fault_ip": fault_ip,
        "fault_imm": fault_imm,
        "exception": IA64_EXCP_RESERVED_REG_FIELD,
        "fault_code": IA64_EXCP_RESERVED_REG_FIELD,
    }, entry=entry)


# ── RSE tests ──

test_alloc_m34_ignored_bits_decode = require_registers(
    "alloc_m34_ignored_bits_decode", [
        (0x10, 0x00, alloc_m(5, 80, 72, 9, 1,
                              ignored31=1, ignored36=1),
         nop_i(), nop_i()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_cond(0x20, 0x20)),
    ], {
        "ip": 0x20,
        "exception": IA64_EXCP_NONE,
        "r5": 0,
        "cfm_sof": 80,
        "cfm_sol": 72,
        "cfm_sor": 9,
    }, entry=0x10)

test_alloc_predicated_illegal = require_exception(
    "alloc_predicated_illegal", [
        (0x10, 0x00, alloc_m(5, 8, 8, 0, 0, qp=1), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_rse_alloc_call_ret = require_registers("rse_alloc_call_ret", [
    (0x10, 0x00, nop_m(), alloc(2, 1, 1, 0, 0),
     adds(1, 0x42, 0)),
    (0x20, 0x00, nop_m(), adds(2, 0x99, 0),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_call(0, 0x30, 0x50)),
    (0x50, 0x00, nop_m(), alloc(3, 1, 1, 0, 0),
     adds(2, 0x77, 0)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {"ip": 0x60, "r1": 0x42, "r2": 0x77}, entry=0x10)

test_rse_call_sets_callee_input_frame = require_registers(
    "rse_call_sets_callee_input_frame", [
        (0x10, 0x00, nop_m(), alloc(2, 5, 2, 0, 0),
         nop_i()),
        (0x20, 0x00, nop_m(), addl(34, 0x11, 0),
         addl(35, 0x22, 0)),
        (0x30, 0x00, nop_m(), addl(36, 0x33, 0),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_call(0, 0x40, 0x60)),
        (0x60, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r8": 0x11,
        "cfm_sof": 3,
        "cfm_sol": 0,
        "ar_pfs": 0x105,
    }, entry=0x10)

test_rse_nested_alloc_call_preserves_output_arg = require_registers(
    "rse_nested_alloc_call_preserves_output_arg", [
        (0x10, 0x00, nop_m(), alloc(2, 5, 4, 0, 0),
         nop_i()),
        (0x20, *movl_mlx(36, 0x123456789abcdef0)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_call(0, 0x30, 0x80)),
        (0x80, 0x00, nop_m(), alloc(34, 5, 4, 0, 0),
         nop_i()),
        (0x90, 0x00, nop_m(), adds(36, 0, 32),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xa0, 0xe0)),
        (0xe0, 0x00, nop_m(), alloc(34, 7, 4, 0, 0),
         nop_i()),
        (0xf0, 0x00, nop_m(), adds(36, 0, 32),
         adds(37, 0, 0)),
        (0x100, 0x00, nop_m(), addl(38, 560, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(0, 0x110, 0x150)),
        (0x150, 0x00, nop_m(), alloc(31, 3, 3, 0, 0),
         nop_i()),
        (0x160, 0x00, nop_m(), adds(8, 0, 32),
         adds(9, 0, 34)),
        (0x170, 0x10, nop_m(), nop_i(),
         br_cond(0x170, 0x170)),
    ], {
        "ip": 0x170,
        "r8": 0x123456789abcdef0,
        "r9": 560,
    }, entry=0x10)

test_rse_call_uses_high_sol_output_arg = require_registers(
    "rse_call_uses_high_sol_output_arg", [
        (0x10, 0x00, nop_m(), alloc(45, 19, 16, 0, 0),
         nop_i()),
        (0x20, *movl_mlx(48, 0xfedcba9876543210)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_call(0, 0x30, 0x50)),
        (0x50, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r8": 0xfedcba9876543210,
        "cfm_sof": 3,
        "cfm_sol": 0,
        "ar_pfs": 0x813,
    }, entry=0x10)

test_rse_call_maps_all_high_output_args = require_registers(
    "rse_call_maps_all_high_output_args", [
        (0x10, 0x00, nop_m(), alloc(56, 32, 28, 0, 0), nop_i()),
        (0x20, *movl_mlx(60, 0x200)),
        (0x30, *movl_mlx(61, 1007)),
        (0x40, *movl_mlx(62, 1)),
        (0x50, 0x10, nop_m(), nop_i(), br_call(0, 0x50, 0x80)),
        (0x80, 0x00, nop_m(), or_reg(8, 32, 0), or_reg(9, 33, 0)),
        (0x90, 0x00, nop_m(), or_reg(10, 34, 0), add_one(11, 32, 33)),
        (0xa0, 0x10, nop_m(), nop_i(), br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "r8": 0x200,
        "r9": 1007,
        "r10": 1,
        "r11": 0x5f0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_rse_call_moves_output_nat_across_word_boundary = require_registers(
    "rse_call_moves_output_nat_across_word_boundary", [
        (0x10, 0x00, nop_m(), alloc(20, 96, 30, 0, 0), nop_i()),
        (0x20, 0x00, mov_m_imm_ar(36, 1),
         addl(6, 0x400, 0), nop_i()),
        (0x30, 0x08, ld8_fill_postinc(62, 6, 0), nop_i(), nop_i()),
        (0x40, 0x08, ld8_fill_postinc(64, 6, 0), nop_i(), nop_i()),
        (0x50, 0x08, ld8_fill_postinc(94, 6, 0), nop_i(), nop_i()),
        (0x60, 0x08, ld8_fill_postinc(126, 6, 0), nop_i(), nop_i()),
        # r33 starts NaT, but must be cleared by the source r63 bit.
        (0x70, 0x08, ld8_fill_postinc(33, 6, 0), nop_i(), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_call(0, 0x80, 0x100)),

        # The caller's r62..r127 outputs become the callee's r32..r97.
        # The terminal GR NaT map directly covers both sides of every bit-63
        # boundary; no guest-side predicate observer is involved.
        (0x100, 0x00, nop_m(), nop_i(), nop_i()),
        (0x110, 0x00, nop_m(), nop_i(), nop_i()),
        (0x120, 0x00, nop_m(), nop_i(), nop_i()),
        (0x130, 0x00, nop_m(), nop_i(), nop_i()),
        (0x140, 0x00, nop_m(), nop_i(), nop_i()),
        (0x150, 0x00, nop_m(), nop_i(), nop_i()),
        (0x160, 0x00, nop_m(), nop_i(), nop_i()),
        (0x170, 0x00, nop_m(), nop_i(), nop_i()),
        (0x180, 0x10, nop_m(), nop_i(), br_cond(0x180, 0x180)),
        (0x400, 0x00, 0, 0, 0),
    ], {
        "ip": 0x180,
        "exception": IA64_EXCP_NONE,
        "cfm_sof": 66,
        "cfm_sol": 0,
        "r32_nat": 1,
        "r33_nat": 0,
        "r34_nat": 1,
        "r63_nat": 0,
        "r64_nat": 1,
        "r65_nat": 0,
        "r96_nat": 1,
        "r97_nat": 0,
    }, entry=0x10)

test_rse_callee_alloc_stores_input_arg = require_registers(
    "rse_callee_alloc_stores_input_arg", [
        (0x10, 0x00, nop_m(), alloc(45, 19, 16, 0, 0),
         nop_i()),
        (0x20, *movl_mlx(48, 0x123456789abcdef0)),
        (0x30, *movl_mlx(12, 0x1000)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_call(0, 0x40, 0x80)),
        (0x80, 0x00, alloc_m(45, 24, 16, 0, 0), adds(12, -16, 12),
         nop_i()),
        (0x90, 0x00, nop_m(), adds(14, 16, 12),
         nop_i()),
        (0xa0, 0x00, st8(14, 32), nop_i(),
         nop_i()),
        (0xb0, 0x00, ld8(8, 14), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
    }, entry=0x10)

test_rse_alloc_preserves_ar_pfs = require_registers(
    "rse_alloc_preserves_ar_pfs", [
        (0x10, 0x00, nop_m(), alloc(2, 5, 2, 0, 0),
         nop_i()),
        (0x20, 0x00, nop_m(), addl(34, 0x11, 0),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_call(0, 0x30, 0x50)),
        (0x50, 0x00, nop_m(), alloc(12, 6, 5, 0, 0),
         adds(8, 0, 32)),
        (0x60, 0x00, nop_m(), adds(9, 0, 12),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r8": 0x11,
        "r9": 0x105,
        "cfm_sof": 6,
        "cfm_sol": 5,
        "ar_pfs": 0x105,
    }, entry=0x10)

test_alloc_clears_destination_nat = require_registers(
    "alloc_clears_destination_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x00, nop_m(), alloc(1, 6, 4, 0, 0),
         nop_i()),
        (0x30, 0x08, ld8_fill_postinc(34, 6, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, nop_m(), adds(35, 0, 34),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x00, nop_m(), alloc(34, 6, 4, 0, 0),
         nop_i()),
        (0x70, 0x00, nop_m(), nop_i(), nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_ar(34, 64), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r34_nat": 0,
        "r35_nat": 1,
    }, entry=0x10)

test_br_call_ret_preserves_ec = require_registers(
    "br_call_ret_preserves_ec", [
        (0x10, 0x00, mov_m_imm_ar(66, 25), nop_i(),
         nop_i()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_call(6, 0x20, 0x60)),
        (0x30, 0x00, mov_m_ar_gr(4, 66), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (0x60, 0x00, mov_m_imm_ar(66, 1), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_ret(6)),
    ], {"ip": 0x40, "r4": 25}, entry=0x10)

test_rse_bsp_is_current_frame_base = require_registers(
    "rse_bsp_is_current_frame_base", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 3, 2, 0, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "r8": 0x100000,
        "cfm_sof": 3,
        "cfm_sol": 2,
    }, entry=0x10)

test_rse_call_ret_updates_bsp_base = require_registers(
    "rse_call_ret_updates_bsp_base", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_call(0, 0x40, 0x70)),
        (0x50, 0x00, mov_m_ar_gr(9, 17), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x70, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x60,
        "r8": 0x100018,
        "r9": 0x100000,
        "cfm_sof": 5,
        "cfm_sol": 3,
    }, entry=0x10)

test_rse_call_ret_preserves_caller_local = require_registers(
    "rse_call_ret_preserves_caller_local", [
        (0x10, 0x00, nop_m(), alloc(36, 8, 6, 0, 0), nop_i()),
        (0x20, *movl_mlx(34, 0x123456789abcdef0)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_call(0, 0x30, 0x60)),
        (0x40, 0x00, nop_m(), adds(8, 0, 34), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x60, 0x00, nop_m(), alloc(34, 6, 4, 0, 0), nop_i()),
        (0x70, *movl_mlx(34, 0x0badf00d0badf00d)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x50,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 8,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_large_callee_preserves_high_caller_local = require_registers(
    "rse_large_callee_preserves_high_caller_local", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(56, 32, 28, 0, 0), nop_i()),
        (0x40, *movl_mlx(37, 1008)),
        (0x50, 0x10, nop_m(), nop_i(), br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 37), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(40, 96, 88, 0, 0), nop_i()),
        (0x110, *movl_mlx(37, 0x0badf00d0badf00d)),
        (0x120, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {
        "ip": 0x70,
        "r8": 1008,
        "exception": IA64_EXCP_NONE,
        "cfm_sof": 32,
        "cfm_sol": 28,
    }, entry=0x10)

test_rse_parent_spill_keeps_call_snapshot = require_registers(
    "rse_parent_spill_keeps_call_snapshot", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(36, 60, 50, 0, 0), nop_i()),
        (0x40, *movl_mlx(34, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 34), nop_i()),
        (0x70, 0x00, nop_m(), adds(9, 0, 36), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x100, 0x00, nop_m(), alloc(37, 60, 50, 0, 0),
         nop_i()),
        (0x110, *movl_mlx(34, 0x0badf00d0badf00d)),
        (0x120, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0,
        "cfm_sof": 60,
        "cfm_sol": 50,
    }, entry=0x10)

test_rse_call_preserves_same_bundle_local_write = require_registers(
    "rse_call_preserves_same_bundle_local_write", [
        (0x10, 0x00, nop_m(), alloc(53, 29, 23, 0, 0), nop_i()),
        (0x20, *movl_mlx(12, 0x1000)),
        (0x30, 0x00, nop_m(), adds(47, 66, 12), nop_i()),
        (0x40, 0x10, nop_m(), adds(47, 32, 12),
         br_call(0, 0x40, 0x100)),
        (0x50, 0x00, nop_m(), adds(8, 0, 47), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x100, 0x00, nop_m(), alloc(32, 8, 6, 0, 0), nop_i()),
        (0x110, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {
        "ip": 0x60,
        "r8": 0x1020,
        "r47": 0x1020,
        "cfm_sof": 29,
        "cfm_sol": 23,
    }, entry=0x10)

test_rse_cover_skips_trailing_rnat_slot = require_registers(
    "rse_cover_skips_trailing_rnat_slot", [
        (0x10, *movl_mlx(3, 0x100108)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(1, 30, 0, 0, 0),
         nop_i()),
        (0x40, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x50, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r8": 0x100200,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_bspstore_preserves_dirty_partition_across_rnat = require_registers(
    "rse_bspstore_preserves_dirty_partition_across_rnat", [
        (0x10, *movl_mlx(3, 0x100108)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(1, 30, 0, 0, 0),
         nop_i()),
        (0x40, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x50, *movl_mlx(3, 0x200108)),
        (0x60, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "r8": 0x200200,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_loadrs_bspstore_return_uses_covered_frame = require_registers(
    "rse_loadrs_bspstore_return_uses_covered_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(1, 8, 0, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(36, 0x123456789abcdef0)),
        (0x50, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x60, *movl_mlx(3, 64 << 16)),
        (0x70, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x80, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(3, 0x200000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, nop_m(), alloc(39, 8, 0, 0, 0),
         nop_i()),
        (0xc0, *movl_mlx(3, 0x308)),
        (0xd0, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(3, 0x110)),
        (0xf0, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0x100, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x110, 0x00, nop_m(), adds(8, 0, 34),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 8,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_loadrs_zero_current_frame_invalidates_parents = require_registers(
    "rse_loadrs_zero_current_frame_invalidates_parents", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(40, 9, 5, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(35, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x200)),
        (0x70, 0x00, nop_m(), adds(8, 0, 35),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),

        (0x100, 0x00, nop_m(), alloc(35, 4, 0, 0, 0),
         nop_i()),
        (0x110, 0x00, mov_m_ar_gr(20, 17), mov_gr_b(21, 0),
         nop_i()),
        (0x120, 0x00, nop_m(), adds(21, 16, 21),
         nop_i()),
        (0x130, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x140, *movl_mlx(22, 0x200000)),
        (0x150, 0x00, st8(22, 35), nop_i(),
         nop_i()),
        (0x160, *movl_mlx(22, 0x200008)),
        (0x170, 0x00, st8(22, 20), nop_i(),
         nop_i()),
        (0x180, *movl_mlx(22, 0x200010)),
        (0x190, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x1a0, 0x10, nop_m(), nop_i(),
         br_ret(0)),

        (0x200, 0x00, nop_m(), alloc(38, 7, 5, 0, 0),
         nop_i()),
        (0x210, *movl_mlx(35, 0x206)),
        (0x220, 0x10, nop_m(), nop_i(),
         br_call(0, 0x220, 0x300)),
        (0x230, 0x10, nop_m(), nop_i(),
         br_ret(0)),

        (0x300, 0x00, nop_m(), alloc(33, 2, 0, 0, 0),
         nop_i()),
        (0x310, *movl_mlx(3, 0x200000)),
        (0x320, 0x00, ld8(14, 3), nop_i(),
         nop_i()),
        (0x330, *movl_mlx(3, 0x200008)),
        (0x340, 0x00, ld8(15, 3), nop_i(),
         nop_i()),
        (0x350, *movl_mlx(3, 0x200010)),
        (0x360, 0x00, ld8(16, 3), nop_i(),
         nop_i()),
        (0x370, 0x00, mov_m_gr_ar(0, 16), nop_i(),
         nop_i()),
        (0x380, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x390, 0x00, mov_m_gr_ar(14, 64), nop_i(),
         nop_i()),
        (0x3a0, 0x00, mov_ar(15, 18), nop_i(),
         nop_i()),
        (0x3b0, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 16)),
        (0x3c0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x80,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 9,
        "cfm_sol": 5,
    }, entry=0x10)

test_rse_call_ret_preserves_region7_bsp = require_registers(
    "rse_call_ret_preserves_region7_bsp", [
        (0x10, *movl_mlx(3, 0xe000000000100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(19, 1 << 17)),
        (0x40, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x50, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x90)),
        (0x70, 0x00, mov_m_ar_gr(9, 17), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x90, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x80,
        "r8": 0xe000000000100018,
        "r9": 0xe000000000100000,
        "cfm_sof": 5,
        "cfm_sol": 3,
    }, entry=0x10)

test_rse_flushrs_clears_stale_rnat = require_registers(
    "rse_flushrs_clears_stale_rnat", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 1 << 3)),
        (0x40, 0x00, mov_m_gr_ar(4, 19), nop_i(),
         nop_i()),
        (0x50, 0x00, nop_m(), alloc(36, 8, 5, 0, 0),
         nop_i()),
        (0x60, 0x00, nop_m(), mov_gr_b(35, 0),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x100, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x110, 0x00, mov_m_ar_gr(8, 19), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
    }, entry=0x10)

test_rse_cover_flushrs_spills_covered_frame = require_registers(
    "rse_cover_flushrs_spills_covered_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, *movl_mlx(33, 0x2222)),
        (0x60, *movl_mlx(34, 0x3333)),
        (0x70, *movl_mlx(35, 0x4444)),
        (0x80, *movl_mlx(36, 0x5555)),
        (0x90, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0xa0, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0xb0, *movl_mlx(4, 0x100020)),
        (0xc0, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0xd0, 0x00, ld8(9, 4), nop_i(),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
    ], {
        "ip": 0xe0,
        "r8": 0x1111,
        "r9": 0x5555,
    }, entry=0x10)

test_rse_tracked_return_redirties_reused_frame = require_registers(
    "rse_tracked_return_redirties_reused_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 8, 4, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, *movl_mlx(32, 0x2222)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x120)),
        (0x80, *movl_mlx(3, 0x100000)),
        (0x90, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x120, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xa0,
        "r8": 0x2222,
    }, entry=0x10)

test_rse_nested_return_restores_bspstore_base = require_registers(
    "rse_nested_return_restores_bspstore_base", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(1, 27, 22, 0, 0),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_call(6, 0x40, 0x100)),
        (0x50, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_ar_gr(9, 18), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(33, 32, 27, 0, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(7, 0x110, 0x180)),
        (0x120, 0x00, nop_m(), mov_m_gr_ar(33, 64),
         nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (0x180, 0x00, nop_m(), alloc(1, 13, 11, 0, 0),
         nop_i()),
        (0x190, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x1a0, 0x10, nop_m(), nop_i(),
         br_ret(7)),
    ], {
        "ip": 0x70,
        "r8": 0x100000,
        "r9": 0x100000,
        "cfm_sof": 27,
        "cfm_sol": 22,
    }, entry=0x10)

def deep_rse_return_program(depth):
    bundles = [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 3, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(34, 0x5a)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 34),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ]

    for i in range(depth):
        base = 0x100 + i * 0x60
        bundles.append((base, 0x00, alloc(32, 3, 3, 0, 0), nop_i(),
                        nop_i()))
        bundles.append((base + 0x10, 0x00, nop_m(), mov_gr_b(33, 0),
                        nop_i()))
        if i + 1 < depth:
            bundles.append((base + 0x20, 0x10, nop_m(), nop_i(),
                            br_call(0, base + 0x20, base + 0x60)))
        else:
            bundles.append((base + 0x20, 0x00, nop_m(), nop_i(),
                            nop_i()))
        bundles.append((base + 0x30, 0x00, mov_m_gr_ar(32, 64), nop_i(),
                        nop_i()))
        bundles.append((base + 0x40, 0x09, nop_m(), nop_m(),
                        mov_b_gr(0, 33)))
        bundles.append((base + 0x50, 0x10, nop_m(), nop_i(),
                        br_ret(0)))

    return bundles

test_rse_deep_call_chain_spills_parent_frames = require_registers(
    "rse_deep_call_chain_spills_parent_frames",
    deep_rse_return_program(140), {
        "ip": 0x70,
        "r8": 0x5a,
    }, entry=0x10)

test_rse_evict_parent_frames_preserves_caller_local = require_registers(
    "rse_evict_parent_frames_preserves_caller_local", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(39, 14, 9, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(34, 0x123456789abcdef0)),
        (0x50, *movl_mlx(35, 0x0fedcba987654321)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x100)),
        (0x70, 0x00, nop_m(), adds(8, 0, 34),
         adds(9, 0, 35)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x100, 0x00, nop_m(), alloc(39, 15, 9, 0, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(6, 0x110, 0x180)),
        (0x120, 0x00, nop_m(), mov_m_gr_ar(39, 64), nop_i()),
        (0x130, 0x10, nop_m(), nop_i(), br_ret(0)),
        (0x180, 0x00, nop_m(), alloc(40, 90, 80, 0, 0),
         nop_i()),
        (0x190, 0x00, nop_m(), mov_m_gr_ar(40, 64), nop_i()),
        (0x1a0, 0x10, nop_m(), nop_i(), br_ret(6)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0x0fedcba987654321,
        "cfm_sof": 14,
        "cfm_sol": 9,
    }, entry=0x10)

test_rse_untracked_return_uses_each_rnat_collection = require_registers(
    "rse_untracked_return_uses_each_rnat_collection", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(39, 96, 88, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(32, 0x123456789abcdef0)),
        (0x50, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x60, 0x08, ld8_fill_postinc(95, 6, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x00, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (0x100, 0x00, nop_m(), alloc(40, 90, 80, 0, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r32_nat": 0,
        "r95_nat": 1,
        "cfm_sof": 96,
        "cfm_sol": 88,
    }, entry=0x10)

test_rse_return_reclaims_clean_keeps_unreached_rnat = require_registers(
    "rse_return_reclaims_clean_keeps_unreached_rnat", [
        (0x10, *movl_mlx(3, 0x1001f8)),
        (0x20, *movl_mlx(4, 1 << 57)),
        (0x30, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(3, 0x1001a8)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(39, 14, 10, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(36, 0x123456789abcdef0)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, *movl_mlx(3, 0x1001f8)),
        (0xc0, 0x00, ld8(10, 3), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x100, 0x00, nop_m(), alloc(40, 90, 80, 0, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r36_nat": 0,
        "r10": 1 << 57,
        "cfm_sof": 14,
        "cfm_sol": 10,
    }, entry=0x10)

RSE_TRIM_RNAT_DATA = bundle_words(0x00, 0x123456789abcdef0, 0, 0)[0]

test_rse_untracked_return_resyncs_trimmed_rnat = require_registers(
    "rse_untracked_return_resyncs_trimmed_rnat", [
        (0x10, *movl_mlx(3, 0x100f38)),
        (0x20, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 1 << 17)),
        (0x40, 0x00, mov_m_gr_ar(3, 19), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(3, 72 | (72 << 7))),
        (0x60, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(3, 0xa0)),
        (0x80, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0xa0, *movl_mlx(3, 0x815)),
        (0xb0, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(3, 0xf0)),
        (0xd0, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0xf0, 0x00, nop_m(), nop_i(), nop_i()),
        (0x100, 0x00, nop_m(), nop_i(), nop_i()),
        (0x110, 0x00, nop_m(), adds(10, 0, 35),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (0x100c88, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x100df8, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r35_nat": 0,
        "r10": RSE_TRIM_RNAT_DATA,
        "cfm_sof": 21,
        "cfm_sol": 16,
    }, entry=0x10)

test_rse_bspstore_keeps_saved_frame = require_registers(
    "rse_bspstore_keeps_saved_frame", [
        (0x10, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_call(0, 0x20, 0x50)),
        (0x30, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (0x50, *movl_mlx(3, 0x100000)),
        (0x60, 0x00, mov_ar(3, 18), addl(20, 0x99, 0),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {"ip": 0x40, "r8": 0x5a}, entry=0x10)

test_rse_firmware_unmatched_return_restores_matching_frame = require_registers(
    "rse_firmware_unmatched_return_restores_matching_frame", [
        (0x10, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_call(0, 0x20, 0x100100)),
        (0x30, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (0x100100, 0x00, nop_m(), alloc(2, 1, 0, 0, 0),
         nop_i()),
        (0x100110, 0x10, nop_m(), nop_i(),
         br_call(7, 0x100110, 0x100130)),
        (0x100130, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {"ip": 0x40, "r8": 0x5a}, entry=0x10)

test_rse_untracked_return_redirties_restored_frame = require_registers(
    "rse_untracked_return_redirties_restored_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, *movl_mlx(32, 0x2222)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x160)),
        (0x80, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x100, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x110, *movl_mlx(3, 0x200000)),
        (0x120, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x130, *movl_mlx(3, 0x100018)),
        (0x140, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x160, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x170, *movl_mlx(3, 0x200000)),
        (0x180, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x190, *movl_mlx(3, 0x100018)),
        (0x1a0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x1b0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {"ip": 0x90, "r8": 0x2222}, entry=0x10)

test_rse_untracked_return_restores_high_caller_local = require_registers(
    "rse_untracked_return_restores_high_caller_local", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(37, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x110, *movl_mlx(3, 0x200000)),
        (0x120, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x130, *movl_mlx(3, 0x100030)),
        (0x140, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x70,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_loadrs_cover_span_restores_embedded_frame = require_registers(
    "rse_loadrs_cover_span_restores_embedded_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(37, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, *movl_mlx(3, 0x200000)),
        (0x110, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x120, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x130, 0x00, nop_m(), alloc(2, 0, 0, 0, 0),
         nop_i()),
        (0x140, *movl_mlx(3, 64 << 16)),
        (0x150, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x160, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(3, 0x0ffff0)),
        (0x180, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x70,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_loadrs_cover_span_uses_preserved_sol = require_registers(
    "rse_loadrs_cover_span_uses_preserved_sol", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(37, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, *movl_mlx(3, 0x200000)),
        (0x110, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x120, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x130, 0x00, nop_m(), alloc(2, 0, 0, 0, 0),
         nop_i()),
        (0x140, *movl_mlx(3, 64 << 16)),
        (0x150, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x160, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(3, 0x0ffff0)),
        (0x180, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x190, 0x00, nop_m(), alloc(38, 7, 0, 0, 0),
         nop_i()),
        (0x1a0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x70,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_zero_sol_cover_return_restores_bsp_base = require_registers(
    "rse_zero_sol_cover_return_restores_bsp_base", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(37, 0x123456789abcdef0)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, mov_m_ar_gr(14, 64), nop_i(),
         nop_i()),
        (0x110, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x120, *movl_mlx(15, 56 << 16)),
        (0x130, 0x00, mov_m_gr_ar(15, 16), nop_i(),
         nop_i()),
        (0x140, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x150, *movl_mlx(15, 1 | (1 << 7))),
        (0x160, 0x00, mov_m_gr_ar(15, 64), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(16, 0x1b0)),
        (0x180, 0x09, nop_m(), nop_m(),
         mov_b_gr(6, 16)),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (0x1b0, 0x00, mov_m_gr_ar(14, 64), nop_i(),
         nop_i()),
        (0x1c0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x70,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
        "r37": 0x123456789abcdef0,
    }, entry=0x10)

test_rse_loadrs_zero_sol_return_keeps_bsp_without_cover = require_registers(
    "rse_loadrs_zero_sol_return_keeps_bsp_without_cover", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(1, 8, 0, 0, 0),
         nop_i()),
        (0x40, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x50, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(3, 64 << 16)),
        (0x70, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x80, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(3, 0x8)),
        (0xa0, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(3, 0xe0)),
        (0xc0, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0xe0, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
    ], {
        "ip": 0xf0,
        "r8": 0x100040,
        "cfm_sof": 8,
        "cfm_sol": 0,
    }, entry=0x10)

HIGH_TR_BASE = 0xa000000100000000
HIGH_TR_TARGET = HIGH_TR_BASE + 0x8430
HIGH_TR_PSR = ((1 << 13) | (1 << 17) | (1 << 27) |
               (1 << 36) | (1 << 44))
LOW_VECTOR_TR_PTE = 0x0010000004000661
FOUR_K_ITIR = 12 << 2
LOW_VECTOR_ITIR = 0x38
KERNEL_TR_ITIR = 26 << 2
KERNEL_REGION5_RR = (5 << 8) | LOW_VECTOR_ITIR | 1
PERCPU_ADDR = 0xfffffffffffc0000
PERCPU_ITIR = 18 << 2
REGION7_GRANULE_RR = (7 << 8) | (24 << 2)
PERCPU_NEW_DATA = 0x2222222222222222
PERCPU_NEW_DATA_LOW, _ = bundle_words(0x00, PERCPU_NEW_DATA, 0, 0)
EIGHT_K_ITIR = 13 << 2
PTE_ACCESSED = 1 << 5
PTE_DIRTY = 1 << 6
PTE_ED = 1 << 52
DTR_PTE_WB = 0x0010000000000661
DTR_PTE_UC = 0x0010000000000671
DTR_PTE_NATPAGE = DTR_PTE_WB | (7 << 2)
REGION7_SCRATCH_VA = 0xe000000082fd00b0
REGION7_SCRATCH_PA = 0x4100b0
KEY_TEST_VA = 0x9000
KEY_TEST_RID = 0x123
KEY_TEST_KEY = 0x456
KEY_TEST_RR = (KEY_TEST_RID << 8) | LOW_VECTOR_ITIR
KEY_TEST_ITIR = (KEY_TEST_KEY << 8) | LOW_VECTOR_ITIR
KEY_TEST_PSR = (1 << 13) | (1 << 17) | IA64_PSR_PK
KEY_TEST_PKR = IA64_PKR_VALID | (KEY_TEST_KEY << 8)


def dtr_setup_bundles(start, va, pa, page_shift=16, slot=5,
                      pte_flags=DTR_PTE_WB):
    page_mask = (1 << page_shift) - 1

    if (va & page_mask) != (pa & page_mask):
        raise ValueError("DTR virtual and physical page offsets differ")

    return [
        (start, *movl_mlx(18, (pa & ~page_mask) | pte_flags)),
        (start + 0x10, *movl_mlx(19, va & ~page_mask)),
        (start + 0x20, 0x00, mov_m_gr_cr(19, 20),
         adds(21, page_shift << 2, 0), nop_i()),
        (start + 0x30, 0x00, mov_m_gr_cr(21, 21),
         adds(10, slot, 0), nop_i()),
        (start + 0x40, 0x00, itr_d(10, 18), nop_i(), nop_i()),
        (start + 0x50, 0x00, srlz_d(), nop_i(), nop_i()),
    ]


test_rsc_write_clips_pl_to_cpl = require_registers(
    "rsc_write_clips_pl_to_cpl", [
        (0x10, *movl_mlx(19, IA64_PSR_CPL3)),
        (0x20, 0x00, nop_m(), adds(31, 0x50, 0), nop_i()),
        *rfi_to_gr(0x30, 19, 31),
        (0x50, 0x00, mov_m_gr_ar(0, 16), nop_i(), nop_i()),
        (0x60, 0x00, mov_m_ar_gr(8, 16), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r8": IA64_RSC_PL3,
    }, entry=0x10)

test_rse_uses_rsc_pl_for_access_rights = require_registers(
    "rse_uses_rsc_pl_for_access_rights", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, 0x00, mov_m_gr_ar(0, 16), nop_i(), nop_i()),
        (0x80, *movl_mlx(3, HIGH_TR_BASE + 0x8000)),
        (0x90, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0xa0, 0x00, nop_m(), alloc(1, 1, 0, 0, 0), nop_i()),
        (0xb0, *movl_mlx(32, 0x123456789abcdef0)),
        (0xc0, 0x18, nop_m(), nop_m(), cover_b()),
        (0xd0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT |
                         IA64_PSR_CPL3)),
        (0xe0, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0xf0, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x100)),
        (IA64_DATA_ACCESS_VECTOR, 0x10, nop_m(), adds(31, 0x71, 0),
         br_cond(IA64_DATA_ACCESS_VECTOR, IA64_DATA_ACCESS_VECTOR)),
    ], {
        "ip": 0x100,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_rse_rt_enables_protection_key_checks = require_registers(
    "rse_rt_enables_protection_key_checks", [
        (0x10, *movl_mlx(18, 0x0010000000400661)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE)),
        (0x30, *movl_mlx(21, (KEY_TEST_KEY << 8) | (16 << 2))),
        (0x40, 0x00, mov_m_gr_cr(19, 20), adds(10, 5, 0), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(21, 21), nop_i(), nop_i()),
        (0x60, 0x00, itr_d(10, 18), nop_i(), nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x80, 0x00, mov_m_gr_ar(0, 16), nop_i(), nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x8000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0xb0, 0x00, nop_m(), alloc(1, 1, 0, 0, 0), nop_i()),
        (0xc0, *movl_mlx(32, 0x123456789abcdef0)),
        (0xd0, 0x18, nop_m(), nop_m(), cover_b()),
        (0xe0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_RT | IA64_PSR_PK)),
        (0xf0, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x110, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x20,
                 IA64_DATA_KEY_MISS_VECTOR + 0x20)),
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x8000,
        "r31": IA64_ISR_W | IA64_ISR_RS,
    }, entry=0x10)

test_rse_big_endian_backing_store = require_registers(
    "rse_big_endian_backing_store", [
        (0x10, *movl_mlx(3, IA64_RSC_BE)),
        (0x20, 0x00, mov_m_gr_ar(3, 16), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x100000)),
        (0x40, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), alloc(1, 1, 0, 0, 0), nop_i()),
        (0x60, *movl_mlx(32, 0x1122334455667788)),
        (0x70, 0x18, nop_m(), nop_m(), cover_b()),
        (0x80, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (0x90, *movl_mlx(3, 0x100000)),
        (0xa0, 0x00, ld8(8, 3), nop_i(), nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(), br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x8877665544332211,
    }, entry=0x10)

test_rse_big_endian_rnat_collection = require_registers(
    "rse_big_endian_rnat_collection", [
        (0x10, *movl_mlx(3, IA64_RSC_BE)),
        (0x20, 0x00, mov_m_gr_ar(3, 16), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x1001f0)),
        (0x40, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), alloc(1, 1, 0, 0, 0), nop_i()),
        (0x60, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0), nop_i()),
        (0x70, 0x08, ld8_fill_postinc(32, 6, 0), nop_i(), nop_i()),
        (0x80, 0x18, nop_m(), nop_m(), cover_b()),
        (0x90, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, 0x1001f8)),
        (0xb0, 0x00, ld8(8, 3), nop_i(), nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(), br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_rse_spill_fault_sets_isr_rs = require_registers(
    "rse_spill_fault_sets_isr_rs", [
        (0x10, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT)),
        (0x20, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0x40, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), alloc(1, 1, 0, 0, 0), nop_i()),
        (0x60, *movl_mlx(32, 0x123456789abcdef0)),
        (0x70, 0x18, nop_m(), nop_m(), cover_b()),
        (0x80, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(29, 1, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": HIGH_TR_BASE + 0x10000,
        "r31": IA64_ISR_W | IA64_ISR_RS | IA64_ISR_NI,
    }, entry=0x10)

test_rfi_target_rse_fill_fault_uses_restored_psr = require_registers(
    "rfi_target_rse_fill_fault_uses_restored_psr", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(20, (1 << 63) | 1)),
        (0x40, 0x00, mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (0x50, *movl_mlx(20, 0x200)),
        (0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (0x70, *movl_mlx(20, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT)),
        (0x80, 0x00, mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), rfi_b()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(29, 1, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": HIGH_TR_BASE + 0xfff8,
        "r31": IA64_ISR_R | IA64_ISR_RS | IA64_ISR_IR,
    }, entry=0x10)

test_rfi_retries_interrupted_current_frame_fill = require_registers(
    "rfi_retries_interrupted_current_frame_fill", [
        (0x10, *movl_mlx(3, 0x4000fe8)),
        (0x20, *movl_mlx(4, 0x1122334455667788)),
        (0x30, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0x40, *movl_mlx(3, 0x4000ff0)),
        (0x50, *movl_mlx(4, 0x8877665544332211)),
        (0x60, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0x70, *movl_mlx(3, 0x4000ff8)),
        (0x80, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0xb0, *movl_mlx(20, (1 << 63) | 2)),
        (0xc0, 0x00, mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (0xd0, *movl_mlx(20, 0x200)),
        (0xe0, 0x00, mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (0xf0, *movl_mlx(20, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_RT)),
        (0x100, 0x00, mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (0x110, 0x10, nop_m(), nop_i(), rfi_b()),
        (0x200, 0x00, nop_m(), adds(8, 0, 32), nop_i()),
        (0x210, 0x00, nop_m(), adds(9, 0, 33), nop_i()),
        (0x220, 0x10, nop_m(), nop_i(), br_cond(0x220, 0x220)),
        (IA64_ALT_DTLB_VECTOR, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, nop_m(),
         adds(7, FOUR_K_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, itc_d(18), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0x220,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1122334455667788,
        "r9": 0x8877665544332211,
        "cfm_sof": 2,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_rfi_bspstore_rebase_preserves_interrupted_call = require_registers(
    "rse_rfi_bspstore_rebase_preserves_interrupted_call", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x80, *movl_mlx(37, 0x123456789abcdef0)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_call(0, 0x90, 0x100)),
        (0xa0, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x100, 0x00, ld8(10, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_ALT_DTLB_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_ALT_DTLB_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, mov_ar(3, 18),
         adds(7, LOW_VECTOR_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_rfi_same_iip_preserves_interrupted_call_nat = require_registers(
    "rse_rfi_same_iip_preserves_interrupted_call_nat", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x80, *movl_mlx(37, 0x123456789abcdef0)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_call(0, 0x90, 0x200)),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x200, 0x00, nop_m(), alloc(48, 26, 18, 0, 0),
         nop_i()),
        (0x210, 0x00, ld8(50, 2), nop_i(),
         nop_i()),
        (0x220, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_ALT_DTLB_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, loadrs_enc(),
         adds(7, LOW_VECTOR_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r37": 0x123456789abcdef0,
        "r37_nat": 0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_rfi_bspstore_advanced_iip_spills_parent_frame = require_registers(
    "rse_rfi_bspstore_advanced_iip_spills_parent_frame", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(37, 0x123456789abcdef0)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(20, 0x110)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_rfi_does_not_spill_dirty_frame_rnat = require_registers(
    "rse_rfi_does_not_spill_dirty_frame_rnat", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(4, 1 << 3)),
        (0x70, 0x00, mov_m_gr_ar(4, 19), nop_i(),
         nop_i()),
        (0x80, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x90, *movl_mlx(37, 0x123456789abcdef0)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xa0, 0x120)),
        (0xb0, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (0x120, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x130, 0x00, mov_m_ar_gr(9, 19), nop_i(),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(20, 0x130)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 1 << 3,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_rfi_does_not_overwrite_trailing_rnat = require_registers(
    "rse_rfi_does_not_overwrite_trailing_rnat", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x1001a8)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(39, 14, 10, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(36, 0x123456789abcdef0)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x160)),
        (0x90, 0x00, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x160, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(3, 0x1001f8)),
        (0x180, 0x00, ld8(10, 3), nop_i(),
         nop_i()),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(3, 0x1001a8)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(3, 0x1001f8)),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(4, 1 << 57)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, *movl_mlx(20, 0x170)),
        (IA64_BREAK_VECTOR + 0x90, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0xa0, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r36_nat": 0,
        "r10": 1 << 57,
        "cfm_sof": 14,
        "cfm_sol": 10,
    }, entry=0x10)

test_rse_rfi_advanced_iip_uses_covered_current_frame = require_registers(
    "rse_rfi_advanced_iip_uses_covered_current_frame", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(40, 12, 4, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(33, 0x1122334455667788)),
        (0x80, *movl_mlx(34, 0x8877665544332211)),
        (0x90, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0xa0, 0x00, nop_m(), adds(8, 0, 33),
         nop_i()),
        (0xb0, 0x00, nop_m(), adds(9, 0, 34),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0xa0)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1122334455667788,
        "r9": 0x8877665544332211,
        "r33": 0x1122334455667788,
        "r34": 0x8877665544332211,
        "cfm_sof": 12,
        "cfm_sol": 4,
    }, entry=0x10)

test_rse_rfi_repeated_cover_uses_latest_current_frame = require_registers(
    "rse_rfi_repeated_cover_uses_latest_current_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(40, 12, 4, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(33, 0x1111222233334444)),
        (0x50, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x60, 0x08, ld8_fill_postinc(34, 6, 0), nop_i(),
         nop_i()),
        (0x70, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x80, *movl_mlx(20, (1 << 63) | 12 | (4 << 7))),
        (0x90, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(20, 0xd0)),
        (0xb0, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0xd0, *movl_mlx(33, 0xaaaabbbbccccdddd)),
        (0xe0, *movl_mlx(34, 0x123456789abcdef0)),
        (0xf0, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x100, *movl_mlx(20, (1 << 63) | 12 | (4 << 7))),
        (0x110, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0x120, *movl_mlx(20, 0x150)),
        (0x130, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x150, 0x00, nop_m(), nop_i(), nop_i()),
        (0x160, 0x00, nop_m(), adds(8, 0, 33),
         nop_i()),
        (0x170, 0x10, nop_m(), nop_i(),
         br_cond(0x170, 0x180)),
        (0x180, 0x10, nop_m(), nop_i(),
         br_cond(0x180, 0x180)),
    ], {
        "ip": 0x180,
        "exception": IA64_EXCP_NONE,
        "r8": 0xaaaabbbbccccdddd,
        "r33": 0xaaaabbbbccccdddd,
        "r34": 0x123456789abcdef0,
        "r34_nat": 0,
        "cfm_sof": 12,
        "cfm_sol": 4,
    }, entry=0x10)

test_rse_rfi_repeated_cover_preserves_latest_dirty_partition = require_registers(
    "rse_rfi_repeated_cover_preserves_latest_dirty_partition", [
        (0x10, *movl_mlx(2, 0)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(40, 12, 4, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(33, 0x1111222233334444)),
        (0x80, *movl_mlx(34, 0x5555666677778888)),
        (0x90, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0xa0, *movl_mlx(20, (1 << 63) | 12 | (4 << 7))),
        (0xb0, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(20, 0xf0)),
        (0xd0, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0xf0, *movl_mlx(33, 0xaaaabbbbccccdddd)),
        (0x100, *movl_mlx(34, 0x123456789abcdef0)),
        (0x110, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x120, *movl_mlx(2, 1 << 13)),
        (0x130, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x130, 0x150)),
        (0x150, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x170, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x180, *movl_mlx(3, 0x100008)),
        (0x190, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0x1a0, *movl_mlx(3, 0x100010)),
        (0x1b0, 0x00, ld8(9, 3), nop_i(),
         nop_i()),
        (0x1c0, 0x10, nop_m(), nop_i(),
         br_cond(0x1c0, 0x1c0)),
        (IA64_BREAK_VECTOR, *movl_mlx(20, (1 << 63) | 1)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x170)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x1c0,
        "exception": IA64_EXCP_NONE,
        "r8": 0xaaaabbbbccccdddd,
        "r9": 0x123456789abcdef0,
        "cfm_sof": 1,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_rfi_advanced_iip_bspstore_switch_loads_external_frame = \
    require_registers(
        "rse_rfi_advanced_iip_bspstore_switch_loads_external_frame", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(40, 14, 6, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(33, 0x123456789abcdef0)),
        (0x80, *movl_mlx(34, 0x0fedcba987654321)),
        (0x90, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0xa0, 0x00, nop_m(), adds(8, 0, 33),
         nop_i()),
        (0xb0, 0x00, mov_m_ar_gr(10, 17), adds(9, 0, 34),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (IA64_BREAK_VECTOR, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20,
         *movl_mlx(20, (1 << 63) | 12 | (4 << 7))),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0xa0)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": 0,
        "r10": 0x1fff98,
        "cfm_sof": 12,
        "cfm_sol": 4,
    }, entry=0x10)

test_rse_rfi_advanced_iip_preserves_nested_call_locals = require_registers(
    "rse_rfi_advanced_iip_preserves_nested_call_locals", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x100)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(35, 0),
         nop_i()),
        (0x120, *movl_mlx(37, 0x123456789abcdef0)),
        (0x130, 0x00, addl(38, 0x14000, 0), nop_i(),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         br_call(0, 0x140, 0x200)),
        (0x150, 0x00, addl(38, 0x24000, 0), nop_i(),
         nop_i()),
        (0x160, 0x10, nop_m(), nop_i(),
         br_call(0, 0x160, 0x200)),
        (0x170, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x180, 0x00, mov_m_gr_ar(36, 64), mov_b_gr(0, 35),
         nop_i()),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x200, 0x00, mov_m_ar_gr(11, 64), nop_i(),
         nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_call(6, 0x210, 0x300)),
        (0x220, 0x00, mov_m_gr_ar(11, 64), nop_i(),
         nop_i()),
        (0x230, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x300, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x310, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(20, 0x310)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_rfi_bypassed_call_drops_returned_frame = require_registers(
    "rse_rfi_bypassed_call_drops_returned_frame", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x100)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(36, 7, 6, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(35, 0),
         nop_i()),
        (0x120, *movl_mlx(37, 0x123456789abcdef0)),
        (0x130, 0x10, nop_m(), nop_i(),
         br_call(0, 0x130, 0x200)),
        (0x140, 0x00, nop_m(), adds(8, 0, 37),
         nop_i()),
        (0x150, 0x00, mov_m_gr_ar(36, 64), mov_b_gr(0, 35),
         nop_i()),
        (0x160, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        # Model a no-alloc libc syscall wrapper.  Its gateway call returns
        # through rfi directly to 0x220, without executing br.ret b6.
        (0x200, 0x00, mov_m_ar_gr(11, 64), nop_i(),
         nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_call(6, 0x210, 0x300)),
        (0x220, 0x00, mov_m_gr_ar(11, 64), nop_i(),
         nop_i()),
        (0x230, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x300, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0x220)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_manual_rfi_loadrs_restores_current_frame_base = require_registers(
    "rse_manual_rfi_loadrs_restores_current_frame_base", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(14, 9, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(33, 0x123456789abcdef0)),
        (0x50, *movl_mlx(34, 0x0fedcba987654321)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x100)),
        (0x70, 0x00, nop_m(), adds(8, 0, 33),
         nop_i()),
        (0x80, 0x00, nop_m(), adds(9, 0, 34),
         nop_i()),
        (0x90, 0x00, mov_m_ar_gr(10, 17), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, alloc(68, 49, 41, 0, 0), nop_i(),
         nop_i()),
        (0x110, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x120, *movl_mlx(20, (1 << 63) | 0x14b1)),
        (0x130, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0x140, *movl_mlx(20, 0x200)),
        (0x150, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x160, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(20, (52 * 8) << 16)),
        (0x180, 0x00, mov_m_gr_ar(20, 16), nop_i(),
         nop_i()),
        (0x190, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x1a0, *movl_mlx(20, 0x100000)),
        (0x1b0, 0x00, mov_ar(20, 18), nop_i(),
         nop_i()),
        (0x1c0, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x200, 0x00, mov_m_gr_ar(68, 64), nop_i(),
         nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0x0fedcba987654321,
        "r10": 0x100000,
        "cfm_sof": 9,
        "cfm_sol": 3,
    }, entry=0x10)

test_rse_rfi_user_context_preserves_loadrs_dirty_partition = \
    require_registers(
        "rse_rfi_user_context_preserves_loadrs_dirty_partition", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(2, IA64_PSR_IC)),
        (0x40, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x40, 0x300)),
        # The rfi target deliberately precedes the interrupted IP.  It is a
        # guest-built user context, not a return to the cached break frame.
        (0x200, *movl_mlx(3, 0x200000)),
        (0x210, 0x00, st8_postinc(3, 0, 8), nop_i(), nop_i()),
        (0x220, 0x00, st8_postinc(3, 0, 8), nop_i(), nop_i()),
        (0x230, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x240, 0x00, mov_m_gr_ar(68, 64), nop_i(), nop_i()),
        (0x250, 0x10, nop_m(), nop_i(), br_ret(0)),
        (0x300, 0x00, alloc(14, 9, 3, 0, 0), nop_i(), nop_i()),
        (0x310, *movl_mlx(33, 0x123456789abcdef0)),
        (0x320, *movl_mlx(34, 0x0fedcba987654321)),
        (0x330, 0x10, nop_m(), nop_i(),
         br_call(0, 0x330, 0x400)),
        (0x340, 0x00, nop_m(), adds(8, 0, 33), adds(9, 0, 34)),
        (0x350, 0x10, nop_m(), nop_i(),
         br_cond(0x350, 0x350)),
        (0x400, 0x00, alloc(68, 49, 41, 0, 0), nop_i(), nop_i()),
        (0x410, 0x00, break_m(0x42), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(), cover_b()),
        (IA64_BREAK_VECTOR + 0x10,
         *movl_mlx(20, (52 * 8) << 16)),
        (IA64_BREAK_VECTOR + 0x20, 0x00,
         mov_m_gr_ar(20, 16), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00,
         loadrs_enc(), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0x200000)),
        (IA64_BREAK_VECTOR + 0x50, 0x00,
         mov_ar(20, 18), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, 0x200)),
        (IA64_BREAK_VECTOR + 0x70, 0x00,
         mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x80, *movl_mlx(20, IA64_PSR_CPL3)),
        (IA64_BREAK_VECTOR + 0x90, 0x00,
         mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0xa0, 0x10,
         nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0x350,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0x0fedcba987654321,
        "cfm_sof": 9,
        "cfm_sol": 3,
    }, entry=0x10)

test_rse_manual_rfi_smaller_frame_restores_current_frame_base = \
    require_registers(
        "rse_manual_rfi_smaller_frame_restores_current_frame_base", [
            (0x10, *movl_mlx(3, 0x100000)),
            (0x20, 0x00, mov_ar(3, 18), nop_i(),
             nop_i()),
            (0x30, 0x00, alloc(2, 5, 0, 0, 0), nop_i(),
             nop_i()),
            (0x40, *movl_mlx(32, 0x1111222233334444)),
            (0x50, *movl_mlx(33, 0x5555666677778888)),
            (0x60, *movl_mlx(34, 0x9999aaaabbbbcccc)),
            (0x70, *movl_mlx(35, 0xddddeeeeffff0000)),
            (0x80, *movl_mlx(36, 0x123456789abcdef0)),
            (0x90, 0x18, nop_m(), nop_m(),
             cover_b()),
            (0xa0, 0x00, alloc(2, 8, 6, 0, 0), nop_i(),
             nop_i()),
            (0xb0, *movl_mlx(32, 0xa1a2a3a4a5a6a7a8)),
            (0xc0, *movl_mlx(33, 0xb1b2b3b4b5b6b7b8)),
            (0xd0, *movl_mlx(20, 0x200)),
            (0xe0, 0x00, mov_m_gr_cr(0, 16), nop_i(),
             nop_i()),
            (0xf0, 0x00, mov_m_gr_cr(20, 19), nop_i(),
             nop_i()),
            (0x100, *movl_mlx(20, (1 << 63) | 5)),
            (0x110, 0x00, mov_m_gr_cr(20, 23), nop_i(),
             nop_i()),
            (0x120, 0x10, nop_m(), nop_i(),
             rfi_b()),
            (0x200, 0x00, nop_m(), adds(8, 0, 32),
             adds(9, 0, 33)),
            (0x210, 0x00, nop_m(), adds(10, 0, 34),
             adds(11, 0, 35)),
            (0x220, 0x00, mov_m_ar_gr(13, 17), adds(12, 0, 36),
             nop_i()),
            (0x230, 0x10, nop_m(), nop_i(),
             br_cond(0x230, 0x230)),
        ], {
            "ip": 0x230,
            "exception": IA64_EXCP_NONE,
            "r8": 0x1111222233334444,
            "r9": 0x5555666677778888,
            "r10": 0x9999aaaabbbbcccc,
            "r11": 0xddddeeeeffff0000,
            "r12": 0x123456789abcdef0,
            "r13": 0x100000,
            "cfm_sof": 5,
            "cfm_sol": 0,
        }, entry=0x10)

test_rse_rfi_loadrs_preserves_high_sol_caller_local = require_registers(
    "rse_rfi_loadrs_preserves_high_sol_caller_local", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 62, 57, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(87, 0x123456789abcdef0)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, mov_m_ar_gr(9, 17), adds(8, 0, 87),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, nop_m(), alloc(9, 8, 0, 0, 0),
         nop_i()),
        (0x110, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(20, 0x120)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0x100000,
        "r87": 0x123456789abcdef0,
        "cfm_sof": 62,
        "cfm_sol": 57,
    }, entry=0x10)

test_rse_rfi_loadrs_preserves_low_sol_caller_local = require_registers(
    "rse_rfi_loadrs_preserves_low_sol_caller_local", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 62, 57, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(40, 0x1111222233334444)),
        (0x80, *movl_mlx(41, 0x5555666677778888)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_call(0, 0x90, 0x100)),
        (0xa0, 0x00, nop_m(), adds(8, 0, 40),
         adds(9, 0, 41)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x100, 0x00, nop_m(), alloc(9, 8, 0, 0, 0),
         nop_i()),
        (0x110, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(20, 0x120)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x5555666677778888,
        "r40": 0x1111222233334444,
        "r41": 0x5555666677778888,
        "cfm_sof": 62,
        "cfm_sol": 57,
    }, entry=0x10)

test_rse_rfi_loadrs_preserves_caller_locals_after_nested_return = require_registers(
    "rse_rfi_loadrs_preserves_caller_locals_after_nested_return", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 62, 57, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(40, 0x1111222233334444)),
        (0x80, *movl_mlx(41, 0x5555666677778888)),
        (0x90, *movl_mlx(87, 0x123456789abcdef0)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xa0, 0x100)),
        (0xb0, 0x00, nop_m(), adds(8, 0, 40),
         adds(9, 0, 41)),
        (0xc0, 0x00, nop_m(), adds(10, 0, 87),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x100, 0x00, nop_m(), alloc(9, 8, 0, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(10, 0),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_call(0, 0x120, 0x200)),
        (0x130, 0x00, mov_m_gr_ar(9, 64), mov_b_gr(0, 10),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x200, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, (65 * 8) << 16)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_ar(20, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0x210)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x5555666677778888,
        "r10": 0x123456789abcdef0,
        "r40": 0x1111222233334444,
        "r41": 0x5555666677778888,
        "r87": 0x123456789abcdef0,
        "cfm_sof": 62,
        "cfm_sol": 57,
    }, entry=0x10)

test_rse_rfi_loadrs_preserves_caller_locals_after_syscall_error = require_registers(
    "rse_rfi_loadrs_preserves_caller_locals_after_syscall_error", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 62, 57, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(40, 0x1111222233334444)),
        (0x80, *movl_mlx(41, 0x5555666677778888)),
        (0x90, *movl_mlx(87, 0x123456789abcdef0)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xa0, 0x100)),
        (0xb0, 0x00, nop_m(), adds(8, 0, 40),
         adds(9, 0, 41)),
        (0xc0, 0x00, nop_m(), adds(10, 0, 87),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x100, 0x00, nop_m(), alloc(9, 8, 0, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(11, 0),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_call(0, 0x120, 0x200)),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x180)),
        (0x180, 0x00, nop_m(), alloc(32, 4, 3, 0, 0),
         nop_i()),
        (0x190, 0x00, nop_m(), adds(33, 0, 11),
         adds(34, 0, 9)),
        (0x1a0, 0x10, nop_m(), nop_i(),
         br_call(0, 0x1a0, 0x300)),
        (0x1b0, 0x00, nop_m(), mov_m_gr_ar(34, 64),
         mov_b_gr(0, 33)),
        (0x1c0, 0x10, nop_m(), adds(8, -1, 0), br_ret(0)),
        (0x200, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x210, 0x10, nop_m(), adds(10, 1, 0),
         br_ret(0)),
        (0x300, 0x00, nop_m(), alloc(36, 14, 4, 0, 0),
         nop_i()),
        (0x310, *movl_mlx(40, 0xaaaabbbbccccdddd)),
        (0x320, *movl_mlx(41, 0xddddccccbbbbaaaa)),
        (0x330, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, (65 * 8) << 16)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_ar(20, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0x210)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x5555666677778888,
        "r10": 0x123456789abcdef0,
        "r40": 0x1111222233334444,
        "r41": 0x5555666677778888,
        "r87": 0x123456789abcdef0,
        "cfm_sof": 62,
        "cfm_sol": 57,
    }, entry=0x10)

test_rse_rfi_loadrs_preserves_gp_save_after_syscall_error = require_registers(
    "rse_rfi_loadrs_preserves_gp_save_after_syscall_error", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(1, 0x123456789abcdef0)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x00, nop_m(), adds(9, 0, 1),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x100, 0x00, nop_m(), alloc(33, 4, 3, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(32, 0),
         adds(34, 0, 1)),
        (0x120, 0x10, nop_m(), nop_i(),
         br_call(0, 0x120, 0x200)),
        (0x130, 0x00, nop_m(), adds(1, 0, 34),
         adds(8, 0, 34)),
        (0x140, 0x00, mov_m_gr_ar(33, 64), mov_b_gr(0, 32),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x200, 0x00, nop_m(), alloc(9, 8, 0, 0, 0),
         nop_i()),
        (0x210, 0x00, nop_m(), mov_gr_b(11, 0),
         nop_i()),
        (0x220, 0x10, nop_m(), nop_i(),
         br_call(0, 0x220, 0x300)),
        (0x230, 0x10, nop_m(), nop_i(),
         br_cond(0x230, 0x280)),
        (0x280, 0x00, nop_m(), alloc(32, 4, 3, 0, 0),
         nop_i()),
        (0x290, 0x00, nop_m(), adds(33, 0, 11),
         adds(34, 0, 9)),
        (0x2a0, 0x10, nop_m(), nop_i(),
         br_call(0, 0x2a0, 0x400)),
        (0x2b0, 0x00, nop_m(), mov_m_gr_ar(34, 64),
         mov_b_gr(0, 33)),
        (0x2c0, 0x10, nop_m(), adds(8, -1, 0), br_ret(0)),
        (0x300, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x310, 0x10, nop_m(), adds(10, 1, 0),
         br_ret(0)),
        (0x400, 0x00, nop_m(), alloc(36, 14, 4, 0, 0),
         nop_i()),
        (0x410, *movl_mlx(40, 0xaaaabbbbccccdddd)),
        (0x420, *movl_mlx(41, 0xddddccccbbbbaaaa)),
        (0x430, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, (16 * 8) << 16)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_ar(20, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0x310)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r1": 0x123456789abcdef0,
        "r8": 0x123456789abcdef0,
        "r9": 0x123456789abcdef0,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_rt_translates_with_dt_disabled = require_registers(
    "rse_rt_translates_with_dt_disabled", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, 1 << 27)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, alloc(1, 1, 1, 0, 0), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(32, 0x1234)),
        (0xd0, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0xe0, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0xf0, *movl_mlx(4, 0x04010000)),
        (0x100, 0x00, ld8(8, 4), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1234,
    }, entry=0x10)

test_rse_flushrs_crosses_reverse_mapped_virtual_pages = require_registers(
    "rse_flushrs_crosses_reverse_mapped_virtual_pages", [
        *dtr_setup_bundles(0x10, 0xe0000106014cc000, 0xa096000,
                           page_shift=13, slot=5),
        *dtr_setup_bundles(0x70, 0xe0000106014ce000, 0xa094000,
                           page_shift=13, slot=6),
        (0xd0, *movl_mlx(3, 0xe0000106014cde00)),
        (0xe0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xf0, *movl_mlx(19, IA64_PSR_RT)),
        (0x100, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x110, 0x00, nop_m(), alloc(41, 96, 80, 0, 0),
         nop_i()),
        (0x120, *movl_mlx(32, 0x123456789abcdef0)),
        (0x130, 0x10, nop_m(), nop_i(),
         br_call(0, 0x130, 0x180)),
        (0x180, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x190, *movl_mlx(3, 0xa097e00)),
        (0x1a0, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0x1b0, 0x10, nop_m(), nop_i(),
         br_cond(0x1b0, 0x1b0)),
    ], {
        "ip": 0x1b0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
    }, entry=0x10)

test_rse_bspstore_rewrite_reloads_spilled_frame = require_registers(
    "rse_bspstore_rewrite_reloads_spilled_frame", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 17) | (1 << 27))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xc0, 0x100)),
        (0xd0, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
        (0x100, *movl_mlx(3, HIGH_TR_BASE + 0x10078)),
        (0x110, 0x00, alloc(2, 0, 0, 0, 0), nop_i(),
         nop_i()),
        (0x120, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x130, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xe0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x5a,
    }, entry=0x10)

test_rse_bspstore_physical_alias_survives_rt_disable = require_registers(
    "rse_bspstore_physical_alias_survives_rt_disable", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 17) | (1 << 27))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0xa0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xc0, 0x110)),
        (0xd0, 0x00, mov_m_ar_gr(9, 17), adds(8, 0, 43),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
        (0x110, *movl_mlx(3, 0x04010078)),
        (0x120, 0x00, alloc(2, 0, 0, 0, 0), nop_i(),
         nop_i()),
        (0x130, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x140, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x150, *movl_mlx(19, 0)),
        (0x160, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x170, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xe0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x5a,
        "r9": 0x04010000,
    }, entry=0x10)

test_rse_bspstore_dtlb_miss_retries_spill = require_registers(
    "rse_bspstore_dtlb_miss_retries_spill", [
        (0x10, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x20, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, HIGH_TR_BASE + 0x10000)),
        (0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x50, 0x00, nop_m(), alloc(2, 8, 0, 0, 0),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_call(0, 0x60, 0x100)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(68, 49, 41, 0, 0),
         addl(70, 0x1234, 0)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(6, 0x110, 0x180)),
        (0x120, 0x00, nop_m(), adds(8, 0, 70),
         nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
        (0x180, 0x00, nop_m(), alloc(61, 36, 32, 0, 0),
         nop_i()),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (0x1000, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x1010, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x1020, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x130,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1234,
    }, entry=0x10)

test_rse_br_ret_fill_dtlb_miss_retries_atomically = require_registers(
    "rse_br_ret_fill_dtlb_miss_retries_atomically", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, *movl_mlx(7, EIGHT_K_ITIR)),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x2000)),
        (0x80, *movl_mlx(20, HIGH_TR_BASE + 0x2000)),
        (0x90, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 27))),
        (0xc0, *movl_mlx(3, HIGH_TR_BASE + 0x1f00)),
        (0xd0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xe0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xe0, 0x100)),
        (0x100, 0x00, nop_m(), alloc(2, 8, 0, 0, 0),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(0, 0x110, 0x200)),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (0x200, 0x00, nop_m(), alloc(89, 62, 57, 0, 0),
         nop_i()),
        (0x210, *movl_mlx(40, 0x1111222233334444)),
        (0x220, *movl_mlx(70, 0x5555666677778888)),
        (0x230, *movl_mlx(87, 0x123456789abcdef0)),
        (0x240, 0x10, nop_m(), nop_i(),
         br_call(6, 0x240, 0x300)),
        (0x250, 0x00, nop_m(), adds(8, 0, 40),
         adds(9, 0, 70)),
        (0x260, 0x00, nop_m(), adds(10, 0, 87),
         adds(11, 0, 89)),
        (0x270, 0x00, nop_m(), adds(14, 0, 90),
         adds(15, 0, 91)),
        (0x280, 0x10, nop_m(), nop_i(),
         br_cond(0x280, 0x280)),
        (0x300, 0x00, nop_m(), alloc(61, 36, 32, 0, 0),
         nop_i()),
        (0x310, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x320, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x330, *movl_mlx(3, HIGH_TR_BASE + 0x2000)),
        (0x340, 0x00, ptr_d(3, 7), nop_i(),
         nop_i()),
        (0x350, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x360, *movl_mlx(32, 0xa1a2a3a4a5a6a7a8)),
        (0x370, *movl_mlx(33, 0xb1b2b3b4b5b6b7b8)),
        (0x380, *movl_mlx(34, 0xc1c2c3c4c5c6c7c8)),
        (0x390, *movl_mlx(35, 0xd1d2d3d4d5d6d7d8)),
        (0x3a0, *movl_mlx(36, 0xe1e2e3e4e5e6e7e8)),
        (0x3b0, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (IA64_ALT_DTLB_VECTOR, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x2000)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00,
         adds(7, EIGHT_K_ITIR, 0), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00,
         mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00,
         itc_d(18), adds(29, 0x77, 0),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x280,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x5555666677778888,
        "r10": 0x123456789abcdef0,
        "r11": 0xa1a2a3a4a5a6a7a8,
        "r14": 0xb1b2b3b4b5b6b7b8,
        "r15": 0xc1c2c3c4c5c6c7c8,
        "r29": 0x77,
        "cfm_sof": 62,
        "cfm_sol": 57,
    }, entry=0x10)

test_rse_exception_loadrs_preserves_interrupted_call = require_registers(
    "rse_exception_loadrs_preserves_interrupted_call", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x100, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, *movl_mlx(20, 0x110)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r8": 0x5a,
    }, entry=0x10)

test_rse_rfi_flushed_interrupted_frame_reads_backing_store = \
    require_registers(
        "rse_rfi_flushed_interrupted_frame_reads_backing_store", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 5, 5, 0, 0),
         addl(32, 4, 0)),
        (0x70, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x80, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(4, 3)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 3,
        "r32": 3,
        "cfm_sof": 5,
        "cfm_sol": 5,
    }, entry=0x10)

test_rse_rfi_flushed_same_iip_uses_interrupted_frame = require_registers(
    "rse_rfi_flushed_same_iip_uses_interrupted_frame", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x00, nop_m(), alloc(36, 5, 5, 0, 0),
         addl(32, 4, 0)),
        (0x80, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), addl(32, 5, 0),
         nop_i()),
        (0xa0, 0x00, ld8(10, 2), nop_i(),
         nop_i()),
        (0xb0, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (IA64_ALT_DTLB_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_ALT_DTLB_VECTOR + 0x10, *movl_mlx(3, 0x100000)),
        (IA64_ALT_DTLB_VECTOR + 0x20, *movl_mlx(4, 3)),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, st8(3, 4),
         adds(7, LOW_VECTOR_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x50, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 5,
        "r32": 5,
        "cfm_sof": 5,
        "cfm_sol": 5,
    }, entry=0x10)

test_rse_rfi_nested_handler_preserves_faulting_frame = require_registers(
    "rse_rfi_nested_handler_preserves_faulting_frame", [
        *dtr_setup_bundles(0x10, 0, 0, page_shift=16, slot=6),
        (0x70, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x80, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DT)),
        (0x90, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, *movl_mlx(3, 0x100000)),
        (0xb0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(8, HIGH_TR_BASE + 0x20000)),
        (0xd0, 0x00, nop_m(), alloc(41, 24, 19, 0, 0),
         addl(33, 0x300, 0)),
        (0xe0, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0xf0, 0x00, nop_m(), adds(33, 0, 8),
         nop_i()),
        (0x100, 0x00, st4(33, 0), nop_i(),
         nop_i()),
        (0x110, 0x00, nop_m(), adds(9, 0, 33),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (IA64_ALT_DTLB_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, nop_m(),
         alloc(40, 16, 8, 0, 0), addl(33, 1, 0)),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, mov_m_cr_gr(26, 19),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, mov_m_cr_gr(27, 23),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x00, mov_m_cr_gr(28, 16),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x50, 0x00, ssm(IA64_PSR_IC),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x60, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x70, 0x00, break_m(0x99), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x80, 0x00, rsm(IA64_PSR_IC),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xa0, 0x00, mov_m_gr_cr(28, 16),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xb0, 0x00, mov_m_gr_cr(27, 23),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xc0, 0x00, mov_m_gr_cr(26, 19),
         adds(7, LOW_VECTOR_ITIR, 0), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xd0, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xe0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0xf0, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, nop_m(), adds(20, 16, 20),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r9": HIGH_TR_BASE + 0x20000,
        "r33": HIGH_TR_BASE + 0x20000,
        "cfm_sof": 24,
        "cfm_sol": 19,
    }, entry=0x10)

test_rse_postinc_after_flushrs_preserves_register_value = require_registers(
    "rse_postinc_after_flushrs_preserves_register_value", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(2, 0x8000)),
        (0x70, *movl_mlx(4, 0x1122334455667788)),
        (0x80, 0x00, st8(2, 4), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), alloc(36, 5, 5, 0, 0),
         addl(33, 0x8000, 0)),
        (0xa0, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0xb0, 0x08, ld8_postinc(8, 33, 8), nop_i(),
         nop_i()),
        (0xc0, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0xd0, 0x00, nop_m(), adds(9, 0, 33),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
        (IA64_BREAK_VECTOR, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x100008)),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(4, 0x4444)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0xd0)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xe0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1122334455667788,
        "r9": 0x8008,
        "r33": 0x8008,
        "cfm_sof": 5,
        "cfm_sol": 5,
    }, entry=0x10)

test_rse_rfi_invalid_ifs_unchanged_stack_restores_call = require_registers(
    "rse_rfi_invalid_ifs_unchanged_stack_restores_call", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, *movl_mlx(20, 0x110)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(0, 23),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r8": 0x5a,
    }, entry=0x10)

test_rse_exception_restores_snapshot_arrays = require_registers(
    "rse_exception_restores_snapshot_arrays", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(41, 22, 15, 0, 0), addl(43, 0x5a, 0),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x00, nop_m(), adds(8, 0, 43),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x100, 0x00, alloc(34, 5, 4, 0, 0), nop_i(),
         break_m(0x42)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (IA64_BREAK_VECTOR, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, alloc(2, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         br_call(6, IA64_BREAK_VECTOR + 0x40, IA64_BREAK_VECTOR + 0x100)),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(20, 0x110)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (IA64_BREAK_VECTOR + 0x100, 0x00, alloc(3, 3, 3, 0, 0), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x110, 0x10, nop_m(), nop_i(),
         br_ret(6)),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r8": 0x5a,
    }, entry=0x10)

test_rse_exception_flushrs_preserves_high_local = require_registers(
    "rse_exception_flushrs_preserves_high_local", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(2, 8, 0, 0, 0),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x100, 0x00, nop_m(), alloc(68, 49, 41, 0, 0),
         addl(70, 0x1234, 0)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_call(6, 0x110, 0x180)),
        (0x120, 0x00, nop_m(), adds(8, 0, 70),
         nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
        (0x180, 0x00, nop_m(), alloc(61, 36, 32, 0, 0),
         break_m(0x42)),
        (0x190, 0x10, nop_m(), nop_i(),
         br_ret(6)),
        (IA64_BREAK_VECTOR, 0x00, mov_m_ar_gr(21, 64), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x190)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x00, alloc(2, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x10, nop_m(), nop_i(),
         br_call(7, IA64_BREAK_VECTOR + 0x50,
                 IA64_BREAK_VECTOR + 0x100)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, nop_m(),
         mov_m_gr_ar(21, 64), nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(), rfi_b()),
        (IA64_BREAK_VECTOR + 0x100, 0x00, alloc(3, 3, 3, 0, 0), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x110, 0x10, nop_m(), nop_i(),
         br_ret(7)),
    ], {
        "ip": 0x130,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1234,
    }, entry=0x10)

test_rse_exception_bspstore_restore_skips_unrelated_frame = require_registers(
    "rse_exception_bspstore_restore_skips_unrelated_frame", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(36, 14, 6, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(37, 0x123456789abcdef0)),
        (0x80, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_ar_gr(8, 17), adds(9, 0, 37),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_BREAK_VECTOR, *movl_mlx(3, 0x0ff000)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x18, nop_m(), nop_m(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x30, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x100000,
        "r9": 0x123456789abcdef0,
        "cfm_sof": 14,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_rfi_context_switch_drops_empty_frame_snapshots = require_registers(
    "rse_rfi_context_switch_drops_empty_frame_snapshots", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(1, 5, 5, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(32, 0x1111)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x200, 0x00, nop_m(), alloc(33, 5, 5, 0, 0),
         nop_i()),
        (0x210, *movl_mlx(32, 0x2222)),
        (0x220, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x240, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x250, 0x10, nop_m(), nop_i(),
         br_cond(0x250, 0x250)),
        (IA64_BREAK_VECTOR, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x200)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(21, 1 << 63)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(21, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(22, 0x240)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_ar(0, 64),
         mov_b_gr(0, 22), nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x250,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2222,
    }, entry=0x10)

test_rse_rfi_invalid_ifs_context_switch_drops_snapshot = require_registers(
    "rse_rfi_invalid_ifs_context_switch_drops_snapshot", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(1, 5, 5, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(32, 0x1111)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x200, 0x00, nop_m(), alloc(33, 5, 5, 0, 0),
         nop_i()),
        (0x210, *movl_mlx(32, 0x2222)),
        (0x220, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x240, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x250, 0x10, nop_m(), nop_i(),
         br_cond(0x250, 0x250)),
        (IA64_BREAK_VECTOR, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x200)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_m_gr_cr(0, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(22, 0x240)),
        (IA64_BREAK_VECTOR + 0x60, 0x00, mov_m_gr_ar(0, 64),
         mov_b_gr(0, 22), nop_i()),
        (IA64_BREAK_VECTOR + 0x70, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x250,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2222,
    }, entry=0x10)

test_rse_rfi_invalid_ifs_same_bspstore_keeps_guest_gr = require_registers(
    "rse_rfi_invalid_ifs_same_bspstore_keeps_guest_gr", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(1, 5, 5, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(32, 0x1111)),
        (0x80, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x200, 0x00, nop_m(), adds(8, 0, 32),
         nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_cond(0x210, 0x210)),
        (IA64_BREAK_VECTOR, *movl_mlx(32, 0x2222)),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0x200)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(0, 23),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x210,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2222,
        "r32": 0x2222,
        "cfm_sof": 5,
        "cfm_sol": 5,
    }, entry=0x10)

test_rse_rfi_invalid_ifs_exact_iip_keeps_guest_gr = require_registers(
    "rse_rfi_invalid_ifs_exact_iip_keeps_guest_gr", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x30, *movl_mlx(3, 0x100000)),
        (0x40, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x50, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x50, 0x60)),
        (0x60, 0x00, alloc(1, 5, 5, 0, 0), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(32, 0x1111)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x100)),
        (0x100, 0x00, ld8(4, 2), adds(8, 0, 32),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
        (IA64_ALT_DTLB_VECTOR, 0x00, ssm(IA64_PSR_IC),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, srlz_d(),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, break_m(0x43),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, *movl_mlx(32, 0x2222)),
        (IA64_BREAK_VECTOR + 0x10,
         *movl_mlx(20, IA64_PSR_IC | IA64_PSR_DT | (1 << 41))),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(21, 0x100)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 16),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x00, mov_m_gr_cr(21, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(0, 23),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2222,
        "r32": 0x2222,
        "cfm_sof": 5,
        "cfm_sol": 5,
    }, entry=0x10)

test_rfi_unmatched_context_keeps_interruption_resources = require_registers(
    "rse_rfi_unmatched_context_keeps_guest_interruption_resources", [
        (0x10, *movl_mlx(3, 0x100008)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(2, 1 << 13)),
        (0x40, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x40, 0x60)),
        (0x60, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x200, 0x00, mov_m_cr_gr(8, 20), nop_i(), nop_i()),
        (0x210, 0x10, nop_m(), nop_i(),
         br_cond(0x210, 0x210)),
        (IA64_BREAK_VECTOR, *movl_mlx(3, 0x200008)),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_ar(3, 18),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x123456789abcdef0)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 20),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0x200)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, (1 << 63) | 1)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(20, 23),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x00, mov_m_gr_cr(0, 16),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x10, nop_m(), nop_i(), rfi_b()),
        (0x200000, 0x00, 0x0fedcba987654321, 0, 0),
    ], {
        "ip": 0x210,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r32": bundle_words(0x00, 0x0fedcba987654321, 0, 0)[0],
        "cfm_sof": 1,
    }, entry=0x10)

test_rfi_cross_region_context_ignores_stale_exception_frame = \
    require_registers(
        "rse_rfi_cross_region_context_ignores_stale_exception_frame", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, *movl_mlx(7, KERNEL_TR_ITIR)),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0), nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(), nop_i()),
        (0x70, *movl_mlx(3, 0x100000)),
        (0x80, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x90, 0x00, nop_m(), alloc(1, 4, 4, 0, 0), nop_i()),
        (0xa0, *movl_mlx(2, IA64_PSR_IC)),
        (0xb0, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0xb0, 0xc0)),
        (0xc0, *movl_mlx(32, 0x1111222233334444)),
        (0xd0, 0x00, break_m(0x42), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, *movl_mlx(20, 0x123456789abcdef0)),
        (IA64_BREAK_VECTOR + 0x10, 0x00,
         mov_m_gr_cr(20, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, HIGH_TR_PSR)),
        (IA64_BREAK_VECTOR + 0x30, 0x00,
         mov_m_gr_cr(20, 16), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, HIGH_TR_TARGET)),
        (IA64_BREAK_VECTOR + 0x50, 0x00,
         mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, 0)),
        (IA64_BREAK_VECTOR + 0x70, 0x00,
         mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x10,
         nop_m(), nop_i(), rfi_b()),
        (0x4008430, 0x00, rsm(IA64_PSR_IC), nop_i(), nop_i()),
        (0x4008440, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x4008450, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (0x4008460, 0x10, nop_m(), nop_i(),
         br_cond(HIGH_TR_BASE + 0x8460, HIGH_TR_BASE + 0x8460)),
    ], {
        "ip": HIGH_TR_BASE + 0x8460,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
    }, entry=0x10)

test_rfi_backward_context_ignores_stale_exception_frame = require_registers(
    "rse_rfi_backward_context_ignores_stale_exception_frame", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(2, IA64_PSR_IC)),
        (0x40, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x40, 0x200)),
        (0x100, 0x00, rsm(IA64_PSR_IC), nop_i(), nop_i()),
        (0x110, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x120, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
        (0x200, 0x00, break_m(0x42), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, *movl_mlx(20, 0x123456789abcdef0)),
        (IA64_BREAK_VECTOR + 0x10, 0x00,
         mov_m_gr_cr(20, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x100)),
        (IA64_BREAK_VECTOR + 0x30, 0x00,
         mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(20, 0)),
        (IA64_BREAK_VECTOR + 0x50, 0x00,
         mov_m_gr_cr(20, 23), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10,
         nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0x130,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
    }, entry=0x10)

test_rse_loadrs_clamps_stacked_grs = require_registers(
    "rse_loadrs_clamps_stacked_grs", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(19, HIGH_TR_PSR)),
        (0x30, *movl_mlx(20, HIGH_TR_TARGET)),
        (0x40, *movl_mlx(21, HIGH_TR_BASE)),
        (0x50, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(21, 20), adds(5, 5, 0),
         nop_i()),
        (0x80, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0xb0, 0x10, mov_m_gr_cr(0, 23), nop_i(),
         rfi_b()),
        (0x4008430, *movl_mlx(3, 0x100000)),
        (0x4008440, 0x00, mov_m_gr_ar(3, 18), nop_i(), nop_i()),
        (0x4008450, 0x00, nop_m(), alloc(2, 96, 0, 0, 0),
         nop_i()),
        (0x4008460, 0x00, nop_m(), alloc(2, 96, 0, 0, 0),
         nop_i()),
        (0x4008470, 0x00, nop_m(), nop_i(),
         flushrs_enc()),
        (0x4008480, 0x00, nop_m(), nop_i(),
         loadrs_enc()),
        (0x4008490, 0x00, mov_m_psr_gr(31), nop_i(),
         nop_i()),
        (0x40084a0, 0x10, nop_m(), nop_i(),
         br_cond(HIGH_TR_BASE + 0x84a0, HIGH_TR_BASE + 0x84a0)),
    ], {
        "ip": HIGH_TR_BASE + 0x84a0,
        "exception": IA64_EXCP_NONE,
        "r31": HIGH_TR_PSR,
    }, entry=0x10)

test_rse_loadrs_sets_tear_point = require_registers(
    "rse_loadrs_sets_tear_point", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, *movl_mlx(33, 0x2222)),
        (0x60, *movl_mlx(34, 0x3333)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x100, 0x00, alloc(2, 0, 0, 0, 0), nop_i(),
         nop_i()),
        (0x110, *movl_mlx(3, 8 << 16)),
        (0x120, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x130, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0x140, 0x00, mov_m_ar_gr(8, 18), nop_i(),
         nop_i()),
        (0x150, *movl_mlx(3, 0x200000)),
        (0x160, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x170, 0x00, mov_m_ar_gr(9, 17), nop_i(),
         nop_i()),
        (0x180, 0x10, nop_m(), nop_i(),
         br_cond(0x180, 0x180)),
    ], {
        "ip": 0x180,
        "r8": 0x100010,
        "r9": 0x200008,
    }, entry=0x10)

test_rse_loadrs_preserves_clean_partial_rnat_collection = require_registers(
    "rse_loadrs_preserves_clean_partial_rnat_collection", [
        (0x10, *movl_mlx(3, 0x1001d8)),
        (0x20, *movl_mlx(4, 0xe000000012345678)),
        (0x30, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(3, 0x1001f8)),
        (0x50, 0x00, st8(3, 0), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(3, 0x100220)),
        (0x70, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(4, 1 << 59)),
        (0x90, 0x00, mov_m_gr_ar(4, 19), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(3, 64 << 16)),
        (0xb0, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0xc0, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0xd0, *movl_mlx(3, 16 | (16 << 7))),
        (0xe0, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0xf0, *movl_mlx(3, 0x120)),
        (0x100, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x120, 0x00, nop_m(), nop_i(), nop_i()),
        (0x130, 0x00, nop_m(), nop_i(), nop_i()),
        (0x140, 0x00, nop_m(), adds(10, 0, 40),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_cond(0x150, 0x150)),
    ], {
        "ip": 0x150,
        "exception": IA64_EXCP_NONE,
        "r10": 0xe000000012345678,
        "r40_nat": 0,
        "cfm_sof": 16,
        "cfm_sol": 16,
    }, entry=0x10)

test_rse_loadrs_reloads_same_collection_rnat = require_registers(
    "rse_loadrs_reloads_same_collection_rnat", [
        (0x10, *movl_mlx(3, 0x100120)),
        (0x20, *movl_mlx(4, 0xe000000087654321)),
        (0x30, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(3, 0x1001f8)),
        (0x50, 0x00, st8(3, 0), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(3, 0x100188)),
        (0x70, 0x00, mov_m_gr_ar(3, 18), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(4, 1 << 36)),
        (0x90, 0x00, mov_m_gr_ar(4, 19), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(3, 64 << 16)),
        (0xb0, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0xc0, 0x00, loadrs_enc(), nop_i(),
         nop_i()),
        (0xd0, *movl_mlx(3, 16 | (16 << 7))),
        (0xe0, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0xf0, *movl_mlx(3, 0x120)),
        (0x100, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x120, 0x00, nop_m(), nop_i(), nop_i()),
        (0x130, 0x00, nop_m(), nop_i(), nop_i()),
        (0x140, 0x00, nop_m(), adds(10, 0, 35),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_cond(0x150, 0x150)),
    ], {
        "ip": 0x150,
        "exception": IA64_EXCP_NONE,
        "r10": 0xe000000087654321,
        "r35_nat": 0,
        "cfm_sof": 16,
        "cfm_sol": 16,
    }, entry=0x10)

test_rse_return_growth_keeps_dirty_bsp_distance = require_registers(
    "rse_return_growth_keeps_dirty_bsp_distance", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 57, 6, 0, 0), nop_i(),
         nop_i()),
        (0x40, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x50, *movl_mlx(3, 0x307)),
        (0x60, 0x00, mov_m_gr_ar(3, 64), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(3, 0xa0)),
        (0x80, 0x09, nop_m(), nop_m(),
         mov_b_gr(0, 3)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0xa0, *movl_mlx(3, 0x200000)),
        (0xb0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "r8": 0x200198,
        "cfm_sof": 7,
        "cfm_sol": 6,
    }, entry=0x10)

test_rse_bspstore_write_rebases_dirty_partition = require_registers(
    "rse_bspstore_write_rebases_dirty_partition", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, *movl_mlx(33, 0x2222)),
        (0x60, *movl_mlx(34, 0x3333)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, 0x100)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x100, *movl_mlx(3, 0x200000)),
        (0x110, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x120, 0x00, flushrs_enc(), nop_i(),
         nop_i()),
        (0x130, *movl_mlx(3, 0x200000)),
        (0x140, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0x150, 0x00, nop_m(), adds(3, 8, 3),
         nop_i()),
        (0x160, 0x00, ld8(9, 3), nop_i(),
         nop_i()),
        (0x170, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x80,
        "r8": 0x1111,
        "r9": 0x2222,
    }, entry=0x10)

test_rse_bspstore_rebase_preserves_dirty_cover_prefix = require_registers(
    "rse_bspstore_rebase_preserves_dirty_cover_prefix", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), alloc(2, 8, 0, 0, 0),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111222233334444)),
        (0x50, *movl_mlx(33, 0x2222333344445555)),
        (0x60, *movl_mlx(34, 0x3333444455556666)),
        (0x70, *movl_mlx(35, 0x4444555566667777)),
        (0x80, *movl_mlx(36, 0x5555666677778888)),
        (0x90, *movl_mlx(37, 0x6666777788889999)),
        (0xa0, *movl_mlx(38, 0x777788889999aaaa)),
        (0xb0, *movl_mlx(39, 0x88889999aaaabbbb)),
        (0xc0, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0xd0, *movl_mlx(3, 0x3000e8)),
        (0xe0, *movl_mlx(4, 0xaaaabbbbccccdddd)),
        (0xf0, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x100, *movl_mlx(3, 0x3000f0)),
        (0x110, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x120, *movl_mlx(3, 0x3000f8)),
        (0x130, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x140, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (0x150, *movl_mlx(20, 0x200)),
        (0x160, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x170, *movl_mlx(20, (1 << 63) | 5)),
        (0x180, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0x190, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x200, 0x18, nop_m(), nop_m(),
         cover_b()),
        (0x210, *movl_mlx(3, 0x300100)),
        (0x220, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x230, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (0x240, *movl_mlx(20, 0x300)),
        (0x250, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x260, *movl_mlx(20, (1 << 63) | 8)),
        (0x270, 0x00, mov_m_gr_cr(20, 23), nop_i(),
         nop_i()),
        (0x280, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x300, 0x00, nop_m(), adds(8, 0, 32),
         adds(9, 0, 33)),
        (0x310, 0x00, nop_m(), adds(10, 0, 34),
         adds(11, 0, 35)),
        (0x320, 0x00, nop_m(), adds(12, 0, 36),
         adds(13, 0, 37)),
        (0x330, 0x00, nop_m(), adds(14, 0, 38),
         adds(15, 0, 39)),
        (0x340, 0x10, nop_m(), nop_i(),
         br_cond(0x340, 0x340)),
    ], {
        "ip": 0x340,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x2222333344445555,
        "r10": 0x3333444455556666,
        "r11": 0x4444555566667777,
        "r12": 0x5555666677778888,
        "r13": 0x6666777788889999,
        "r14": 0x777788889999aaaa,
        "r15": 0x88889999aaaabbbb,
        "cfm_sof": 8,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_bspstore_rebase_writes_no_memory = require_registers(
    "rse_bspstore_rebase_writes_no_memory", [
        (0x10, *movl_mlx(3, 0x2001f8)),
        (0x20, *movl_mlx(4, 1 << 57)),
        (0x30, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(3, 0x1001a8)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(39, 14, 10, 0, 0),
         nop_i()),
        (0x70, *movl_mlx(36, 0x123456789abcdef0)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x100, *movl_mlx(3, 0x2001a8)),
        (0x110, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x120, *movl_mlx(3, 0x2001f8)),
        (0x130, 0x00, ld8(8, 3), nop_i(),
         nop_i()),
        (0x140, *movl_mlx(3, 0x2001c8)),
        (0x150, 0x00, ld8(9, 3), nop_i(),
         nop_i()),
        (0x160, 0x10, nop_m(), nop_i(),
         br_cond(0x160, 0x160)),
    ], {
        "ip": 0x160,
        "exception": IA64_EXCP_NONE,
        "r8": 1 << 57,
        "r9": 0,
        "cfm_sof": 4,
        "cfm_sol": 0,
    }, entry=0x10)

test_rse_br_ret_fill_ignores_rsc_mode = require_registers(
    "rse_br_ret_fill_ignores_rsc_mode", [
        (0x10, *movl_mlx(3, 0x100000)),
        (0x20, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x30, 0x00, alloc(1, 5, 3, 0, 0), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(32, 0x1111)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, mov_m_imm_ar(16, 0), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_ar_gr(8, 18), nop_i(), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x100, 0x00, alloc(2, 0, 0, 0, 0), nop_i(), nop_i()),
        (0x110, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (0x120, *movl_mlx(3, 3)),
        (0x130, 0x00, mov_m_gr_ar(3, 16), nop_i(),
         nop_i()),
        (0x140, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0x80,
        "r8": 0x100000,
    }, entry=0x10)

test_gcc_alloc_and_ar_lc = require_registers("gcc_alloc_and_ar_lc", [
    (0x10, 0x00, alloc_m(63, 42, 34, 0, 0), adds(8, 5, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), mov_lc_gr(8),
     mov_ar_lc(9)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r8": 5, "r9": 5}, entry=0x10)

test_ld1_acq_decode = require_registers("ld1_acq_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, nop_m(), ld1_acq(4, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
    (0x100, 0x00, 0x5a, 0,
     0),
], {"ip": 0x30, "r4": 0x40}, entry=0x10)

LD4_BIAS_DATA = bundle_words(0x00, 0x091a2b3c, 0, 0)[0] & 0xffffffff

test_ld4_bias_decode = require_registers("ld4_bias_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, nop_m(), ld4_bias(4, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
    (0x100, 0x00, 0x091a2b3c, 0,
     0),
], {"ip": 0x30, "r4": LD4_BIAS_DATA}, entry=0x10)

CHECK_LOAD_DATA = bundle_words(0x00, 0x123456789abcdef0, 0, 0)[0]
CHECK_LOAD_MISMATCH_DATA = bundle_words(0x00, 0x0fedcba987654321, 0, 0)[0]
ADV_UC_LOAD_VA = HIGH_TR_BASE + 0x9000
ADV_UC_LOAD_PA = 0x409000
ADV_UC_LOAD_DATA = bundle_words(0x00, 0x1122334455667788, 0, 0)[0]
ADV_UC_LOAD_BUNDLE = (ADV_UC_LOAD_PA, 0x00, 0x1122334455667788, 0, 0)

test_ld8_c_nc_hit_preserves_target = require_registers(
    "ld8_c_nc_hit_preserves_target", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x50, "r4": 0x55}, entry=0x10)

test_ld8_c_nc_hit_consumes_nat_base = require_exception(
    "ld8_c_nc_hit_consumes_nat_base", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x40, 0x08, ld8_fill_postinc(5, 6, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8_c_nc(4, 5), nop_i(),
         nop_i()),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x200, 0x00, 0x100, 0,
         0),
    ], IA64_EXCP_NAT_CONSUMPTION, fault_ip=0x50, entry=0x10)

test_ld8_c_clr_hit_clears_entry = require_registers(
    "ld8_c_clr_hit_clears_entry", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_clr(4, 3), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(4, 0xaa)),
        (0x60, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x70, "r4": CHECK_LOAD_DATA}, entry=0x10)

test_ld4_c_clr_hit_clears_entry = require_registers(
    "ld4_c_clr_hit_clears_entry", [
        (0x10, *movl_mlx(2, 0xfeedface89abcdef)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, st8(3, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, ld4_a(4, 3), nop_i(),
         nop_i()),
        (0x50, 0x00, nop_m(), adds(4, 0x55, 0),
         nop_i()),
        # On an ALAT hit, this implementation takes the architecturally
        # permitted option of leaving the target unchanged.  The .c.clr
        # operation must still remove the four-byte entry (SDM Vol. 1,
        # 4.4.5.3).
        (0x60, 0x00, ld4_c_clr(4, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, nop_m(), adds(5, 0, 4),
         nop_i()),
        (0x80, 0x00, nop_m(), adds(4, 0x66, 0),
         nop_i()),
        # The cleared entry makes this check miss and reload exactly four
        # bytes, zero-extending the result into the general register.
        (0x90, 0x00, ld4_c_nc(4, 3), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r4": 0x89abcdef,
        "r5": 0x55,
    }, entry=0x10)

test_zero_alat_check_load_always_reloads = require_registers(
    "zero_alat_check_load_always_reloads", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x50, "r4": CHECK_LOAD_DATA}, entry=0x10, alat=None)

test_zero_alat_chk_a_always_branches = require_registers(
    "zero_alat_chk_a_always_branches", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, chk_a_nc_m(22, 0x30, 0x50), adds(4, 1, 0),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x50, "r4": 0}, entry=0x10, alat=None)

test_ld8_sa_failure_invalidates_old_entry = require_registers(
    "ld8_sa_failure_invalidates_old_entry", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 0x105, 0),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, sum_um(0x8), nop_i(),
         nop_i()),
        (0x40, 0x00, ld8_sa(4, 5), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(4, 0x55)),
        (0x60, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x70, "r4": CHECK_LOAD_DATA}, entry=0x10)

test_ld8_a_uc_zeroes_target_and_skips_alat = require_registers(
    "ld8_a_uc_zeroes_target_and_skips_alat", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_UC),
        (0x70, *movl_mlx(2, ADV_UC_LOAD_VA)),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x90, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0xa0, 0x00, ld8_a(4, 2), nop_i(),
         nop_i()),
        (0xb0, 0x00, nop_m(), adds(5, 0, 4),
         nop_i()),
        (0xc0, 0x00, ld8_c_nc(4, 2), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        ADV_UC_LOAD_BUNDLE,
    ], {"ip": 0xd0, "r4": ADV_UC_LOAD_DATA, "r5": 0,
        "exception": IA64_EXCP_NONE}, entry=0x10)

test_ld8_s_uc_defers = require_registers(
    "ld8_s_uc_defers", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_UC),
        (0x70, *movl_mlx(2, ADV_UC_LOAD_VA)),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x90, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0xa0, 0x00, ld8_s(4, 2), nop_i(),
         nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        ADV_UC_LOAD_BUNDLE,
    ], {"ip": 0xd0, "r4_nat": 1,
        "exception": IA64_EXCP_NONE}, entry=0x10)

test_ld8_c_nc_address_mismatch_reloads = require_registers(
    "ld8_c_nc_address_mismatch_reloads", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 0x110, 0),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_nc(4, 5), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x110, 0x00, 0x0fedcba987654321, 0,
         0),
    ], {"ip": 0x50, "r4": CHECK_LOAD_MISMATCH_DATA}, entry=0x10)

test_ld8_c_clr_address_mismatch_reloads = require_registers(
    "ld8_c_clr_address_mismatch_reloads", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 0x110, 0),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_clr(4, 5), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x110, 0x00, 0x0fedcba987654321, 0,
         0),
    ], {"ip": 0x50, "r4": CHECK_LOAD_MISMATCH_DATA}, entry=0x10)

test_ld16_loads_gr_and_csd = require_registers("ld16_loads_gr_and_csd", [
    (0x10, 0x00, addl(3, 0x104, 0), addl(4, 0x10c, 0),
     nop_i()),
    (0x20, *movl_mlx(16, 0x0123456789abcdef)),
    (0x30, *movl_mlx(17, 0xfedcba9876543210)),
    (0x40, 0x00, st8(3, 16), nop_i(),
     nop_i()),
    (0x50, 0x00, st8(4, 17), nop_i(),
     nop_i()),
    (0x60, 0x00, ld16(8, 3), nop_i(),
     nop_i()),
    (0x70, 0x00, mov_m_ar_gr(9, 25), nop_i(),
     nop_i()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "r8": 0x0123456789abcdef,
    "r9": 0xfedcba9876543210,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_ld16_acq_hint_decode = require_registers("ld16_acq_hint_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), addl(4, 0x108, 0),
     nop_i()),
    (0x20, *movl_mlx(16, 0x1111222233334444)),
    (0x30, *movl_mlx(17, 0x5555666677778888)),
    (0x40, 0x00, st8(3, 16), nop_i(),
     nop_i()),
    (0x50, 0x00, st8(4, 17), nop_i(),
     nop_i()),
    (0x60, 0x00, ld16_acq(8, 3, hint=2), nop_i(),
     nop_i()),
    (0x70, 0x00, mov_m_ar_gr(9, 25), nop_i(),
     nop_i()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "r8": 0x1111222233334444,
    "r9": 0x5555666677778888,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_st16_stores_gr_and_csd = require_registers("st16_stores_gr_and_csd", [
    (0x10, 0x00, addl(3, 0x204, 0), addl(4, 0x20c, 0),
     nop_i()),
    (0x20, *movl_mlx(15, 0x0123456789abcdef)),
    (0x30, *movl_mlx(5, 0xfedcba9876543210)),
    (0x40, 0x00, mov_m_gr_ar(5, 25), nop_i(),
     nop_i()),
    (0x50, 0x00, st16(3, 15), nop_i(),
     nop_i()),
    (0x60, 0x00, ld8(29, 3), nop_i(),
     nop_i()),
    (0x70, 0x00, ld8(30, 4), nop_i(),
     nop_i()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "r29": 0x0123456789abcdef,
    "r30": 0xfedcba9876543210,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_st16_rel_stores_gr_and_csd = require_registers(
    "st16_rel_stores_gr_and_csd", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x208, 0),
         nop_i()),
        (0x20, *movl_mlx(15, 0x1020304050607080)),
        (0x30, *movl_mlx(5, 0x8877665544332211)),
        (0x40, 0x00, mov_m_gr_ar(5, 25), nop_i(),
         nop_i()),
        (0x50, 0x00, st16(3, 15, x6=0x21), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8(29, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, ld8(30, 4), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "r29": 0x1020304050607080,
        "r30": 0x8877665544332211,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)


def montecito_uc_memory_fault_test(name, fault_bundle, address,
                                   expected_isr):
    return require_registers(name, [
        (0x10, *movl_mlx(2, IA64_PSR_IC)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, *movl_mlx(3, address)),
        (0x50, *movl_mlx(4, 0x1122334455667788)),
        (0x60, *fault_bundle),
        (IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR + 0x20,
                 IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR + 0x20)),
    ], {
        "ip": IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_UNSUPPORTED_DATA_REFERENCE,
        "fault_ip": 0x60,
        "r14": address,
        "r15": expected_isr,
    }, entry=0x10)


MONTECITO_UC_16BYTE_ADDRESS = IA64_PHYS_UC_BIT | 0x2000

test_ld16_uc_unsupported_data_reference = montecito_uc_memory_fault_test(
    "ld16_uc_unsupported_data_reference",
    (0x00, ld16(8, 3), nop_i(), nop_i()),
    MONTECITO_UC_16BYTE_ADDRESS, IA64_ISR_R)

test_st16_uc_unsupported_data_reference = montecito_uc_memory_fault_test(
    "st16_uc_unsupported_data_reference",
    (0x00, st16(3, 4), nop_i(), nop_i()),
    MONTECITO_UC_16BYTE_ADDRESS, IA64_ISR_W)

test_cmp8xchg16_uc_unsupported_data_reference = \
    montecito_uc_memory_fault_test(
        "cmp8xchg16_uc_unsupported_data_reference",
        (0x00, cmp8xchg16_acq(8, 3, 4), nop_i(), nop_i()),
        MONTECITO_UC_16BYTE_ADDRESS + 8, IA64_ISR_R | IA64_ISR_W)

# Madison clears CPUID[4].ao, so the 16-byte atomic encodings are reserved.
test_ld16_madison_illegal_operation = require_exception(
    "ld16_madison_illegal_operation", [
        (0x10, 0x00, ld16(8, 3), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10, cpu="madison")

test_st16_madison_illegal_operation = require_exception(
    "st16_madison_illegal_operation", [
        (0x10, 0x00, st16(3, 4), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10, cpu="madison")

test_cmp8xchg16_madison_illegal_operation = require_exception(
    "cmp8xchg16_madison_illegal_operation", [
        (0x10, 0x00, cmp8xchg16_acq(8, 3, 4), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10, cpu="madison")

test_memory_order_completers_decode = require_registers(
    "memory_order_completers_decode", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x300, 0),
         nop_i()),
        (0x20, *movl_mlx(10, 0x0102030405060708)),
        (0x30, 0x00, nop_m(), addl(11, 10, 0),
         nop_i()),
        (0x40, 0x00, st8_rel(3, 10), nop_i(),
         nop_i()),
        (0x50, 0x00, st4(4, 11), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8_c_clr_acq(12, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, fetchadd4_rel(13, 4, 1), nop_i(),
         nop_i()),
        (0x80, 0x00, ld8(14, 4), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r12": 0x0102030405060708,
        "r13": 10,
        "r14": 11,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_data_big_endian_load_store = require_registers(
    "data_big_endian_load_store", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x201, 0),
         addl(5, 0x202, 0)),
        (0x20, 0x00, addl(6, 0x203, 0), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(16, 0x11223344)),
        (0x40, 0x00, sum_um(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0x50, 0x08, st4(3, 16), ld4(17, 3),
         nop_i()),
        (0x60, 0x00, rum(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0x70, 0x08, ld1(18, 3), ld1(19, 4),
         nop_i()),
        (0x80, 0x08, ld1(20, 5), ld1(21, 6),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r17": 0x11223344,
        "r18": 0x11,
        "r19": 0x22,
        "r20": 0x33,
        "r21": 0x44,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_data_big_endian_cmpxchg4 = require_registers(
    "data_big_endian_cmpxchg4", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x201, 0),
         addl(5, 0x202, 0)),
        (0x20, 0x00, addl(6, 0x203, 0), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(10, 0x01020304)),
        (0x40, *movl_mlx(16, 0x01020304)),
        (0x50, *movl_mlx(18, 0x11223344)),
        (0x60, 0x00, sum_um(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0x70, 0x00, st4(3, 16), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_ar(10, 32), nop_i(),
         nop_i()),
        (0x90, 0x00, cmpxchg4_acq(17, 3, 18), nop_i(),
         nop_i()),
        (0xa0, 0x00, rum(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0xb0, 0x08, ld1(19, 3), ld1(20, 4),
         nop_i()),
        (0xc0, 0x08, ld1(21, 5), ld1(22, 6),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "r17": 0x01020304,
        "r19": 0x11,
        "r20": 0x22,
        "r21": 0x33,
        "r22": 0x44,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_data_big_endian_stf_spill_ldf_fill = require_registers(
    "data_big_endian_stf_spill_ldf_fill", [
        (0x10, 0x00, addl(3, 0x204, 0), addl(4, 0x209, 0),
         addl(5, 0x20b, 0)),
        (0x20, 0x00, addl(6, 0x20c, 0), addl(7, 0x213, 0),
         nop_i()),
        (0x30, *movl_mlx(16, 0x1122334455667788)),
        (0x40, 0x09, setf_sig(8, 16), nop_i(),
         nop_i()),
        (0x50, 0x00, sum_um(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0x60, 0x08, stf_spill_postinc(3, 8, 0), nop_i(),
         nop_i()),
        (0x70, 0x09, setf_sig(8, 0), nop_i(),
         nop_i()),
        (0x80, 0x08, ldf_fill_postinc(8, 3, 0), nop_i(),
         nop_i()),
        (0x90, 0x09, rum(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0xa0, 0x08, ld1(10, 3), ld1(11, 4),
         nop_i()),
        (0xb0, 0x08, ld1(12, 5), ld1(13, 6),
         nop_i()),
        (0xc0, 0x08, ld1(14, 7), nop_m(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "f8": ExpectedFP(0x1122334455667788, 0x1003e),
        "r10": 0,
        "r11": 1,
        "r12": 0x3e,
        "r13": 0x11,
        "r14": 0x88,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_data_big_endian_ldfe_stfe = require_registers(
    "data_big_endian_ldfe_stfe", [
        (0x10, 0x00, addl(3, 0x204, 0), addl(4, 0x224, 0),
         addl(5, 0x225, 0)),
        (0x20, 0x00, addl(6, 0x226, 0), addl(7, 0x22d, 0),
         adds(16, 0x3f, 0)),
        (0x30, 0x00, adds(17, 0xff, 0), adds(18, 0x80, 0),
         nop_i()),
        (0x40, 0x08, st1_postinc(3, 16, 1), st1_postinc(3, 17, 1),
         nop_i()),
        (0x50, 0x00, st1_postinc(3, 18, 1), nop_i(),
         nop_i()),
        (0x60, 0x00, addl(3, 0x204, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, sum_um(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0x80, 0x00, ldfe(8, 3), nop_i(),
         nop_i()),
        (0x90, 0x00, stfe(4, 8), nop_i(),
         nop_i()),
        (0xa0, 0x00, rum(IA64_PSR_BE), nop_i(),
         nop_i()),
        (0xb0, 0x08, ld1(10, 4), ld1(11, 5),
         nop_i()),
        (0xc0, 0x08, ld1(12, 6), ld1(13, 7),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "r10": 0x3f,
        "r11": 0xff,
        "r12": 0x80,
        "r13": 0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_store_invalidates_advanced_load = require_registers(
    "store_invalidates_advanced_load", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(5, 0xfeedfacecafebeef)),
        (0x40, 0x00, st8(3, 5), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(4, 0xaa)),
        (0x60, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x70, "r4": 0xfeedfacecafebeef}, entry=0x10)

test_rse_call_invalidates_stacked_alat = require_registers(
    "rse_call_invalidates_stacked_alat", [
        (0x10, 0x00, addl(3, 0x100, 0), alloc(35, 5, 3, 0, 0),
         nop_i()),
        (0x20, 0x00, ld8_a(36, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(36, 0x55)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_call(0, 0x40, 0x80)),
        (0x50, 0x00, ld8_c_nc(36, 3), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x60, "r36": CHECK_LOAD_DATA}, entry=0x10)

test_semaphore_ops_invalidate_advanced_loads = require_registers(
    "semaphore_ops_invalidate_advanced_loads", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x10, 0),
         nop_i()),
        (0x20, 0x08, st4(3, 4), ld4_a(5, 3),
         nop_i()),
        (0x30, 0x00, fetchadd4_acq(7, 3, 1, hint=3, ignored=0xf),
         addl(5, 0xaa, 0),
         nop_i()),
        (0x40, 0x00, ld4_c_nc(5, 3), addl(3, 0x210, 0),
         addl(4, 0x20, 0)),

        (0x50, 0x08, st4(3, 4), ld4_a(8, 3),
         addl(6, 0x33, 0)),
        (0x60, 0x00, xchg4(9, 3, 6), addl(8, 0xbb, 0),
         nop_i()),
        (0x70, 0x00, ld4_c_nc(8, 3), addl(3, 0x220, 0),
         addl(4, 0x40, 0)),

        (0x80, 0x08, st4(3, 4), ld4_a(10, 3),
         addl(6, 0x55, 0)),
        (0x90, 0x00, mov_m_imm_ar(32, 0x40), addl(10, 0xcc, 0),
         nop_i()),
        (0xa0, 0x00, cmpxchg4_acq(11, 3, 6), nop_i(),
         nop_i()),
        (0xb0, 0x00, ld4_c_nc(10, 3), addl(3, 0x230, 0),
         addl(4, 0x60, 0)),

        (0xc0, 0x08, st4(3, 4), ld4_a(12, 3),
         addl(6, 0x66, 0)),
        (0xd0, 0x00, mov_m_imm_ar(32, 0x61), addl(12, 0xdd, 0),
         nop_i()),
        (0xe0, 0x00, cmpxchg4_acq(13, 3, 6), nop_i(),
         nop_i()),
        (0xf0, 0x10, ld4_c_nc(12, 3), nop_i(),
         br_cond(0xf0, 0x100)),
        (0x100, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
    ], {"ip": 0x100, "r5": 0x11, "r7": 0x10,
        "r8": 0x33, "r9": 0x20, "r10": 0x55, "r11": 0x40,
        "r12": 0xdd, "r13": 0x60}, entry=0x10)

test_xchg4_result_base_alias_invalidates_alat = require_registers(
    "xchg4_result_base_alias_invalidates_alat", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x11, 0),
         nop_i()),
        (0x20, 0x08, st4(3, 4), ld4_a(5, 3),
         addl(6, 0x22, 0)),
        (0x30, 0x00, xchg4(3, 3, 6), addl(5, 0xaa, 0),
         nop_i()),
        (0x40, 0x00, addl(7, 0x200, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, ld4_c_nc(5, 7), nop_i(),
         nop_i()),
        (0x60, 0x00, ld4(8, 7), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {"ip": 0x70, "r3": 0x11, "r5": 0x22, "r8": 0x22},
    entry=0x10)

test_fetchadd4_result_base_alias_invalidates_alat = require_registers(
    "fetchadd4_result_base_alias_invalidates_alat", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x10, 0),
         nop_i()),
        (0x20, 0x08, st4(3, 4), ld4_a(5, 3),
         nop_i()),
        (0x30, 0x00, fetchadd4_acq(3, 3, 1), addl(5, 0xaa, 0),
         nop_i()),
        (0x40, 0x00, addl(7, 0x200, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, ld4_c_nc(5, 7), nop_i(),
         nop_i()),
        (0x60, 0x00, ld4(8, 7), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {"ip": 0x70, "r3": 0x10, "r5": 0x11, "r8": 0x11},
    entry=0x10)

test_cmpxchg4_result_base_alias_success_invalidates_alat = require_registers(
    "cmpxchg4_result_base_alias_success_invalidates_alat", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x40, 0),
         nop_i()),
        (0x20, 0x08, st4(3, 4), ld4_a(5, 3),
         addl(6, 0x55, 0)),
        (0x30, 0x00, mov_m_imm_ar(32, 0x40), nop_i(),
         nop_i()),
        (0x40, 0x00, cmpxchg4_acq(3, 3, 6), addl(5, 0xaa, 0),
         nop_i()),
        (0x50, 0x00, addl(7, 0x200, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, ld4_c_nc(5, 7), nop_i(),
         nop_i()),
        (0x70, 0x00, ld4(8, 7), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r3": 0x40, "r5": 0x55, "r8": 0x55},
    entry=0x10)

test_cmpxchg4_result_base_alias_failure_keeps_alat = require_registers(
    "cmpxchg4_result_base_alias_failure_keeps_alat", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x40, 0),
         nop_i()),
        (0x20, 0x08, st4(3, 4), ld4_a(5, 3),
         addl(6, 0x55, 0)),
        (0x30, 0x00, mov_m_imm_ar(32, 0x41), nop_i(),
         nop_i()),
        (0x40, 0x00, cmpxchg4_acq(3, 3, 6), addl(5, 0xaa, 0),
         nop_i()),
        (0x50, 0x00, addl(7, 0x200, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, ld4_c_nc(5, 7), nop_i(),
         nop_i()),
        (0x70, 0x00, ld4(8, 7), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r3": 0x40, "r5": 0xaa, "r8": 0x40},
    entry=0x10)

test_cmpxchg4_full_ar_ccv_compare = require_registers(
    "cmpxchg4_full_ar_ccv_compare", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0x40, 0),
         nop_i()),
        (0x20, *movl_mlx(9, 0x100000040)),
        (0x30, 0x08, st4(3, 4), ld4_a(5, 3),
         addl(6, 0x55, 0)),
        (0x40, 0x00, mov_m_gr_ar(9, 32), addl(5, 0xaa, 0),
         nop_i()),
        (0x50, 0x00, cmpxchg4_acq(10, 3, 6), nop_i(),
         nop_i()),
        (0x60, 0x00, ld4_c_nc(5, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, ld4(8, 3), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r5": 0xaa, "r8": 0x40, "r10": 0x40},
    entry=0x10)

test_semaphore_ops_clear_result_nat = require_registers(
    "semaphore_ops_clear_result_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),

        (0x20, *movl_mlx(3, 0x300)),
        (0x30, 0x00, addl(4, 0x44, 0), nop_i(),
         nop_i()),
        (0x40, 0x08, st4(3, 4), ld8_fill_postinc(7, 6, 0),
         nop_i()),
        (0x50, 0x00, fetchadd4_acq(7, 3, 1), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x00, nop_m(), nop_i(), nop_i()),

        (0x80, *movl_mlx(3, 0x310)),
        (0x90, 0x00, addl(4, 0x55, 0), addl(8, 0x66, 0),
         nop_i()),
        (0xa0, 0x08, st4(3, 4), ld8_fill_postinc(9, 6, 0),
         nop_i()),
        (0xb0, 0x00, xchg4(9, 3, 8), nop_i(),
         nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x00, nop_m(), nop_i(), nop_i()),

        (0xe0, *movl_mlx(3, 0x320)),
        (0xf0, 0x00, addl(4, 0x77, 0), addl(10, 0x88, 0),
         nop_i()),
        (0x100, 0x08, st4(3, 4), ld8_fill_postinc(11, 6, 0),
         nop_i()),
        (0x110, 0x00, mov_m_gr_ar(4, 32), nop_i(),
         nop_i()),
        (0x120, 0x00, cmpxchg4_acq(11, 3, 10), nop_i(),
         nop_i()),
        (0x130, 0x00, nop_m(), nop_i(), nop_i()),
        (0x140, 0x00, nop_m(), nop_i(), nop_i()),

        (0x150, *movl_mlx(3, 0x330)),
        (0x160, 0x00, addl(4, 0x99, 0), addl(10, 0xaa, 0),
         nop_i()),
        (0x170, 0x08, st4(3, 4), ld8_fill_postinc(12, 6, 0),
         nop_i()),
        (0x180, 0x00, mov_m_imm_ar(32, 0x98), nop_i(),
         nop_i()),
        (0x190, 0x00, cmpxchg4_acq(12, 3, 10), nop_i(),
         nop_i()),
        (0x1a0, 0x00, nop_m(), nop_i(), nop_i()),
        (0x1b0, 0x00, nop_m(), nop_i(), nop_i()),

        (0x1c0, 0x10, nop_m(), nop_i(),
         br_cond(0x1c0, 0x1c0)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x1c0, "r7": 0x44, "r7_nat": 0,
        "r9": 0x55, "r9_nat": 0,
        "r11": 0x77, "r11_nat": 0,
        "r12": 0x99, "r12_nat": 0}, entry=0x10)

test_fetchadd4_alt_dtlb_sets_read_write_isr = require_registers(
    "fetchadd4_alt_dtlb_sets_read_write_isr", [
        (0x10, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 44))),
        (0x20, *movl_mlx(3, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, fetchadd4_acq(7, 3, 1), nop_i(),
         nop_i()),
        (0x1000, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x1010, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x1020, 0x10, nop_m(), nop_i(),
         br_cond(0x1020, 0x1020)),
    ], {
        "ip": 0x1020,
        "exception": IA64_EXCP_NONE,
        "r14": HIGH_TR_BASE + 0x20000,
        "r15": IA64_ISR_R | IA64_ISR_W,
    }, entry=0x10)

test_fetchadd4_unaligned_sets_read_write_isr = require_registers(
    "fetchadd4_unaligned_sets_read_write_isr", [
        (0x10, 0x00, addl(3, 0x101, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x40, 0x00, fetchadd4_acq(7, 3, 1), nop_i(),
         nop_i()),
        (0x5a00, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5a10, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5a20, 0x10, nop_m(), nop_i(),
         br_cond(0x5a20, 0x5a20)),
    ], {
        "ip": 0x5a20,
        "exception": IA64_EXCP_NONE,
        "r14": 0x101,
        "r15": IA64_ISR_R | IA64_ISR_W,
    }, entry=0x10)

test_fetchadd4_nat_base_sets_read_write_isr = require_registers(
    "fetchadd4_nat_base_sets_read_write_isr", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, fetchadd4_acq(7, 3, 1), nop_i(),
         nop_i()),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x5620,
        "exception": IA64_EXCP_NONE,
        "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_NA |
               IA64_ISR_R | IA64_ISR_W,
    }, entry=0x10)

NORMAL_LOAD_DATA = bundle_words(0x00, 0xdead, 0, 0)[0]

test_integer_nat_propagates_and_clears = require_registers(
    "integer_nat_propagates_and_clears", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(4, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(5, 4, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), adds(6, 1, 5),
         adds(7, 1, 0)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x60, "r6_nat": 1, "r7_nat": 0}, entry=0x10)

test_normal_load_clears_stale_nat = require_registers(
    "normal_load_clears_stale_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(5, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x08, ld8(5, 6), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (0x200, 0x00, 0xdead, 0,
         0),
    ], {"ip": 0x40, "r5": NORMAL_LOAD_DATA, "r5_nat": 0},
    entry=0x10)

test_integer_compare_nat_source_rules = require_registers(
    "integer_compare_nat_source_rules", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(8, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 8, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, cmp4_eq_imm(6, 7, 1, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, cmp_ge_or(8, 9, 3), nop_i(),
         nop_i()),
        (0x50, 0x00, cmp4_eq_unc_imm(10, 0, 0, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, cmp4_eq_unc_imm(11, 0, 0, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, cmp_eq_and(10, 11, 0, 3), nop_i(),
         nop_i()),
        (0x80, 0x00, nop_m(), adds(4, 1, 0, qp=6),
         adds(5, 1, 0, qp=7)),
        (0x90, 0x00, nop_m(), adds(12, 1, 0, qp=8),
         adds(13, 1, 0, qp=9)),
        (0xa0, 0x00, nop_m(), adds(14, 1, 0, qp=10),
         adds(15, 1, 0, qp=11)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0xb0,
        "r4": 0,
        "r5": 0,
        "r12": 0,
        "r13": 0,
        "r14": 0,
        "r15": 0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_tbit_nat_source_rules = require_registers(
    "tbit_nat_source_rules", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(8, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 8, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, nop_m(), tbit_z(6, 7, 3, 0),
         nop_i()),
        (0x40, 0x00, nop_m(), tbit_z_or(8, 9, 3, 0),
         nop_i()),
        (0x50, 0x00, cmp4_eq_unc_imm(10, 0, 0, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, cmp4_eq_unc_imm(11, 0, 0, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, nop_m(), tbit_z_and(10, 11, 3, 0),
         nop_i()),
        (0x80, 0x00, nop_m(), adds(4, 1, 0, qp=6),
         adds(5, 1, 0, qp=7)),
        (0x90, 0x00, nop_m(), adds(12, 1, 0, qp=8),
         adds(13, 1, 0, qp=9)),
        (0xa0, 0x00, nop_m(), adds(14, 1, 0, qp=10),
         adds(15, 1, 0, qp=11)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0xb0,
        "r4": 0,
        "r5": 0,
        "r12": 0,
        "r13": 0,
        "r14": 0,
        "r15": 0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_normal_load_consumes_nat_base = require_exception(
    "normal_load_consumes_nat_base", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x08, ld1(4, 3), nop_i(),
         nop_i()),
        (0x200, 0x00, 0, 0,
         0),
    ], IA64_EXCP_NAT_CONSUMPTION, fault_ip=0x30, entry=0x10)

test_nat_consumption_sets_ifa_isr = require_registers(
    "nat_consumption_sets_ifa_isr", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x08, ld1(4, 3), nop_i(),
         nop_i()),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x5620, "exception": IA64_EXCP_NONE, "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_NA | IA64_ISR_R},
    entry=0x10)

test_nat_store_data_consumption_is_access = require_registers(
    "nat_store_data_consumption_is_access", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(5, 6, 0), addl(7, 0x208, 0),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, st8(7, 5), nop_i(),
         nop_i()),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x5620, "exception": IA64_EXCP_NONE, "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_W}, entry=0x10)

test_speculative_load_defers_nat_base = require_registers(
    "speculative_load_defers_nat_base", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x08, ld8_s(4, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x60, "exception": IA64_EXCP_NONE, "r4_nat": 1},
    entry=0x10)

test_speculative_load_defers_psr_ed = require_registers(
    "speculative_load_defers_psr_ed", [
        (0x10, *movl_mlx(16, IA64_PSR_ED)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(17, 0x100)),
        (0x40, 0x00, mov_m_gr_cr(16, 16), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(17, 19), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x100, 0x00, ld8_s(4, 3), nop_i(),
         nop_i()),
        (0x110, 0x00, nop_m(), nop_i(), nop_i()),
        (0x120, 0x00, nop_m(), nop_i(), nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
        (0x200, 0x00, 0x12345678, 0,
         0),
    ], {"ip": 0x130, "exception": IA64_EXCP_NONE, "r4_nat": 1},
    entry=0x10)

test_speculative_load_no_recovery_tlb_miss_faults = require_registers(
    "speculative_load_no_recovery_tlb_miss_faults", [
        (0x10, *movl_mlx(2, 0xa000000100020000)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8_s(4, 2), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_ISR_R | IA64_ISR_SP,
    }, entry=0x10)

# A control-speculative load whose page has no ED bit and that runs with
# instruction translation off (PSR.it == 0, as the OS loaders and early kernel
# do) must still defer a deferrable TLB fault when the matching DCR mask bit is
# set: DCR-based deferral is independent of PSR.it and of the code page's ED
# bit.  Without this, XP's SETUPLDR/NTOSKRNL ld.s over a NaTVal pointer faults
# instead of deferring, cascading into a break loop.  (The existing
# speculative_recovery_dcr_dm_defers_tlb_miss test sets PSR.it and ED as well,
# so it did not exercise the DCR-only path.)
test_speculative_load_defers_via_dcr_without_ed = require_registers(
    "speculative_load_defers_via_dcr_without_ed", [
        (0x10, *movl_mlx(20, IA64_DCR_DM)),
        (0x20, 0x00, mov_m_gr_cr(20, 0), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(2, 0xa000000100020000)),
        (0x40, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x50, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x60, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x70, 0x00, ld8_s(4, 2), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r4_nat": 1,
    }, entry=0x10)

test_speculative_load_handler_psr_ed_defers_retry = require_registers(
    "speculative_load_handler_psr_ed_defers_retry", [
        (0x10, *movl_mlx(2, 0xa000000100020000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8_s_postinc(4, 2, 8), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_psr_gr(8), nop_i(),
         nop_i()),
        (0x70, 0x00, nop_m(), nop_i(), nop_i()),
        (0x80, 0x00, nop_m(), tbit_z(3, 4, 8, 43),
         nop_i()),
        (0x90, 0x00, nop_m(), addl(9, 1, 0, qp=3),
         addl(10, 1, 0, qp=4)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(20, 16),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, *movl_mlx(21, IA64_PSR_ED)),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x00, nop_m(),
         or_reg(20, 20, 21), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 16),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r2": 0xa000000100020008,
        "r4_nat": 1,
        "r9": 1,
        "r10": 0,
    }, entry=0x10)

test_speculative_unaligned_no_recovery_faults = require_registers(
    "speculative_unaligned_no_recovery_faults", [
        (0x10, 0x00, nop_m(), addl(3, 0x104, 0),
         nop_i()),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 3))),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8_s(4, 3), nop_i(),
         nop_i()),
        (IA64_UNALIGNED_VECTOR, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_UNALIGNED_VECTOR + 0x10,
                 IA64_UNALIGNED_VECTOR + 0x10)),
    ], {
        "ip": IA64_UNALIGNED_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_ISR_R | IA64_ISR_SP,
    }, entry=0x10)

test_speculative_unimplemented_physical_unaligned_defers = require_registers(
    "speculative_unimplemented_physical_unaligned_defers", [
        (0x10, *movl_mlx(3, 0x76520ec5b2369f9e)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_AC)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, ld8_s(4, 3), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "r4_nat": 1,
    }, entry=0x10)

test_unimplemented_physical_load_faults = require_registers(
    "unimplemented_physical_load_faults", [
        (0x10, *movl_mlx(3, 1 << IA64_IMPL_PA_BITS)),
        (0x20, *movl_mlx(19, IA64_PSR_IC)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, ld8(4, 3), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x00, mov_m_cr_gr(10, 20),
         nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x30,
                 IA64_GENERAL_VECTOR + 0x30)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0x50,
        "r9": IA64_GENEX_UNIMPL_DATA_ADDR | IA64_ISR_R,
        "r10": 1 << IA64_IMPL_PA_BITS,
    }, entry=0x10)

test_unimplemented_physical_precludes_unaligned = require_registers(
    "unimplemented_physical_precludes_unaligned", [
        (0x10, *movl_mlx(3, (1 << IA64_IMPL_PA_BITS) | 1)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_AC)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, ld8(4, 3), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x00, mov_m_cr_gr(10, 20),
         nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x30,
                 IA64_GENERAL_VECTOR + 0x30)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0x50,
        "r9": IA64_GENEX_UNIMPL_DATA_ADDR | IA64_ISR_R,
        "r10": (1 << IA64_IMPL_PA_BITS) | 1,
    }, entry=0x10)

test_unimplemented_physical_instruction_traps = require_registers(
    "unimplemented_physical_instruction_traps", [
        (0x10, *movl_mlx(3, 1 << IA64_IMPL_PA_BITS)),
        (0x20, *movl_mlx(19, IA64_PSR_IC)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), mov_br_gr(7, 3), nop_i()),
        (0x60, 0x11, nop_m(), nop_i(), br_indirect(7)),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR, 0x00,
         mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(9, 17), nop_i(), nop_i()),
        (IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20,
                 IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20)),
    ], {
        "ip": IA64_LOWER_PRIV_TRANSFER_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": IA64_GENEX_UNIMPL_INST_ADDR | IA64_ISR_X,
    }, entry=0x10)

test_speculative_recovery_dcr_dm_defers_tlb_miss = require_registers(
    "speculative_recovery_dcr_dm_defers_tlb_miss", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 36))),
        (0x30, *movl_mlx(20, IA64_DCR_DM)),
        (0x40, *movl_mlx(2, 0xa000000100020000)),
        (0x50, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(20, 0), nop_i(),
         nop_i()),
        (0x80, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x90, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_d(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0xb0, 19, 31),
        (0x4000430, 0x00, ld8_s(31, 2), nop_i(),
         nop_i()),
        (0x4000440, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000450, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000460, 0x10, nop_m(), nop_i(),
         br_cond(0x4000460, 0x460)),
    ], {
        "ip": 0x460,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

test_speculative_recovery_dcr_da_defers_access_bit = require_registers(
    "speculative_recovery_dcr_da_defers_access_bit", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, *movl_mlx(23, LOW_VECTOR_TR_PTE & ~PTE_ACCESSED)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 36))),
        (0x40, *movl_mlx(20, IA64_DCR_DA)),
        (0x50, *movl_mlx(2, 0x2000)),
        (0x60, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(20, 0), adds(6, 6, 0),
         nop_i()),
        (0x90, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0xa0, 0x00, itr_d(6, 23), nop_i(),
         nop_i()),
        (0xb0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xc0, 0x00, srlz_d(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0xd0, 19, 31),
        (0x4000430, 0x00, ld8_s(31, 2), nop_i(),
         nop_i()),
        (0x4000440, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000450, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000460, 0x10, nop_m(), nop_i(),
         br_cond(0x4000460, 0x460)),
    ], {
        "ip": 0x460,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

test_speculative_recovery_dcr_dk_defers_key_miss = require_registers(
    "speculative_recovery_dcr_dk_defers_key_miss", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, *movl_mlx(23, LOW_VECTOR_TR_PTE)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 17) |
                         (1 << 36) | IA64_PSR_PK)),
        (0x40, *movl_mlx(20, IA64_DCR_DK)),
        (0x50, *movl_mlx(2, 0x2000)),
        (0x60, *movl_mlx(4, IA64_PKR_VALID)),
        (0x70, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x90, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(20, 0), adds(3, 0, 0),
         nop_i()),
        (0xb0, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(7, KEY_TEST_ITIR)),
        (0xd0, 0x00, mov_m_gr_cr(7, 21), adds(6, 6, 0),
         nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xf0, 0x00, itr_d(6, 23), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0x110, 0x00, srlz_d(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0x120, 19, 31),
        (0x4000430, 0x00, ld8_s(31, 2), nop_i(),
         nop_i()),
        (0x4000440, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000450, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000460, 0x10, nop_m(), nop_i(),
         br_cond(0x4000460, 0x460)),
    ], {
        "ip": 0x460,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

test_speculative_recovery_unaligned_defers = require_registers(
    "speculative_recovery_unaligned_defers", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, 0x00, nop_m(), addl(3, 0x104, 0),
         nop_i()),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 36) | (1 << 3))),
        (0x40, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_i(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0x80, 19, 31),
        (0x4000430, 0x00, ld8_s(31, 3), nop_i(),
         nop_i()),
        (0x4000440, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000450, 0x00, nop_m(), nop_i(), nop_i()),
        (0x4000460, 0x10, nop_m(), nop_i(),
         br_cond(0x4000460, 0x460)),
    ], {
        "ip": 0x460,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

test_ws2003_cmd646_unaligned_check_load_sets_ed = require_registers(
    "ws2003_cmd646_unaligned_check_load_sets_ed", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, 0x00, nop_m(), addl(3, 0x101, 0),
         nop_i()),
        (0x30, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_IT | IA64_PSR_AC)),
        (0x40, 0x00, adds(7, 16 << 2, 0), adds(5, 5, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_i(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0x80, 19, 31),
        (0x4000430, 0x00, ld2_sa(30, 3), nop_i(),
         nop_i()),
        (0x4000440, 0x00, ld2_c_clr(30, 3), nop_i(),
         nop_i()),
        (0x4000000 + IA64_UNALIGNED_VECTOR, 0x00,
         mov_m_cr_gr(14, 20),
         nop_i(), nop_i()),
        (0x4000000 + IA64_UNALIGNED_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17),
         nop_i(), nop_i()),
        (0x4000000 + IA64_UNALIGNED_VECTOR + 0x20, 0x00,
         mov_m_cr_gr(16, 22),
         nop_i(), nop_i()),
        (0x4000000 + IA64_UNALIGNED_VECTOR + 0x30, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_UNALIGNED_VECTOR + 0x30,
                 IA64_UNALIGNED_VECTOR + 0x30)),
    ], {
        "ip": IA64_UNALIGNED_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r14": 0x101,
        "r15": IA64_ISR_R | IA64_ISR_ED,
        "r16": 0x430,
    }, entry=0x10)

test_ld8_s_d2_hint_decode = require_registers("ld8_s_d2_hint_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, ld8_s_hint(4, 3, 2), nop_i(),
     nop_i()),
    (0x30, 0x00, nop_m(), nop_i(), nop_i()),
    (0x40, 0x00, nop_m(), nop_i(), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
    (0x100, 0x00, 0x1122334455667788, 0,
     0),
], {"ip": 0x50, "exception": IA64_EXCP_NONE, "r4_nat": 1}, entry=0x10)

test_mov_crgr_clears_stale_nat = require_registers(
    "mov_crgr_clears_stale_nat", [
        (0x10, 0x00, addl(3, 0x104, 0), addl(5, 0x200, 0),
         nop_i()),
        (0x20, 0x00, sum_um(0x8), addl(16, 0x188, 0),
         nop_i()),
        (0x30, 0x00, ld8_s(28, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(16, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_cr_gr(28, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, st8(5, 28), nop_i(),
         nop_i()),
        (0x70, 0x00, ld8(31, 5), nop_i(),
         nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x00, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {"ip": 0xa0, "exception": IA64_EXCP_NONE, "r28_nat": 0,
        "r31": 0x188}, entry=0x10)

test_ld1_postinc_decode = require_registers("ld1_postinc_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, ld1_postinc(4, 3, 1), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
    (0x100, 0x00, 0x5a, 0,
     0),
], {"ip": 0x30, "r3": 0x101, "r4": 0x40}, entry=0x10)

test_ld1_reg_postinc_decode = require_registers(
    "ld1_reg_postinc_decode", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 1, 0),
         nop_i()),
        (0x20, 0x08, ld1_reg_postinc(4, 3, 5), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
        (0x100, 0x00, 0x5a, 0,
        0),
    ], {"ip": 0x30, "r3": 0x101, "r4": 0x40}, entry=0x10)

test_ld1_reg_postinc_uses_old_increment = require_registers(
    "ld1_reg_postinc_uses_old_increment", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 1, 0),
         nop_i()),
        (0x20, 0x08, ld1_reg_postinc(5, 3, 5), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
        (0x100, 0x00, 0x5a, 0,
         0),
    ], {"ip": 0x30, "r3": 0x101, "r5": 0x40}, entry=0x10)

test_ld_reg_postinc_same_target_illegal = require_exception(
    "ld_reg_postinc_same_target_illegal", [
        (0x10, 0x08, ld1_reg_postinc(3, 3, 5), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_ld_imm_postinc_same_target_illegal = require_exception(
    "ld_imm_postinc_same_target_illegal", [
        (0x10, 0x08, ld1_postinc(3, 3, 0), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_ld_postinc_same_target_predicated_false = require_registers(
    "ld_postinc_same_target_predicated_false", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x08, ld1_postinc(3, 3, 0, qp=1), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
        (0x100, 0x00, 0x5a, 0,
         0),
    ], {"ip": 0x30, "r3": 0x100, "exception": IA64_EXCP_NONE}, entry=0x10)

test_ld1_sa_postinc_decode = require_registers("ld1_sa_postinc_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, ld1_sa_postinc(4, 3, 2), nop_i(),
     nop_i()),
    (0x30, 0x00, nop_m(), nop_i(), nop_i()),
    (0x40, 0x00, nop_m(), nop_i(), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
    (0x100, 0x00, 0x5a, 0,
     0),
], {"ip": 0x50, "r3": 0x102, "r4_nat": 1},
   entry=0x10)

test_ld8_nt1_postinc_decode = require_registers("ld8_nt1_postinc_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, ld8_postinc(4, 3, 8, hint=1), nop_i(),
     nop_i()),
    (0x30, 0x08, ld8_s_postinc(5, 3, 8, hint=1), nop_i(),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
    (0x100, 0x00, 0x12345678, 0,
     0),
], {"ip": 0x40, "r3": 0x110, "exception": IA64_EXCP_NONE}, entry=0x10)

MEMORY_HINT_LD2_DATA = bundle_words(0x00, 0x1234, 0, 0)[0] & 0xffff
MEMORY_HINT_XCHG_OLD = bundle_words(0x00, 0x12, 0, 0)[0] & 0xff
MEMORY_HINT_CMPXCHG_OLD = bundle_words(0x00, 0x3344, 0, 0)[0] & 0xffff
MEMORY_HINT_LD4_ACQ_DATA = bundle_words(0x00, 0x778899aa, 0, 0)[0] & 0xffffffff

test_memory_cache_hints_decode = require_registers(
    "memory_cache_hints_decode", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 2, 0),
         nop_i()),
        (0x20, 0x00, ld2_c_clr_reg_update(4, 3, 5, hint=3), addl(6, 0xab, 0),
         addl(8, 0x200, 0)),
        (0x30, 0x00, xchg(0, 7, 8, 6, hint=3), nop_i(),
         nop_i()),
        (0x40, 0x00, ld1(9, 8), addl(10, 0x210, 0),
         addl(11, 0x5566, 0)),
        (0x50, 0x00, addl(14, MEMORY_HINT_CMPXCHG_OLD, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_ar(14, 32), nop_i(),
         nop_i()),
        (0x70, 0x00, cmpxchg_rel(1, 12, 10, 11, hint=1), nop_i(),
         nop_i()),
        (0x80, 0x00, ld2(13, 10), addl(15, 0x220, 0),
         nop_i()),
        (0x90, 0x10, ld4_c_clr_acq(16, 15, hint=3), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, 0x1234, 0,
         0),
        (0x200, 0x00, 0x12, 0,
         0),
        (0x210, 0x00, 0x3344, 0,
         0),
        (0x220, 0x00, 0x778899aa, 0,
         0),
    ], {
        "ip": 0xa0,
        "r3": 0x102,
        "r4": MEMORY_HINT_LD2_DATA,
        "r7": MEMORY_HINT_XCHG_OLD,
        "r9": 0xab,
        "r12": MEMORY_HINT_CMPXCHG_OLD,
        "r13": 0x5566,
        "r16": MEMORY_HINT_LD4_ACQ_DATA,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ld8_fill_st8_spill_postinc_decode = require_registers(
    "ld8_fill_st8_spill_postinc_decode", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, *movl_mlx(16, 0x123456789abcdef0)),
        (0x30, 0x00, st8_spill_postinc(3, 16, 16), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(16, 0)),
        (0x50, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8_fill_postinc(17, 3, 16), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r3": 0x110,
        "r16": 0,
        "r17": 0x123456789abcdef0,
    }, entry=0x10)

test_ld8_fill_restores_unat_bit = require_registers(
    "ld8_fill_restores_unat_bit", [
        (0x10, *movl_mlx(9, 1 << 32)),
        (0x20, 0x00, mov_m_gr_ar(9, 36), addl(3, 0x100, 0),
         nop_i()),
        (0x30, 0x00, ld8_fill_postinc(17, 3, 0), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r17_nat": 1,
        "ar_unat": 1 << 32,
    }, entry=0x10)

test_st8_spill_updates_unat_bit = require_registers(
    "st8_spill_updates_unat_bit", [
        (0x10, *movl_mlx(9, 1 << 32)),
        (0x20, 0x00, mov_m_gr_ar(9, 36), addl(3, 0x100, 0),
         nop_i()),
        (0x30, *movl_mlx(16, 0x123456789abcdef0)),
        (0x40, 0x00, st8_spill_postinc(3, 16, 16), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {"ip": 0x50, "ar_unat": 0}, entry=0x10)

test_integer_postinc_imm9_decode = require_registers(
    "integer_postinc_imm9_decode", [
        (0x10, 0x00, addl(3, 0x300, 0), nop_i(),
         nop_i()),
        (0x20, *movl_mlx(16, 0x8877665544332211)),
        (0x30, 0x00, st8_spill_postinc(3, 16, 176), nop_i(),
         nop_i()),
        (0x40, 0x00, nop_m(), adds(4, 0, 3),
         nop_i()),
        (0x50, 0x00, addl(3, 0x300, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8_fill_postinc(17, 3, -200), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r3": 0x238,
        "r4": 0x3b0,
        "r17": 0x8877665544332211,
    }, entry=0x10)

LDF8_DATA = bundle_words(0x00, 0x123456789a, 0x1abcdef, 0)[0]

test_ldf8_decode = require_registers("ldf8_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, ldf8(6, 3, hint=1), nop_i(),
     nop_i()),
    (0x30, 0x00, ldf8_s(7, 3), nop_i(),
     nop_i()),
    (0x40, 0x00, ldf8_sa(8, 3), nop_i(),
     nop_i()),
    (0x50, 0x00, getf_sig(4, 6), nop_i(),
     nop_i()),
    (0x60, 0x00, getf_sig(5, 7), nop_i(),
     nop_i()),
    (0x70, 0x00, getf_sig(6, 8), nop_i(),
     nop_i()),
    (0x80, 0x00, nop_m(), nop_i(), nop_i()),
    (0x90, 0x00, nop_m(), nop_i(), nop_i()),
    (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
    (0x100, 0x00, 0x123456789a, 0x1abcdef,
     0),
], {"ip": 0xb0, "r4": LDF8_DATA, "r5_nat": 1, "r6_nat": 1,
    "exception": IA64_EXCP_NONE}, entry=0x10)

LDFD_MEMORY_BITS = 0xc004000000000001

test_ldfd_loads_double_memory_format = require_registers(
    "ldfd_loads_double_memory_format", [
        (0x10, *movl_mlx(2, LDFD_MEMORY_BITS)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, st8(3, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, ldfd(8, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "exception": IA64_EXCP_NONE,
        # Observe the architected FR representation directly: ldfd expands
        # the IEEE binary64 memory encoding into register format (SDM Vol. 1,
        # Figure 5-5), rather than treating it as an integer payload.
        "f8": ExpectedFP(*binary64_to_spill(LDFD_MEMORY_BITS)),
    }, entry=0x10)

test_ldf8_s_chk_s_f_defers_nat_base = require_registers(
    "ldf8_s_chk_s_f_defers_nat_base", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, chk_s_f(7, 0x40, 0x60), nop_i(),
         nop_i()),
        (0x50, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x200, 0x00, 0, 0,
         0),
    ], {"ip": 0x60, "r4": 0, "exception": IA64_EXCP_NONE}, entry=0x10)

test_ldf8_a_chk_a_f_hit = require_registers("ldf8_a_chk_a_f_hit", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, ldf8_a(7, 3), nop_i(),
     nop_i()),
    (0x30, 0x00, chk_a_nc_f(7, 0x30, 0x50), adds(31, 0x56, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
    (0x100, 0x00, 0x123456789abcdef0, 0,
     0),
], {"ip": 0x40, "r31": 0x56, "exception": IA64_EXCP_NONE}, entry=0x10)

test_ldf8_c_nc_hit_preserves_target = require_registers(
    "ldf8_c_nc_hit_preserves_target", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(4, 0x55, 0),
         nop_i()),
        (0x20, 0x00, ldf8_a(7, 3), nop_i(),
         nop_i()),
        (0x30, 0x09, setf_sig(7, 4), nop_i(),
         nop_i()),
        (0x40, 0x00, ldf8_c_nc(7, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, getf_sig(5, 7), nop_i(),
         br_cond(0x50, 0x60)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x60, "r5": 0x55, "exception": IA64_EXCP_NONE}, entry=0x10)

test_ldf8_c_nc_hit_consumes_nat_base = require_exception(
    "ldf8_c_nc_hit_consumes_nat_base", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ldf8_a(7, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x40, 0x08, ld8_fill_postinc(5, 6, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, ldf8_c_nc(7, 5), nop_i(),
         nop_i()),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x200, 0x00, 0x100, 0,
         0),
    ], IA64_EXCP_NAT_CONSUMPTION, fault_ip=0x50, entry=0x10)

test_ldf8_a_uc_zeroes_target_and_skips_alat = require_registers(
    "ldf8_a_uc_zeroes_target_and_skips_alat", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_UC),
        (0x70, *movl_mlx(2, ADV_UC_LOAD_VA)),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x90, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0xa0, 0x00, ldf8_a(7, 2), nop_i(),
         nop_i()),
        (0xb0, 0x00, getf_sig(5, 7), nop_i(),
         nop_i()),
        (0xc0, 0x00, ldf8_c_nc(7, 2), nop_i(),
         nop_i()),
        (0xd0, 0x10, getf_sig(6, 7), nop_i(),
         br_cond(0xd0, 0xe0)),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
        ADV_UC_LOAD_BUNDLE,
    ], {"ip": 0xe0, "r5": 0, "r6": ADV_UC_LOAD_DATA,
        "exception": IA64_EXCP_NONE}, entry=0x10)

test_fp_alat_does_not_satisfy_gr_check_load = require_registers(
    "fp_alat_does_not_satisfy_gr_check_load", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ldf8_a(4, 3), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x55)),
        (0x40, 0x00, ld8_c_nc(4, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x50, "r4": CHECK_LOAD_DATA, "exception": IA64_EXCP_NONE},
    entry=0x10)

test_invala_e_fp_invalidates_selected_register = require_registers(
    "invala_e_fp_invalidates_selected_register", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ldf8_a(7, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_a(8, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, invala_e_fp(7), nop_i(),
         nop_i()),
        (0x50, 0x00, chk_a_nc_f(7, 0x50, 0x90), adds(4, 1, 0),
         nop_i()),
        (0x60, 0x00, adds(6, 1, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x90, 0x00, chk_a_nc_f(8, 0x90, 0xc0), adds(5, 1, 0),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0xc0, 0x00, adds(7, 1, 0), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0xa0, "r4": 0, "r5": 1, "r6": 0, "r7": 0,
        "exception": IA64_EXCP_NONE}, entry=0x10)

LDFP8_LOW, LDFP8_HIGH = bundle_words(0x00, 0x0123456789, 0x01abcdef, 0)

test_ldfp8_postinc_decode = require_registers("ldfp8_postinc_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, ldfp8_postinc(6, 7, 3), nop_i(),
     nop_i()),
    (0x30, 0x09, getf_sig(4, 6), getf_sig(5, 7),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
    (0x100, 0x00, 0x0123456789, 0x01abcdef,
     0),
], {"ip": 0x40, "r3": 0x110, "r4": LDFP8_LOW, "r5": LDFP8_HIGH,
    "exception": IA64_EXCP_NONE}, entry=0x10)

test_ldf_fill_postinc_decode = require_registers("ldf_fill_postinc_decode", [
    (0x10, *movl_mlx(2, 0x123456789abcdef0)),
    (0x20, 0x00, addl(3, 0x204, 0), addl(7, 0x20c, 0),
     nop_i()),
    (0x30, 0x00, addl(5, 0x1003e, 0), nop_i(),
     nop_i()),
    (0x40, 0x08, st8(3, 2), st8(7, 5),
     nop_i()),
    (0x50, 0x08, ldf_fill_postinc(9, 3, -48), nop_i(),
     nop_i()),
    (0x60, 0x00, getf_sig(4, 9), nop_i(),
     nop_i()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
], {
    "ip": 0x70,
    "r3": 0x1d4,
    "r4": 0x123456789abcdef0,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_ldf8_loads_integer_register_format = require_registers(
    "ldf8_loads_integer_register_format", [
        (0x10, *movl_mlx(2, 0x8000000000000000)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, st8(3, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, ldf8(6, 3), nop_i(),
         nop_i()),
        (0x50, 0x0d, nop_m(), fcvt_fxu(7, 6),
         nop_i()),
        (0x60, 0x10, getf_sig(4, 7), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r4": 0x8000000000000000,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ldfs_expands_single_memory_format = require_registers(
    "ldfs_expands_single_memory_format", [
        (0x10, *movl_mlx(2, 0x3f4ccccd)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(), nop_i()),
        (0x30, 0x00, st4(3, 2), nop_i(), nop_i()),
        (0x40, 0x00, ldfs(6, 3), nop_i(), nop_i()),
        (0x50, 0x09, getf_s(4, 6), getf_d(5, 6), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r4": 0x3f4ccccd,
        "r5": 0x3fe99999a0000000,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ldfs_preserves_single_nan_payload = require_registers(
    "ldfs_preserves_single_nan_payload", [
        (0x10, *movl_mlx(2, 0x7f812345)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(), nop_i()),
        (0x30, 0x00, st4(3, 2), nop_i(), nop_i()),
        (0x40, 0x00, ldfs(6, 3), nop_i(), nop_i()),
        (0x50, 0x10, getf_s(4, 6), nop_i(), br_cond(0x50, 0x60)),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r4": 0x7f812345,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ldfps_expands_both_single_values = require_registers(
    "ldfps_expands_both_single_values", [
        (0x10, *movl_mlx(2, 0xc02000003f800000)),
        (0x20, 0x00, addl(3, 0x204, 0), nop_i(), nop_i()),
        (0x30, 0x00, st8(3, 2), nop_i(), nop_i()),
        (0x40, 0x00, ldfps(6, 7, 3), nop_i(), nop_i()),
        (0x50, 0x09, getf_s(4, 6), getf_s(5, 7), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r4": 0x3f800000,
        "r5": 0xc0200000,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_stfs_stfd_convert_register_format = require_registers(
    "stfs_stfd_convert_register_format", [
        (0x10, *movl_mlx(2, 0x3ff8000000000000)),
        (0x20, *movl_mlx(5, 0xffffffffffffffff)),
        (0x30, 0x00, addl(3, 0x200, 0), addl(8, 0x208, 0), nop_i()),
        (0x40, 0x09, setf_d(6, 2), setf_sig(7, 5), nop_i()),
        (0x50, 0x00, stfs(3, 6), nop_i(), nop_i()),
        (0x60, 0x00, stfd(8, 7), nop_i(), nop_i()),
        (0x70, 0x09, ld4(4, 3), ld8(9, 8), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "r4": 0x3fc00000,
        "r9": 0x43efffffffffffff,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_getf_exact_register_format_translation = require_registers(
    "getf_exact_register_format_translation", [
        (0x10, *movl_mlx(2, 0xffffffffffffffff)),
        (0x20, 0x00, setf_sig(6, 2), nop_i(), nop_i()),
        (0x30, 0x09, getf_s(4, 6), getf_d(5, 6), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r4": 0x5f7fffff,
        "r5": 0x43efffffffffffff,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_stf8_stfe_convert_register_format = require_registers(
    "stf8_stfe_convert_register_format", [
        (0x10, *movl_mlx(2, 0x3ff0000000000000)),
        (0x20, *movl_mlx(5, 1)),
        (0x30, 0x00, addl(3, 0x200, 0), addl(4, 0x210, 0),
         addl(10, 0x218, 0)),
        (0x40, 0x09, setf_d(6, 2), setf_sig(7, 5), nop_i()),
        (0x50, 0x00, stf8(3, 6), nop_i(), nop_i()),
        (0x60, 0x00, stfe(4, 7), nop_i(), nop_i()),
        (0x70, 0x09, ld8(8, 3), ld8(9, 4), nop_i()),
        (0x80, 0x00, ld2(11, 10), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r8": 0x8000000000000000,
        "r9": 1,
        "r11": 0x403e,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)


def fp_store_natval_consumption_test(name, store):
    return require_registers(name, [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), addl(4, 0x300, 0),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(), nop_i()),
        (0x40, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x50, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x60, 0x00, store(4, 7), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 19), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
        (0x200, 0x00, 0, 0, 0),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r14": 0x60,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_W,
    }, entry=0x10)


test_stfs_natval_consumption = fp_store_natval_consumption_test(
    "stfs_natval_consumption", stfs)
test_stfd_natval_consumption = fp_store_natval_consumption_test(
    "stfd_natval_consumption", stfd)
test_stf8_natval_consumption = fp_store_natval_consumption_test(
    "stf8_natval_consumption", stf8)
test_stfe_natval_consumption = fp_store_natval_consumption_test(
    "stfe_natval_consumption", stfe)

test_stf_spill_preserves_natval = require_registers(
    "stf_spill_preserves_natval", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), addl(4, 0x300, 0),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), addl(5, 0x308, 0), nop_i()),
        (0x40, 0x00, stf_spill_postinc(4, 7, 0), nop_i(), nop_i()),
        (0x50, 0x09, ld8(8, 4), ld8(9, 5), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        (0x200, 0x00, 0, 0, 0),
    ], {
        "ip": 0x60,
        "r8": 0,
        "r9": 0x1fffe,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ldf8_f1_does_not_change_fixed_register = require_registers(
    "ldf8_f1_does_not_change_fixed_register", [
        (0x10, *movl_mlx(2, 0xdeadbeefcafebabe)),
        (0x20, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, st8(3, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, ldf8(1, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "f1": ExpectedFP(0x8000000000000000, 0xffff),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_stf_spill_ldf_fill_preserves_sig = require_registers(
    "stf_spill_ldf_fill_preserves_sig", [
        (0x10, *movl_mlx(2, 0x0020c49ba5e353f7)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x200, 0),
         nop_i()),
        (0x30, 0x00, setf_sig(8, 2), nop_i(),
         nop_i()),
        (0x40, 0x08, stf_spill_postinc(3, 8, 16), nop_i(),
         nop_i()),
        (0x50, 0x00, setf_sig(8, 0), nop_i(),
         nop_i()),
        (0x60, 0x08, ldf_fill_postinc(8, 4, 16), nop_i(),
         nop_i()),
        (0x70, 0x0d, nop_m(), fcvt_fxu(8, 8),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r3": 0x210,
        "r4": 0x210,
        "f8": ExpectedFP(0x0020c49ba5e353f7, 0x1003e),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_chk_s_f_decode = require_registers("chk_s_f_decode", [
    (0x10, 0x00, addl(2, 0x55, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, setf_sig(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x00, chk_s_f(6, 0x30, 0x50), adds(4, 1, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 1, "exception": IA64_EXCP_NONE}, entry=0x10)

test_setf_exp_decode = require_registers("setf_exp_decode", [
    (0x10, 0x00, addl(2, 0x1234, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, setf_exp(6, 2, ignored=3), nop_i(),
     nop_i()),
    (0x30, 0x10, getf_exp(4, 6), nop_i(),
     br_cond(0x30, 0x40)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 0x1234, "exception": IA64_EXCP_NONE}, entry=0x10)

test_setf_sig_ignored_bits_decode = require_registers(
    "setf_sig_ignored_bits_decode", [
        (0x10, *movl_mlx(28, 0x123456789abcdef0)),
        (0x20, 0x00, setf_sig(66, 28, ignored=3), nop_i(),
         nop_i()),
        (0x30, 0x10, getf_sig(4, 66), nop_i(),
         br_cond(0x30, 0x40)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {"ip": 0x40, "r4": 0x123456789abcdef0}, entry=0x10)

test_getf_sig_ignored_bits_decode = require_registers(
    "getf_sig_ignored_bits_decode", [
        (0x10, *movl_mlx(28, 0x123456789abcdef0)),
        (0x20, 0x00, setf_sig(66, 28), nop_i(),
         nop_i()),
        (0x30, 0x10, getf_sig(4, 66, ignored=3), nop_i(),
         br_cond(0x30, 0x40)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {"ip": 0x40, "r4": 0x123456789abcdef0}, entry=0x10)

test_popcnt_decode = require_registers("popcnt_decode", [
    (0x10, *movl_mlx(3, 0xf0f0f0f0f0f0f0f0)),
    (0x20, 0x00, nop_m(), popcnt(4, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 32, "exception": IA64_EXCP_NONE}, entry=0x10)

test_clz_decode = require_registers("clz_decode", [
    (0x10, *movl_mlx(3, 0x0000f00000000000)),
    (0x20, 0x00, nop_m(), clz(4, 3),
     nop_i()),
    (0x30, 0x00, nop_m(), clz(5, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "r4": 16,
    "r5": 64,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_pmpy2_decode = require_registers("pmpy2_decode", [
    (0x10, *movl_mlx(29, 0xffff800000020003)),
    (0x20, *movl_mlx(31, 0x0002000300040005)),
    (0x30, 0x02, nop_m(), pmpy2(4, 29, 31),
     nop_i()),
    (0x40, 0x02, nop_m(), pmpy2(5, 29, 31, right=True),
     nop_i()),
    (0x50, 0x02, nop_m(), pmpy2(6, 29, 31, right=True, ignored=1),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r4": 0xfffffffe00000008,
    "r5": 0xfffe80000000000f,
    "r6": 0xfffe80000000000f,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_mix_decode = require_registers("mix_decode", [
    (0x10, *movl_mlx(8, 0x1122334455667788)),
    (0x20, *movl_mlx(9, 0xaabbccddeeff0011)),
    (0x30, 0x02, nop_m(), mix1_l(2, 8, 9),
     mix1_r(3, 8, 9, ignored=1)),
    (0x40, 0x02, nop_m(), mix2_l(4, 8, 9),
     mix2_r(5, 8, 9)),
    (0x50, 0x02, nop_m(), mix4_l(6, 8, 9),
     mix4_r(7, 8, 9)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r2": 0x11aa33cc55ee7700,
    "r3": 0x22bb44dd66ff8811,
    "r4": 0x1122aabb5566eeff,
    "r5": 0x3344ccdd77880011,
    "r6": 0x11223344aabbccdd,
    "r7": 0x55667788eeff0011,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_unpack2_l_decode = require_registers("unpack2_l_decode", [
    (0x10, *movl_mlx(17, 0x1122334455667788)),
    (0x20, *movl_mlx(18, 0xaabbccddeeff0011)),
    (0x30, 0x02, nop_m(), unpack1_l(16, 17, 18),
     unpack1_h(19, 17, 18)),
    (0x40, 0x02, nop_m(), unpack2_l(20, 17, 18),
     unpack2_h(21, 17, 18)),
    (0x50, 0x02, nop_m(), unpack4_l(22, 17, 18),
     unpack4_h(23, 17, 18)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r16": 0x55ee66ff77008811,
    "r19": 0x11aa22bb33cc44dd,
    "r20": 0x5566eeff77880011,
    "r21": 0x1122aabb3344ccdd,
    "r22": 0x55667788eeff0011,
    "r23": 0x11223344aabbccdd,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_pmpyshr2_decode = require_registers("pmpyshr2_decode", [
    (0x10, *movl_mlx(29, 0xffff800000020003)),
    (0x20, *movl_mlx(31, 0x0002000300040005)),
    (0x30, 0x02, nop_m(), pmpyshr2(4, 29, 31, 16),
     nop_i()),
    (0x40, 0x02, nop_m(), pmpyshr2(5, 29, 31, 16, signed=True),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "r4": 0x0001000100000000,
    "r5": 0xfffffffe00000000,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_st1_postinc_decode = require_registers("st1_postinc_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), adds(4, 0x5a, 0),
     nop_i()),
    (0x20, 0x08, st1_postinc(3, 4, -1), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r3": 0xff}, entry=0x10)

test_st8_postinc_same_base_value_uses_old_base = require_registers(
    "st8_postinc_same_base_value_uses_old_base", [
        (0x10, 0x00, addl(3, 0x200, 0), addl(5, 0x200, 0),
         nop_i()),
        (0x20, 0x08, st8_postinc(3, 3, 8), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8(4, 5), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r3": 0x208,
        "r4": 0x200,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_cmpxchg4_uses_ar_ccv = require_registers("cmpxchg4_uses_ar_ccv", [
    (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0xff, 0),
     nop_i()),
    (0x20, 0x00, st4(3, 4), addl(6, 0xf7, 0),
     nop_i()),
    (0x30, 0x00, mov_m_gr_ar(4, 32), nop_i(),
     nop_i()),
    (0x40, 0x00, cmpxchg4(5, 3, 6), nop_i(),
     nop_i()),
    (0x50, 0x00, load_mem(0x02, 7, 3), nop_i(),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r5": 0xff,
    "r7": 0xf7,
    "ar_ccv": 0xff,
}, entry=0x10)

test_xchg4_decode = require_registers("xchg4_decode", [
    (0x10, 0x00, addl(3, 0x200, 0), addl(4, 0xff, 0),
     nop_i()),
    (0x20, 0x00, st4(3, 4), addl(6, 0xf7, 0),
     nop_i()),
    (0x30, 0x00, xchg4(5, 3, 6), nop_i(),
     nop_i()),
    (0x40, 0x00, load_mem(0x02, 7, 3), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r5": 0xff, "r7": 0xf7}, entry=0x10)

test_cmpxchg4_repeated_word_updates = require_registers(
    "cmpxchg4_repeated_word_updates", [
        (0x10, *movl_mlx(3, 0x200)),
        (0x20, *movl_mlx(4, 0xffffffff)),
        (0x30, *movl_mlx(6, 0xfffffffe)),
        (0x40, *movl_mlx(7, 0xfffffffc)),
        (0x50, *movl_mlx(8, 0xfffffff8)),
        (0x60, 0x00, st4(3, 4), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_ar(4, 32), nop_i(),
         nop_i()),
        (0x80, 0x00, cmpxchg4(5, 3, 6), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_ar(6, 32), nop_i(),
         nop_i()),
        (0xa0, 0x00, cmpxchg4(9, 3, 7), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_ar(7, 32), nop_i(),
         nop_i()),
        (0xc0, 0x00, cmpxchg4(10, 3, 8), nop_i(),
         nop_i()),
        (0xd0, 0x00, load_mem(0x02, 11, 3), nop_i(),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
    ], {
        "ip": 0xe0,
        "r5": 0xffffffff,
        "r9": 0xfffffffe,
        "r10": 0xfffffffc,
        "r11": 0xfffffff8,
    }, entry=0x10)

test_cmpxchg4_region7_store = require_registers("cmpxchg4_region7_store", [
    *dtr_setup_bundles(0x10, REGION7_SCRATCH_VA, REGION7_SCRATCH_PA),
    (0x70, *movl_mlx(3, REGION7_SCRATCH_VA)),
    (0x80, *movl_mlx(4, 0xffffffff)),
    (0x90, *movl_mlx(6, 0xffffff7f)),
    (0xa0, 0x00, ssm(1 << 17), nop_i(),
     nop_i()),
    (0xb0, 0x00, st4(3, 4), nop_i(),
     nop_i()),
    (0xc0, 0x00, mov_m_gr_ar(4, 32), nop_i(),
     nop_i()),
    (0xd0, 0x00, cmpxchg4(5, 3, 6), nop_i(),
     nop_i()),
    (0xe0, 0x00, load_mem(0x02, 7, 3), nop_i(),
     nop_i()),
    (0xf0, 0x10, nop_m(), nop_i(),
     br_cond(0xf0, 0xf0)),
], {
    "ip": 0xf0,
    "exception": IA64_EXCP_NONE,
    "r5": 0xffffffff,
    "r7": 0xffffff7f,
}, entry=0x10)

test_cmp8xchg16_acq_stores_pair = require_registers(
    "cmp8xchg16_acq_stores_pair", [
        (0x10, *movl_mlx(20, 0x200)),
        (0x20, *movl_mlx(21, 0x208)),
        (0x30, *movl_mlx(4, 0x1111111122222222)),
        (0x40, *movl_mlx(5, 0x3333333344444444)),
        (0x50, *movl_mlx(6, 0x5555555566666666)),
        (0x60, *movl_mlx(7, 0x7777777788888888)),
        (0x70, 0x09, st8(20, 4), st8(21, 5),
         nop_i()),
        (0x80, 0x09, mov_m_gr_ar(5, 32), mov_m_gr_ar(7, 25),
         nop_i()),
        (0x90, 0x00, cmp8xchg16_acq(8, 21, 6, hint=3), nop_i(),
         nop_i()),
        (0xa0, 0x08, ld8(9, 20), ld8(10, 21),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "r8": 0x3333333344444444,
        "r9": 0x5555555566666666,
        "r10": 0x7777777788888888,
    }, entry=0x10)

test_cmp8xchg16_rel_mismatch_keeps_pair = require_registers(
    "cmp8xchg16_rel_mismatch_keeps_pair", [
        (0x10, *movl_mlx(20, 0x240)),
        (0x20, *movl_mlx(21, 0x248)),
        (0x30, *movl_mlx(4, 0xaaaaaaaa55555555)),
        (0x40, *movl_mlx(5, 0xbbbbbbbb66666666)),
        (0x50, *movl_mlx(6, 0xcccccccc77777777)),
        (0x60, *movl_mlx(7, 0xdddddddd88888888)),
        (0x70, 0x09, st8(20, 4), st8(21, 5),
         nop_i()),
        (0x80, 0x09, mov_m_gr_ar(6, 32), mov_m_gr_ar(7, 25),
         nop_i()),
        (0x90, 0x00, cmp8xchg16_rel(8, 21, 6, hint=1), nop_i(),
         nop_i()),
        (0xa0, 0x08, ld8(9, 20), ld8(10, 21),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "r8": 0xbbbbbbbb66666666,
        "r9": 0xaaaaaaaa55555555,
        "r10": 0xbbbbbbbb66666666,
    }, entry=0x10)

test_cmp8xchg16_unaligned = require_exception(
    "cmp8xchg16_unaligned", [
        (0x10, 0x00, addl(3, 0x204, 0), addl(2, 1, 0),
         nop_i()),
        (0x20, 0x00, cmp8xchg16_acq(4, 3, 2), nop_i(),
         nop_i()),
    ],
    IA64_EXCP_UNALIGNED, fault_ip=0x20,
)

# SDM Vol 2, section 4.4.8: instruction fetches, non-speculative loads,
# stores and semaphores to a page marked NaTPage raise a NaT Page
# Consumption fault; only control-speculative loads defer it.
def natpage_access_test(name, access_bundle, expected_isr):
    return require_registers(name, [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x200)),
        (0xb0, *movl_mlx(4, 0x1122334455667788)),
        (0xc0, 0x00, access_bundle, nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x00,
         mov_m_cr_gr(16, 19), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x30, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x30,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x30)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "r14": HIGH_TR_BASE + 0x200,
        "r15": expected_isr,
        "r16": 0xc0,
    }, entry=0x10)

test_natpage_load_raises_nat_consumption = natpage_access_test(
    "natpage_load_raises_nat_consumption", ld8(8, 3),
    IA64_ISR_R | 0x20)

test_natpage_store_raises_nat_consumption = natpage_access_test(
    "natpage_store_raises_nat_consumption", st8(3, 4),
    IA64_ISR_W | 0x20)

test_natpage_xchg_raises_nat_consumption = natpage_access_test(
    "natpage_xchg_raises_nat_consumption", xchg(3, 8, 3, 4),
    IA64_ISR_R | IA64_ISR_W | 0x20)

# Unaligned Data Reference is the lowest-priority data fault: the access
# translates before the read or write reports misalignment, so a misaligned
# store to a NaTPage translation reports NaT Page Consumption even with
# PSR.ac forcing the alignment check.
test_natpage_unaligned_store_outranks_unaligned = require_registers(
    "natpage_unaligned_store_outranks_unaligned", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_AC)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x201)),
        (0xb0, *movl_mlx(4, 0x1122334455667788)),
        (0xc0, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x00,
         mov_m_cr_gr(16, 19), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x30, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x30,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x30)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "r14": HIGH_TR_BASE + 0x201,
        "r15": IA64_ISR_W | 0x20,
        "r16": 0xc0,
    }, entry=0x10)

# The control case: with a well-formed translation the same misaligned
# store still reports Unaligned Data Reference.
test_unaligned_store_reports_unaligned_when_mapped = require_registers(
    "unaligned_store_reports_unaligned_when_mapped", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_AC)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x201)),
        (0xb0, *movl_mlx(4, 0x1122334455667788)),
        (0xc0, 0x00, st8(3, 4), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_UNALIGNED_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_UNALIGNED_VECTOR + 0x20,
                 IA64_UNALIGNED_VECTOR + 0x20)),
    ], {
        "ip": IA64_UNALIGNED_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_UNALIGNED,
        "r14": HIGH_TR_BASE + 0x201,
        "r15": IA64_ISR_W,
    }, entry=0x10)

# A control-speculative load defers instead of faulting, and the deferred
# exception indicator is written to the target register.
test_natpage_speculative_load_defers = require_registers(
    "natpage_speculative_load_defers", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x200)),
        (0xb0, 0x00, ld8_s(31, 3), nop_i(), nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(), br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

# The same rule applies when the NaTPage translation arrives through a
# short-format VHPT walk rather than a pinned translation register.
test_natpage_short_vhpt_load_raises_nat_consumption = require_registers(
    "natpage_short_vhpt_load_raises_nat_consumption", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661 | (7 << 2))),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0), nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(), nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0), nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(), nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT), nop_i(), nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x110, 0x00, ld8(8, 2), nop_i(), nop_i()),
        (0x120, 0x10, nop_m(), nop_i(), br_cond(0x120, 0x120)),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x00,
         mov_m_cr_gr(16, 19), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x30, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x30,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x30)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "r14": 0xa000000000000430,
        "r15": IA64_ISR_R | 0x20,
        "r16": 0x110,
    }, entry=0x10)

# An instruction fetch from a NaTPage reports the same vector with ISR.x
# set and no read/write bits.
test_natpage_instruction_fetch_raises_nat_consumption = require_registers(
    "natpage_instruction_fetch_raises_nat_consumption", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, 0x00, adds(7, 16 << 2, 0), adds(5, 5, 0), nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20), nop_i()),
        (0x40, 0x00, itr_i(5, 18), nop_i(), nop_i()),
        (0x50, *movl_mlx(19, (LOW_VECTOR_TR_PTE + 0x10000) | (7 << 2))),
        (0x60, *movl_mlx(6, 0x10000)),
        (0x70, 0x00, mov_m_gr_cr(6, 20), adds(8, 6, 0), nop_i()),
        (0x80, 0x00, itr_i(8, 19), nop_i(), nop_i()),
        (0x90, *movl_mlx(20, IA64_PSR_IC | IA64_PSR_IT)),
        (0xa0, 0x00, srlz_i(), adds(31, 0x430, 0), nop_i()),
        *rfi_to_gr(0xb0, 20, 31),
        (0x4000430, *movl_mlx(9, 0x10000)),
        (0x4000440, 0x00, nop_m(), nop_i(), mov_br_gr(1, 9)),
        (0x4000450, 0x10, nop_m(), nop_i(), br_indirect(1)),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "r14": 0x10000,
        "r15": IA64_ISR_X | 0x20,
    }, entry=0x10)

test_cmp8xchg16_natpage_consumption = require_registers(
    "cmp8xchg16_natpage_consumption", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x208)),
        (0xb0, *movl_mlx(4, 0x1122334455667788)),
        (0xc0, 0x00, cmp8xchg16_acq(8, 3, 4), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "fault_ip": 0xc0,
        "r14": HIGH_TR_BASE + 0x208,
        "r15": 0x20 | IA64_ISR_R | IA64_ISR_W,
    }, entry=0x10)

test_cmpxchg4_acq_region7_store = require_registers("cmpxchg4_acq_region7_store", [
    *dtr_setup_bundles(0x10, REGION7_SCRATCH_VA, REGION7_SCRATCH_PA),
    (0x70, *movl_mlx(3, REGION7_SCRATCH_VA)),
    (0x80, *movl_mlx(4, 0xffffffff)),
    (0x90, *movl_mlx(6, 0xffffff7f)),
    (0xa0, 0x00, ssm(1 << 17), nop_i(),
     nop_i()),
    (0xb0, 0x00, st4(3, 4), nop_i(),
     nop_i()),
    (0xc0, 0x00, mov_m_gr_ar(4, 32), nop_i(),
     nop_i()),
    (0xd0, 0x00, cmpxchg4_acq(5, 3, 6), nop_i(),
     nop_i()),
    (0xe0, 0x00, load_mem(0x02, 7, 3), nop_i(),
     nop_i()),
    (0xf0, 0x10, nop_m(), nop_i(),
     br_cond(0xf0, 0xf0)),
], {
    "ip": 0xf0,
    "exception": IA64_EXCP_NONE,
    "r5": 0xffffffff,
    "r7": 0xffffff7f,
}, entry=0x10)

test_andcm_imm_negative_mask_round_trip = require_registers(
    "andcm_imm_negative_mask_round_trip", [
        (0x10, *movl_mlx(25, 1 << 9)),
        (0x20, 0x00, andcm_imm(18, -1, 25), nop_i(),
         nop_i()),
        (0x30, 0x00, andcm_imm(30, -1, 18), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r18": 0xfffffffffffffdff,
        "r30": 0x200,
    }, entry=0x10)

test_stf_spill_postinc_decode = require_registers("stf_spill_postinc_decode", [
    (0x10, 0x00, addl(3, 0x200, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, stf_spill_postinc(3, 0, 128), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r3": 0x280}, entry=0x10)

test_stf8_postinc_imm9_decode = require_registers("stf8_postinc_imm9_decode", [
    (0x10, 0x00, addl(3, 0x200, 0), nop_i(),
     nop_i()),
    (0x20, 0x08, stf8_postinc(3, 0, 128), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r3": 0x280}, entry=0x10)

test_stf8_postinc_stores_setf_sig = require_registers(
    "stf8_postinc_stores_setf_sig", [
        (0x10, *movl_mlx(2, 0xffffffffffffffff)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x200, 0),
         nop_i()),
        (0x30, 0x00, setf_sig(6, 2), nop_i(),
         nop_i()),
        (0x40, 0x08, stf8_postinc(3, 6, 128), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8(5, 4), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {"ip": 0x60, "r3": 0x280, "r5": 0xffffffffffffffff},
    entry=0x10)

test_stfe_stores_extended_float = require_registers(
    "stfe_stores_extended_float", [
        (0x10, *movl_mlx(2, 0x3ff0000000000000)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x208, 0),
         nop_i()),
        (0x30, 0x00, setf_d(6, 2), nop_i(),
         nop_i()),
        (0x40, 0x08, stfe(3, 6), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8(5, 3), nop_i(),
         nop_i()),
        (0x60, 0x00, ld2(7, 4), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r5": 0x8000000000000000,
        "r7": 0x3fff,
    }, entry=0x10)

test_ldfe_stfe_preserves_extended_payload = require_registers(
    "ldfe_stfe_preserves_extended_payload", [
        (0x10, *movl_mlx(2, 0x8000000000000001)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x208, 0),
         nop_i()),
        (0x30, 0x00, st8(3, 2), addl(2, 0x4000, 0),
         nop_i()),
        (0x40, 0x00, st2(4, 2), addl(5, 0x300, 0),
         nop_i()),
        (0x50, 0x00, addl(6, 0x308, 0), nop_i(), nop_i()),
        (0x60, 0x00, ldfe(10, 3), nop_i(), nop_i()),
        (0x70, 0x00, stfe(5, 10), nop_i(), nop_i()),
        (0x80, 0x00, ld8(8, 5), nop_i(), nop_i()),
        (0x90, 0x00, ld2(9, 6), nop_i(), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "r8": 0x8000000000000001,
        "r9": 0x4000,
    }, entry=0x10)

test_fma_preserves_extended_precision = require_registers(
    "fma_preserves_extended_precision", [
        (0x10, *movl_mlx(2, 0x8000000000000000)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x208, 0),
         nop_i()),
        (0x30, 0x00, st8(3, 2), addl(5, 0x3fff, 0), nop_i()),
        (0x40, 0x00, st2(4, 5), addl(6, 0x210, 0), nop_i()),
        (0x50, 0x00, addl(7, 0x218, 0), nop_i(), nop_i()),
        (0x60, 0x00, st8(6, 2), addl(5, 0x3fc0, 0), nop_i()),
        (0x70, 0x00, st2(7, 5), nop_i(), nop_i()),
        (0x80, 0x00, ldfe(6, 3), nop_i(), nop_i()),
        (0x90, 0x00, ldfe(7, 6), nop_i(), nop_i()),
        (0xa0, 0x00, ldfe(9, 3), nop_i(), nop_i()),
        (0xb0, 0x0d, nop_m(), fma_s0(8, 6, 9, 7), nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(), br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "f8": ExpectedFP(0x8000000000000001, 0xffff),
    }, entry=0x10)

test_fp_divzero_fault_discards_result = require_registers(
    "fp_divzero_fault_discards_result", [
        (0x10, *movl_mlx(2, 0x33b)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x3ff0000000000000)),
        (0x40, *movl_mlx(4, 0)),
        (0x50, *movl_mlx(5, 0x4000000000000000)),
        (0x60, 0x00, setf_d(6, 3), nop_i(), nop_i()),
        (0x70, 0x00, setf_d(7, 4), nop_i(), nop_i()),
        (0x80, 0x00, setf_d(8, 5), nop_i(), nop_i()),
        (0x90, 0x0d, nop_m(), frcpa(8, 6, 6, 7), nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x10,
                 IA64_FP_FAULT_VECTOR + 0x10)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 4,
        "f8": ExpectedFP(0x8000000000000000, 0x10000),
    }, entry=0x10)

test_fcmp_invalid_fault_restores_predicates = require_registers(
    "fcmp_invalid_fault_restores_predicates", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(), nop_i()),
        (0x30, 0x00, cmp4_eq_unc_imm(6, 7, 0, 0), nop_i(), nop_i()),
        (0x40, *movl_mlx(3, 0x7ff0000000000001)),
        (0x50, *movl_mlx(4, 0x3ff0000000000000)),
        (0x60, 0x09, setf_d(6, 3), setf_d(7, 4), nop_i()),
        (0x70, 0x1c, nop_m(), fcmp(6, 7, 6, 7), nop_b()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x10,
                 IA64_FP_FAULT_VECTOR + 0x10)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 1,
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=1 << 6),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_fp_inexact_trap_commits_result = require_registers(
    "fp_inexact_trap_commits_result", [
        (0x10, *movl_mlx(2, 0x31f)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x400c000000000000)),
        (0x40, 0x00, setf_d(6, 3), nop_i(), nop_i()),
        (0x50, 0x0d, nop_m(), fcvt_fxu(8, 6), nop_i()),
        (IA64_FP_TRAP_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_TRAP_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_TRAP_VECTOR + 0x10,
                 IA64_FP_TRAP_VECTOR + 0x10)),
    ], {
        "ip": IA64_FP_TRAP_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x2001,
        "f8": ExpectedFP(3, 0x1003e),
    }, entry=0x10)

test_probe_r_fault_ignored_fields_decode = require_registers(
    "probe_r_fault_ignored_fields_decode", [
        (0x10, *movl_mlx(24, HIGH_TR_BASE + 0x80000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x08, probe_r_fault_ignored(24, 3, ignored5=0x0c,
                                            ignored7=0x45, bit36=1),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x80000,
        "r31": IA64_ISR_NA | IA64_ISR_R | 5,
    }, entry=0x10)

test_probe_w_imm_decode = require_registers(
    "probe_w_imm_decode", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (3 << 7))),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, addl(3, 0x200, 0), nop_i(),
         nop_i()),
        (0x70, 0x08, probe_w_imm(7, 3, 1), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r7": 1}, entry=0x10)

test_probe_result_clears_destination_nat = require_registers(
    "probe_result_clears_destination_nat", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (3 << 7))),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(9, 1 << 32)),
        (0x70, 0x00, mov_m_gr_ar(9, 36), addl(3, 0x100, 0),
         nop_i()),
        (0x80, 0x00, ld8_fill_postinc(17, 3, 0), nop_i(),
         nop_i()),
        (0x90, 0x08, probe_w_imm(17, 3, 0), nop_i(),
         nop_i()),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r17": 1,
        "r17_nat": 0,
    }, entry=0x10)

test_probe_stacked_result_survives_call_return = require_registers(
    "probe_stacked_result_survives_call_return", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (3 << 7))),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, nop_m(), alloc(8, 2, 2, 0, 0),
         addl(3, 0x100, 0)),
        (0x70, 0x08, probe_w_imm(33, 3, 0), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_call(0, 0x80, 0x100)),
        (0x90, 0x00, nop_m(), adds(8, 0, 33),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 1,
        "r33": 1,
        "cfm_sof": 2,
        "cfm_sol": 2,
    }, entry=0x10)


def probe_register_level_nat_consumption_test(name, probe, isr_access):
    return require_registers(name, [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(2, 6, 0), addl(3, 0x100, 0),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x08, probe(7, 3, 2), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
        (0x200, 0x00, 0, 0, 0),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_NA | isr_access | 2,
    }, entry=0x10)


test_probe_r_register_level_nat_consumption = \
    probe_register_level_nat_consumption_test(
        "probe_r_register_level_nat_consumption", probe_r_reg, IA64_ISR_R)
test_probe_w_register_level_nat_consumption = \
    probe_register_level_nat_consumption_test(
        "probe_w_register_level_nat_consumption", probe_w_reg, IA64_ISR_W)

test_probe_w_dt_disabled_miss_raises_alt_dtlb = require_registers(
    "probe_w_dt_disabled_miss_raises_alt_dtlb", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x80000)),
        (0x20, *movl_mlx(19, 1 << 13)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x08, probe_w_imm(7, 3, 1), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x80000,
        "r31": IA64_ISR_NA | IA64_ISR_W | 2,
    }, entry=0x10)

# A data-translation miss taken with PSR.ic clear reports the Data Nested
# TLB vector in place of the Alternate Data TLB vector, exactly as an
# ordinary data reference does.
test_probe_w_dt_disabled_ic_clear_miss_raises_data_nested_tlb = \
    require_registers(
        "probe_w_dt_disabled_ic_clear_miss_raises_data_nested_tlb", [
            (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x80000)),
            (0x20, *movl_mlx(19, 1 << 13)),
            (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
             nop_i()),
            (0x40, 0x00, srlz_d(), nop_i(),
             nop_i()),
            (0x50, 0x00, rsm(1 << 13), nop_i(),
             nop_i()),
            (0x60, 0x00, srlz_d(), nop_i(),
             nop_i()),
            (0x70, 0x08, probe_w_imm(7, 3, 1), nop_i(),
             nop_i()),
            (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(31, 0x71, 0),
             br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                     IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
            (IA64_DATA_NESTED_TLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
             br_cond(IA64_DATA_NESTED_TLB_VECTOR + 0x10,
                     IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
        ], {
            "ip": IA64_DATA_NESTED_TLB_VECTOR + 0x10,
            "exception": IA64_EXCP_NONE,
            "r31": 0x71,
        }, entry=0x10)

# With PSR.dt=1 the non-faulting probe still takes TLB-miss faults through
# tlb_grant_permission(); with the walker disabled for the region the miss
# reports through the Alternate Data TLB vector.
test_probe_w_dt_enabled_miss_raises_alt_dtlb = require_registers(
    "probe_w_dt_enabled_miss_raises_alt_dtlb", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x80000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | (1 << 17))),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x08, probe_w_imm(7, 3, 1), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x80000,
        "r31": IA64_ISR_NA | IA64_ISR_W | 2,
    }, entry=0x10)

# Maintenance conditions do not gate the granted access: a clean page still
# grants a write probe instead of reporting a Data Dirty Bit fault.
test_probe_w_clean_page_dirty_bit_not_checked = require_registers(
    "probe_w_clean_page_dirty_bit_not_checked", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~PTE_DIRTY)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, IA64_PSR_IC | (1 << 17))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, probe_w_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r8": 1,
    }, entry=0x10)

# Permission failures report through GR r1 without a fault: a privilege
# level 3 probe of a privilege level 0 page returns 0.
test_probe_r_insufficient_privilege_returns_zero = require_registers(
    "probe_r_insufficient_privilege_returns_zero", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, IA64_PSR_IC | (1 << 17))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, probe_r_imm(8, 2, 3), nop_i(),
         nop_i()),
        (0xb0, 0x00, probe_r_imm(9, 2, 0), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": 1,
    }, entry=0x10)

# A NaTPage translation is in tlb_grant_permission()'s checked list, so the
# non-faulting probe raises Data NaT Page Consumption instead of granting.
test_probe_r_natpage_dtr_raises_nat_consumption = require_registers(
    "probe_r_natpage_dtr_raises_nat_consumption", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x208)),
        (0xb0, 0x00, probe_r_imm(8, 3, 0), nop_i(),
         nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x10,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x10)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "fault_ip": 0xb0,
        "r14": HIGH_TR_BASE + 0x208,
    }, entry=0x10)

# NaT Page Consumption outranks the Key Miss, Key Permission, Access Rights,
# Access Bit and Dirty Bit checks, so a NaTPage that also fails one of those
# still reports NaT Page Consumption.  The ISR carries the Data NaT Page
# Consumption class (code{5:4} = 2) above the non-access instruction code in
# code{3:0}, and reports ed and sp as 0.
def natpage_priority_probe_test(name, pte_flags, probe_insn, expected_isr,
                                psr_extra=0):
    return require_registers(name, [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, pte_flags)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT | psr_extra), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xb0, 0x00, probe_insn, nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "fault_ip": 0xb0,
        "r14": KEY_TEST_VA,
        "r15": expected_isr,
    }, entry=0x10)


# PSR.pk is on and no PKR matches the page key, which alone would raise Data
# Key Miss.  NaTPage takes priority.
test_probe_natpage_outranks_key_miss = natpage_priority_probe_test(
    "probe_natpage_outranks_key_miss",
    LOW_VECTOR_TR_PTE | (7 << 2),
    probe_w_imm(8, 2, 0),
    IA64_ISR_NA | IA64_ISR_W | 0x22,
    psr_extra=IA64_PSR_PK)

# A probe at privilege level 3 against a privilege level 0 page would return
# 0 on its own.  NaTPage takes priority and faults instead.
test_probe_natpage_outranks_access_rights = natpage_priority_probe_test(
    "probe_natpage_outranks_access_rights",
    LOW_VECTOR_TR_PTE | (7 << 2),
    probe_r_imm(8, 2, 3),
    IA64_ISR_NA | IA64_ISR_R | 0x22)

# An unaccessed page grants the probe on its own; NaTPage still faults.
test_probe_natpage_outranks_access_bit = natpage_priority_probe_test(
    "probe_natpage_outranks_access_bit",
    (LOW_VECTOR_TR_PTE & ~PTE_ACCESSED) | (7 << 2),
    probe_r_imm(8, 2, 0),
    IA64_ISR_NA | IA64_ISR_R | 0x22)

# A clean page grants a write probe on its own; NaTPage still faults.
test_probe_natpage_outranks_dirty_bit = natpage_priority_probe_test(
    "probe_natpage_outranks_dirty_bit",
    (LOW_VECTOR_TR_PTE & ~PTE_DIRTY) | (7 << 2),
    probe_w_imm(8, 2, 0),
    IA64_ISR_NA | IA64_ISR_W | 0x22)

# Data NaT Page Consumption reports ISR.ed as 0 even while the executing
# code runs under an instruction translation whose PTE.ed is set, which
# would otherwise set ISR.ed (see ws2003_cmd646_unaligned_check_load_sets_ed).
test_probe_natpage_reports_isr_ed_zero = require_registers(
    "probe_natpage_reports_isr_ed_zero", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | PTE_ED)),
        (0x20, 0x00, adds(7, 16 << 2, 0), adds(5, 5, 0),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x40, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(2, KEY_TEST_VA)),
        (0x60, *movl_mlx(19, LOW_VECTOR_TR_PTE | (7 << 2))),
        (0x70, 0x00, adds(6, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(6, 21), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(19), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(20,
                         IA64_PSR_IC | IA64_PSR_IT | IA64_PSR_DT)),
        (0xc0, 0x00, srlz_i(), adds(31, 0x430, 0),
         nop_i()),
        *rfi_to_gr(0xd0, 20, 31),
        (0x4000430, 0x00, probe_r_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (0x4000000 + IA64_NAT_CONSUMPTION_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x20,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x20)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "r14": KEY_TEST_VA,
        "r15": IA64_ISR_NA | IA64_ISR_R | 0x22,
    }, entry=0x10)

# Page Not Present outranks NaT Page Consumption, so a non-present NaTPage
# reports the Page Not Present vector.
test_probe_not_present_outranks_natpage = require_registers(
    "probe_not_present_outranks_natpage", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(18,
                         (LOW_VECTOR_TR_PTE | (7 << 2)) & ~1)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT), nop_i(),
         nop_i()),
        (0x80, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x90, 0x00, probe_r_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
                 IA64_PAGE_NOT_PRESENT_VECTOR + 0x20)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_PAGE_NOT_PRESENT,
        "fault_ip": 0x90,
        "r14": KEY_TEST_VA,
        "r15": IA64_ISR_NA | IA64_ISR_R | 2,
    }, entry=0x10)

# The non-access subcode is preserved beside the NaT Page Consumption class
# for each non-access instruction that can reach a NaTPage translation.
test_probe_r_fault_natpage_isr_code = natpage_priority_probe_test(
    "probe_r_fault_natpage_isr_code",
    LOW_VECTOR_TR_PTE | (7 << 2),
    probe_r_fault(2, 0),
    IA64_ISR_NA | IA64_ISR_R | 0x25)

test_probe_rw_fault_natpage_isr_code = natpage_priority_probe_test(
    "probe_rw_fault_natpage_isr_code",
    LOW_VECTOR_TR_PTE | (7 << 2),
    probe_rw_fault(2, 0),
    IA64_ISR_NA | IA64_ISR_R | IA64_ISR_W | 0x25)

test_lfetch_fault_natpage_isr_code = natpage_priority_probe_test(
    "lfetch_fault_natpage_isr_code",
    LOW_VECTOR_TR_PTE | (7 << 2),
    lfetch_fault(2),
    IA64_ISR_NA | IA64_ISR_R | 0x24)


# The faulting probe forms list Data NaT Page Consumption as well.
test_probe_r_fault_natpage_raises_nat_consumption = require_registers(
    "probe_r_fault_natpage_raises_nat_consumption", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000,
                           pte_flags=DTR_PTE_NATPAGE),
        (0x70, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(3, HIGH_TR_BASE + 0x208)),
        (0xb0, 0x00, probe_r_fault_ignored(3, 0), nop_i(),
         nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x10,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x10)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "fault_ip": 0xb0,
        "r14": HIGH_TR_BASE + 0x208,
    }, entry=0x10)

# The same NaTPage rule applies when the translation arrives through a
# short-format VHPT walk rather than an already-cached entry.
test_probe_w_natpage_short_vhpt_walk_raises_nat_consumption = \
    require_registers(
        "probe_w_natpage_short_vhpt_walk_raises_nat_consumption", [
            (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
            (0x20, *movl_mlx(17, 0xa000000000000000)),
            (0x30, *movl_mlx(18, 0x539)),
            (0x40, *movl_mlx(19, 0xbffc000000000000)),
            (0x50, *movl_mlx(20, 0x0010000004009661)),
            (0x60, *movl_mlx(21, 0x0010000004000661 | (7 << 2))),
            (0x70, *movl_mlx(22, 0x4008000)),
            (0x80, 0x00, st8(22, 21), nop_i(),
             nop_i()),
            (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
             nop_i()),
            (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
             nop_i()),
            (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
             nop_i()),
            (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
             nop_i()),
            (0xd0, 0x00, itr_d(5, 20), nop_i(),
             nop_i()),
            (0xe0, *movl_mlx(2, 0xa000000000000430)),
            (0xf0, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT), nop_i(),
             nop_i()),
            (0x100, 0x00, srlz_d(), nop_i(),
             nop_i()),
            (0x110, 0x00, probe_w_imm(8, 2, 0), nop_i(),
             nop_i()),
            (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
             mov_m_cr_gr(14, 20), nop_i(), nop_i()),
            (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x10,
             nop_m(), nop_i(),
             br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x10,
                     IA64_NAT_CONSUMPTION_VECTOR + 0x10)),
        ], {
            "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x10,
            "exception": IA64_EXCP_NONE,
            "fault_code": IA64_EXCP_NAT_CONSUMPTION,
            "fault_ip": 0x110,
            "r14": 0xa000000000000430,
        }, entry=0x10)

# The dt=0 probe queries the DTLB with a virtual address, so NaTPage
# translations raise Data NaT Page Consumption there as well.
test_probe_r_dt_disabled_natpage_raises_nat_consumption = require_registers(
    "probe_r_dt_disabled_natpage_raises_nat_consumption", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE | (7 << 2))),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, 0x00, ssm(IA64_PSR_IC), nop_i(),
         nop_i()),
        (0x80, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x90, 0x00, probe_r_imm(8, 2, 0), nop_i(),
         nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_NAT_CONSUMPTION_VECTOR + 0x10, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_NAT_CONSUMPTION_VECTOR + 0x10,
                 IA64_NAT_CONSUMPTION_VECTOR + 0x10)),
    ], {
        "ip": IA64_NAT_CONSUMPTION_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_NAT_CONSUMPTION,
        "fault_ip": 0x90,
        "r14": 0x9000,
    }, entry=0x10)

# Maintenance conditions do not gate the dt=0 probe either: an unaccessed
# page still grants a read and a clean page still grants a write.
test_probe_dt_disabled_maintenance_bits_grant = require_registers(
    "probe_dt_disabled_maintenance_bits_grant", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~PTE_ACCESSED)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(3, 0xd000)),
        (0x80, *movl_mlx(19, LOW_VECTOR_TR_PTE & ~PTE_DIRTY)),
        (0x90, 0x00, mov_m_gr_cr(3, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(19), nop_i(),
         nop_i()),
        (0xb0, 0x00, probe_r_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0xc0, 0x00, probe_w_imm(9, 3, 0), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r8": 1,
        "r9": 1,
    }, entry=0x10)

# Protection keys apply to the probe query whenever PSR.pk is 1, even with
# PSR.dt = 0: a missing PKR raises Data Key Miss.
test_probe_w_dt_disabled_key_miss_raises_data_key_miss = require_registers(
    "probe_w_dt_disabled_key_miss_raises_data_key_miss", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, 0x00, ssm(IA64_PSR_IC | IA64_PSR_PK), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xb0, 0x00, probe_w_imm(8, 2, 0), nop_i(),
         nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00,
         mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x10,
                 IA64_DATA_KEY_MISS_VECTOR + 0x10)),
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "fault_code": IA64_EXCP_DATA_KEY_MISS,
        "fault_ip": 0xb0,
        "r14": KEY_TEST_VA,
    }, entry=0x10)

# The read-disable bit is the symmetric case: probe.r reports 0 while the
# write side stays granted.
test_probe_r_dt_disabled_key_read_disable_returns_zero = require_registers(
    "probe_r_dt_disabled_key_read_disable_returns_zero", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, *movl_mlx(4, KEY_TEST_PKR | IA64_PKR_RD)),
        (0x60, 0x00, mov_rr_write(16, 0), adds(3, 0, 0),
         nop_i()),
        (0x70, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xb0, 0x00, ssm(IA64_PSR_IC | IA64_PSR_PK), nop_i(),
         nop_i()),
        (0xc0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xd0, 0x00, probe_r_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0xe0, 0x00, probe_w_imm(9, 2, 0), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
    ], {
        "ip": 0xf0,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": 1,
    }, entry=0x10)

# A matching PKR with the write-disable bit set reports through GR r1
# instead of faulting, and the read side stays granted.
test_probe_w_dt_disabled_key_write_disable_returns_zero = require_registers(
    "probe_w_dt_disabled_key_write_disable_returns_zero", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, *movl_mlx(4, KEY_TEST_PKR | IA64_PKR_WD)),
        (0x60, 0x00, mov_rr_write(16, 0), adds(3, 0, 0),
         nop_i()),
        (0x70, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xb0, 0x00, ssm(IA64_PSR_IC | IA64_PSR_PK), nop_i(),
         nop_i()),
        (0xc0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xd0, 0x00, probe_w_imm(8, 2, 0), nop_i(),
         nop_i()),
        (0xe0, 0x00, probe_r_imm(9, 2, 0), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
    ], {
        "ip": 0xf0,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": 1,
    }, entry=0x10)

test_lfetch_decode = require_registers("lfetch_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), addl(4, 0x180, 0),
     nop_i()),
    (0x20, 0x08, lfetch(3), lfetch(4, 0x2d),
     nop_i()),
    (0x30, 0x08, lfetch_postinc(3, 64), lfetch_postinc(4, 128, 0x2d, 1),
     nop_i()),
    (0x40, 0x08, adds(5, 0x20, 0), lfetch_reg_postinc(3, 5, 0x2e, 2),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
    br_cond(0x50, 0x50)),
], {"ip": 0x50, "r3": 0x160, "r4": 0x200}, entry=0x10)

test_lfetch_nonfault_suppresses_translation_fault = require_registers(
    "lfetch_nonfault_suppresses_translation_fault", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x80000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x08, lfetch(3), nop_m(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_lfetch_fault_checks_translation = require_registers(
    "lfetch_fault_checks_translation", [
        (0x10, *movl_mlx(3, HIGH_TR_BASE + 0x80000)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x08, lfetch(3, 0x2e), nop_m(), nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x80000,
        "r31": IA64_ISR_NA | IA64_ISR_R | 4,
    }, entry=0x10)

test_hint_m_decode = require_registers("hint_m_decode", [
    (0x10, 0x00, hint_m(), adds(31, 0x66, 0),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "exception": IA64_EXCP_NONE, "r31": 0x66}, entry=0x10)

test_hint_i_decode = require_registers("hint_i_decode", [
    (0x10, 0x00, nop_m(), hint_i(),
     adds(31, 0x66, 0)),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "exception": IA64_EXCP_NONE, "r31": 0x66}, entry=0x10)

test_xma_h_decode = require_registers("xma_h_decode", [
    (0x10, 0x1d, nop_m(), xma_h(8, 0, 6, 7),
     br_cond(0x10, 0x20)),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {
    "ip": 0x20,
    "f8": ExpectedFP(0, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_xma_hu_decode = require_registers("xma_hu_decode", [
    (0x10, *movl_mlx(20, 0xffffffffffffffff)),
    (0x20, *movl_mlx(21, 2)),
    (0x30, *movl_mlx(22, 5)),
    (0x40, 0x00, setf_sig(10, 20), nop_i(),
     nop_i()),
    (0x50, 0x00, setf_sig(70, 21), nop_i(),
     nop_i()),
    (0x60, 0x00, setf_sig(9, 22), nop_i(),
     nop_i()),
    (0x70, 0x1d, nop_m(), xma_hu(11, 9, 10, 70),
     nop_b()),
    (0x80, 0x1d, nop_m(), xmpy_hu(12, 10, 70),
     nop_b()),
    (0x90, 0x10, nop_m(), nop_i(),
     nop_b()),
    (0xa0, 0x10, nop_m(), nop_i(),
     nop_b()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "f11": ExpectedFP(2, 0x1003e),
    "f12": ExpectedFP(1, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_xma_natval_propagates = require_registers("xma_natval_propagates", [
    (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
     nop_i()),
    (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
     nop_i()),
    (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
     nop_i()),
    (0x40, 0x1d, nop_m(), xma_l(9, 8, 7, 8),
     nop_b()),
    (0x50, 0x1d, nop_m(), xma_h(10, 8, 7, 8),
     nop_b()),
    (0x60, 0x1d, nop_m(), xmpy_hu(11, 7, 8),
     nop_b()),
    (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0xd0)),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0xe0, 0xe0)),
    (0x90, 0x00, chk_s_f(10, 0x90, 0xb0), adds(5, 1, 0),
     nop_i()),
    (0xa0, 0x10, nop_m(), nop_i(),
     br_cond(0xe0, 0xe0)),
    (0xb0, 0x00, chk_s_f(11, 0xb0, 0xd0), adds(12, 1, 0),
     nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(),
     br_cond(0xe0, 0xe0)),
    (0xd0, 0x10, nop_m(), nop_i(),
     br_cond(0xd0, 0xd0)),
    (0xe0, 0x10, nop_m(), nop_i(),
     br_cond(0xe0, 0xe0)),
    (0x200, 0x00, 0, 0,
     0),
], {
    "ip": 0xd0,
    "f9": ExpectedFP(0, 0x1fffe, nat=True),
    "f10": ExpectedFP(0, 0x1fffe, nat=True),
    "f11": ExpectedFP(0, 0x1fffe, nat=True),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fnorm_normalizes_setf_sig_payload = require_registers(
    "fnorm_normalizes_setf_sig_payload", [
    (0x10, 0x00, addl(2, 1, 0), addl(3, 0x895, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), dep(3, 2, 3, 62, 1),
     nop_i()),
    (0x30, 0x00, setf_sig(6, 3), nop_i(),
     nop_i()),
    (0x40, 0x1d, nop_m(), fnorm(7, 0, 6),
     nop_b()),
    (0x50, 0x00, setf_sig(8, 0), nop_i(),
     nop_i()),
    (0x60, 0x1d, nop_m(), fnorm(9, 0, 8, sf=2),
     nop_b()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
], {
    "ip": 0x70,
    "f7": ExpectedFP(*fnorm_setf_sig(0x4000000000000895)),
    "f9": ExpectedFP(*fnorm_setf_sig(0)),
    "ar_fpsr": (DEFAULT_FPSR |
                (FPSR_SF_D_FLAG <<
                 (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)) |
                (FPSR_SF_D_FLAG <<
                 (FPSR_SF2_SHIFT + FPSR_SF_FLAGS_SHIFT))),
}, entry=0x10)

_GETF_EXP_SIG_VALUE = 0x115557000
_GETF_EXP_SIG_EXPECTED = 0xffff + (_GETF_EXP_SIG_VALUE.bit_length() - 1)

test_getf_exp_after_fnorm_sig = require_registers("getf_exp_after_fnorm_sig", [
    (0x10, *movl_mlx(3, _GETF_EXP_SIG_VALUE)),
    (0x20, 0x00, setf_sig(6, 3), nop_i(),
     nop_i()),
    (0x30, 0x1d, nop_m(), fnorm(7, 0, 6),
     nop_b()),
    (0x40, 0x10, getf_exp(4, 7), nop_i(),
     br_cond(0x40, 0x50)),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": _GETF_EXP_SIG_EXPECTED}, entry=0x10)

test_fpabs_fpneg_decode = require_registers("fpabs_fpneg_decode", [
    (0x10, *movl_mlx(2, 0xbff0000000000000)),
    (0x20, *movl_mlx(3, 0x3ff0000000000000)),
    (0x30, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x50, 0x0d, nop_m(), fpabs(8, 6),
     nop_i()),
    (0x60, 0x0d, nop_m(), fpneg(9, 7),
     nop_i()),
    (0x70, 0x0d, nop_m(), fpnegabs(10, 7),
     nop_i()),
    (0x80, 0x00, nop_m(), nop_i(), nop_i()),
    (0x90, 0x00, nop_m(), nop_i(), nop_i()),
    (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "f8": ExpectedFP(*binary64_to_spill(0x3ff0000000000000)),
    "f9": ExpectedFP(*binary64_to_spill(0xbff0000000000000)),
    "f10": ExpectedFP(*binary64_to_spill(0xbff0000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fmerge_forms_decode = require_registers("fmerge_forms_decode", [
    (0x10, *movl_mlx(2, 0xc008000000000001)),
    (0x20, *movl_mlx(3, 0xbff0000000000002)),
    (0x30, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x50, 0x0d, nop_m(), fmerge_ns(8, 6, 7),
     nop_i()),
    (0x60, 0x0d, nop_m(), fmerge_s(9, 6, 7),
     nop_i()),
    (0x70, 0x0d, nop_m(), fmerge_se(10, 6, 7),
     nop_i()),
    (0x80, 0x10, nop_m(), nop_i(),
     nop_b()),
    (0x90, 0x10, nop_m(), nop_i(),
     nop_b()),
    (0xa0, 0x10, nop_m(), nop_i(),
     br_cond(0xa0, 0xa0)),
], {
    "ip": 0xa0,
    "f8": ExpectedFP(*binary64_to_spill(0x3ff0000000000002)),
    "f9": ExpectedFP(*binary64_to_spill(0xbff0000000000002)),
    "f10": ExpectedFP(*binary64_to_spill(0xc000000000000002)),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fmerge_natval_propagates = require_registers(
    "fmerge_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x0d, nop_m(), fmerge_s(8, 7, 1),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x00, adds(5, 1, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f8": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fminmax_scalar_decode = require_registers("fminmax_scalar_decode", [
    (0x10, *movl_mlx(2, 0x3ff0000000000000)),
    (0x20, *movl_mlx(3, 0xc000000000000000)),
    (0x30, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x50, 0x0d, nop_m(), fmin(8, 6, 7),
     nop_i()),
    (0x60, 0x0d, nop_m(), fmax(9, 6, 7, sf=1),
     nop_i()),
    (0x70, 0x0d, nop_m(), famin(10, 6, 7, sf=2),
     nop_i()),
    (0x80, 0x0d, nop_m(), famax(11, 6, 7, sf=3, bit36=1),
     nop_i()),
    (0x90, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xa0, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "f8": ExpectedFP(*binary64_to_spill(0xc000000000000000)),
    "f9": ExpectedFP(*binary64_to_spill(0x3ff0000000000000)),
    "f10": ExpectedFP(*binary64_to_spill(0x3ff0000000000000)),
    "f11": ExpectedFP(*binary64_to_spill(0xc000000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fminmax_scalar_tie_uses_f3 = require_registers(
    "fminmax_scalar_tie_uses_f3", [
        (0x10, *movl_mlx(2, 0x0000000000000000)),
        (0x20, *movl_mlx(3, 0x8000000000000000)),
        (0x30, *movl_mlx(4, 0x3ff0000000000000)),
        (0x40, *movl_mlx(5, 0xbff0000000000000)),
        (0x50, 0x09, setf_d(6, 2), setf_d(7, 3),
         nop_i()),
        (0x60, 0x09, setf_d(8, 4), setf_d(9, 5),
         nop_i()),
        (0x70, 0x0d, nop_m(), fmin(10, 6, 7),
         nop_i()),
        (0x80, 0x0d, nop_m(), fmax(11, 6, 7),
         nop_i()),
        (0x90, 0x0d, nop_m(), famin(12, 8, 9),
         nop_i()),
        (0xa0, 0x0d, nop_m(), famax(13, 8, 9),
         nop_i()),
        (0xb0, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xc0, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "f10": ExpectedFP(*binary64_to_spill(0x8000000000000000)),
        "f11": ExpectedFP(*binary64_to_spill(0x8000000000000000)),
        "f12": ExpectedFP(*binary64_to_spill(0xbff0000000000000)),
        "f13": ExpectedFP(*binary64_to_spill(0xbff0000000000000)),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fp_logical_and_swap_decode = require_registers("fp_logical_and_swap_decode", [
    (0x10, *movl_mlx(2, 0x0123456789abcdef)),
    (0x20, *movl_mlx(3, 0xf0f0f0f00f0f0f0f)),
    (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
     nop_i()),
    (0x40, 0x0d, nop_m(), fand(8, 6, 7),
     nop_i()),
    (0x50, 0x0d, nop_m(), fandcm(9, 6, 7),
     nop_i()),
    (0x60, 0x0d, nop_m(), for_(10, 6, 7),
     nop_i()),
    (0x70, 0x0d, nop_m(), fxor(11, 6, 7),
     nop_i()),
    (0x80, 0x0d, nop_m(), fswap(12, 6, 7),
     nop_i()),
    (0x90, 0x0d, nop_m(), fswap_nl(13, 6, 7),
     nop_i()),
    (0xa0, 0x0d, nop_m(), fswap_nr(14, 6, 7),
     nop_i()),
    (0xb0, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xc0, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xd0, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xe0, 0x10, nop_m(), nop_i(),
     br_cond(0xe0, 0xe0)),
], {
    "ip": 0xe0,
    "f8": ExpectedFP(0x00204060090b0d0f, 0x1003e),
    "f9": ExpectedFP(0x0103050780a0c0e0, 0x1003e),
    "f10": ExpectedFP(0xf1f3f5f78fafcfef, 0x1003e),
    "f11": ExpectedFP(0xf1d3b59786a4c2e0, 0x1003e),
    "f12": ExpectedFP(0x0f0f0f0f01234567, 0x1003e),
    "f13": ExpectedFP(0x8f0f0f0f01234567, 0x1003e),
    "f14": ExpectedFP(0x0f0f0f0f81234567, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fp_logical_swap_natval_propagates = require_registers(
    "fp_logical_swap_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fswap_nr(10, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fp_mix_sign_extend_decode = require_registers("fp_mix_sign_extend_decode", [
    (0x10, *movl_mlx(2, 0x8123456789abcdef)),
    (0x20, *movl_mlx(3, 0x70f0f0f00f0f0f0f)),
    (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
     nop_i()),
    (0x40, 0x0d, nop_m(), fmix_lr(8, 6, 7),
     nop_i()),
    (0x50, 0x0d, nop_m(), fmix_r(9, 6, 7),
     nop_i()),
    (0x60, 0x0d, nop_m(), fmix_l(10, 6, 7, ignored=7),
     nop_i()),
    (0x70, 0x0d, nop_m(), fsxt_r(11, 6, 7),
     nop_i()),
    (0x80, 0x0d, nop_m(), fsxt_l(12, 6, 7),
     nop_i()),
    (0x90, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xa0, 0x09, nop_m(), nop_m(),
     nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "f8": ExpectedFP(0x812345670f0f0f0f, 0x1003e),
    "f9": ExpectedFP(0x89abcdef0f0f0f0f, 0x1003e),
    "f10": ExpectedFP(0x8123456770f0f0f0, 0x1003e),
    "f11": ExpectedFP(0xffffffff0f0f0f0f, 0x1003e),
    "f12": ExpectedFP(0xffffffff70f0f0f0, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fp_mix_sign_extend_natval_propagates = require_registers(
    "fp_mix_sign_extend_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fmix_l(10, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fpsr_status_field_controls = require_registers(
    "fpsr_status_field_controls", [
        (0x10, *movl_mlx(2, (0x2a << FPSR_SF0_SHIFT) |
                         (0x3f << (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)))),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fsetc(1, 0x0f, 0x10),
         nop_i()),
        (0x40, 0x0d, nop_m(), fclrf(1),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "ar_fpsr": ((0x2a << FPSR_SF0_SHIFT) |
                    (0x1a << FPSR_SF1_SHIFT)),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpsr_td_suppresses_fp_fault = require_registers(
    "fpsr_td_suppresses_fp_fault", [
        (0x10, *movl_mlx(2, 0x33b)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fsetc(1, 0x7f, FPSR_SF_TD),
         nop_i()),
        (0x40, *movl_mlx(3, 0x3ff0000000000000)),
        (0x50, *movl_mlx(4, 0)),
        (0x60, 0x09, setf_d(6, 3), setf_d(7, 4),
         nop_i()),
        (0x70, 0x0d, nop_m(), frcpa(8, 6, 6, 7, sf=1),
         nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x00, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "f8": ExpectedFP(*binary64_to_spill(0x7ff0000000000000)),
        "ar_fpsr": 0x1260033b,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fsetc_sf0_td_reserved_field_fault = require_exception(
    "fsetc_sf0_td_reserved_field_fault", [
        (0x10, 0x0d, nop_m(), fsetc(0, 0x7f, FPSR_SF_TD),
         nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x10)

test_fsetc_pc1_reserved_field_fault = require_exception(
    "fsetc_pc1_reserved_field_fault", [
        (0x10, 0x0d, nop_m(), fsetc(1, 0, FPSR_SF_RESERVED_PC1),
         nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x10)

test_fsetc_fclrf_ignored_bit36_decode = require_registers(
    "fsetc_fclrf_ignored_bit36_decode", [
        (0x10, *movl_mlx(2, 0x3f)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fsetc(1, 0x0f, 0x10) | bitfield(1, 36, 1),
         nop_i()),
        (0x40, 0x0d, nop_m(), fclrf(1) | bitfield(1, 36, 1),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "ar_fpsr": 0x3f | (0x10 << FPSR_SF1_SHIFT),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fchkf_no_branch_when_flags_committed = require_registers(
    "fchkf_no_branch_when_flags_committed", [
        (0x10, *movl_mlx(2, 0x3f |
                         (0x01 << (FPSR_SF0_SHIFT + FPSR_SF_FLAGS_SHIFT)) |
                         (0x01 << (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)))),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fchkf(1, 0x30, 0x80),
         nop_i()),
        (0x40, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x50, "r4": 1, "exception": IA64_EXCP_NONE},
    entry=0x10)

test_fchkf_branches_on_uncommitted_flag = require_registers(
    "fchkf_branches_on_uncommitted_flag", [
        (0x10, *movl_mlx(2, 0x3f |
                         (0x01 << (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)))),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fchkf(1, 0x30, 0x80),
         nop_i()),
        (0x40, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r4": 0, "exception": IA64_EXCP_NONE},
    entry=0x10)

test_fchkf_positive_target_ignores_bit26 = require_registers(
    "fchkf_positive_target_ignores_bit26", [
        (0x10, *movl_mlx(2, 0x3f |
                         (0x01 << (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)))),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fchkf(1, 0x30, 0x80, ignored26=1),
         nop_i()),
        (0x40, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r4": 0, "exception": IA64_EXCP_NONE},
    entry=0x10)

test_fchkf_negative_target_uses_bit36 = require_registers(
    "fchkf_negative_target_uses_bit36", [
        (0x10, *movl_mlx(2, 0x3f |
                         (0x01 << (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT)))),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x50)),
        (0x40, 0x10, adds(4, 1, 0), nop_i(),
         br_cond(0x40, 0x80)),
        (0x50, 0x0d, nop_m(), fchkf(1, 0x50, 0x40),
         nop_i()),
        (0x60, 0x00, adds(5, 1, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "r4": 1,
        "r5": 0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcmp_p2_high_bit_not_fchkfs = require_registers(
    "fcmp_p2_high_bit_not_fchkfs", [
        (0x10, 0x1c, nop_m(), fcmp(6, 32, 1, 1, rel=2),
         nop_b()),
        (0x20, 0x00, nop_m(), nop_i(), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 32),
                                value=1 << 6),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpmerge_parallel_forms_decode = require_registers(
    "fpmerge_parallel_forms_decode", [
        (0x10, *movl_mlx(2, 0x8123456789abcdef)),
        (0x20, *movl_mlx(3, 0x70f0f0f00f0f0f0f)),
        (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpmerge_s(8, 6, 7),
         nop_i()),
        (0x50, 0x0d, nop_m(), fpmerge_ns(9, 6, 7),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpmerge_se(10, 6, 7),
         nop_i()),
        (0x70, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "f8": ExpectedFP(0xf0f0f0f08f0f0f0f, 0x1003e),
        "f9": ExpectedFP(0x70f0f0f00f0f0f0f, 0x1003e),
        "f10": ExpectedFP(0x8170f0f0898f0f0f, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpminmax_parallel_decode = require_registers(
    "fpminmax_parallel_decode", [
        (0x10, *movl_mlx(2, 0x3f800000c0800000)),
        (0x20, *movl_mlx(3, 0x40000000c0400000)),
        (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpmin(8, 6, 7),
         nop_i()),
        (0x50, 0x0d, nop_m(), fpmax(9, 6, 7, sf=1),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpamin(10, 6, 7, sf=2),
         nop_i()),
        (0x70, 0x0d, nop_m(), fpamax(11, 6, 7, sf=3),
         nop_i()),
        (0x80, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0x90, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "f8": ExpectedFP(0x3f800000c0800000, 0x1003e),
        "f9": ExpectedFP(0x40000000c0400000, 0x1003e),
        "f10": ExpectedFP(0x3f800000c0400000, 0x1003e),
        "f11": ExpectedFP(0x40000000c0800000, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpminmax_simd_high_lane_fault_isr = require_registers(
    "fpminmax_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33d)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x000000013f800000)),
        (0x40, *movl_mlx(4, 0x3f80000040000000)),
        (0x50, *movl_mlx(5, 0x4000000040400000)),
        (0x60, 0x09, setf_sig(6, 3), setf_sig(7, 4),
         nop_i()),
        (0x70, 0x00, setf_sig(8, 5), nop_i(),
         nop_i()),
        (0x80, 0x0d, nop_m(), fpmax(8, 6, 7),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x20,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33d,
    }, entry=0x10)

test_fpminmax_nan_invalid_fault = require_registers(
    "fpminmax_nan_invalid_fault", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x7fc000003f800000)),
        (0x40, *movl_mlx(4, 0x3f80000040000000)),
        (0x50, *movl_mlx(5, 0x4000000040400000)),
        (0x60, 0x09, setf_sig(6, 3), setf_sig(7, 4),
         nop_i()),
        (0x70, 0x00, setf_sig(8, 5), nop_i(),
         nop_i()),
        (0x80, 0x0d, nop_m(), fpmax(8, 6, 7),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x10,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_fpcmp_parallel_decode = require_registers(
    "fpcmp_parallel_decode", [
        (0x10, *movl_mlx(2, 0x3f800000c0800000)),
        (0x20, *movl_mlx(3, 0x40000000c0400000)),
        (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpcmp(0, 8, 6, 7),
         nop_i()),
        (0x50, 0x0d, nop_m(), fpcmp(1, 9, 6, 7, sf=1),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpcmp(4, 10, 6, 7, sf=2),
         nop_i()),
        (0x70, 0x0d, nop_m(), fpcmp(7, 11, 6, 7, sf=3),
         nop_i()),
        (0x80, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0x90, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "f8": ExpectedFP(0, 0x1003e),
        "f9": ExpectedFP(0xffffffffffffffff, 0x1003e),
        "f10": ExpectedFP(0xffffffffffffffff, 0x1003e),
        "f11": ExpectedFP(0xffffffffffffffff, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpcmp_simd_high_lane_fault_isr = require_registers(
    "fpcmp_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x7fa000003f800000)),
        (0x40, *movl_mlx(4, 0x3f8000003f800000)),
        (0x50, *movl_mlx(5, 0x4000000040400000)),
        (0x60, 0x09, setf_sig(6, 3), setf_sig(7, 4),
         nop_i()),
        (0x70, 0x00, setf_sig(8, 5), nop_i(),
         nop_i()),
        (0x80, 0x0d, nop_m(), fpcmp(0, 8, 6, 7),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x10,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_fp_parallel_natval_propagates = require_registers(
    "fp_parallel_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpcmp(1, 10, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fpcvt_parallel_decode = require_registers(
    "fpcvt_parallel_decode", [
        (0x10, *movl_mlx(2, 0x3fc00000c0300000)),
        (0x20, *movl_mlx(3, 0x3fc0000040300000)),
        (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpcvt_fx(8, 6),
         nop_i()),
        (0x50, 0x0d, nop_m(), fpcvt_fx_trunc(9, 6, sf=2),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpcvt_fxu(10, 7, sf=1),
         nop_i()),
        (0x70, 0x0d, nop_m(), fpcvt_fxu_trunc(11, 7, sf=3),
         nop_i()),
        (0x80, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0x90, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "f8": ExpectedFP(0x00000002fffffffd, 0x1003e),
        "f9": ExpectedFP(0x00000001fffffffe, 0x1003e),
        "f10": ExpectedFP(0x0000000200000003, 0x1003e),
        "f11": ExpectedFP(0x0000000100000002, 0x1003e),
        "ar_fpsr": 0x0209904c8274033f,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpcvt_parallel_natval_propagates = require_registers(
    "fpcvt_parallel_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpcvt_fx(10, 7),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fpcvt_simd_high_lane_fault_isr = require_registers(
    "fpcvt_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x7fc000003f800000)),
        (0x40, *movl_mlx(4, 0x4000000040400000)),
        (0x50, 0x09, setf_sig(6, 3), setf_sig(8, 4),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpcvt_fx(8, 6),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x10,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_fpma_parallel_decode = require_registers(
    "fpma_parallel_decode", [
        (0x10, *movl_mlx(2, 0x3f80000040000000)),
        (0x20, *movl_mlx(3, 0x4000000040400000)),
        (0x30, *movl_mlx(4, 0x4080000040a00000)),
        (0x40, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x50, 0x00, setf_sig(8, 4), nop_i(),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpma(9, 6, 7, 8),
         nop_i()),
        (0x70, 0x0d, nop_m(), fpms(10, 6, 7, 8, sf=1),
         nop_i()),
        (0x80, 0x0d, nop_m(), fpnma(11, 6, 7, 8, sf=2),
         nop_i()),
        (0x90, 0x09, nop_m(), nop_m(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "f9": ExpectedFP(0x4110000041880000, 0x1003e),
        "f10": ExpectedFP(0x40e0000041500000, 0x1003e),
        "f11": ExpectedFP(0xc0e00000c1500000, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpma_parallel_natval_propagates = require_registers(
    "fpma_parallel_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpma(10, 8, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fpma_simd_high_lane_fault_isr = require_registers(
    "fpma_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x000000003f800000)),
        (0x40, *movl_mlx(4, 0x7f8000003f800000)),
        (0x50, *movl_mlx(5, 0x000000003f800000)),
        (0x60, *movl_mlx(6, 0x4000000040400000)),
        (0x70, 0x09, setf_sig(7, 3), setf_sig(8, 4),
         nop_i()),
        (0x80, 0x09, setf_sig(9, 5), setf_sig(10, 6),
         nop_i()),
        (0x90, 0x0d, nop_m(), fpma(10, 7, 8, 9),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(11, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r11": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x10,
        "f10": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_fp_unary_natval_propagates = require_registers(
    "fp_unary_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x0d, nop_m(), fnorm(8, 0, 7),
         nop_i()),
        (0x50, 0x0d, nop_m(), fpabs(9, 7),
         nop_i()),
        (0x60, 0x0d, nop_m(), fpneg(10, 7),
         nop_i()),
        (0x70, 0x0d, nop_m(), fpnegabs(11, 7),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x110)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
        (0xa0, 0x00, chk_s_f(9, 0xa0, 0xc0), adds(5, 1, 0),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
        (0xc0, 0x00, chk_s_f(10, 0xc0, 0xe0), adds(12, 1, 0),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
        (0xe0, 0x00, chk_s_f(11, 0xe0, 0x110), adds(13, 1, 0),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
        (0x100, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x110,
        "f8": ExpectedFP(0, 0x1fffe, nat=True),
        "f9": ExpectedFP(0, 0x1fffe, nat=True),
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "f11": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fp_arithmetic_natval_propagates = require_registers(
    "fp_arithmetic_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_d(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fmpy_s1(9, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x50,
        "f9": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_getf_natval_sets_gr_nat = require_registers(
    "getf_natval_sets_gr_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x10, getf_sig(8, 7), nop_i(),
         nop_b()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x50,
        "r8_nat": 1,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fpack_decode = require_registers("fpack_decode", [
    (0x10, *movl_mlx(2, 0x3ff0000000000000)),
    (0x20, *movl_mlx(3, 0xc000000000000000)),
    (0x30, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x50, 0x0d, nop_m(), fpack(8, 6, 7),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "f8": ExpectedFP(0x3f800000c0000000, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_frsqrta_decode = require_registers("frsqrta_decode", [
    (0x10, *movl_mlx(2, 0x4010000000000000)),
    (0x20, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x0d, nop_m(), frsqrta(8, 6, 6),
     nop_i()),
    (0x40, 0x00, nop_m(), nop_i(), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "f8": ExpectedFP(0xff80000000000000, 0x0fffd),
    "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_frsqrta_pred_false_clears = require_registers(
    "frsqrta_pred_false_clears", [
        (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(6, 7, 0, 16),
         nop_i()),
        (0x20, *movl_mlx(2, 0x4010000000000000)),
        (0x30, 0x00, setf_d(6, 2), nop_i(),
         nop_i()),
        (0x40, 0x0d, nop_m(), frsqrta(8, 6, 6, qp=7),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "f8": ExpectedFP(0, 0),
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=0),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_frsqrta_special_returns_operand = require_registers(
    "frsqrta_special_returns_operand", [
        (0x10, *movl_mlx(2, 0x0000000000000000)),
        (0x20, 0x00, setf_d(6, 2), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), frsqrta(8, 6, 6),
         nop_i()),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, *movl_mlx(2, 0x8000000000000000)),
        (0x60, 0x00, setf_d(6, 2), nop_i(),
         nop_i()),
        (0x70, 0x0d, nop_m(), frsqrta(9, 6, 6),
         nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, *movl_mlx(2, 0x7ff0000000000000)),
        (0xa0, 0x00, setf_d(6, 2), nop_i(),
         nop_i()),
        (0xb0, 0x0d, nop_m(), frsqrta(12, 6, 6),
         nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "f8": ExpectedFP(*binary64_to_spill(0x0000000000000000)),
        "f9": ExpectedFP(*binary64_to_spill(0x8000000000000000)),
        "f12": ExpectedFP(*binary64_to_spill(0x7ff0000000000000)),
        "pr_mask": ExpectedBits(mask=1 << 6, value=0),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_frsqrta_swa_fault_discards_result = require_registers(
    "frsqrta_swa_fault_discards_result", [
        (0x10, 0x00, addl(2, 64, 0), nop_i(),
         nop_i()),
        (0x20, *movl_mlx(3, 0x4000000000000000)),
        (0x30, 0x00, setf_exp(6, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, setf_d(8, 3), nop_i(),
         nop_i()),
        (0x50, 0x0d, nop_m(), frsqrta(8, 6, 6),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 8,
        "f8": ExpectedFP(*binary64_to_spill(0x4000000000000000)),
        "ar_fpsr": DEFAULT_FPSR,
    }, entry=0x10)

test_fprsqrta_decode = require_registers("fprsqrta_decode", [
    (0x10, *movl_mlx(2, 0x4080000041800000)),
    (0x20, 0x00, setf_sig(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x0d, nop_m(), fprsqrta(8, 6, 6),
     nop_i()),
    (0x40, 0x00, nop_m(), nop_i(), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "f8": ExpectedFP(0x3eff80003e7f8000, 0x1003e),
    "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fprsqrta_simd_high_lane_fault_isr = require_registers(
    "fprsqrta_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33e)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0xbf8000003f800000)),
        (0x40, *movl_mlx(4, 0x4000000040400000)),
        (0x50, 0x00, setf_sig(6, 3), nop_i(),
         nop_i()),
        (0x60, 0x00, setf_sig(8, 4), nop_i(),
         nop_i()),
        (0x70, 0x0d, nop_m(), fprsqrta(8, 6, 6),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x10,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33e,
    }, entry=0x10)

test_w2k_fp_s1_pred_false_decode = require_registers("w2k_fp_s1_pred_false_decode", [
    (0x10, 0x1c, nop_m(), fnma_s1(7, 9, 6, 1, qp=6),
     nop_b()),
    (0x20, 0x0d, nop_m(), fmpy_s1(10, 8, 6, qp=6),
     nop_i()),
    (0x30, 0x1c, nop_m(), fma_s1(10, 7, 10, 10, qp=6),
     nop_b()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "f7": ExpectedFP(0, 0),
    "f10": ExpectedFP(0, 0),
    "pr_mask": ExpectedBits(mask=1 << 6, value=0),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fma_d_s0_decode = require_registers("fma_d_s0_decode", [
    (0x10, *movl_mlx(2, 0x4000000000000000)),
    (0x20, *movl_mlx(3, 0x4008000000000000)),
    (0x30, *movl_mlx(4, 0x4010000000000000)),
    (0x40, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x50, 0x00, setf_d(2, 3), nop_i(),
     nop_i()),
    (0x60, 0x00, setf_d(3, 4), nop_i(),
     nop_i()),
    (0x70, 0x1c, nop_m(), fma_d_s0(6, 6, 2, 3),
     nop_b()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "f6": ExpectedFP(*binary64_to_spill(0x4024000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fnmpy_s_s1_decode = require_registers("fnmpy_s_s1_decode", [
    (0x10, *movl_mlx(2, 0x4008000000000000)),
    (0x20, *movl_mlx(3, 0x4000000000000000)),
    (0x30, 0x09, setf_d(29, 2), setf_d(30, 3),
     nop_i()),
    (0x40, 0x1c, nop_m(), fnmpy_s_s1(7, 29, 30),
     nop_b()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "f7": ExpectedFP(*binary64_to_spill(0xc018000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fsub_d_s0_decode = require_registers("fsub_d_s0_decode", [
    (0x10, *movl_mlx(2, 0x4024000000000000)),
    (0x20, *movl_mlx(3, 0x4010000000000000)),
    (0x30, 0x00, setf_d(2, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(6, 3), nop_i(),
     nop_i()),
    (0x50, 0x1c, nop_m(), fsub_d_s0(2, 2, 6),
     nop_b()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "f2": ExpectedFP(*binary64_to_spill(0x4018000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fmpy_s0_decode = require_registers("fmpy_s0_decode", [
    (0x10, *movl_mlx(2, 0x4000000000000000)),
    (0x20, *movl_mlx(3, 0x4008000000000000)),
    (0x30, 0x00, setf_d(8, 2), nop_i(),
     nop_i()),
    (0x40, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x50, 0x1c, nop_m(), fmpy_s0(9, 8, 7),
     nop_b()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "f9": ExpectedFP(*binary64_to_spill(0x4018000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fmpy_s_s1_decode = require_registers("fmpy_s_s1_decode", [
    (0x10, *movl_mlx(2, 0x4000000000000000)),
    (0x20, 0x00, setf_d(21, 2), nop_i(),
     nop_i()),
    (0x30, 0x1c, nop_m(), fmpy_s_s1(5, 21, 0),
     nop_b()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "f5": ExpectedFP(0, 0),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fms_s3_decode = require_registers("fms_s3_decode", [
    (0x10, *movl_mlx(2, 0x4000000000000000)),
    (0x20, *movl_mlx(3, 0x4008000000000000)),
    (0x30, *movl_mlx(4, 0x4010000000000000)),
    (0x40, 0x00, setf_d(18, 2), nop_i(),
     nop_i()),
    (0x50, 0x00, setf_d(19, 3), nop_i(),
     nop_i()),
    (0x60, 0x00, setf_d(20, 4), nop_i(),
     nop_i()),
    (0x70, 0x1c, nop_m(), fms_s3(4, 18, 19, 20),
     nop_b()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "f4": ExpectedFP(*binary64_to_spill(0x4000000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fnma_d_s1_decode = require_registers("fnma_d_s1_decode", [
    (0x10, *movl_mlx(2, 0x4000000000000000)),
    (0x20, *movl_mlx(3, 0x4008000000000000)),
    (0x30, *movl_mlx(4, 0x4024000000000000)),
    (0x40, 0x00, setf_d(8, 2), nop_i(),
     nop_i()),
    (0x50, 0x00, setf_d(12, 3), nop_i(),
     nop_i()),
    (0x60, 0x00, setf_d(31, 4), nop_i(),
     nop_i()),
    (0x70, 0x1c, nop_m(), fnma_d_s1(10, 8, 12, 31),
     nop_b()),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "f10": ExpectedFP(*binary64_to_spill(0x4010000000000000)),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fclass_m_decode = require_registers("fclass_m_decode", [
    (0x10, *movl_mlx(2, 0x7ff0000000000000)),
    (0x20, 0x00, setf_d(8, 2), nop_i(),
     nop_i()),
    (0x30, 0x1c, nop_m(), fclass_m(6, 7, 8, 0x21),
     nop_b()),
    (0x40, 0x02, nop_m(), nop_i(), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=1 << 6),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fclass_m_ignored_bits_decode = require_registers(
    "fclass_m_ignored_bits_decode", [
        (0x10, *movl_mlx(2, 0x7ff0000000000000)),
        (0x20, 0x00, setf_d(8, 2), nop_i(),
         nop_i()),
        (0x30, 0x1c, nop_m(), fclass_m(10, 11, 8, 0x21, ignored=3),
         nop_b()),
        (0x40, 0x02, nop_m(), nop_i(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "pr_mask": ExpectedBits(mask=(1 << 10) | (1 << 11),
                                value=1 << 10),
        "ar_fpsr": DEFAULT_FPSR,
    }, entry=0x10)

test_fclass_same_pred_pred_false_noop = require_registers(
    "fclass_same_pred_pred_false_noop", [
        (0x10, 0x1c, nop_m(), fclass_m(6, 6, 1, 0x8, qp=7),
         nop_b()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_cond(0x20, 0x20)),
    ], {
        "ip": 0x20,
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=0),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcmp_natval_clears_predicates = require_registers(
    "fcmp_natval_clears_predicates", [
        (0x10, 0x00, cmp4_eq_unc_imm(6, 0, 0, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, cmp4_eq_unc_imm(7, 0, 0, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_imm_ar(36, 1), addl(8, 0x200, 0),
         nop_i()),
        (0x40, 0x08, ld8_fill_postinc(3, 8, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, ldf8_s(9, 3), nop_i(),
         nop_i()),
        (0x60, 0x1c, nop_m(), fcmp(6, 7, 9, 1),
         nop_b()),
        (0x70, 0x02, nop_m(), nop_i(), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=0),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcmp_status_field_decode = require_registers(
    "fcmp_status_field_decode", [
        (0x10, *movl_mlx(2, 0x3ff0000000000000)),
        (0x20, *movl_mlx(3, 0x4000000000000000)),
        (0x30, 0x00, setf_d(10, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, setf_d(11, 3), nop_i(),
         nop_i()),
        (0x50, 0x1c, nop_m(), fcmp(7, 8, 10, 11, rel=1, sf=1),
         nop_b()),
        (0x60, 0x1c, nop_m(), fcmp(9, 10, 10, 10, rel=2, sf=3),
         nop_b()),
        (0x70, 0x02, nop_m(), nop_i(), nop_i()),
        (0x80, 0x02, nop_m(), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "pr_mask": ExpectedBits(
            mask=(1 << 7) | (1 << 8) | (1 << 9) | (1 << 10),
            value=(1 << 7) | (1 << 9)),
        "ar_fpsr": DEFAULT_FPSR,
    },
    entry=0x10)

test_fcmp_same_pred_illegal = require_exception(
    "fcmp_same_pred_illegal",
    [(0x10, 0x1c, nop_m(), fcmp(6, 6, 1, 1), nop_b())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_fclass_unc_same_pred_pred_false_illegal = require_exception(
    "fclass_unc_same_pred_pred_false_illegal",
    [(0x10, 0x1c, nop_m(), fclass_m(6, 6, 1, 0x1ff, unc=True, qp=7),
      nop_b())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_fcvt_fxu_double_to_uint = require_registers("fcvt_fxu_double_to_uint", [
    (0x10, *movl_mlx(2, 0x400e000000000000)),
    (0x20, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x0d, nop_m(), fcvt_fxu(7, 6),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "f7": ExpectedFP(3, 0x1003e),
    "ar_fpsr": 0x0009804c8270033f,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fcvt_fxu_rounds_sf0 = require_registers("fcvt_fxu_rounds_sf0", [
    (0x10, *movl_mlx(2, 0x400e000000000000)),
    (0x20, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x0d, nop_m(), fcvt_fxu(7, 6, trunc=False, sf=0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "f7": ExpectedFP(4, 0x1003e),
    "ar_fpsr": 0x0009804c0274033f,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fcvt_fx_signed_trunc = require_registers("fcvt_fx_signed_trunc", [
    (0x10, *movl_mlx(2, 0xc00e000000000000)),
    (0x20, 0x00, setf_d(6, 2), nop_i(),
     nop_i()),
    (0x30, 0x0d, nop_m(), fcvt_fx(7, 6, trunc=True),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "f7": ExpectedFP(0xfffffffffffffffd, 0x1003e),
    "ar_fpsr": 0x0009804c8270033f,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fcvt_fxu_preserves_sig_payload = require_registers(
    "fcvt_fxu_preserves_sig_payload", [
        (0x10, 0x00, addl(2, 0x2a, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, setf_sig(6, 2), nop_i(),
         nop_i()),
        (0x30, 0x0d, nop_m(), fcvt_fxu(7, 6),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "f7": ExpectedFP(0x2a, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)

test_fcvt_xf_signed_sig_to_float = require_registers(
    "fcvt_xf_signed_sig_to_float", [
        (0x10, 0x00, addl(2, 42, 0), adds(3, -3, 0),
         nop_i()),
        (0x20, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x30, 0x0d, nop_m(), fcvt_xf(8, 6),
         nop_i()),
        (0x40, 0x0d, nop_m(), fcvt_xf(9, 7),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "f8": ExpectedFP(*binary64_to_spill(0x4045000000000000)),
        "f9": ExpectedFP(*binary64_to_spill(0xc008000000000000)),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcvt_xf_ignores_prior_precision = require_registers(
    "fcvt_xf_ignores_prior_precision", [
        (0x10, *movl_mlx(2, 0xc3369a5a)),
        (0x20, 0x00, setf_sig(6, 2), nop_i(), nop_i()),
        # Prime SoftFloat with an operation whose static precision is single.
        (0x30, 0x0d, nop_m(), fma_s1(7, 1, 1, 0), nop_i()),
        (0x40, 0x0d, nop_m(), fcvt_xf(8, 6), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "f8": ExpectedFP(0xc3369a5a00000000, 0x1001e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcvt_xf_reads_register_significand = require_registers(
    "fcvt_xf_reads_register_significand", [
        (0x10, *movl_mlx(2, 0xc3369a5a)),
        (0x20, 0x00, setf_sig(6, 2), nop_i(), nop_i()),
        (0x30, 0x0d, nop_m(), fcvt_xf(8, 6), nop_i()),
        # The second conversion consumes f8's architectural significand,
        # not the binary64 cache used internally for display/convenience.
        (0x40, 0x0d, nop_m(), fcvt_xf(9, 8), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "f8": ExpectedFP(0xc3369a5a00000000, 0x1001e),
        "f9": ExpectedFP(0xf325969800000000, 0x3003c),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcvt_xf_extreme_signed_round_trip = require_registers(
    "fcvt_xf_extreme_signed_round_trip", [
        (0x10, *movl_mlx(2, 0x7fffffffffffffff)),
        (0x20, *movl_mlx(3, 0x8000000000000000)),
        (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3), nop_i()),
        (0x40, 0x0d, nop_m(), fcvt_xf(8, 6), nop_i()),
        (0x50, 0x0d, nop_m(), fcvt_xf(9, 7), nop_i()),
        (0x60, 0x0d, nop_m(), fcvt_fx(10, 8, trunc=True), nop_i()),
        (0x70, 0x0d, nop_m(), fcvt_fx(11, 9, trunc=True), nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "f8": ExpectedFP(0xfffffffffffffffe, 0x1003d),
        "f9": ExpectedFP(0x8000000000000000, 0x3003e),
        "f10": ExpectedFP(0x7fffffffffffffff, 0x1003e),
        "f11": ExpectedFP(0x8000000000000000, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fcvt_xf_natval_propagates = require_registers(
    "fcvt_xf_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ldf8_s(7, 3), nop_i(),
         nop_i()),
        (0x40, 0x0d, nop_m(), fcvt_xf(8, 7),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         nop_b()),
        (0x60, 0x02, nop_m(), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x70,
        "f8": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_setf_sig_direct_scalar_operand = require_registers(
    "setf_sig_direct_scalar_operand", [
        (0x10, 0x00, addl(2, 2, 0), addl(3, 3, 0),
         nop_i()),
        (0x20, 0x09, setf_sig(6, 2), setf_sig(7, 3),
         nop_i()),
        (0x30, 0x0d, nop_m(), fma_s0(8, 6, 7, 1),
         nop_i()),
        (0x40, 0x0d, nop_m(), fpneg(9, 6),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "f8": ExpectedFP(0xe000000000000000, 0x10001),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_fr1_is_read_only_one = require_registers("fr1_is_read_only_one", [
    (0x10, *movl_mlx(2, 0)),
    (0x20, 0x00, setf_d(1, 2), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {
    "ip": 0x30,
    "f0": ExpectedFP(0, 0),
    "f1": ExpectedFP(0x8000000000000000, 0xffff),
}, entry=0x10)

test_w2k_frcpa_capacity_calc = require_registers("w2k_frcpa_capacity_calc", [
    (0x10, 0x00, addl(24, 0x230, 0), adds(25, 0x28, 0),
     nop_i()),
    (0x20, 0x09, setf_sig(8, 24), setf_sig(9, 25),
     cmp_ltu_unc(6, 0, 0, 25)),
    (0x30, 0x0d, nop_m(), fnorm(6, 0, 8),
     nop_i()),
    (0x40, 0x0d, nop_m(), fnorm(7, 0, 9),
     nop_i()),
    (0x50, 0x0d, nop_m(), frcpa(8, 6, 6, 7),
     nop_i()),
    (0x60, 0x1c, nop_m(), fnma_s1(9, 7, 8, 1, qp=6),
     nop_b()),
    (0x70, 0x0d, nop_m(), fmpy_s1(10, 6, 8, qp=6),
     nop_i()),
    (0x80, 0x1c, nop_m(), fma_s1(8, 9, 8, 8, qp=6),
     nop_b()),
    (0x90, 0x0d, nop_m(), fcvt_fxu(8, 8),
     nop_i()),
    (0xa0, 0x10, nop_m(), nop_i(),
     br_cond(0xa0, 0xb0)),
    (0xb0, 0x00, nop_m(), adds(4, 1, 4),
     nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(),
     br_cond(0xc0, 0xc0)),
], {
    "ip": 0xc0,
    "r4": 1,
    "f8": ExpectedFP(0, 0x1003e),
    "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
    "ar_fpsr": (0x0009804c8270033f |
                (FPSR_SF_D_FLAG <<
                 (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT))),
}, entry=0x10)

test_coreutils_hash_bucket_float_division = require_registers(
    "coreutils_hash_bucket_float_division", [
        (0x10, *movl_mlx(2, 103)),
        (0x20, *movl_mlx(3, 0x5f8000003f4ccccd)),
        (0x30, 0x00, addl(4, 0x200, 0), nop_i(), nop_i()),
        (0x40, 0x09, st8(4, 3), setf_sig(8, 2), nop_i()),
        (0x50, 0x0d, ldfs(7, 4), fnorm(6, 0, 8), nop_i()),
        (0x60, 0x0d, nop_m(), fmov(9, 7), nop_i()),
        (0x70, 0x0d, nop_m(), fmov(8, 6), nop_i()),
        (0x80, 0x0d, nop_m(), frcpa(6, 6, 8, 9, sf=0), nop_i()),
        (0x90, 0x1c, nop_m(), fnma_s1(10, 9, 6, 1, qp=6), nop_b()),
        (0xa0, 0x1c, nop_m(), fma_s1(7, 6, 10, 6, qp=6), nop_b()),
        (0xb0, 0x1c, nop_m(), fma_s1(7, 7, 10, 6, qp=6), nop_b()),
        (0xc0, 0x0d, nop_m(), fmpy_s_s1(10, 8, 7, qp=6), nop_i()),
        (0xd0, 0x1c, nop_m(), fnma_s1(8, 10, 9, 8, qp=6), nop_b()),
        (0xe0, 0x1c, nop_m(), fma_s_s0(6, 8, 7, 10, qp=6), nop_b()),
        (0xf0, 0x00, nop_m(), adds(3, 4, 4), nop_i()),
        (0x100, 0x0d, nop_m(), fmov(7, 6), nop_i()),
        (0x110, 0x00, ldfs(6, 3), nop_i(), nop_i()),
        (0x120, 0x0d, nop_m(), fcmp(6, 7, 6, 7, rel=2), nop_i()),
        (0x130, 0x00, nop_m(), nop_i(), nop_i()),
        (0x140, 0x0d, nop_m(), fcvt_fxu(7, 7, sf=0), nop_i()),
        (0x150, 0x10, nop_m(), nop_i(), br_cond(0x150, 0x150)),
    ], {
        "ip": 0x150,
        "f7": ExpectedFP(128, 0x1003e),
        "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=1 << 7),
        "ar_fpsr": (0x0009804c8274033f |
                    (FPSR_SF_D_FLAG <<
                     (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT))),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_ws2003_vga_frcpa_integer_division = require_registers(
    "ws2003_vga_frcpa_integer_division", [
        (0x10, *movl_mlx(26, 0x3f800040)),
        (0x20, 0x00, addl(24, 400, 0), adds(25, 12, 0),
         nop_i()),
        (0x30, 0x09, setf_sig(10, 24), setf_sig(9, 25),
         nop_i()),
        (0x40, 0x0d, setf_s(8, 26), fnorm(10, 0, 10),
         nop_i()),
        (0x50, 0x0d, nop_m(), fnorm(9, 0, 9),
         nop_i()),
        (0x60, 0x0d, nop_m(), frcpa(6, 6, 10, 9),
         nop_i()),
        (0x70, 0x0d, nop_m(), fmpy_s1(10, 6, 10, qp=6),
         nop_i()),
        (0x80, 0x1c, nop_m(), fnma_s1(9, 9, 6, 8, qp=6),
         nop_b()),
        (0x90, 0x1c, nop_m(), fma_s1(6, 9, 10, 10, qp=6),
         nop_b()),
        (0xa0, 0x0d, nop_m(), fcvt_fxu(6, 6),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "f6": ExpectedFP(33, 0x1003e),
        "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
        "ar_fpsr": (0x0009804c8270033f |
                    (FPSR_SF_D_FLAG <<
                     (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT))),
    }, entry=0x10)

_HIGH_SIG_DIVIDEND = 0xa0000001006ad328

test_frcpa_setf_sig_high_integer_remainder = require_registers(
    "frcpa_setf_sig_high_integer_remainder", [
        (0x10, *movl_mlx(22, _HIGH_SIG_DIVIDEND)),
        (0x20, *movl_mlx(23, 16)),
        (0x30, 0x09, setf_sig(8, 22), setf_sig(9, 23),
         nop_i()),
        (0x40, 0x0d, nop_m(), fnorm(8, 0, 8),
         nop_i()),
        (0x50, 0x0d, nop_m(), fnorm(9, 0, 9),
         nop_i()),
        (0x60, 0x0d, nop_m(), frcpa(11, 6, 8, 9),
         nop_i()),
        (0x70, 0x0d, nop_m(), fcvt_fxu(11, 11),
         nop_i()),
        (0x80, *movl_mlx(23, (-16) & 0xffffffffffffffff)),
        (0x90, 0x00, setf_sig(9, 23), nop_i(),
         nop_i()),
        (0xa0, 0x1d, nop_m(), xma_l(11, 8, 11, 9),
         nop_b()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "f11": ExpectedFP(_HIGH_SIG_DIVIDEND, 0x1003e),
        "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
        "ar_fpsr": (0x0009804c8270033f |
                    (FPSR_SF_D_FLAG <<
                     (FPSR_SF1_SHIFT + FPSR_SF_FLAGS_SHIFT))),
    }, entry=0x10)

test_umodsi3_hash_remainder = require_registers(
    "umodsi3_hash_remainder", [
        # Arithmetic core of an IA-64 __umodsi3 implementation, using an
        # operand pair observed in a guest hash-table bucket lookup.
        (0x10, *movl_mlx(22, 0xc3369a5a)),
        (0x20, *movl_mlx(23, 17)),
        (0x30, 0x00, addl(2, 65501, 0), nop_i(), nop_i()),
        (0x40, 0x09, setf_sig(13, 22), setf_sig(9, 23), nop_i()),
        # Leave SoftFloat in single precision before fcvt.xf, as the guest
        # process did.  fcvt.xf is architecturally exact and must not inherit
        # the precision of the preceding status-field-controlled operation.
        (0x50, 0x0d, nop_m(), fma_s1(6, 1, 1, 0), nop_i()),
        (0x60, 0x0d, sub_reg(23, 0, 23), fcvt_xf(8, 13), nop_i()),
        (0x70, 0x0d, nop_m(), fcvt_xf(9, 9), nop_i()),
        (0x80, 0x0d, setf_exp(11, 2), frcpa(10, 6, 8, 9), nop_i()),
        (0x90, 0x0c, nop_m(), fmpy_s1(12, 8, 10, qp=6), nop_i()),
        (0xa0, 0x0d, nop_m(), fnma_s1(10, 9, 10, 1, qp=6), nop_i()),
        (0xb0, 0x0c, setf_sig(9, 23),
         fma_s1(12, 10, 12, 12, qp=6), nop_i()),
        (0xc0, 0x0d, nop_m(), fma_s1(10, 10, 10, 11, qp=6), nop_i()),
        (0xd0, 0x0d, nop_m(), fma_s1(10, 10, 12, 12, qp=6), nop_i()),
        (0xe0, 0x0d, nop_m(), fcvt_fxu(10, 10), nop_i()),
        (0xf0, 0x0d, nop_m(), xma_l(10, 13, 10, 9), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x100)),
    ], {
        "ip": 0x100,
        "f10": ExpectedFP(0, 0x1003e),
        "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
        "ar_fpsr": 0x0009804c8270033f,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_frcpa_double_normal_reciprocal = require_registers(
    "frcpa_double_normal_reciprocal", [
        (0x10, *movl_mlx(2, 0x4010000000000000)),
        (0x20, *movl_mlx(3, 0x4000000000000000)),
        (0x30, 0x09, setf_d(6, 2), setf_d(7, 3),
         nop_i()),
        (0x40, 0x0d, nop_m(), frcpa(8, 6, 6, 7),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "f8": ExpectedFP(0xff80000000000000, 0x0fffd),
        "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_frcpa_swa_fault_discards_result = require_registers(
    "frcpa_swa_fault_discards_result", [
        (0x10, 0x00, addl(2, 64, 0), nop_i(),
         nop_i()),
        (0x20, *movl_mlx(3, 0x4000000000000000)),
        (0x30, 0x00, setf_exp(6, 2), nop_i(),
         nop_i()),
        (0x40, 0x00, setf_d(8, 3), nop_i(),
         nop_i()),
        (0x50, 0x0d, nop_m(), frcpa(8, 6, 6, 1),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 8,
        "f8": ExpectedFP(*binary64_to_spill(0x4000000000000000)),
        "ar_fpsr": DEFAULT_FPSR,
    }, entry=0x10)

test_frcpa_special_quotient = require_registers("frcpa_special_quotient", [
    (0x10, *movl_mlx(2, 0x4010000000000000)),
    (0x20, *movl_mlx(3, 0x7ff0000000000000)),
    (0x30, 0x09, setf_d(6, 2), setf_d(7, 3),
     nop_i()),
    (0x40, 0x0d, nop_m(), frcpa(8, 6, 6, 7),
     nop_i()),
    (0x50, 0x00, nop_m(), nop_i(), nop_i()),
    (0x60, *movl_mlx(3, 0x0000000000000000)),
    (0x70, 0x00, setf_d(7, 3), nop_i(),
     nop_i()),
    (0x80, 0x0d, nop_m(), frcpa(9, 6, 6, 7),
     nop_i()),
    (0x90, 0x00, nop_m(), nop_i(), nop_i()),
    (0xa0, 0x10, nop_m(), nop_i(),
     br_cond(0xa0, 0xa0)),
], {
    "ip": 0xa0,
    "f8": ExpectedFP(*binary64_to_spill(0x0000000000000000)),
    "f9": ExpectedFP(*binary64_to_spill(0x7ff0000000000000)),
    "pr_mask": ExpectedBits(mask=1 << 6, value=0),
    "ar_fpsr": 0x0009804c1270033f,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_frcpa_pred_false_clears = require_registers("frcpa_pred_false_clears", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(6, 7, 0, 16),
     nop_i()),
    (0x20, *movl_mlx(20, 0x3ff0000000000000)),
    (0x30, *movl_mlx(21, 0x4010000000000000)),
    (0x40, *movl_mlx(22, 0x4000000000000000)),
    (0x50, 0x09, setf_d(8, 20), setf_d(6, 21),
     nop_i()),
    (0x60, 0x00, setf_d(7, 22), nop_i(),
     nop_i()),
    (0x70, 0x0d, nop_m(), frcpa(8, 6, 6, 7, qp=7),
     nop_i()),
    (0x80, 0x00, nop_m(), nop_i(), nop_i()),
    (0x90, 0x10, nop_m(), nop_i(),
     br_cond(0x90, 0x90)),
], {
    "ip": 0x90,
    "f8": ExpectedFP(*binary64_to_spill(0x3ff0000000000000)),
    "pr_mask": ExpectedBits(mask=(1 << 6) | (1 << 7), value=0),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_frcpa_p2_high_bits_decode = require_registers("frcpa_p2_high_bits_decode", [
    (0x10, 0x00, addl(24, 0x800, 0), addl(25, 0x800, 0),
     nop_i()),
    (0x20, 0x09, setf_sig(6, 24), setf_sig(7, 25),
     nop_i()),
    (0x30, 0x0d, nop_m(), frcpa(8, 10, 6, 7),
     nop_i()),
    (0x40, 0x0d, nop_m(), fcvt_fxu(8, 8),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "f8": ExpectedFP(0, 0x1003e),
    "pr_mask": ExpectedBits(mask=1 << 10, value=1 << 10),
    "ar_fpsr": 0x0009804c8270033f,
}, entry=0x10)

test_frcpa_natval_propagates = require_registers("frcpa_natval_propagates", [
    (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
     nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), addl(14, 0x800, 0),
     nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(6, 14),
     cmp_ltu_unc(8, 0, 0, 1)),
    (0x40, 0x0d, nop_m(), frcpa(8, 8, 6, 7),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
    (0x200, 0x00, 0, 0,
     0),
], {
    "ip": 0x80,
    "f8": ExpectedFP(0, 0x1fffe, nat=True),
    "pr_mask": ExpectedBits(mask=1 << 8, value=0),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
},
    entry=0x10)

test_fprcpa_decode = require_registers("fprcpa_decode", [
    (0x10, *movl_mlx(2, 0x3f8000003f800000)),
    (0x20, *movl_mlx(3, 0x4080000041800000)),
    (0x30, 0x09, setf_sig(6, 2), setf_sig(7, 3),
     nop_i()),
    (0x40, 0x0d, nop_m(), fprcpa(8, 6, 6, 7),
     nop_i()),
    (0x50, 0x00, nop_m(), nop_i(), nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "f8": ExpectedFP(0x3e7f80003d7f8000, 0x1003e),
    "pr_mask": ExpectedBits(mask=1 << 6, value=1 << 6),
    "ar_fpsr": DEFAULT_FPSR,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fprcpa_simd_high_lane_fault_isr = require_registers(
    "fprcpa_simd_high_lane_fault_isr", [
        (0x10, *movl_mlx(2, 0x33b)),
        (0x20, 0x00, mov_m_gr_ar(2, 40), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(3, 0x3f8000003f800000)),
        (0x40, *movl_mlx(4, 0x000000003f800000)),
        (0x50, *movl_mlx(5, 0x4000000040400000)),
        (0x60, 0x09, setf_sig(6, 3), setf_sig(7, 4),
         nop_i()),
        (0x70, 0x00, setf_sig(8, 5), nop_i(),
         nop_i()),
        (0x80, 0x0d, nop_m(), fprcpa(8, 6, 6, 7),
         nop_i()),
        (IA64_FP_FAULT_VECTOR, 0x00, mov_m_cr_gr(10, 17),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x10, 0x00, nop_m(),
         nop_i(), nop_i()),
        (IA64_FP_FAULT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FP_FAULT_VECTOR + 0x20,
                 IA64_FP_FAULT_VECTOR + 0x20)),
    ], {
        "ip": IA64_FP_FAULT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r10": IA64_ISR_NI | (1 << IA64_ISR_EI_SHIFT) | 0x40,
        "f8": ExpectedFP(0x4000000040400000, 0x1003e),
        "ar_fpsr": 0x33b,
    }, entry=0x10)

test_cmp_lt_unc_imm_decode = require_registers("cmp_lt_unc_imm_decode", [
    (0x10, 0x00, adds(3, 20, 0), cmp_lt_unc_imm(7, 8, 15, 3),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "pr_mask": 1 | (1 << 7)}, entry=0x10)

test_cmp4_lt_unc_decode = require_registers("cmp4_lt_unc_decode", [
    (0x10, 0x00, adds(3, -1, 0), cmp4_lt_unc(7, 8, 3, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=7),
     adds(5, 1, 0, qp=8)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 1, "r5": 0}, entry=0x10)

test_cmp_ltu_unc_p0_decode = require_registers("cmp_ltu_unc_p0_decode", [
    (0x10, 0x00, adds(16, 3, 0), cmp_ltu_unc(13, 14, 0, 16),
     nop_i()),
    (0x20, 0x00, cmp_ltu_unc(0, 13, 0, 16), nop_i(),
     adds(4, 1, 0, qp=13)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0}, entry=0x10)

test_cmp4_ltu_unc_p0_register_decode = require_registers(
    "cmp4_ltu_unc_p0_register_decode",
    [
        (0x10, 0x00, alloc(32, 8, 0, 0, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, adds(35, 4, 0), cmp4_ltu_unc(0, 15, 0, 35),
         nop_i()),
        (0x30, 0x00, nop_m(), adds(4, 1, 0, qp=15),
         nop_i()),
        (0x40, 0x00, adds(35, 0, 0), cmp4_ltu_unc(0, 15, 0, 35),
         nop_i()),
        (0x50, 0x00, nop_m(), adds(5, 1, 0, qp=15),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ],
    {"ip": 0x60, "r4": 0, "r5": 1},
    entry=0x10,
)

test_cmp4_eq_unc_imm_p0_decode = require_registers("cmp4_eq_unc_imm_p0_decode", [
    (0x10, 0x00, adds(31, 1, 0), cmp4_eq_unc_imm(0, 15, 1, 31),
     nop_i()),
    (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=15),
     adds(5, 1, 0)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0, "r5": 1}, entry=0x10)

test_cmp4_eq_imm_decode = require_registers("cmp4_eq_imm_decode", [
    (0x10, 0x00, adds(3, -128, 0), cmp4_eq_imm(8, 7, -128, 3),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20, qp=8)),
], {"ip": 0x20, "r3": 0xffffffffffffff80}, entry=0x10)

test_cmp_ltu_imm_negative_decode = require_registers("cmp_ltu_imm_negative_decode", [
    (0x10, 0x00, adds(8, 7, 0), cmp_ltu_imm(6, 7, -5, 8),
     nop_i()),
    (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=6),
     adds(5, 1, 0, qp=7)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0, "r5": 1}, entry=0x10)

test_cmp4_ltu_imm_negative_decode = require_registers("cmp4_ltu_imm_negative_decode", [
    (0x10, 0x00, adds(8, 7, 0), cmp4_ltu_imm(6, 7, -5, 8),
     nop_i()),
    (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=6),
     adds(5, 1, 0, qp=7)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0, "r5": 1}, entry=0x10)

test_cmp_unc_pred_false_clears = require_registers("cmp_unc_pred_false_clears", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(15, 0, 0, 16),
     nop_i()),
    (0x20, 0x00, cmp_ltu_unc(15, 0, 0, 16, qp=6), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x50, qp=15)),
    (0x40, 0x00, adds(4, 1, 0), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": 1}, entry=0x10)

test_cmp4_ltu_unc_imm_pred_false_clears = require_registers(
    "cmp4_ltu_unc_imm_pred_false_clears",
    [
        (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(15, 0, 0, 16),
         nop_i()),
        (0x20, 0x00, cmp4_ltu_unc_imm(0, 15, 79, 41, qp=6), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x50, qp=15)),
        (0x40, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ],
    {"ip": 0x50, "r4": 1},
    entry=0x10,
)

test_cmp_unc_self_predicate_reads_old_qp = require_registers(
    "cmp_unc_self_predicate_reads_old_qp",
    [
        (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(12, 0, 0, 16),
         nop_i()),
        (0x20, 0x00, adds(17, 1, 0), adds(18, 2, 0),
         cmp_ltu_unc(12, 0, 17, 18, qp=12)),
        (0x30, 0x00, adds(4, 1, 0, qp=12), nop_i(), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ],
    {"ip": 0x40, "r4": 1},
    entry=0x10,
)

test_tbit_unc_pred_false_clears = require_registers("tbit_unc_pred_false_clears", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(11, 0, 0, 16),
     cmp_ltu_unc(12, 0, 0, 16)),
    (0x20, 0x00, nop_m(), tbit_z_unc(11, 12, 21, 3, qp=6),
     nop_i()),
    (0x30, 0x00, adds(17, 1, 0, qp=11), adds(18, 1, 0, qp=12),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r17": 0, "r18": 0}, entry=0x10)

test_cmp_same_pred_illegal = require_exception(
    "cmp_same_pred_illegal",
    [(0x10, 0x00, cmp4_eq_imm(6, 6, 0, 0), nop_i(), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_cmp_unc_same_pred_pred_false_illegal = require_exception(
    "cmp_unc_same_pred_pred_false_illegal",
    [(0x10, 0x00, cmp4_eq_unc_imm(6, 6, 0, 0, qp=7), nop_i(),
      nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_tbit_same_pred_illegal = require_exception(
    "tbit_same_pred_illegal",
    [(0x10, 0x00, nop_m(), tbit_z(6, 6, 0, 0), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_tnat_unc_same_pred_pred_false_illegal = require_exception(
    "tnat_unc_same_pred_pred_false_illegal",
    [(0x10, 0x00, nop_m(), tnat_z_unc(6, 6, 0, qp=7), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_tnat_nz_or_decode = require_registers("tnat_nz_or_decode", [
    (0x10, 0x00, nop_m(), adds(3, 0x104, 0),
     nop_i()),
    (0x20, 0x00, sum_um(0x8), nop_i(),
     nop_i()),
    (0x30, 0x00, ld8_s(15, 3), nop_i(),
     nop_i()),
    (0x40, 0x00, nop_m(), tnat_nz_or(7, 0, 15),
     nop_i()),
    (0x50, 0x00, nop_m(), adds(31, 1, 0, qp=7),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {"ip": 0x60, "r31": 1}, entry=0x10)

test_tnat_nz_and_ignored_bits_decode = require_registers(
    "tnat_nz_and_ignored_bits_decode", [
        (0x10, 0x00, cmp4_eq_imm(5, 31, 0, 0), adds(3, 0x104, 0),
         nop_i()),
        (0x20, 0x00, sum_um(0x8), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8_s(15, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, nop_m(), tnat_nz_and(5, 31, 15, ignored=0x0d),
         nop_i()),
        (0x50, 0x00, nop_m(), adds(31, 1, 0, qp=5),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {"ip": 0x60, "r31": 1}, entry=0x10)

test_tf_feature_predicate_updates = require_registers(
    "tf_feature_predicate_updates", [
        (0x10, 0x00, adds(16, 1, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, nop_m(), tf_z(6, 7, 35),
         tf_nz_or_andcm(8, 9, 32)),
        (0x30, 0x00, nop_m(), cmp_ltu_unc(10, 0, 0, 16),
         cmp_ltu_unc(11, 0, 0, 16)),
        (0x40, 0x00, nop_m(), tf_nz_and(10, 11, 35),
         nop_i()),
        (0x50, 0x00, adds(4, 1, 0, qp=6), adds(5, 1, 0, qp=7),
         adds(8, 1, 0, qp=8)),
        (0x60, 0x00, adds(9, 1, 0, qp=9), adds(10, 1, 0, qp=10),
         adds(11, 1, 0, qp=11)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r4": 1,
        "r5": 0,
        "r8": 0,
        "r9": 0,
        "r10": 0,
        "r11": 0,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_tf_upper_cpuid_feature_bits = require_registers(
    "tf_upper_cpuid_feature_bits", [
        (0x10, 0x00, nop_m(), addl(31, 4, 0),
         nop_i()),
        (0x20, 0x00, mov_cpuid(29, 31), tf_nz_or_andcm(6, 7, 33),
         nop_i()),
        (0x30, 0x00, nop_m(), tf_z(8, 9, 34),
         nop_i()),
        (0x40, 0x00, adds(4, 1, 0, qp=6), adds(5, 1, 0, qp=7),
         adds(6, 1, 0, qp=8)),
        (0x50, 0x00, nop_m(), adds(7, 1, 0, qp=9),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "r4": 0,
        "r5": 0,
        "r6": 1,
        "r7": 0,
        "r29": 0x0000000000000005,
    }, entry=0x10)

test_tf_same_pred_illegal = require_exception(
    "tf_same_pred_illegal",
    [(0x10, 0x00, nop_m(), tf_z(6, 6, 34), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_tf_unc_same_pred_pred_false_illegal = require_exception(
    "tf_unc_same_pred_pred_false_illegal",
    [(0x10, 0x00, nop_m(), tf_z_unc(6, 6, 34, qp=7), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_cmp_eq_and_decode = require_registers("cmp_eq_and_decode", [
    (0x10, 0x00, adds(16, 1, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, cmp_ltu_unc(7, 0, 0, 16), nop_i(),
     nop_i()),
    (0x30, 0x00, adds(17, 5, 0), adds(18, 5, 0),
     nop_i()),
    (0x40, 0x00, cmp_eq_and(7, 0, 17, 18), nop_i(),
     nop_i()),
    (0x50, 0x00, adds(4, 1, 0, qp=7), adds(18, 6, 0),
     nop_i()),
    (0x60, 0x00, cmp_eq_and(7, 0, 17, 18), nop_i(),
     nop_i()),
    (0x70, 0x10, adds(5, 1, 0, qp=7), nop_i(),
     br_cond(0x70, 0x80)),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {"ip": 0x80, "r4": 1, "r5": 0}, entry=0x10)

test_cmp_ne_and_parallel_semantics = require_registers(
    "cmp_ne_and_parallel_semantics", [
        (0x10, 0x00, adds(16, 5, 0), adds(17, 6, 0),
         nop_i()),
        (0x20, 0x00, nop_m(),
         mov_pr_rot_imm((1 << 16) | (1 << 17) |
                        (1 << 18) | (1 << 19)),
         nop_i()),
        # For the AND compare type, a true relation leaves both targets
        # unchanged while a false relation clears both (SDM Vol. 1,
        # Table 4-9).  Use unequal and equal sources in parallel so an
        # accidental cmp.eq.and decode produces the exact opposite state.
        (0x30, 0x00, cmp_ne_and(16, 17, 16, 17),
         cmp_ne_and(18, 19, 16, 16), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "exception": IA64_EXCP_NONE,
        "pr_mask": 1 | (1 << 16) | (1 << 17),
    }, entry=0x10)

test_ws2003_compare_update_decode = require_registers(
    "ws2003_compare_update_decode", [
        (0x10, *movl_mlx(10, 0x100000005)),
        (0x20, *movl_mlx(9, 0x200000005)),
        (0x30, 0x00, adds(16, 1, 0), adds(17, -1, 0),
         nop_i()),
        (0x40, 0x00, cmp_ltu_unc(7, 0, 0, 16),
         cmp_ltu_unc(6, 0, 0, 16), nop_i()),
        (0x50, 0x00, nop_m(), cmp4_eq_and(7, 0, 10, 9),
         cmp_gt_and(6, 0, 17, ignored=0x24)),
        (0x60, 0x00, nop_m(), cmp_le_or(13, 0, 16, ignored=0x0d),
         adds(4, 1, 0, qp=7)),
        (0x70, 0x02, nop_m(), adds(5, 1, 0, qp=6),
         adds(6, 1, 0, qp=13)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r4": 1, "r5": 1, "r6": 1}, entry=0x10)

test_cmp4_ge_or_andcm_decode = require_registers("cmp4_ge_or_andcm_decode", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(14, 13, 0, 16),
     nop_i()),
    (0x20, 0x00, adds(29, -1, 0), cmp4_ge_or_andcm(13, 14, 29),
     nop_i()),
    (0x30, 0x02, nop_m(), adds(4, 1, 0, qp=13),
     adds(5, 1, 0, qp=14)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 1, "r5": 0}, entry=0x10)

test_cmp_ne_or_andcm_decode = require_registers("cmp_ne_or_andcm_decode", [
    (0x10, 0x00, addl(26, 0x895, 0), cmp4_eq_unc_imm(0, 13, 1, 0),
     nop_i()),
    (0x20, 0x00, cmp_ne_or_andcm(0, 13, 0, 26), nop_i(),
     nop_i()),
    (0x30, 0x00, adds(4, 1, 0, qp=13), cmp4_eq_unc_imm(0, 14, 1, 0),
     nop_i()),
    (0x40, 0x00, cmp_ne_or_andcm(0, 14, 0, 0), nop_i(),
     nop_i()),
    (0x50, 0x10, adds(5, 1, 0, qp=14), nop_i(),
     br_cond(0x50, 0x60)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {"ip": 0x60, "r4": 0, "r5": 1}, entry=0x10)

test_cmp_ne_or_andcm_imm_negative_decode = require_registers(
    "cmp_ne_or_andcm_imm_negative_decode", [
        (0x10, 0x00, adds(23, 0, 0), cmp_ne_or_andcm_imm(13, 0, -1, 23),
         nop_i()),
        (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=13),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 1}, entry=0x10)

test_cmp4_ne_or_andcm_decode = require_registers("cmp4_ne_or_andcm_decode", [
    (0x10, 0x00, addl(26, 0x895, 0), cmp4_eq_unc_imm(0, 13, 1, 0),
     nop_i()),
    (0x20, 0x00, cmp4_ne_or_andcm(0, 13, 0, 26), nop_i(),
     nop_i()),
    (0x30, 0x00, adds(4, 1, 0, qp=13), cmp4_eq_unc_imm(0, 14, 1, 0),
     nop_i()),
    (0x40, 0x00, cmp4_ne_or_andcm(0, 14, 0, 0), nop_i(),
     nop_i()),
    (0x50, 0x10, adds(5, 1, 0, qp=14), nop_i(),
     br_cond(0x50, 0x60)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {"ip": 0x60, "r4": 0, "r5": 1}, entry=0x10)

test_cmp4_eq_ne_or_decode = require_registers("cmp4_eq_ne_or_decode", [
    (0x10, *movl_mlx(16, 0x100000005)),
    (0x20, *movl_mlx(17, 0x200000005)),
    (0x30, *movl_mlx(18, 0x200000006)),
    (0x40, 0x00, cmp4_eq_or(13, 0, 16, 17),
     cmp4_ne_or(14, 0, 16, 17), nop_i()),
    (0x50, 0x00, cmp4_ne_or(15, 0, 16, 18),
     adds(4, 1, 0, qp=13), adds(5, 1, 0, qp=14)),
    (0x60, 0x00, adds(6, 1, 0, qp=15), nop_i(),
     nop_i()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
], {"ip": 0x70, "r4": 1, "r5": 0, "r6": 1}, entry=0x10)

test_cmp_imm_update_decode = require_registers(
    "cmp_imm_update_decode", [
        (0x10, *movl_mlx(9, 0x100000004)),
        (0x20, 0x00, adds(8, 4, 0), adds(16, 1, 0),
         mov_pr_rot_imm(0x00ff0000)),
        (0x30, 0x00, cmp_eq_and_imm(16, 17, 4, 8),
         cmp_ne_and_imm(18, 19, 4, 8), cmp4_eq_and_imm(20, 21, 4, 9)),
        (0x40, 0x00, cmp4_ne_and_imm(22, 23, -1, 9),
         cmp_eq_or_imm(24, 25, -1, 8), cmp_ne_or_imm(26, 27, -1, 8)),
        (0x50, 0x00, cmp4_eq_or_imm(28, 29, 4, 9),
         cmp4_ne_or_imm(30, 31, -1, 9), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "pr_mask": (1 | (1 << 16) | (1 << 17) |
                    (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23) |
                    (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) |
                    (1 << 30) | (1 << 31)),
    }, entry=0x10)

test_chk_s_m_branches_on_nat = require_registers(
    "chk_s_m_branches_on_nat", [
        (0x10, *movl_mlx(9, 1 << 32)),
        (0x20, 0x00, mov_m_gr_ar(9, 36), addl(3, 0x100, 0),
         nop_i()),
        (0x30, 0x00, ld8_fill_postinc(17, 3, 0), nop_i(),
         nop_i()),
        (0x40, 0x08, nop_m(), chk_s_m(17, 0x40, 0x60),
         nop_i()),
        (0x50, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {"ip": 0x60, "r4": 0}, entry=0x10)

test_chk_a_nc_m_decode = require_registers("chk_a_nc_m_decode", [
    (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, ld8_a(27, 3), nop_i(),
     nop_i()),
    (0x30, 0x00, chk_a_nc_m(27, 0x30, 0x50), adds(31, 0x56, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
    (0x100, 0x00, 0x123456789abcdef0, 0,
     0),
], {"ip": 0x40, "exception": IA64_EXCP_NONE, "r31": 0x56}, entry=0x10)

test_mlx_chk_a_clr_nop_x_decode = require_registers(
    "mlx_chk_a_clr_nop_x_decode", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x30, 0x04, chk_a_clr_m(22, 0x30, 0x50), 0,
         nop_x()),
        (0x40, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x40, 0x50)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x50, "exception": IA64_EXCP_NONE, "r31": 0x55},
    entry=0x10)

test_mlx_false_predicate_long_nop_decode = require_registers(
    "mlx_false_predicate_long_nop_decode", [
        (0x10, 0x04, nop_m(), 1, nop_x(qp=1)),
        (0x20, 0x10, nop_m(), nop_i(),
         br_cond(0x20, 0x20)),
    ], {"ip": 0x20, "exception": IA64_EXCP_NONE}, entry=0x10)

test_mlx_long_nop_x_imm_decode = require_registers(
    "mlx_long_nop_x_imm_decode", [
        (0x10, *nop_x_mlx(0x30200000)),
        (0x20, 0x00, adds(4, 0x5a, 0), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 0x5a, "exception": IA64_EXCP_NONE}, entry=0x10)

test_chk_a_m_branches_on_miss = require_registers(
    "chk_a_m_branches_on_miss", [
        (0x10, 0x00, chk_a_nc_m(27, 0x10, 0x30), nop_i(),
         nop_i()),
        (0x20, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 0}, entry=0x10)

test_chk_a_clr_removes_entry = require_registers(
    "chk_a_clr_removes_entry", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, chk_a_clr_m(22, 0x30, 0x60), nop_i(),
         nop_i()),
        (0x40, 0x00, chk_a_nc_m(22, 0x40, 0x60), adds(4, 1, 0),
         nop_i()),
        (0x50, 0x00, adds(5, 1, 0), nop_i(),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0x60, "r4": 0, "r5": 0}, entry=0x10)

test_invala_e_gr_invalidates_selected_register = require_registers(
    "invala_e_gr_invalidates_selected_register", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8_a(23, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, invala_e_gr(22), nop_i(),
         nop_i()),
        (0x50, 0x00, chk_a_nc_m(22, 0x50, 0x90), adds(4, 1, 0),
         nop_i()),
        (0x60, 0x00, adds(6, 1, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x90, 0x00, chk_a_nc_m(23, 0x90, 0xc0), adds(5, 1, 0),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0xc0, 0x00, adds(7, 1, 0), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0xa0, "r4": 0, "r5": 1, "r6": 0, "r7": 0},
    entry=0x10)

test_alat_reloading_register_does_not_leave_duplicate = require_registers(
    "alat_reloading_register_does_not_leave_duplicate", [
        (0x10, 0x00, addl(3, 0x100, 0), addl(5, 0x110, 0),
         nop_i()),
        (0x20, 0x00, ld8_a(21, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8_a(22, 5), nop_i(),
         nop_i()),
        (0x40, 0x00, invala_e_gr(21), addl(5, 0x120, 0),
         nop_i()),
        (0x50, 0x00, ld8_a(22, 5), nop_i(),
         nop_i()),
        (0x60, 0x00, invala_e_gr(22), nop_i(),
         nop_i()),
        (0x70, 0x00, chk_a_nc_m(22, 0x70, 0xa0), nop_i(),
         nop_i()),
        (0x80, 0x00, adds(4, 1, 0), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x100, 0x00, 0x1111111111111111, 0,
         0),
        (0x110, 0x00, 0x2222222222222222, 0,
         0),
        (0x120, 0x00, 0x3333333333333333, 0,
         0),
    ], {"ip": 0xa0, "r4": 0}, entry=0x10)

test_invala_clears_all_alat_entries = require_registers(
    "invala_clears_all_alat_entries", [
        (0x10, 0x00, addl(3, 0x100, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8_a(23, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, invala(), nop_i(),
         nop_i()),
        (0x50, 0x00, chk_a_nc_m(22, 0x50, 0x80), adds(4, 1, 0),
         nop_i()),
        (0x60, 0x00, adds(6, 1, 0), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x80, 0x00, chk_a_nc_m(23, 0x80, 0xb0), adds(5, 1, 0),
         nop_i()),
        (0x90, 0x00, adds(7, 1, 0), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x100, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {"ip": 0xb0, "r4": 0, "r5": 0, "r6": 0, "r7": 0},
    entry=0x10)

test_dep_decode = require_registers("dep_decode", [
    (0x10, 0x00, addl(2, 0xab, 0), addl(3, 0x1234, 0),
     nop_i()),
    (0x20, 0x01, nop_m(), dep(4, 2, 3, 8, 8),
     dep(5, 2, 3, 4, 12)),
    # cpos=14 and len=2 encode bits 35:27 as 0xe1.  This remains a valid
    # I15 dep; the same bits identify getf.sig only when used in an M-unit.
    (0x30, 0x01, nop_m(), dep(6, 2, 3, 49, 2),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 0xab34, "r5": 0xab4,
    "r6": 0x6000000001234}, entry=0x10)

test_extr_u_ignored_bit36_decode = require_registers(
    "extr_u_ignored_bit36_decode", [
        (0x10, *movl_mlx(3, 0xffff000000000000)),
        (0x20, 0x02, nop_m(), extr_u(4, 3, 48, 16, bit36=1),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 0xffff}, entry=0x10)

test_extr_signed_truncates_overlong_field = require_registers(
    "extr_signed_truncates_overlong_field", [
        (0x10, *movl_mlx(3, 0x8000000000000000)),
        (0x20, 0x02, nop_m(), extr(4, 3, 60, 8),
         extr(5, 3, 4, 64)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 0xfffffffffffffff8,
        "r5": 0xf800000000000000}, entry=0x10)

test_dep_source_alias_decode = require_registers("dep_source_alias_decode", [
    (0x10, *movl_mlx(4, 0x07c5080f)),
    (0x20, *movl_mlx(5, 0x000f8a10)),
    (0x30, 0x02, nop_m(), dep(4, 4, 5, 25, 7),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 0x1e0f8a10}, entry=0x10)

test_page_frame_record_address_arithmetic = require_registers(
    "page_frame_record_address_arithmetic", [
        (0x10, *movl_mlx(28, 0x001000019b502661)),
        (0x20, *movl_mlx(20, 0x1ffffeda00000000)),
        (0x30, 0x02, nop_m(), extr_u(27, 28, 13, 37), nop_i()),
        (0x40, 0x02, nop_m(), shladd(26, 27, 1, 27), nop_i()),
        (0x50, 0x02, nop_m(), shladd(24, 26, 4, 0), nop_i()),
        (0x60, 0x02, nop_m(), sub_reg(25, 24, 20), nop_i()),
        (0x70, 0x02, nop_m(), adds(31, 28, 25), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "r27": 0xcda81,
        "r25": 0xe00001260268f830,
        "r31": 0xe00001260268f84c,
    }, entry=0x10)

test_page_table_pointer_dep_cascade = require_registers(
    "page_table_pointer_dep_cascade", [
        (0x10, *movl_mlx(2, 0x100000)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x40, *movl_mlx(31, 0xe00000000000cdef)),
        (0x50, *movl_mlx(55, 0x89ab)),
        (0x60, *movl_mlx(54, 0x4567)),
        (0x70, *movl_mlx(53, 0x123)),
        (0x80, 0x02, nop_m(), dep(104, 55, 31, 16, 16), nop_i()),
        (0x90, 0x02, nop_m(), dep(103, 54, 104, 32, 16), nop_i()),
        (0xa0, 0x02, nop_m(), dep(98, 53, 103, 48, 13), nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(), br_cond(0xb0, 0xb0)),
    ], {
        "ip": 0xb0,
        "r98": 0xe123456789abcdef,
    }, entry=0x10)

def test_high_ram_above_4g_physical_and_translated_access(qemu):
    # Match the physical address of the PFN accounting word from the crash
    # dump and cover it with a supported large CPU translation.  The word is
    # in the upper 4 KiB half of an 8 KiB guest page.  Keep a distinct value
    # at the corresponding address below 4 GiB so that a truncating physical
    # address path cannot pass merely by reading back its own aliased write.
    count_pa = 0x000000010368f84c
    low_count_pa = count_pa & 0xffffffff
    page_pa = 0x000000019b502000
    count_va = 0xe00001260268f84c
    page_va = 0xe00001269b502000
    run_program(qemu, [
        *dtr_setup_bundles(0x10, count_va, count_pa,
                           page_shift=24, slot=5),
        *dtr_setup_bundles(0x70, page_va, page_pa, slot=6),
        (0xd0, *movl_mlx(2, count_va)),
        (0xe0, *movl_mlx(3, page_va)),
        (0xf0, *movl_mlx(6, low_count_pa)),
        (0x100, *movl_mlx(7, 0xabcd)),
        (0x110, 0x00, st2(6, 7), nop_i(), nop_i()),
        (0x120, *movl_mlx(4, 0x1234)),
        (0x130, 0x00, ssm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x140, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x150, 0x00, st2(2, 4), nop_i(), nop_i()),
        (0x160, 0x00, ld2_bias(8, 2), nop_i(), nop_i()),
        (0x170, 0x00, ld2_s(11, 2), nop_i(), nop_i()),
        # Exercise an atomic update in the same high physical PFN record;
        # it must neither alias nor overwrite the adjacent 16-bit count.
        (0x180, *movl_mlx(13, count_va - 0x14)),
        (0x190, *movl_mlx(14, 0x1020304050607080)),
        (0x1a0, 0x00, st8(13, 14), nop_i(), nop_i()),
        (0x1b0, *movl_mlx(14, 0x8877665544332211)),
        (0x1c0, 0x00, xchg(3, 15, 13, 14), nop_i(), nop_i()),
        (0x1d0, 0x00, ld8(16, 13), nop_i(), nop_i()),
        (0x1e0, *movl_mlx(5, 0x1122334455667788)),
        (0x1f0, 0x00, st8(3, 5), nop_i(), nop_i()),
        (0x200, *movl_mlx(6, 0x8877665544332211)),
        (0x210, 0x00, xchg(3, 9, 3, 6), nop_i(), nop_i()),
        (0x220, 0x00, ld8(10, 3), nop_i(), nop_i()),
        (0x230, 0x00, ld2(17, 2), nop_i(), nop_i()),
        (0x240, 0x00, rsm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x250, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x260, *movl_mlx(6, low_count_pa)),
        (0x270, 0x00, ld2(12, 6), nop_i(), nop_i()),
        (0x280, 0x10, nop_m(), nop_i(), br_cond(0x280, 0x280)),
    ], entry=0x10, terminal_ip=0x280, memory="8G", expected={
        "r8": 0x1234,
        "r11": 0x1234,
        "r12": 0xabcd,
        "r15": 0x1020304050607080,
        "r16": 0x8877665544332211,
        "r17": 0x1234,
        "r9": 0x1122334455667788,
        "r10": 0x8877665544332211,
    }, name="high_ram_above_4g_physical_and_translated_access")


def test_long_vhpt_large_page_high_ram_subword_remap(qemu):
    # Reproduce the mapping which contained the corrupt PFN count in the
    # crash dump.  Unlike the pinned-DTR coverage above, install the 16 MiB
    # mapping through a long-format VHPT walk, update its leaf translation,
    # purge the old TC, and refill it at the same virtual address.
    page_shift = 24
    page_mask = (1 << page_shift) - 1
    rid = 7
    count_va = 0xe00001260268f84c
    count_a_pa = 0x000000010368f84c
    count_b_pa = 0x000000011368f84c
    low_count_pa = count_a_pa & 0xffffffff
    pta = 0x10013d
    pta_size = (pta >> 2) & 0x3f
    hpn_bits = IA64_IMPL_VA_MSB + 1 - page_shift
    payload = count_va & ((1 << (IA64_IMPL_VA_MSB + 1)) - 1)
    hpn = payload >> page_shift
    entries = 1 << (pta_size - 5)
    vhpt_hash = (hpn ^ (hpn >> 7) ^ rid) & (entries - 1)
    entry_pa = (pta & ~((1 << pta_size) - 1)) | (vhpt_hash << 5)
    tag = (rid << hpn_bits) | (hpn & ((1 << hpn_bits) - 1))
    pte_a = (count_a_pa & ~page_mask) | DTR_PTE_WB
    pte_b = (count_b_pa & ~page_mask) | DTR_PTE_WB
    rr = (rid << 8) | (page_shift << 2) | 1
    itir = page_shift << 2

    run_program(qemu, [
        (0x10, *movl_mlx(2, count_a_pa)),
        (0x20, *movl_mlx(3, count_b_pa)),
        (0x30, *movl_mlx(4, low_count_pa)),
        (0x40, *movl_mlx(5, 0x1111)),
        (0x50, 0x00, st2(2, 5), nop_i(), nop_i()),
        (0x60, *movl_mlx(5, 0x2222)),
        (0x70, 0x00, st2(3, 5), nop_i(), nop_i()),
        (0x80, *movl_mlx(5, 0x5555)),
        (0x90, 0x00, st2(4, 5), nop_i(), nop_i()),
        (0xa0, *movl_mlx(15, entry_pa)),
        (0xb0, *movl_mlx(16, pte_a)),
        (0xc0, *movl_mlx(17, itir)),
        (0xd0, *movl_mlx(18, tag)),
        (0xe0, 0x00, st8(15, 16), adds(6, 8, 15), nop_i()),
        (0xf0, 0x00, st8(6, 17), adds(6, 16, 15), nop_i()),
        (0x100, 0x00, st8(6, 18), nop_i(), nop_i()),
        (0x110, *movl_mlx(19, pta)),
        (0x120, 0x00, mov_m_gr_cr(19, 8), nop_i(), nop_i()),
        (0x130, *movl_mlx(20, rr)),
        (0x140, *movl_mlx(21, count_va)),
        (0x150, 0x00, mov_rr_write(20, 21), nop_i(), nop_i()),
        (0x160, 0x00, ssm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x170, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x180, 0x00, ld2(8, 21), nop_i(), nop_i()),
        (0x190, *movl_mlx(22, 0x3333)),
        (0x1a0, 0x00, st2(21, 22), nop_i(), nop_i()),
        (0x1b0, 0x00, ld2(9, 21), nop_i(), nop_i()),

        # Modify the VHPT leaf with translation disabled, then perform the
        # architected local purge/serialization before the second walk.
        (0x1c0, 0x00, rsm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x1d0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x1e0, *movl_mlx(16, pte_b)),
        (0x1f0, 0x00, st8(15, 16), nop_i(), nop_i()),
        (0x200, 0x00, ptc_l(21, 17), nop_i(), nop_i()),
        (0x210, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x220, 0x00, ssm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x230, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x240, 0x00, ld2(10, 21), nop_i(), nop_i()),
        (0x250, *movl_mlx(22, 0x4444)),
        (0x260, 0x00, st2(21, 22), nop_i(), nop_i()),
        (0x270, 0x00, ld2(11, 21), nop_i(), nop_i()),
        (0x280, 0x00, rsm(IA64_PSR_DT), nop_i(), nop_i()),
        (0x290, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x2a0, 0x00, ld2(12, 2), nop_i(), nop_i()),
        (0x2b0, 0x00, ld2(13, 3), nop_i(), nop_i()),
        (0x2c0, 0x00, ld2(14, 4), nop_i(), nop_i()),
        (0x2d0, 0x10, nop_m(), nop_i(), br_cond(0x2d0, 0x2d0)),
    ], entry=0x10, terminal_ip=0x2d0, memory="8G", expected={
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111,
        "r9": 0x3333,
        "r10": 0x2222,
        "r11": 0x4444,
        "r12": 0x3333,
        "r13": 0x4444,
        "r14": 0x5555,
    }, name="long_vhpt_large_page_high_ram_subword_remap")


test_st4_variants_preserve_adjacent_halfword = require_registers(
    "st4_variants_preserve_adjacent_halfword", [
        (0x10, *movl_mlx(2, 0x4000)),
        (0x20, *movl_mlx(3, 0xa1b2c3d455667788)),
        (0x30, *movl_mlx(4, 0x01234567deadbeef)),

        (0x40, 0x00, st8(2, 3), nop_i(), nop_i()),
        (0x50, 0x00, st4(2, 4), nop_i(), nop_i()),
        (0x60, 0x00, ld8(8, 2), nop_i(), nop_i()),

        (0x70, 0x00, st8(2, 3), nop_i(), nop_i()),
        (0x80, 0x00, st4_rel(2, 4), nop_i(), nop_i()),
        (0x90, 0x00, ld8(9, 2), nop_i(), nop_i()),

        (0xa0, 0x00, st8(2, 3), adds(5, 0, 2), nop_i()),
        (0xb0, 0x00, st4_postinc(5, 4, 4), nop_i(), nop_i()),
        (0xc0, 0x00, ld8(10, 2), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r5": 0x4004,
        "r8": 0xa1b2c3d4deadbeef,
        "r9": 0xa1b2c3d4deadbeef,
        "r10": 0xa1b2c3d4deadbeef,
    }, entry=0x10)


# SDM Vol 3, Table 4-29 (integer load/store x6 opcode extensions): spill and
# fill exist only as the 8-byte forms (ld8.fill x6=0x1b, st8.spill x6=0x3b).
# The x6 values 0x18-0x1a and 0x38-0x3a are blank in the table, so every
# instruction format that shares the integer load/store x6 space must raise
# an Illegal Operation fault for them.  The no-update (M1/M4) and
# imm-base-update (M3/M5) forms are covered separately so a future decoder
# split per format keeps faulting on the reserved values.
def reserved_memory_x6_test(name, slot0):
    return require_exception(name, [
        (0x10, 0x00, slot0, nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_load_x6_18_reserved_illegal_operation = reserved_memory_x6_test(
    "load_x6_18_reserved_illegal_operation", load_mem(0x18, 8, 3))

test_load_x6_19_reserved_illegal_operation = reserved_memory_x6_test(
    "load_x6_19_reserved_illegal_operation", load_mem(0x19, 8, 3))

test_load_x6_1a_reserved_illegal_operation = reserved_memory_x6_test(
    "load_x6_1a_reserved_illegal_operation", load_mem(0x1a, 8, 3))

test_load_postinc_x6_18_reserved_illegal_operation = reserved_memory_x6_test(
    "load_postinc_x6_18_reserved_illegal_operation",
    load_mem_postinc(0x18, 8, 3, 8))

test_load_postinc_x6_19_reserved_illegal_operation = reserved_memory_x6_test(
    "load_postinc_x6_19_reserved_illegal_operation",
    load_mem_postinc(0x19, 8, 3, 8))

test_load_postinc_x6_1a_reserved_illegal_operation = reserved_memory_x6_test(
    "load_postinc_x6_1a_reserved_illegal_operation",
    load_mem_postinc(0x1a, 8, 3, 8))

# The register base-update form (M2) shares the same x6 space; stores have
# no register base-update form, so only the load side applies.
test_load_reg_postinc_x6_18_reserved_illegal_operation = \
    reserved_memory_x6_test(
        "load_reg_postinc_x6_18_reserved_illegal_operation",
        load_mem_reg_postinc(0x18, 8, 3, 4))

test_load_reg_postinc_x6_19_reserved_illegal_operation = \
    reserved_memory_x6_test(
        "load_reg_postinc_x6_19_reserved_illegal_operation",
        load_mem_reg_postinc(0x19, 8, 3, 4))

test_load_reg_postinc_x6_1a_reserved_illegal_operation = \
    reserved_memory_x6_test(
        "load_reg_postinc_x6_1a_reserved_illegal_operation",
        load_mem_reg_postinc(0x1a, 8, 3, 4))

test_store_x6_38_reserved_illegal_operation = reserved_memory_x6_test(
    "store_x6_38_reserved_illegal_operation", store_mem(0x38, 3, 4))

test_store_x6_39_reserved_illegal_operation = reserved_memory_x6_test(
    "store_x6_39_reserved_illegal_operation", store_mem(0x39, 3, 4))

test_store_x6_3a_reserved_illegal_operation = reserved_memory_x6_test(
    "store_x6_3a_reserved_illegal_operation", store_mem(0x3a, 3, 4))

test_store_postinc_x6_38_reserved_illegal_operation = reserved_memory_x6_test(
    "store_postinc_x6_38_reserved_illegal_operation",
    store_mem_postinc(0x38, 3, 4, 8))

test_store_postinc_x6_39_reserved_illegal_operation = reserved_memory_x6_test(
    "store_postinc_x6_39_reserved_illegal_operation",
    store_mem_postinc(0x39, 3, 4, 8))

test_store_postinc_x6_3a_reserved_illegal_operation = reserved_memory_x6_test(
    "store_postinc_x6_3a_reserved_illegal_operation",
    store_mem_postinc(0x3a, 3, 4, 8))

test_depz_decode = require_registers("depz_decode", [
    (0x10, *movl_mlx(6, 0x12345678)),
    (0x20, 0x02, nop_m(), depz_imm(4, 5, 24, 3),
     nop_i()),
    (0x30, 0x02, nop_m(), depz_imm(5, -9, 0, 28),
     nop_i()),
    (0x40, 0x02, nop_m(), depz_reg(7, 6, 16, 32),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": 0x05000000, "r5": 0x0ffffff7,
    "r7": 0x123456780000}, entry=0x10)

test_depz_len64_decode = require_registers("depz_len64_decode", [
    (0x10, *movl_mlx(6, 0x8123456789abcdef)),
    (0x20, 0x02, nop_m(), depz_reg(7, 6, 0, 64),
     depz_reg(8, 6, 4, 64)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r7": 0x8123456789abcdef,
    "r8": 0x123456789abcdef0}, entry=0x10)

test_sxt1_decode = require_registers("sxt1_decode", [
    (0x10, 0x00, addl(3, 0xff, 0), nop_i(),
     nop_i()),
    (0x20, 0x02, nop_m(), nop_i(),
     sxt1(4, 3)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0xffffffffffffffff}, entry=0x10)

test_mov_lc_imm_decode = require_registers("mov_lc_imm_decode", [
    (0x10, 0x02, nop_m(), nop_i(),
     mov_lc_imm(15)),
    (0x20, 0x02, nop_m(), nop_i(),
     mov_ar_lc(4)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 15}, entry=0x10)

test_mov_lc_negative_imm_sign_extends = require_registers(
    "mov_lc_negative_imm_sign_extends", [
        (0x10, 0x02, nop_m(), nop_i(), mov_lc_imm(-1)),
        (0x20, 0x02, nop_m(), nop_i(), mov_ar_lc(4)),
        (0x30, 0x10, nop_m(), nop_i(), br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": UINT64_MAX}, entry=0x10)

test_mov_m_negative_imm_ar_sign_extends = require_registers(
    "mov_m_negative_imm_ar_sign_extends", [
        (0x10, 0x00, mov_m_imm_ar(36, -1), nop_i(), nop_i()),
        (0x20, 0x00, mov_m_ar_gr(4, 36), nop_i(), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(), br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": UINT64_MAX}, entry=0x10)

test_mov_m_imm_ar_decode = require_registers("mov_m_imm_ar_decode", [
    (0x10, 0x00, mov_m_imm_ar(36, 0x5a), nop_i(),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "ar_unat": 0x5a}, entry=0x10)

test_mov_m_psr_gr_decode = require_registers("mov_m_psr_gr_decode", [
    (0x10, 0x00, sum_um(IA64_PSR_UP), nop_i(),
     nop_i()),
    (0x20, 0x00, mov_m_psr_gr(29), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r29": IA64_PSR_UP, "psr": IA64_PSR_UP}, entry=0x10)

test_mov_m_gr_psrl_decode = require_registers("mov_m_gr_psrl_decode", [
    (0x10, 0x00, addl(2, IA64_PSR_UP, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, mov_m_gr_psrl(2), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "psr": IA64_PSR_UP}, entry=0x10)

test_cover_b_ignored_fields_decode = require_registers(
    "cover_b_ignored_fields_decode", [
        (0x10, 0x00, nop_m(), alloc(5, 8, 4, 0, 0), nop_i()),
        (0x20, 0x18, nop_m(), nop_m(),
         cover_b_ignored_fields(qp=1)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "exception": IA64_EXCP_NONE,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_epc_b_ignored_fields_decode = require_registers(
    "epc_b_ignored_fields_decode", [
        (0x10, 0x10, nop_m(), nop_i(),
         epc_b(qp=1, ignored=0xf78c1)),
        (0x20, 0x10, nop_m(), addl(4, 0x44, 0),
         br_cond(0x20, 0x30)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "exception": IA64_EXCP_NONE,
        "r4": 0x44,
    }, entry=0x10)

test_bsw0_clears_bn_bit = require_registers("bsw0_clears_bn_bit", [
    (0x10, *movl_mlx(18, 1 << 44)),
    (0x20, 0x00, mov_gr_psr_full(18), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     bsw0()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "psr": 0}, entry=0x10)

test_bsw0_in_b_slot_falls_through = require_registers("bsw0_in_b_slot_falls_through", [
    (0x10, *movl_mlx(18, 1 << 44)),
    (0x20, 0x00, mov_gr_psr_full(18), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     bsw0()),
    (0x40, 0x10, nop_m(), adds(2, 0x33, 0),
     br_cond(0x40, 0x50)),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "psr": 0, "r2": 0x33}, entry=0x10)

test_bsw1_sets_bn_bit = require_registers("bsw1_sets_bn_bit", [
    (0x10, 0x10, nop_m(), nop_i(),
     bsw1()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "psr": 1 << 44}, entry=0x10)

# Montecito implements the virtualization extensions but this model provides
# no virtual-machine environment, so vmsw reports the architected fault.
test_vmsw1_montecito_virtualization_fault = require_exception(
    "vmsw1_montecito_virtualization_fault", [
        (0x10, 0x10, nop_m(), nop_i(),
         vmsw1(qp=1)),
    ], IA64_EXCP_VIRTUALIZATION, fault_ip=0x10)

test_vmsw0_montecito_virtualization_fault = require_exception(
    "vmsw0_montecito_virtualization_fault", [
        (0x10, 0x10, nop_m(), nop_i(),
         vmsw0(qp=1)),
    ], IA64_EXCP_VIRTUALIZATION, fault_ip=0x10)

# The virtualization extensions post-date Madison, so the encoding is
# reserved there.
test_vmsw1_madison_illegal_operation = require_exception(
    "vmsw1_madison_illegal_operation", [
        (0x10, 0x10, nop_m(), nop_i(),
         vmsw1(qp=1)),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10, cpu="madison")

test_vmsw0_madison_illegal_operation = require_exception(
    "vmsw0_madison_illegal_operation", [
        (0x10, 0x10, nop_m(), nop_i(),
         vmsw0(qp=1)),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10, cpu="madison")

# On models with the virtualization extensions vmsw is a privileged
# instruction, so the privilege check precedes the Virtualization fault.
# (PSR.ic must be cleared before the rfi setup writes IPSR and IIP.)
test_vmsw_cpl3_montecito_privileged_operation = require_exception(
    "vmsw_cpl3_montecito_privileged_operation", [
        (0x10, 0x00, rsm(IA64_PSR_IC), nop_i(), nop_i()),
        (0x20, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x30, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_CPL3)),
        (0x40, 0x00, nop_m(), adds(31, 0x70, 0), nop_i()),
        *rfi_to_gr(0x50, 19, 31),
        (0x70, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         vmsw1(qp=1)),
    ], IA64_EXCP_PRIVILEGED_OP, fault_ip=0x80)

# The reserved encoding on Madison stays an Illegal Operation fault even at
# a lower privilege level: there is no privilege semantic for it at all.
test_vmsw_cpl3_madison_illegal_operation = require_exception(
    "vmsw_cpl3_madison_illegal_operation", [
        (0x10, 0x00, rsm(IA64_PSR_IC), nop_i(), nop_i()),
        (0x20, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x30, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_CPL3)),
        (0x40, 0x00, nop_m(), adds(31, 0x70, 0), nop_i()),
        *rfi_to_gr(0x50, 19, 31),
        (0x70, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         vmsw1(qp=1)),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x80, cpu="madison")

test_bsw_switches_r16_r31_bank = require_registers("bsw_switches_r16_r31_bank", [
    (0x10, *movl_mlx(16, 0x1111)),
    (0x20, 0x10, nop_m(), nop_i(),
     bsw1()),
    (0x30, *movl_mlx(16, 0x2222)),
    (0x40, 0x00, adds(2, 0, 16), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     bsw0()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "psr": 0,
    "r2": 0x2222,
    "r16": 0x1111,
}, entry=0x10)

test_bsw_restores_banked_nat = require_registers(
    "bsw_restores_banked_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x13, nop_m(), nop_b(), bsw1()),
        # Clear the bank-1 r16 NaT while bank 0's NaT is saved.  Switching
        # back must restore the saved NaT bit together with the GR bank
        # (SDM Vol. 2, 3.3.7).
        (0x40, *movl_mlx(16, 0x55)),
        (0x50, 0x13, nop_m(), nop_b(), bsw0()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x200, 0x00, 0, 0, 0),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "psr": 0,
        "r16_nat": 1,
    }, entry=0x10)

test_mov_m_cr_gr_decode = require_registers("mov_m_cr_gr_decode", [
    (0x10, 0x00, addl(2, 0x1234, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, mov_m_gr_cr(2, 19), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_m_cr_gr(29, 19), nop_i(),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r29": 0x1234}, entry=0x10)

test_itr_i_indexed_decode = require_registers("itr_i_indexed_decode", [
    (0x10, *movl_mlx(18, 0x0010000004000661)),
    (0x20, *movl_mlx(19, 1 << 36)),
    (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
     nop_i()),
    (0x60, 0x00, itr_i(5, 18), addl(31, 0x8430, 0),
     nop_i()),
    *rfi_to_gr(0x70, 19, 31),
    (0x4008430, 0x10, nop_m(), adds(31, 0x7b, 0),
     br_cond(0x4008430, 0x8440)),
    (0x4008440, 0x10, nop_m(), nop_i(),
     br_cond(0x4008440, 0x8440)),
], {"ip": 0x8440, "exception": IA64_EXCP_NONE, "r31": 0x7b}, entry=0x10)

test_itr_i_slot_uses_low_8_bits = require_registers(
    "itr_i_slot_uses_low_8_bits", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(19, 1 << 36)),
        (0x30, *movl_mlx(5, 0x1234000000000005)),
        (0x40, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x70, 0x00, itr_i(5, 18), addl(31, 0x8430, 0),
         nop_i()),
        *rfi_to_gr(0x80, 19, 31),
        (0x4008430, 0x10, nop_m(), adds(31, 0x7b, 0),
         br_cond(0x4008430, 0x8440)),
        (0x4008440, 0x10, nop_m(), nop_i(),
         br_cond(0x4008440, 0x8440)),
    ], {
        "ip": 0x8440,
        "exception": IA64_EXCP_NONE,
        "r31": 0x7b,
    }, entry=0x10)

test_itr_i_reserved_slot_faults = require_exception(
    "itr_i_reserved_slot_faults", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, 0x00, adds(5, IA64_TR_COUNT, 0), nop_i(), nop_i()),
        (0x30, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x30, entry=0x10)

test_itr_i_resumes_next_slot_after_tb_exit = require_registers(
    "itr_i_resumes_next_slot_after_tb_exit", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itr_i(5, 18), adds(31, 1, 0),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_itr_i_8k_translation_uses_unrounded_paddr = require_registers(
    "itr_i_8k_translation_uses_unrounded_paddr", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x2000)),
        (0x20, *movl_mlx(19, 1 << 36)),
        (0x30, 0x00, adds(7, EIGHT_K_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), adds(31, 0x430, 0),
         nop_i()),
        (0x70, 0x00, srlz_i(), nop_i(),
         nop_i()),
        *rfi_to_gr(0x80, 19, 31),
        (0x4000430, 0x10, nop_m(), adds(31, 0x16, 0),
         br_cond(0x4000430, 0x4000430)),
        (0x4002430, 0x10, nop_m(), adds(31, 0x2b, 0),
         br_cond(0x4002430, 0x4002440)),
        (0x4002440, 0x10, nop_m(), nop_i(),
         br_cond(0x4002440, 0x4002440)),
    ], {
        "ip": 0x440,
        "exception": IA64_EXCP_NONE,
        "r31": 0x2b,
    }, entry=0x10)

IT_ONLY_DATA_BUNDLE = (0x4009000, 0x10, nop_m(), nop_i(),
                       br_cond(0x4009000, 0x4009000))
IT_ONLY_DATA_LOW, _ = bundle_words(*IT_ONLY_DATA_BUNDLE[1:])

test_it_only_keeps_data_physical = require_registers("it_only_keeps_data_physical", [
    (0x10, *movl_mlx(18, 0x0010000004000661)),
    (0x20, *movl_mlx(19, 1 << 36)),
    (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
     nop_i()),
    (0x60, 0x00, itr_i(5, 18), addl(31, 0x8430, 0),
     nop_i()),
    *rfi_to_gr(0x70, 19, 31),
    (0x4008430, *movl_mlx(2, 0x4009000)),
    (0x4008440, 0x00, ld8(31, 2), nop_i(),
     nop_i()),
    (0x4008450, 0x10, nop_m(), nop_i(),
     br_cond(0x4008450, 0x8450)),
    IT_ONLY_DATA_BUNDLE,
], {"ip": 0x8450, "exception": IA64_EXCP_NONE, "r31": IT_ONLY_DATA_LOW}, entry=0x10)

PHYSICAL_ALIAS_ADDR = 0x220000
PHYSICAL_ALIAS_UC_ADDR = IA64_PHYS_UC_BIT | PHYSICAL_ALIAS_ADDR
PHYSICAL_ALIAS_FIRST = 0x1122334455667788
PHYSICAL_ALIAS_SECOND = 0x8877665544332211

test_data_physical_uc_bit_aliases_wbl_space = require_registers(
    "data_physical_uc_bit_aliases_wbl_space", [
        (0x10, *movl_mlx(3, PHYSICAL_ALIAS_ADDR)),
        (0x20, *movl_mlx(4, PHYSICAL_ALIAS_UC_ADDR)),
        (0x30, *movl_mlx(5, PHYSICAL_ALIAS_FIRST)),
        (0x40, *movl_mlx(6, PHYSICAL_ALIAS_SECOND)),
        (0x50, 0x00, st8(3, 5), nop_i(), nop_i()),
        (0x60, 0x00, ld8(8, 4), nop_i(), nop_i()),
        (0x70, 0x00, st8(4, 6), nop_i(), nop_i()),
        (0x80, 0x00, ld8(9, 3), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r8": PHYSICAL_ALIAS_FIRST,
        "r9": PHYSICAL_ALIAS_SECOND,
    }, entry=0x10)

test_itr_i_uses_region_rid = require_registers("itr_i_uses_region_rid", [
    (0x10, *movl_mlx(18, 0x0010000004000661)),
    (0x20, *movl_mlx(19, (1 << 36) | (1 << 44))),
    (0x30, *movl_mlx(20, (0x12345 << 8) | 0x68)),
    (0x40, 0x00, mov_rr_write(20, 0), nop_i(),
     nop_i()),
    (0x50, 0x00, adds(7, 0x68, 0), nop_i(),
     nop_i()),
    (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
     nop_i()),
    (0x70, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
     nop_i()),
    (0x80, 0x00, itr_i(5, 18), addl(31, 0x8430, 0),
     nop_i()),
    *rfi_to_gr(0x90, 19, 31),
    (0x4008430, 0x10, nop_m(), adds(31, 0x7b, 0),
     br_cond(0x4008430, 0x8440)),
    (0x4008440, 0x10, nop_m(), nop_i(),
     br_cond(0x4008440, 0x8440)),
], {"ip": 0x8440, "exception": IA64_EXCP_NONE, "r31": 0x7b}, entry=0x10)

test_itr_i_survives_region_register_write = require_registers(
    "itr_i_survives_region_register_write", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(19, (1 << 36) | (1 << 44))),
        (0x30, *movl_mlx(20, (0x12345 << 8) | 0x68)),
        (0x40, 0x00, mov_rr_write(20, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
         nop_i()),
        (0x80, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_rr_write(20, 0), addl(31, 0x8430, 0),
         nop_i()),
        *rfi_to_gr(0xa0, 19, 31),
        (0x4008430, 0x10, nop_m(), adds(31, 0x7f, 0),
         br_cond(0x4008430, 0x8440)),
        (0x4008440, 0x10, nop_m(), nop_i(),
         br_cond(0x4008440, 0x8440)),
    ], {
        "ip": 0x8440,
        "exception": IA64_EXCP_NONE,
        "r31": 0x7f,
    }, entry=0x10)

test_itr_i_match_ignores_vrn = require_registers(
    "itr_i_match_ignores_vrn", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(2, 0xa000000000000430)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 36))),
        (0x40, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x70, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x80, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), mov_br_gr(7, 2),
         nop_i()),
        *rfi_to_gr(0xa0, 19, 2),
        (0x4000430, 0x10, nop_m(), adds(31, 0x5a, 0),
         br_cond(0x4000430, 0x4000440)),
        (0x4000440, 0x10, nop_m(), nop_i(),
         br_cond(0x4000440, 0x4000440)),
    ], {
        "ip": 0xa000000000000440,
        "exception": IA64_EXCP_NONE,
        "r31": 0x5a,
    }, entry=0x10)

test_itr_i_cached_translation_survives_region_register_write = \
    require_registers(
        "itr_i_cached_translation_survives_region_register_write", [
            (0x10, *movl_mlx(18, 0x0010000004000661)),
            (0x20, *movl_mlx(19, 0x0010000004010661)),
            (0x30, *movl_mlx(20, (0x12345 << 8) | LOW_VECTOR_ITIR)),
            (0x40, *movl_mlx(21, 0x8000)),
            (0x50, *movl_mlx(22, 0x20000)),
            (0x60, *movl_mlx(23, (1 << 13) | (1 << 36) | (1 << 44))),
            (0x70, 0x00, mov_rr_write(20, 0), adds(7, LOW_VECTOR_ITIR, 0),
             adds(5, 5, 0)),
            (0x80, 0x00, mov_m_gr_cr(21, 20), nop_i(), nop_i()),
            (0x90, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (0xa0, 0x00, itr_i(5, 18), nop_i(), nop_i()),
            (0xb0, 0x00, mov_m_gr_cr(22, 20), nop_i(), nop_i()),
            (0xc0, 0x00, itr_i(5, 19), nop_i(), nop_i()),
            (0xd0, 0x00, mov_rr_write(20, 0), nop_i(), nop_i()),
            (0xe0, 0x00, srlz_i(), addl(31, 0x8430, 0), nop_i()),
            *rfi_to_gr(0xf0, 23, 31),
            (0x4000430, 0x10, nop_m(), adds(31, 0x73, 0),
             br_cond(0x8430, 0x8440)),
            (0x4000440, 0x10, nop_m(), nop_i(),
             br_cond(0x8440, 0x8440)),
        ], {
            "ip": 0x8440,
            "exception": IA64_EXCP_NONE,
            "r31": 0x73,
        }, entry=0x10)

ITC_DATA_BUNDLE = (0x4009000, 0x00, 0x123456789a, 0, 0)
ITC_DATA_LOW, _ = bundle_words(*ITC_DATA_BUNDLE[1:])
KEY_TEST_DATA_BUNDLE = (0x4001000, *ITC_DATA_BUNDLE[1:])

test_itc_d_uses_source_pte_and_cr_ifa = require_registers(
    "itc_d_uses_source_pte_and_cr_ifa", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x9000)),
        (0x30, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(2, 0x9000)),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        ITC_DATA_BUNDLE,
    ], {"ip": 0xa0, "exception": IA64_EXCP_NONE, "r31": ITC_DATA_LOW},
    entry=0x10)

test_dtr_match_ignores_vrn = require_registers(
    "dtr_match_ignores_vrn", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x9000)),
        (0x30, *movl_mlx(20, (0x12345 << 8) | LOW_VECTOR_ITIR)),
        (0x40, *movl_mlx(21, 0xe000000000000000)),
        (0x50, 0x00, mov_rr_write(20, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_rr_write(20, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(19, 20), adds(7, LOW_VECTOR_ITIR, 0),
         adds(5, 5, 0)),
        (0x90, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0xa0, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(2, 0xe000000000009000)),
        (0xd0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0xe0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        ITC_DATA_BUNDLE,
    ], {"ip": 0xf0, "exception": IA64_EXCP_NONE, "r31": ITC_DATA_LOW},
    entry=0x10)

test_itc_d_pl0_user_read_faults = require_registers(
    "itc_d_pl0_user_read_faults", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x9000)),
        (0x30, 0x00, adds(7, 0x38, 0), adds(31, 0xb0, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(2, 0x9000)),
        (0x80, *movl_mlx(3, (1 << 13) | (1 << 17) |
                         (3 << 32) | (1 << 44))),
        *rfi_to_gr(0x90, 3, 31),
        (0xb0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (IA64_DATA_ACCESS_VECTOR, 0x10, nop_m(), adds(31, 0x71, 0),
         br_cond(IA64_DATA_ACCESS_VECTOR,
                 IA64_DATA_ACCESS_VECTOR + 0x10)),
        (IA64_DATA_ACCESS_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_ACCESS_VECTOR + 0x10,
                 IA64_DATA_ACCESS_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_ACCESS_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x71,
    }, entry=0x10)

test_br_ret_cpl_change_does_not_reuse_kernel_tlb = require_registers(
    "br_ret_cpl_change_does_not_reuse_kernel_tlb", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x9000)),
        (0x30, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(2, 0x9000)),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(3, 3 << 62)),
        (0xb0, *movl_mlx(4, 0xe0)),
        (0xc0, 0x00, nop_m(), mov_m_gr_ar(3, 64),
         mov_br_gr(0, 4)),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0xe0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        (IA64_DATA_ACCESS_VECTOR, 0x10, nop_m(), adds(31, 0x72, 0),
         br_cond(IA64_DATA_ACCESS_VECTOR,
                 IA64_DATA_ACCESS_VECTOR + 0x10)),
        (IA64_DATA_ACCESS_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_ACCESS_VECTOR + 0x10,
                 IA64_DATA_ACCESS_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_ACCESS_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r28": ITC_DATA_LOW,
        "r31": 0x72,
    }, entry=0x10)

def test_itc_d_replaces_full_tc(qemu):
    tc_fill_count = IA64_TLB_MAX
    fill_base = 0x100000
    final_va = fill_base + (tc_fill_count + 1) * 0x4000 + 0x1000
    cursor = 0x40
    bundles = [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
    ]

    for i in range(tc_fill_count):
        va = fill_base + i * 0x4000
        bundles.extend([
            (cursor, *movl_mlx(19, va)),
            (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(),
             nop_i()),
            (cursor + 0x20, 0x00, itc_d(18), nop_i(),
             nop_i()),
        ])
        cursor += 0x30

    bundles.extend([
        (cursor, *movl_mlx(19, final_va)),
        (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (cursor + 0x20, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (cursor + 0x30, *movl_mlx(2, final_va)),
        (cursor + 0x40, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (cursor + 0x50, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (cursor + 0x60, 0x10, nop_m(), nop_i(),
         br_cond(cursor + 0x60, cursor + 0x60)),
        ITC_DATA_BUNDLE,
    ])

    run_program(qemu, bundles, entry=0x10, expected={
        "ip": cursor + 0x60,
        "exception": IA64_EXCP_NONE,
        "r31": ITC_DATA_LOW,
    }, name="itc_d_replaces_full_tc")

def test_itc_d_full_tc_replacement_rotates(qemu):
    tc_fill_count = IA64_TLB_MAX
    fill_base = 0x100000
    first_va = fill_base + (tc_fill_count + 1) * 0x4000 + 0x1000
    second_va = first_va + 0x4000
    cursor = 0x40
    bundles = [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
    ]

    for i in range(tc_fill_count):
        va = fill_base + i * 0x4000
        bundles.extend([
            (cursor, *movl_mlx(19, va)),
            (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(),
             nop_i()),
            (cursor + 0x20, 0x00, itc_d(18), nop_i(),
             nop_i()),
        ])
        cursor += 0x30

    for va in (first_va, second_va):
        bundles.extend([
            (cursor, *movl_mlx(19, va)),
            (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(),
             nop_i()),
            (cursor + 0x20, 0x00, itc_d(18), nop_i(),
             nop_i()),
        ])
        cursor += 0x30

    bundles.extend([
        (cursor, *movl_mlx(2, first_va)),
        (cursor + 0x10, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (cursor + 0x20, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (cursor + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(cursor + 0x30, cursor + 0x30)),
        ITC_DATA_BUNDLE,
    ])

    run_program(qemu, bundles, entry=0x10, expected={
        "ip": cursor + 0x30,
        "exception": IA64_EXCP_NONE,
        "r31": ITC_DATA_LOW,
    }, name="itc_d_full_tc_replacement_rotates")


def test_itc_d_evicted_refill_flushes_host_tlb(qemu):
    page_shift = 14
    page_size = 1 << page_shift
    itir = page_shift << 2
    target_va = 0x08000000
    fill_va = 0x10000000
    page_a = 0x05000000
    page_b = page_a + page_size
    value_a = 0x1122334455667788
    value_b = 0x8877665544332211
    cursor = 0x10
    bundles = []

    def append_itc(va, pa):
        nonlocal cursor

        bundles.extend([
            (cursor, *movl_mlx(18, pa | DTR_PTE_WB)),
            (cursor + 0x10, *movl_mlx(19, va)),
            (cursor + 0x20, 0x00, mov_m_gr_cr(19, 20),
             adds(7, itir, 0), nop_i()),
            (cursor + 0x30, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (cursor + 0x40, 0x00, itc_d(18), nop_i(), nop_i()),
        ])
        cursor += 0x50

    # Warm QEMU's translated soft-TLB with A, then evict the modeled TC
    # entry without explicitly purging the address.  A later refill of the
    # same virtual page must not continue using the obsolete host mapping.
    append_itc(target_va, page_a)
    bundles.extend([
        (cursor, *movl_mlx(2, target_va)),
        (cursor + 0x10, 0x00, ssm(IA64_PSR_DT), nop_i(), nop_i()),
        (cursor + 0x20, 0x00, srlz_d(), nop_i(), nop_i()),
        (cursor + 0x30, 0x00, ld8(30, 2), nop_i(), nop_i()),
        (cursor + 0x40, 0x00, rsm(IA64_PSR_DT), nop_i(), nop_i()),
        (cursor + 0x50, 0x00, srlz_d(), nop_i(), nop_i()),
    ])
    cursor += 0x60

    for index in range(IA64_TLB_MAX):
        append_itc(fill_va + index * page_size, page_a)

    append_itc(target_va, page_b)
    terminal_ip = cursor + 0x40
    bundles.extend([
        (cursor, 0x00, ssm(IA64_PSR_DT), nop_i(), nop_i()),
        (cursor + 0x10, 0x00, srlz_d(), nop_i(), nop_i()),
        (cursor + 0x20, 0x00, ld8(31, 2), nop_i(), nop_i()),
        (cursor + 0x30, 0x00, rsm(IA64_PSR_DT), nop_i(), nop_i()),
        (terminal_ip, 0x10, nop_m(), nop_i(),
         br_cond(terminal_ip, terminal_ip)),
        raw_bundle(page_a, value_a, ~value_a & UINT64_MAX),
        raw_bundle(page_b, value_b, ~value_b & UINT64_MAX),
    ])

    run_program(qemu, bundles, entry=0x10, terminal_ip=terminal_ip,
                expected={
                    "exception": IA64_EXCP_NONE,
                    "r30": value_a,
                    "r31": value_b,
                }, name="itc_d_evicted_refill_flushes_host_tlb",
                timeout=5.0)


def test_itr_d_all_tr_slots_survive_tc_churn(qemu):
    page_shift = 14
    page_size = 1 << page_shift
    tr_va_base = 0x01000000
    tr_pa_base = 0x02000000
    tc_va_base = 0x10000000
    target_tc_va = tc_va_base - page_size
    target_tc_pa_a = 0x04000000
    target_tc_pa_b = target_tc_pa_a + page_size
    target_tc_value_a = 0x0123456789abcdef
    target_tc_value_b = 0xfedcba9876543210
    tc_fill_count = IA64_TLB_MAX + IA64_TR_COUNT
    cursor = 0x10
    bundles = []
    data_bundles = []
    mappings = []

    for slot in range(IA64_TR_COUNT):
        va = tr_va_base + slot * page_size
        pa = tr_pa_base + slot * page_size
        value = 0xa5a5000000000000 | (slot << 8) | (slot ^ 0x5a)

        mappings.append((va, value))
        data_bundles.append(raw_bundle(pa, value, ~value))
        bundles.extend(dtr_setup_bundles(
            cursor, va, pa, page_shift=page_shift, slot=slot))
        cursor += 0x60

    bundles.extend([
        (cursor, 0x00, srlz_d(), nop_i(), nop_i()),
        (cursor + 0x10, 0x00, ssm(1 << 17), adds(31, 0, 0), nop_i()),
        (cursor + 0x20, 0x00, srlz_d(), nop_i(), nop_i()),
    ])
    cursor += 0x30

    def append_mapping_checks():
        nonlocal cursor

        for va, value in mappings:
            bundles.extend([
                (cursor, *movl_mlx(2, va)),
                (cursor + 0x10, *movl_mlx(4, value)),
                (cursor + 0x20, 0x01, ld8(3, 2), nop_i(), nop_i()),
                (cursor + 0x30, 0x01, nop_m(), nop_i(),
                 sub_reg(3, 3, 4)),
                (cursor + 0x40, 0x01, nop_m(), or_reg(31, 31, 3),
                 nop_i()),
            ])
            cursor += 0x50

    # Warm the translated host cache as well as checking the model entries.
    append_mapping_checks()

    tc_pte = target_tc_pa_a | DTR_PTE_WB
    bundles.extend([
        (cursor, *movl_mlx(18, tc_pte)),
        (cursor + 0x10, 0x00, adds(7, page_shift << 2, 0), nop_i(),
         nop_i()),
        (cursor + 0x20, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
    ])
    cursor += 0x30

    # Keep one ordinary TC alongside every DTR and warm its translated
    # host entry before the replacement churn.  The later refill must not
    # retain this first physical mapping.
    bundles.extend([
        (cursor, *movl_mlx(19, target_tc_va)),
        (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (cursor + 0x20, 0x00, itc_d(18), nop_i(), nop_i()),
        (cursor + 0x30, *movl_mlx(2, target_tc_va)),
        (cursor + 0x40, 0x00, ld8(12, 2), nop_i(), nop_i()),
    ])
    cursor += 0x50

    # The DTRs share the TLB array with the TC, so IA64_TR_COUNT
    # pinned entries leave IA64_TLB_MAX minus that many ordinary data-TC
    # slots.  Insert enough unique translations to fill those slots and
    # rotate through replacement.
    for index in range(tc_fill_count):
        va = tc_va_base + index * page_size
        bundles.extend([
            (cursor, *movl_mlx(19, va)),
            (cursor + 0x10, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
            (cursor + 0x20, 0x00, itc_d(18), nop_i(), nop_i()),
        ])
        cursor += 0x30

    bundles.extend([
        (cursor, *movl_mlx(18, target_tc_pa_b | DTR_PTE_WB)),
        (cursor + 0x10, *movl_mlx(19, target_tc_va)),
        (cursor + 0x20, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (cursor + 0x30, 0x00, itc_d(18), nop_i(), nop_i()),
        (cursor + 0x40, 0x00, ld8(13, 2), nop_i(), nop_i()),
    ])
    cursor += 0x50

    bundles.append((cursor, 0x00, srlz_d(), nop_i(), nop_i()))
    cursor += 0x10
    append_mapping_checks()
    terminal_ip = cursor
    bundles.extend([
        (terminal_ip, 0x10, nop_m(), nop_i(),
         br_cond(terminal_ip, terminal_ip)),
        *data_bundles,
        raw_bundle(target_tc_pa_a, target_tc_value_a,
                   ~target_tc_value_a & UINT64_MAX),
        raw_bundle(target_tc_pa_b, target_tc_value_b,
                   ~target_tc_value_b & UINT64_MAX),
    ])

    run_program(qemu, bundles, entry=0x10, expected={
        "ip": terminal_ip,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
        "r12": target_tc_value_a,
        "r13": target_tc_value_b,
    }, name="itr_d_all_tr_slots_survive_tc_churn", timeout=5.0)

test_itc_d_preserves_24bit_key = require_registers(
    "itc_d_preserves_24bit_key", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(7, (0x12345 << 8) | LOW_VECTOR_ITIR)),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, 0x00, tak(31, 19), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r31": 0x12345,
    }, entry=0x10)

test_itc_d_4g_page_size_reserved_field_fault = \
    require_uncollected_reserved_field(
    "itc_d_4g_page_size_reserved_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, 32 << 2, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_d(18), entry=0x10)

test_itr_d_4g_page_size_reserved_field_fault = \
    require_uncollected_reserved_field(
    "itr_d_4g_page_size_reserved_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, 32 << 2, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), adds(5, 5, 0), nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itr_d(5, 18), entry=0x10)

test_itc_d_present_reserved_pte_field_fault = \
    require_uncollected_reserved_field(
    "itc_d_present_reserved_pte_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (1 << 1))),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_d(18), entry=0x10)

test_itc_d_present_reserved_itir_field_fault = \
    require_uncollected_reserved_field(
    "itc_d_present_reserved_itir_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(7, LOW_VECTOR_ITIR | (1 << 63))),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_d(18), entry=0x10)

test_itc_d_present_reserved_ma_field_fault = \
    require_uncollected_reserved_field(
    "itc_d_present_reserved_ma_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (1 << 2))),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_d(18), entry=0x10)

test_itc_i_present_reserved_pte_field_fault = \
    require_uncollected_reserved_field(
    "itc_i_present_reserved_pte_field_fault", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (1 << 1))),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_i(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_i(18), entry=0x10)

test_itc_d_not_present_rejects_low_itir_reserved_field = \
    require_uncollected_reserved_field(
    "itc_d_not_present_rejects_low_itir_reserved_field", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~1)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR | 1, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
    ], fault_ip=0x60, fault_imm=itc_d(18), entry=0x10)

test_itc_d_not_present_raises_page_fault = require_registers(
    "itc_d_not_present_raises_page_fault", [
        (0x10, *movl_mlx(2, 0xa000000000000430)),
        (0x20, *movl_mlx(18, 0x0010000004000660)),
        (0x30, *movl_mlx(7, LOW_VECTOR_ITIR | (1 << 63))),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x80, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_R,
    }, entry=0x10)

test_tak_not_present_dtlb_returns_one = require_registers(
    "tak_not_present_dtlb_returns_one", [
        (0x10, *movl_mlx(18, 0x0010000004000660)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE + 0x20000)),
        (0x30, *movl_mlx(7, (0x12345 << 8) | LOW_VECTOR_ITIR)),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, 0x00, tak(31, 19), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_itr_d_not_present_raises_page_fault = require_registers(
    "itr_d_not_present_raises_page_fault", [
        (0x10, *movl_mlx(2, 0xa000000000000430)),
        (0x20, *movl_mlx(18, 0x0010000004000660)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x80, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_R,
    }, entry=0x10)

test_itc_d_clear_accessed_raises_data_access_bit = require_registers(
    "itc_d_clear_accessed_raises_data_access_bit", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~PTE_ACCESSED)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x80, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_ACCESS_BIT_VECTOR + 0x20,
                 IA64_DATA_ACCESS_BIT_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_ACCESS_BIT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x9000,
        "r31": IA64_ISR_R,
    }, entry=0x10)

test_itc_d_clear_dirty_raises_dirty_bit = require_registers(
    "itc_d_clear_dirty_raises_dirty_bit", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~PTE_DIRTY)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(29, 0x1122334455667788)),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x90, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xb0, 0x00, st8(2, 29), nop_i(),
         nop_i()),
        (IA64_DATA_DIRTY_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_DIRTY_VECTOR + 0x20,
                 IA64_DATA_DIRTY_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_DIRTY_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x9000,
        "r31": IA64_ISR_W,
    }, entry=0x10)

test_itc_d_clean_page_read_fill_store_raises_dirty_bit = require_registers(
    "itc_d_clean_page_read_fill_store_raises_dirty_bit", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, 0x0010000004009661 & ~PTE_DIRTY)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x80, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xa0, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(29, 0x1122334455667788)),
        (0xc0, 0x00, st8(2, 29), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (IA64_DATA_DIRTY_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_DIRTY_VECTOR + 0x20,
                 IA64_DATA_DIRTY_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_DIRTY_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r28": ITC_DATA_LOW,
        "r30": 0x9000,
        "r31": IA64_ISR_W,
    }, entry=0x10)

test_data_dirty_rfi_retries_word_store_once = require_registers(
    "data_dirty_rfi_retries_word_store_once", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18,
                         0x0010000004009661 & ~PTE_DIRTY)),
        (0x30, *movl_mlx(23, 0x0010000004009661)),
        (0x40, *movl_mlx(29, 0x1234)),
        (0x50, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x60, 0x00, mov_m_gr_cr(2, 20), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(), nop_i()),
        (0x90, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xa0, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0xb0, 0x08, st2(2, 29), adds(16, 1, 16),
         adds(17, 1, 17)),
        (0xc0, 0x00, ld2(31, 2), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_DATA_DIRTY_VECTOR, 0x00, mov_m_gr_cr(7, 21),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x10, 0x00, itc_d(23),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x20, 0x00, nop_m(),
         adds(30, 1, 30), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x30, 0x10, nop_m(), nop_i(), rfi_b()),
        ITC_DATA_BUNDLE,
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r16": 1,
        "r17": 1,
        "r30": 1,
        "r31": 0x1234,
    }, entry=0x10)

test_data_dirty_rfi_preserves_bank1_word_store = require_registers(
    "data_dirty_rfi_preserves_bank1_word_store", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18,
                         0x0010000004009661 & ~PTE_DIRTY)),
        (0x30, 0x00, adds(6, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(6, 21), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
        (0x70, *movl_mlx(7, IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_BN)),
        (0x80, 0x10, nop_m(), nop_i(), bsw1()),
        (0x90, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0xa0, 0x00, nop_m(), adds(22, 0, 2),
         adds(19, 0x1234, 0)),
        (0xb0, 0x08, st2(22, 19), adds(10, 1, 10), nop_i()),
        (0xc0, 0x00, ld2(8, 2), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_DATA_DIRTY_VECTOR, *movl_mlx(18, 0x0010000004009661)),
        (IA64_DATA_DIRTY_VECTOR + 0x10, 0x00, mov_m_gr_cr(6, 21),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x20, 0x00, itc_d(18),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x30, 0x00, nop_m(),
         adds(19, 0x55, 0), adds(22, 0x66, 0)),
        (IA64_DATA_DIRTY_VECTOR + 0x40, 0x00, nop_m(),
         adds(9, 1, 9), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x50, 0x10,
         nop_m(), nop_i(), rfi_b()),
        ITC_DATA_BUNDLE,
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "psr": IA64_PSR_IC | IA64_PSR_DT | IA64_PSR_BN,
        "r8": 0x1234,
        "r9": 1,
        "r10": 1,
        "r19": 0x1234,
        "r22": 0x9000,
    }, entry=0x10)

# A store to a page with both A and D clear reports the Data Dirty Bit
# fault: it outranks the Data Access Bit fault, which is what lets one
# handler set both bits instead of faulting twice.
test_itc_d_clear_accessed_store_precedes_access_bit = require_registers(
    "itc_d_clear_accessed_store_precedes_access_bit", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE &
                         ~(PTE_ACCESSED | PTE_DIRTY))),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(29, 0x1122334455667788)),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x90, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xb0, 0x00, st8(2, 29), nop_i(),
         nop_i()),
        (IA64_DATA_DIRTY_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_DATA_DIRTY_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_DIRTY_VECTOR + 0x20,
                 IA64_DATA_DIRTY_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_DIRTY_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x9000,
        "r31": IA64_ISR_W,
    }, entry=0x10)

test_itc_d_psr_da_suppresses_one_data_access_bit = require_registers(
    "itc_d_psr_da_suppresses_one_data_access_bit", [
        (0x10, *movl_mlx(2, 0x9000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE & ~PTE_ACCESSED)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 38))),
        (0x80, *movl_mlx(20, 0x100)),
        (0x90, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x100, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (0x110, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (IA64_DATA_ACCESS_BIT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_ACCESS_BIT_VECTOR + 0x20,
                 IA64_DATA_ACCESS_BIT_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_ACCESS_BIT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r28": 0,
        "r30": 0x9000,
        "r31": IA64_ISR_R,
    }, entry=0x10)

test_itc_d_data_key_miss_raises_key_vector = require_registers(
    "itc_d_data_key_miss_raises_key_vector", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, *movl_mlx(20, 0x123456789abc0000)),
        (0x60, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x90, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(20, 25), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, KEY_TEST_PSR)),
        (0xc0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xc0, 0xd0)),
        (0xd0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xe0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x20, 0x00, mov_m_cr_gr(28, 21),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x30, 0x00, mov_m_cr_gr(27, 25),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x40,
                 IA64_DATA_KEY_MISS_VECTOR + 0x40)),
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x40,
        "exception": IA64_EXCP_NONE,
        "r30": KEY_TEST_VA,
        "r31": IA64_ISR_R,
        "r28": KEY_TEST_RR,
        "r27": 0x123456789abc0000,
    }, entry=0x10)

test_itc_d_key_permission_store_raises_permission_vector = require_registers(
    "itc_d_key_permission_store_raises_permission_vector", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, *movl_mlx(4, KEY_TEST_PKR | IA64_PKR_WD)),
        (0x60, 0x00, mov_rr_write(16, 0), adds(3, 0, 0),
         nop_i()),
        (0x70, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(29, 0x1122334455667788)),
        (0xc0, *movl_mlx(19, KEY_TEST_PSR)),
        (0xd0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xd0, 0xe0)),
        (0xe0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xf0, 0x00, st8(2, 29), nop_i(),
         nop_i()),
        (IA64_KEY_PERMISSION_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_KEY_PERMISSION_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_KEY_PERMISSION_VECTOR + 0x20, 0x00, mov_m_cr_gr(28, 21),
         nop_i(), nop_i()),
        (IA64_KEY_PERMISSION_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_KEY_PERMISSION_VECTOR + 0x30,
                 IA64_KEY_PERMISSION_VECTOR + 0x30)),
    ], {
        "ip": IA64_KEY_PERMISSION_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r30": KEY_TEST_VA,
        "r31": IA64_ISR_W,
        "r28": KEY_TEST_RR,
    }, entry=0x10)

test_itc_d_matching_pkr_allows_keyed_load = require_registers(
    "itc_d_matching_pkr_allows_keyed_load", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, *movl_mlx(4, KEY_TEST_PKR)),
        (0x60, 0x00, mov_rr_write(16, 0), adds(3, 0, 0),
         nop_i()),
        (0x70, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, KEY_TEST_PSR)),
        (0xc0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xc0, 0xd0)),
        (0xd0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xe0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        KEY_TEST_DATA_BUNDLE,
    ], {
        "ip": 0xf0,
        "exception": IA64_EXCP_NONE,
        "r31": ITC_DATA_LOW,
    }, entry=0x10)

test_ssm_pk_invalidates_cached_keyless_access = require_registers(
    "ssm_pk_invalidates_cached_keyless_access", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT), nop_i(),
         nop_i()),
        (0xa0, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (0xb0, 0x00, ssm(IA64_PSR_PK), nop_i(),
         nop_i()),
        (0xc0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00, nop_m(), adds(31, 0x74, 0),
         nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x10,
                 IA64_DATA_KEY_MISS_VECTOR + 0x10)),
        KEY_TEST_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r28": ITC_DATA_LOW,
        "r31": 0x74,
    }, entry=0x10)

test_tpa_key_miss_raises_data_key_miss = require_registers(
    "tpa_key_miss_raises_data_key_miss", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(19, KEY_TEST_PSR)),
        (0xa0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xa0, 0xb0)),
        (0xb0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xc0, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x20,
                 IA64_DATA_KEY_MISS_VECTOR + 0x20)),
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": KEY_TEST_VA,
        "r31": IA64_ISR_NA,
    }, entry=0x10)

# The non-faulting probe forms evaluate the address with the architected
# tlb_grant_permission() function, which raises Key Miss faults like a
# normal reference; only permission failures report through GR r1.
test_probe_w_key_miss_raises_data_key_miss = require_registers(
    "probe_w_key_miss_raises_data_key_miss", [
        (0x10, *movl_mlx(2, KEY_TEST_VA)),
        (0x20, *movl_mlx(16, KEY_TEST_RR)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(7, KEY_TEST_ITIR)),
        (0x50, 0x00, mov_rr_write(16, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(19, KEY_TEST_PSR)),
        (0xa0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xa0, 0xb0)),
        (0xb0, 0x00, srlz_d(), adds(31, 0x55, 0),
         nop_i()),
        (0xc0, 0x08, probe_w_imm(7, 2, 0), nop_i(),
         nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_DATA_KEY_MISS_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_KEY_MISS_VECTOR + 0x20,
                 IA64_DATA_KEY_MISS_VECTOR + 0x20)),
    ], {
        "ip": IA64_DATA_KEY_MISS_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": KEY_TEST_VA,
        "r31": IA64_ISR_NA | IA64_ISR_W | 2,
    }, entry=0x10)

test_itr_i_instruction_key_miss_raises_key_vector = require_registers(
    "itr_i_instruction_key_miss_raises_key_vector", [
        (0x10, *movl_mlx(16, KEY_TEST_RR)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(19, (1 << 13) | (1 << 36) | IA64_PSR_PK)),
        (0x50, 0x00, mov_rr_write(16, 17), nop_i(),
         nop_i()),
        (0x60, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), mov_m_gr_cr(0, 20),
         nop_i()),
        (0x80, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(2, 0xa000000000000430)),
        (0xa0, *movl_mlx(7, KEY_TEST_ITIR)),
        (0xb0, 0x00, mov_m_gr_cr(7, 21), adds(6, 6, 0),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(2, 20), nop_i(),
         nop_i()),
        (0xd0, 0x00, itr_i(6, 18), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(4, IA64_PKR_VALID)),
        (0xf0, 0x00, adds(3, 0, 0), mov_br_gr(7, 2),
         nop_i()),
        (0x100, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        *rfi_to_gr(0x110, 19, 2),
        (0x4000000 + IA64_INST_KEY_MISS_VECTOR, 0x00,
         mov_m_cr_gr(30, 20), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_KEY_MISS_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_KEY_MISS_VECTOR + 0x20, 0x00,
         mov_m_cr_gr(28, 21), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_KEY_MISS_VECTOR + 0x30, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_INST_KEY_MISS_VECTOR + 0x30,
                 IA64_INST_KEY_MISS_VECTOR + 0x30)),
    ], {
        "ip": IA64_INST_KEY_MISS_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_X,
        "r28": KEY_TEST_RR,
    }, entry=0x10)

test_itr_d_8k_translation_uses_unrounded_paddr = require_registers(
    "itr_d_8k_translation_uses_unrounded_paddr", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x2000)),
        (0x20, *movl_mlx(2, 0x4000430)),
        (0x30, *movl_mlx(3, 0x1111111111111111)),
        (0x40, *movl_mlx(4, 0x4002430)),
        (0x50, *movl_mlx(5, 0x2222222222222222)),
        (0x60, 0x00, st8(2, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, st8(4, 5), nop_i(),
         nop_i()),
        (0x80, 0x00, adds(7, EIGHT_K_ITIR, 0), adds(6, 5, 0),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0xb0, 0x00, itr_d(6, 18), nop_i(),
         nop_i()),
        (0xc0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xd0, *movl_mlx(19, 1 << 17)),
        (0xe0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xf0, *movl_mlx(2, 0x430)),
        (0x100, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r31": 0x2222222222222222,
    }, entry=0x10)

test_itr_d_8k_odd_subpage_store_visible_across_call = require_registers(
    "itr_d_8k_odd_subpage_store_visible_across_call", [
        *dtr_setup_bundles(0x10, 0xe0000106014cdcf0, 0x4101cf0,
                           page_shift=13),
        (0x70, *movl_mlx(3, 0xe0000106014cdcf0)),
        (0x80, *movl_mlx(4, 0x1122334455667788)),
        (0x90, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0xa0, 0x00, st8(3, 4), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xb0, 0x100)),
        (0x100, 0x00, ld8(31, 3), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r31": 0x1122334455667788,
    }, entry=0x10)

test_itc_d_virtual_stack_local_passed_as_high_sol_output = require_registers(
    "itc_d_virtual_stack_local_passed_as_high_sol_output", [
        (0x10, *movl_mlx(18, 0x001000000a096461)),
        (0x20, *movl_mlx(19, 0xe0000106014cdcf0)),
        (0x30, *movl_mlx(21, (1 << 8) | EIGHT_K_ITIR)),
        (0x40, 0x00, mov_rr_write(21, 19), nop_i(),
         nop_i()),
        (0x50, 0x08, mov_m_gr_cr(19, 20), mov_m_gr_cr(21, 21),
         nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(12, 0xe0000106014cdcf0)),
        (0x80, 0x00, nop_m(), alloc(35, 4, 0, 0, 0),
         nop_i()),
        (0x90, *movl_mlx(32, 0x1ec50000)),
        (0xa0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xb0, 0x200)),
        (0x200, 0x00, alloc_m(41, 19, 11, 0, 0),
         adds(12, -16, 12), nop_i()),
        (0x210, 0x00, nop_m(), adds(14, 16, 12),
         nop_i()),
        (0x220, 0x00, st8(14, 32), adds(43, 16, 12),
         nop_i()),
        (0x230, 0x10, nop_m(), nop_i(),
         br_call(0, 0x230, 0x300)),
        (0x300, 0x00, alloc_m(36, 8, 7, 0, 0), nop_i(),
         nop_i()),
        (0x310, 0x00, ld8(8, 32), adds(9, 0, 32),
         nop_i()),
        (0x320, 0x10, nop_m(), nop_i(),
         br_cond(0x320, 0x320)),
    ], {
        "ip": 0x320,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1ec50000,
        "r9": 0xe0000106014cdcf0,
    }, entry=0x10)

test_itc_i_m_unit_decode = require_registers("itc_i_m_unit_decode", [
    (0x10, *movl_mlx(18, 0x0010000004000661)),
    (0x20, *movl_mlx(19, 1 << 36)),
    (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
     nop_i()),
    (0x60, 0x00, itc_i(18), addl(31, 0x8430, 0),
     nop_i()),
    *rfi_to_gr(0x70, 19, 31),
    (0x4008430, 0x10, nop_m(), adds(31, 0x7b, 0),
     br_cond(0x4008430, 0x8440)),
    (0x4008440, 0x10, nop_m(), nop_i(),
     br_cond(0x4008440, 0x8440)),
], {"ip": 0x8440, "exception": IA64_EXCP_NONE, "r31": 0x7b},
   entry=0x10)

test_itc_i_resumes_next_slot_after_tb_exit = require_registers(
    "itc_i_resumes_next_slot_after_tb_exit", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itc_i(18), adds(31, 1, 0),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_ptc_l_4g_page_size_is_purgeable = require_registers(
    "ptc_l_4g_page_size_is_purgeable", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(20, 0x9000)),
        (0x30, 0x00, adds(7, 0x38, 0), adds(24, 32 << 2, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(), nop_i()),
        (0x60, 0x00, itc_d(18), nop_i(), nop_i()),
        (0x70, 0x08, nop_m(), ptc_l(20, 24), nop_i()),
        (0x80, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x90, *movl_mlx(22, IA64_PSR_IC | IA64_PSR_DT)),
        (0xa0, 0x00, mov_gr_psr_full(22), nop_i(), nop_i()),
        (0xb0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xc0, 0x00, ld8(29, 20), nop_i(), nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(), br_cond(0xd0, 0xd0)),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x9000,
        "r31": IA64_ISR_R,
    }, entry=0x10)

PTC_SURVIVOR_BUNDLE = (0x4010000, 0x00, 0xfeedfacecafebeef, 0, 0)
PTC_SURVIVOR_LOW, _ = bundle_words(*PTC_SURVIVOR_BUNDLE[1:])

test_ptc_l_keeps_nonoverlapping_tc = require_registers(
    "ptc_l_keeps_nonoverlapping_tc", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x4010661)),
        (0x30, *movl_mlx(20, 0x9000)),
        (0x40, *movl_mlx(21, 0x20000)),
        (0x50, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(20, 20), nop_i(), nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(21, 20), nop_i(), nop_i()),
        (0xa0, 0x00, itc_d(19), nop_i(), nop_i()),
        (0xb0, 0x00, ssm(IA64_PSR_IC | IA64_PSR_DT), nop_i(), nop_i()),
        (0xc0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xd0, 0x00, ld8(28, 20), nop_i(), nop_i()),
        (0xe0, 0x08, nop_m(), ptc_l(20, 7), nop_i()),
        (0xf0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x100, 0x00, ld8(31, 21), nop_i(), nop_i()),
        (0x110, 0x00, ld8(29, 20), nop_i(), nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (0x1000, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
        ITC_DATA_BUNDLE,
        PTC_SURVIVOR_BUNDLE,
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r30": 0x9000,
        "r28": ITC_DATA_LOW,
        "r31": PTC_SURVIVOR_LOW,
    }, entry=0x10)

test_ptc_l_does_not_clear_local_alat = require_registers(
    "ptc_l_does_not_clear_local_alat", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(19, 0x9000)),
        (0x90, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0xc0, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xd0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(22, (1 << 13) | (1 << 17))),
        (0xf0, 0x00, mov_gr_psr_full(22), nop_i(),
         nop_i()),
        (0x100, *movl_mlx(2, HIGH_TR_BASE + 0x9000)),
        (0x110, 0x00, ld8_a(31, 2), nop_i(),
         nop_i()),
        (0x120, *movl_mlx(31, 0x55)),
        (0x130, 0x00, ptc_l(19, 7), nop_i(),
         nop_i()),
        (0x140, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x150, 0x00, ld8_c_clr(31, 2), nop_i(),
         nop_i()),
        (0x160, 0x10, nop_m(), nop_i(),
         br_cond(0x160, 0x160)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": 0x160,
        "exception": IA64_EXCP_NONE,
        "r31": 0x55,
    }, entry=0x10)

def test_ar_itc_advances_in_guest_loop(qemu):
    result = run_program(qemu, [
        (0x10, 0x02, mov_m_ar_gr(16, 44), nop_i(),
         addl(8, 4095, 0)),
        (0x20, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cloop(0x30, 0x30)),
        (0x40, 0x02, mov_m_ar_gr(17, 44), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], entry=0x10, terminal_ip=0x50)
    state = result.state
    if state.gr[17] <= state.gr[16]:
        raise RuntimeError(
            "ar_itc_advances_in_guest_loop failed: "
            f"r16={state.gr[16]!r} r17={state.gr[17]!r}\n"
            f"{result.register_output}")

def test_cloop_zero_st1_timer_interrupts_batched_loop(qemu):
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, *movl_mlx(8, 0x100000000)),
        (0x30, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x40, 0x02, mov_m_ar_gr(3, 44), nop_i(),
         nop_i()),
        (0x50, 0x00, addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x60, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x70, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xa0, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0xb0, 0x10, st1_postinc(2, 0, 1), nop_i(),
         br_cloop(0xb0, 0xb0)),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
        (0x3000, 0x02, nop_m(), mov_ar_lc(9),
         nop_i()),
        (0x3010, 0x00, nop_m(), adds(8, 0, 2),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], entry=0x10, terminal_ip=0x3020)
    state = result.state
    advanced = state.gr[8] - 0x8000
    if (state.ip != 0x3020 or
        state.exception != IA64_EXCP_NONE or
        advanced <= 0 or
        state.gr[9] >= 0x100000000):
        raise RuntimeError(
            "cloop_zero_st1_timer_interrupts_batched_loop failed: "
            f"advanced={advanced!r} lc={state.gr[9]!r} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")

test_cloop_zero_st1_invalidates_alat_range = require_registers(
    "cloop_zero_st1_invalidates_alat_range", [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, adds(3, 8, 2), nop_i(),
         nop_i()),
        (0x30, 0x00, ld8_a(22, 3), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(8, 15, 0), nop_i(),
         nop_i()),
        (0x50, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x60, 0x10, st1_postinc(2, 0, 1), nop_i(),
         br_cloop(0x60, 0x60)),
        (0x70, 0x00, chk_a_nc_m(22, 0x70, 0xa0), adds(4, 1, 0),
         nop_i()),
        (0x80, 0x00, adds(5, 1, 0), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r2": 0x8010,
        "r4": 0,
        "r5": 0,
    }, entry=0x10)

test_cloop_zero_st1_clears_cross_page_range = require_registers(
    "cloop_zero_st1_clears_cross_page_range", [
        (0x10, *movl_mlx(2, 0x7ff0)),
        (0x20, 0x00, adds(4, 0xff, 0),
         addl(8, 8224 - 1, 0), nop_i()),
        (0x30, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0x40, 0x10, st1_postinc(2, 4, 1), nop_i(),
         br_cloop(0x40, 0x40)),

        (0x50, *movl_mlx(2, 0x7ff0)),
        (0x60, 0x00, addl(8, 8224 - 1, 0), nop_i(), nop_i()),
        (0x70, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0x80, 0x10, st1_postinc(2, 0, 1), nop_i(),
         br_cloop(0x80, 0x80)),

        (0x90, *movl_mlx(2, 0x7ff0)),
        (0xa0, 0x00, addl(8, 8224 - 1, 0), adds(10, 0, 0), nop_i()),
        (0xb0, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xc0, 0x10, ld1_postinc(11, 2, 1), or_reg(10, 10, 11),
         br_cloop(0xc0, 0xc0)),
        (0xd0, 0x02, nop_m(), mov_ar_lc(9), nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(), br_cond(0xe0, 0xe0)),
    ], {
        "ip": 0xe0,
        "exception": IA64_EXCP_NONE,
        "r2": 0xa010,
        "r9": 0,
        "r10": 0,
    }, entry=0x10)

test_mov_to_ivr_illegal = require_exception(
    "mov_to_ivr_illegal", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_mov_to_irr_illegal = require_exception(
    "mov_to_irr_illegal", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IRR3), nop_i(),
         nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_mov_to_read_only_cr_predicate_false = require_registers(
    "mov_to_read_only_cr_predicate_false", [
        (0x10, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IVR, qp=1),
         nop_i(), nop_i()),
        (0x20, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_IRR3, qp=1),
         nop_i(), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_async_timer_interrupt_enters_ivt = require_registers(
    "async_timer_interrupt_enters_ivt", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x60)),
        (0x3000, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x55,
    }, entry=0x10)

test_async_timer_interrupt_records_boundary_ri = require_registers(
    "async_timer_interrupt_records_boundary_ri", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x60)),
        (0x3000, 0x00, mov_m_cr_gr(31, 16), nop_i(),
         nop_i()),
        (0x3010, 0x10, mov_m_cr_gr(30, 19), nop_i(),
         br_cond(0x3010, 0x3020)),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], {
        "ip": 0x3020,
        "exception": IA64_EXCP_NONE,
        "r30": 0x60,
        "r31": (1 << 13) | (1 << 14),
    }, entry=0x10)

def test_async_timer_interrupt_never_resumes_mlx_slot2(qemu):
    program = [
        (0x10, 0x02, mov_m_ar_gr(3, 44), nop_i(), nop_i()),
        (0x20, 0x00,
         addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x30, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x40, 0x00, adds(3, 0xef, 0), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(), nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(), nop_i()),
    ]
    mlx_addresses = set()
    loop_addresses = set()
    loop_start = 0x80
    address = loop_start

    # Alternate fully occupied bundles with MLX bundles.  A host timer kick
    # at a bundle boundary must never combine the following MLX address with
    # the completed preceding bundle's slot-2 restart state.
    for index in range(32):
        loop_addresses.add(address)
        program.append((address, 0x01,
                        adds(22, index, 0),
                        adds(23, index + 1, 0),
                        adds(24, index + 2, 0)))
        address += 0x10
        mlx_addresses.add(address)
        loop_addresses.add(address)
        program.append((address, *movl_mlx(25, index)))
        address += 0x10

    loop_addresses.add(address)
    program.extend([
        (address, 0x10, nop_m(), nop_i(),
         br_cond(address, loop_start)),
        (0x3000, 0x00, mov_m_cr_gr(30, 19), nop_i(), nop_i()),
        (0x3010, 0x10, mov_m_cr_gr(31, 16), nop_i(),
         br_cond(0x3010, 0x3010)),
    ])

    result = run_program(qemu, program, entry=0x10, terminal_ip=0x3010)
    state = result.state
    interrupted_ip = state.gr[30]
    interrupted_ri = (state.gr[31] >> 41) & 3
    if (state.ip != 0x3010 or
        state.exception != IA64_EXCP_NONE or
        interrupted_ip not in loop_addresses or
        (interrupted_ip in mlx_addresses and interrupted_ri not in (0, 1))):
        raise RuntimeError(
            "async_timer_interrupt_never_resumes_mlx_slot2 failed: "
            f"iip={interrupted_ip:#x} ri={interrupted_ri} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")


def test_repeated_timer_rfi_preserves_word_rmw(qemu):
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, st2(2, 0), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8010)),
        (0x40, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x50, 0x00, mov_m_gr_ar(0, 44), nop_i(), nop_i()),
        (0x60, *movl_mlx(4, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x70, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x80, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0xa0, *movl_mlx(8, iterations - 1)),
        (0xb0, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xc0, *movl_mlx(19, (1 << 13) | (1 << 14) | (1 << 44))),
        (0xd0, 0x08, mov_gr_psr_full(19), srlz_d(), nop_i()),
        (0xe0, 0x00, ld2(4, 2), nop_i(), nop_i()),
        (0xf0, 0x00, nop_m(), adds(4, 1, 4), nop_i()),
        (0x100, 0x10, st2(2, 4), nop_i(), br_cloop(0x100, 0xe0)),
        (0x110, 0x00, rsm(1 << 14), nop_i(), nop_i()),
        (0x120, 0x00, ld2(8, 2), nop_i(), nop_i()),
        (0x130, 0x00, ld8(9, 3), nop_i(), nop_i()),
        (0x140, 0x10, nop_m(), nop_i(), br_cond(0x140, 0x140)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x00, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), nop_i(), nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x140, timeout=8.0)
    state = result.state
    expected = iterations & 0xffff
    if (state.ip != 0x140 or
        state.exception != IA64_EXCP_NONE or
        state.gr[8] != expected or
        state.gr[9] < 2):
        raise RuntimeError(
            "repeated_timer_rfi_preserves_word_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")


def test_timer_interrupt_preserves_banked_word_rmw(qemu):
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, st2(2, 0), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8010)),
        (0x40, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x50, 0x02, mov_m_ar_gr(4, 44), nop_i(), nop_i()),
        (0x60, *movl_mlx(5, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x70, 0x00, nop_m(), add(4, 4, 5), nop_i()),
        (0x80, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x90, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0xb0, *movl_mlx(8, iterations - 1)),
        (0xc0, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xd0, *movl_mlx(7, IA64_PSR_IC | IA64_PSR_I | IA64_PSR_BN)),
        (0xe0, 0x10, nop_m(), nop_i(), bsw1()),
        (0xf0, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x1fe0)),
        (0x1fe0, 0x00, nop_m(), adds(22, 0, 2), nop_i()),
        # Match the page-table accounting sequence: a banked address and
        # loaded value survive an interruptible host-TB boundary before the
        # 16-bit store.  Splitting the two bundles across an 8 KiB page makes
        # that boundary deterministic; the handler clobbers the other bank.
        (0x1ff0, 0x08, ld2_bias(21, 22), adds(19, 1, 21), nop_i()),
        (0x2000, 0x10, st2(22, 19), nop_i(),
         br_cloop(0x2000, 0x1ff0)),
        (0x2010, 0x00, rsm(IA64_PSR_I), nop_i(), nop_i()),
        (0x2020, 0x00, ld2(8, 2), nop_i(), nop_i()),
        (0x2030, 0x00, ld8(9, 3), nop_i(), nop_i()),
        (0x2040, 0x10, nop_m(), nop_i(), br_cond(0x2040, 0x2040)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), adds(21, 0x55, 0),
         adds(22, 0x66, 0)),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x2040, timeout=8.0)
    state = result.state
    expected = iterations & 0xffff
    if (state.ip != 0x2040 or
        state.exception != IA64_EXCP_NONE or
        state.psr != IA64_PSR_IC | IA64_PSR_BN or
        state.gr[8] != expected or
        state.gr[9] < 1):
        raise RuntimeError(
            "timer_interrupt_preserves_banked_word_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")


def test_timer_cover_rfi_preserves_large_frame_halfword_rmw(qemu):
    result = run_program(qemu, [
        # Place a 73-register frame beside an RNAT collection boundary.
        # Derive r91 from a movl temporary exactly as the page-table mapping
        # helper derives its PFN-database bias.  Recompute r44 from that high
        # local for every interrupted RMW so an RSE restore cannot silently
        # preserve the cached address while corrupting the bias itself.
        (0x10, *movl_mlx(2, 0x1001e8)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x40, *movl_mlx(80, 0x7ff8)),
        (0x50, 0x01, nop_m(), adds(91, 8, 80), nop_i()),
        (0x60, 0x00, st2(91, 0), nop_i(), nop_i()),
        (0x70, *movl_mlx(13, 0x8010)),
        (0x80, 0x00, st8(13, 0), nop_i(), nop_i()),
        (0x90, *movl_mlx(5, 0x8020)),
        (0xa0, 0x00, st8(5, 0), nop_i(), nop_i()),
        (0xb0, 0x02, mov_m_ar_gr(3, 44), nop_i(), nop_i()),
        (0xc0, 0x00,
         addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0xe0, 0x00, adds(3, 0xef, 0), nop_i(), nop_i()),
        (0xf0, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(), nop_i()),
        (0x100, *movl_mlx(7, IA64_PSR_IC | IA64_PSR_I | IA64_PSR_BN)),
        (0x110, 0x10, nop_m(), nop_i(), bsw1()),
        (0x120, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x130, 0x00, nop_m(), adds(47, 0, 0), nop_i()),
        (0x140, 0x10, nop_m(), nop_i(), br_cond(0x140, 0x1fb0)),

        # Match the non-atomic page-table entry accounting sequence.  The
        # unfinished instruction group crosses an 8 KiB boundary between
        # the checked load/add and store, making an interrupt there
        # deterministic once the timer is due.
        (0x1fb0, 0x01, nop_m(), adds(44, 0, 91), nop_i()),
        (0x1fc0, 0x03, ld2_sa(29, 44), nop_i(), nop_i()),
        (0x1fd0, 0x01, nop_m(), nop_i(), nop_i()),
        (0x1fe0, 0x01, nop_m(), nop_i(), nop_i()),
        (0x1ff0, 0x00, ld2_c_clr(29, 44), adds(31, 1, 29),
         addl(52, 2, 0)),
        (0x2000, 0x0b, adds(47, 1, 47), st2(44, 31), nop_i()),
        (0x2010, 0x00, ld8(9, 13), nop_i(), nop_i()),
        (0x2020, 0x01, nop_m(), cmp4_eq_imm(6, 7, 0, 9), nop_i()),
        (0x2030, 0x10, nop_m(), nop_i(),
         br_cond(0x2030, 0x1fb0, qp=6)),
        (0x2040, 0x00, rsm(IA64_PSR_I), nop_i(), nop_i()),
        (0x2050, 0x00, ld2(8, 44), adds(10, 0, 44),
         adds(11, 0, 47)),
        (0x2060, 0x00, ld8(12, 5), adds(14, 0, 91), nop_i()),
        (0x2070, 0x10, nop_m(), nop_i(), br_cond(0x2070, 0x2070)),

        # A realistic low-level handler covers the interrupted frame, calls
        # code with a full-size nested frame (forcing RSE spill/reload),
        # unwinds to the vector's zero frame, and only then executes rfi.
        (0x3000, 0x18, nop_m(), nop_m(), cover_b()),
        (0x3010, 0x00, mov_m_ar_gr(20, 64), nop_i(), nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_call(0, 0x3020, 0x4000)),
        (0x3030, 0x00, mov_m_gr_ar(20, 64), nop_i(), nop_i()),
        (0x3040, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),

        (0x4000, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x4010, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
        (0x4020, 0x00, mov_m_cr_gr(21, 19), nop_i(), nop_i()),
        (0x4030, *movl_mlx(23, 0x2000)),
        (0x4040, 0x01, nop_m(), cmp4_eq_unc_imm(6, 7, 0, 0),
         nop_i()),
        (0x4050, 0x01, nop_m(), cmp_eq_and(6, 7, 23, 21), nop_i()),
        (0x4060, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x4070, *movl_mlx(24, 10 * IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x4080, 0x00, nop_m(), add(17, 17, 24), nop_i()),
        (0x4090, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x40a0, *movl_mlx(22, 0x8020)),
        (0x40b0, 0x00, st8(22, 21, qp=6), nop_i(), nop_i()),
        (0x40c0, *movl_mlx(18, 0x8010)),
        (0x40d0, 0x00, ld8(19, 18, qp=6), nop_i(), nop_i()),
        (0x40e0, 0x00, nop_m(), adds(19, 1, 19, qp=6), nop_i()),
        (0x40f0, 0x00, st8(18, 19, qp=6), nop_i(), nop_i()),
        (0x4100, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x4110, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], entry=0x10, terminal_ip=0x2070, timeout=10.0,
       alat=None, smp="4")
    state = result.state
    expected = state.gr[11] & 0xffff
    if (state.ip != 0x2070 or
        state.exception != IA64_EXCP_NONE or
        state.psr != IA64_PSR_IC | IA64_PSR_BN or
        state.gr[8] != expected or
        state.gr[9] < 1 or
        state.gr[10] != 0x8000 or
        state.gr[14] != 0x8000 or
        state.gr[12] != 0x2000 or
        state.cfm.get("sof") != 73 or
        state.cfm.get("sol") != 70):
        raise RuntimeError(
            "timer_cover_rfi_preserves_large_frame_halfword_rmw failed: "
            f"counter={state.gr[8]!r} expected={expected!r} "
            f"interrupts={state.gr[9]!r} address={state.gr[10]!r} "
            f"bias={state.gr[14]!r} "
            f"iip={state.gr[12]!r} "
            f"sof={state.cfm.get('sof')!r} sol={state.cfm.get('sol')!r} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")


def test_ld2_bias_st2_raw_large_frame_sequence(qemu):
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x8000)),
        (0x20, 0x00, st2(2, 0), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8010)),
        (0x40, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x60, *movl_mlx(88, 0x8010)),
        (0x70, *movl_mlx(5, 13)),
        (0x80, 0x02, nop_m(), mov_lc_gr(5), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), bsw1()),
        (0xa0, *movl_mlx(22, 0x8000)),

        # Preserve the original instruction words, template stops, and the
        # unrelated speculative load around the 16-bit accounting update.
        # Fourteen iterations match the number of live entries observed in
        # the failing leaf table.
        raw_bundle(0xb0, 0x093010882c00a80b, 0x0004000000420054),
        raw_bundle(0xc0, 0x067011882c4c0018, 0x2000000000207160),
        (0xd0, 0x11, nop_m(), nop_i(), br_cloop(0xd0, 0xb0)),
        (0xe0, 0x01, ld2(8, 22), nop_i(), nop_i()),
        (0xf0, 0x11, nop_m(), nop_i(), br_cond(0xf0, 0xf0)),
    ], entry=0x10, terminal_ip=0xf0, expected={
        "exception": IA64_EXCP_NONE,
        "r8": 14,
    }, name="ld2_bias_st2_raw_large_frame_sequence")
    if result.state.gr[8] != 14:
        raise RuntimeError(
            "ld2_bias_st2_raw_large_frame_sequence failed: "
            f"counter={result.state.gr[8]!r}\n{result.register_output}")


def test_rse_small_kernel_frame_preserves_counter_across_spill_calls(qemu):
    bundles = [
        # The caller supplies 19 output registers.  Its thirteenth output is
        # the callee's r44, matching the page-table counter pointer in the
        # failing SOF=21/SOL=19 kernel frame.
        (0x10, *movl_mlx(2, 0x1001e8)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        (0x30, *movl_mlx(3, 0x8000)),
        (0x40, 0x00, st2(3, 0), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), alloc(2, 21, 2, 0, 0), nop_i()),
        (0x60, *movl_mlx(46, 0x8000)),
        (0x70, 0x10, nop_m(), nop_i(), br_call(0, 0x70, 0x100)),

        # alloc r49=ar.pfs,19,0,2,0 encodes SOF=21/SOL=19.
        (0x100, 0x00, nop_m(), alloc(49, 21, 19, 0, 0), nop_i()),
        (0x110, 0x00, nop_m(), adds(47, 0, 0), nop_i()),
    ]
    cursor = 0x120
    for _ in range(13):
        bundles.extend([
            # Preserve the checked-load/add/store grouping used by the
            # kernel, then call through a frame large enough to evict and
            # reload the small caller's stacked registers.
            (cursor, 0x03, ld2_sa(29, 44), nop_i(), nop_i()),
            (cursor + 0x10, 0x01, nop_m(), nop_i(), nop_i()),
            (cursor + 0x20, 0x01, nop_m(), nop_i(), nop_i()),
            (cursor + 0x30, 0x00, ld2_c_clr(29, 44),
             adds(31, 1, 29), addl(52, 2, 0)),
            (cursor + 0x40, 0x0b, adds(47, 1, 47), st2(44, 31),
             nop_i()),
            (cursor + 0x50, 0x10, nop_m(), nop_i(),
             br_call(0, cursor + 0x50, 0x4000)),
        ])
        cursor += 0x60

    terminal_ip = cursor + 0x10
    bundles.extend([
        (cursor, 0x00, ld2(8, 44), adds(9, 0, 44), adds(10, 0, 47)),
        (terminal_ip, 0x10, nop_m(), nop_i(),
         br_cond(terminal_ip, terminal_ip)),

        (0x4000, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x4010, *movl_mlx(127, 0x8877665544332211)),
        (0x4020, 0x00, flushrs_enc(), nop_i(), nop_i()),
        (0x4030, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x4040, 0x10, nop_m(), nop_i(), br_ret(0)),
    ])

    run_program(qemu, bundles, entry=0x10, terminal_ip=terminal_ip,
                timeout=5.0, alat=None, smp="4", expected={
                    "exception": IA64_EXCP_NONE,
                    "r8": 13,
                    "r9": 0x8000,
                    "r10": 13,
                    "cfm_sof": 21,
                    "cfm_sol": 19,
                }, name=(
                    "rse_small_kernel_frame_preserves_counter_across_"
                    "spill_calls"))


def test_rse_large_frame_timer_rfi_preserves_high_caller_local(qemu):
    sentinels = {
        53: 0x1111111111111153,
        54: 0x2222222222222254,
        55: 0x3333333333333355,
        76: 0x4444444444444476,
        91: 0x5555555555555591,
        98: 0x6666666666666698,
    }
    iterations = 0x100001
    result = run_program(qemu, [
        (0x10, *movl_mlx(2, 0x100000)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        # Shift the caller's bottom-of-frame before constructing the exact
        # 73-register kernel frame.  Its high locals then wrap around the
        # 96-entry physical stacked-register file.
        (0x30, 0x00, nop_m(), alloc(40, 45, 41, 0, 0), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_call(0, 0x40, 0x100)),

        (0x100, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x110, *movl_mlx(53, sentinels[53])),
        (0x120, *movl_mlx(54, sentinels[54])),
        (0x130, *movl_mlx(55, sentinels[55])),
        (0x140, *movl_mlx(76, sentinels[76])),
        (0x150, *movl_mlx(91, sentinels[91])),
        (0x160, *movl_mlx(98, sentinels[98])),
        (0x170, *movl_mlx(3, 0x8010)),
        (0x180, 0x00, st8(3, 0), nop_i(), nop_i()),
        (0x190, 0x00, nop_m(), nop_i(), nop_i()),
        (0x1a0, 0x10, nop_m(), nop_i(), br_call(0, 0x1a0, 0x300)),
        (0x1b0, 0x00, ld8(2, 3), adds(8, 0, 53), adds(9, 0, 54)),
        (0x1c0, 0x00, nop_m(), adds(10, 0, 55), adds(11, 0, 76)),
        (0x1d0, 0x00, nop_m(), adds(14, 0, 91), adds(15, 0, 98)),
        (0x1e0, 0x10, nop_m(), nop_i(), br_cond(0x1e0, 0x1e0)),

        (0x300, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x310, 0x02, mov_m_ar_gr(2, 44), nop_i(), nop_i()),
        (0x320, 0x00,
         addl(4, IA64_ITC_TICKS_PER_MILLISECOND, 2), nop_i(), nop_i()),
        (0x330, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(), nop_i()),
        (0x340, 0x00, adds(4, 0xef, 0), nop_i(), nop_i()),
        (0x350, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(), nop_i()),
        (0x360, *movl_mlx(8, iterations - 1)),
        (0x370, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0x380, *movl_mlx(7, (1 << 13) | (1 << 14) | (1 << 44))),
        (0x390, 0x08, mov_gr_psr_full(7), srlz_d(), nop_i()),
        (0x3a0, 0x10, nop_m(), adds(10, 1, 10),
         br_cloop(0x3a0, 0x3a0)),
        (0x3b0, 0x00, rsm(1 << 14), nop_i(), nop_i()),
        (0x3c0, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x3d0, 0x10, nop_m(), nop_i(), br_ret(0)),

        (0x3000, 0x00, mov_m_cr_gr(16, IA64_CR_SAPIC_IVR),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(17, 44), nop_i(), nop_i()),
        (0x3020, *movl_mlx(20, IA64_ITC_TICKS_PER_MILLISECOND)),
        (0x3030, 0x00, nop_m(), add(17, 17, 20), nop_i()),
        (0x3040, 0x00, mov_m_gr_cr(17, IA64_CR_ITM), nop_i(), nop_i()),
        (0x3050, *movl_mlx(18, 0x8010)),
        (0x3060, 0x00, ld8(19, 18), nop_i(), nop_i()),
        (0x3070, 0x00, nop_m(), adds(19, 1, 19), nop_i()),
        (0x3080, 0x00, st8(18, 19), nop_i(), nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
    ], entry=0x10, terminal_ip=0x1e0, timeout=8.0)
    state = result.state
    observed = {
        53: state.gr[8],
        54: state.gr[9],
        55: state.gr[10],
        76: state.gr[11],
        91: state.gr[14],
        98: state.gr[15],
    }
    if (state.ip != 0x1e0 or
        state.exception != IA64_EXCP_NONE or
        observed != sentinels or
        state.gr[2] < 1 or
        state.cfm.get("sof") != 73 or
        state.cfm.get("sol") != 70):
        raise RuntimeError(
            "rse_large_frame_timer_rfi_preserves_high_caller_local failed: "
            f"caller_locals={observed!r} expected={sentinels!r} "
            f"interrupts={state.gr[2]!r} sof={state.cfm.get('sof')!r} "
            f"sol={state.cfm.get('sol')!r} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")


def test_rse_seventy_output_handoff_preserves_kernel_locals(qemu):
    sentinels = {
        53: 0x1111111111111153,
        54: 0x2222222222222254,
        55: 0x3333333333333355,
        76: 0x4444444444444476,
        91: 0x5555555555555591,
        98: 0x6666666666666698,
    }
    result = run_program(qemu, [
        # Start beside an RNAT collection boundary and shift BOF so both the
        # 70-register handoff and the nested frame wrap the physical stack.
        (0x10, *movl_mlx(2, 0x1001e8)),
        (0x20, 0x00, mov_ar(2, 18), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), alloc(40, 45, 41, 0, 0), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_call(0, 0x40, 0x100)),

        # A 96-register caller with SOL=26 passes 70 output registers.  The
        # selected output positions become the same r53/r54/r55/r76/r91/r98
        # inputs used by the page-table mapping helper in the crash image.
        (0x100, 0x00, nop_m(), alloc(41, 96, 26, 0, 0), nop_i()),
        (0x110, *movl_mlx(79, sentinels[53])),
        (0x120, *movl_mlx(80, sentinels[54])),
        (0x130, *movl_mlx(81, sentinels[55])),
        (0x140, *movl_mlx(102, sentinels[76])),
        (0x150, *movl_mlx(117, sentinels[91])),
        (0x160, *movl_mlx(124, sentinels[98])),
        (0x170, 0x10, nop_m(), nop_i(), br_call(0, 0x170, 0x300)),

        # Match the kernel frame (SOF=73, SOL=70), then force a wide nested
        # frame to spill and reload across the RNAT boundary before checking
        # the inherited values.
        (0x300, 0x00, nop_m(), alloc(100, 73, 70, 0, 0), nop_i()),
        (0x310, 0x10, nop_m(), nop_i(), br_call(0, 0x310, 0x500)),
        (0x320, 0x00, nop_m(), adds(8, 0, 53), adds(9, 0, 54)),
        (0x330, 0x00, nop_m(), adds(10, 0, 55), adds(11, 0, 76)),
        (0x340, 0x00, nop_m(), adds(14, 0, 91), adds(15, 0, 98)),
        (0x350, 0x10, nop_m(), nop_i(), br_cond(0x350, 0x350)),

        (0x500, 0x00, nop_m(), alloc(36, 96, 88, 0, 0), nop_i()),
        (0x510, 0x00, mov_m_gr_ar(36, 64), nop_i(), nop_i()),
        (0x520, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], entry=0x10, terminal_ip=0x350, timeout=8.0)
    state = result.state
    observed = {
        53: state.gr[8],
        54: state.gr[9],
        55: state.gr[10],
        76: state.gr[11],
        91: state.gr[14],
        98: state.gr[15],
    }
    if (state.ip != 0x350 or
        state.exception != IA64_EXCP_NONE or
        observed != sentinels or
        state.cfm.get("sof") != 73 or
        state.cfm.get("sol") != 70):
        raise RuntimeError(
            "rse_seventy_output_handoff_preserves_kernel_locals failed: "
            f"locals={observed!r} expected={sentinels!r} "
            f"sof={state.cfm.get('sof')!r} sol={state.cfm.get('sol')!r} "
            f"ip={state.ip!r} exception={state.exception!r}\n"
            f"{result.register_output}")

def test_timer_interrupt_exits_chained_loop_after_virtual_deadline(qemu):
    result = run_program(qemu, [
        (0x10, 0x02, mov_m_ar_gr(3, 44), nop_i(),
         nop_i()),
        (0x20, 0x00, addl(4, 10 * IA64_ITC_TICKS_PER_MILLISECOND, 3),
         nop_i(), nop_i()),
        (0x30, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x02, mov_m_cr_gr(30, IA64_CR_ITM),
         nop_i(), nop_i()),
        (0x3010, 0x02, mov_m_ar_gr(31, 44),
         nop_i(), nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3020)),
    ], entry=0x10, terminal_ip=0x3020,
       poll_initial_s=0.100, poll_max_s=0.100)
    state = result.state
    delta = state.gr[31] - state.gr[30]
    if (state.ip != 0x3020 or
        state.exception != IA64_EXCP_NONE or
        state.gr[31] < state.gr[30] or
        delta > 100 * IA64_ITC_TICKS_PER_MILLISECOND or
        result.polls != 1):
        raise RuntimeError(
            "timer_interrupt_exits_chained_loop_after_virtual_deadline "
            f"failed: itm={state.gr[30]!r} itc={state.gr[31]!r} "
            f"delta={delta!r} polls={result.polls} ip={state.ip!r} "
            f"exception={state.exception!r}\n{result.register_output}")

test_async_timer_interrupt_preserves_bank1_grs = require_registers(
    "async_timer_interrupt_preserves_bank1_grs", [
        (0x10, *movl_mlx(16, 0x1116)),
        (0x20, *movl_mlx(27, 0x1127)),
        (0x30, 0x10, nop_m(), nop_i(),
         bsw1()),
        (0x40, *movl_mlx(16, 0x2216)),
        (0x50, *movl_mlx(27, 0x2227)),
        (0x60, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(19, (1 << 13) | (1 << 14) | (1 << 44))),
        (0xb0, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR), nop_i(),
         nop_i()),
        (0x3010, *movl_mlx(16, 0xa016)),
        (0x3020, *movl_mlx(27, 0xa027)),
        (0x3030, 0x10, nop_m(), nop_i(),
         bsw1()),
        (0x3040, 0x00, nop_m(), adds(2, 0, 16),
         nop_i()),
        (0x3050, 0x00, nop_m(), adds(3, 0, 27),
         nop_i()),
        (0x3060, 0x10, nop_m(), nop_i(),
         bsw0()),
        (0x3070, *movl_mlx(4, 0x100)),
        (0x3080, 0x00, mov_m_gr_cr(4, 19), nop_i(),
         nop_i()),
        (0x3090, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
        (0x100, 0x00, nop_m(), adds(8, 0, 16),
         nop_i()),
        (0x110, 0x00, nop_m(), adds(9, 0, 27),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "psr": (1 << 13) | (1 << 14) | (1 << 44),
        "r2": 0x2216,
        "r3": 0x2227,
        "r8": 0x2216,
        "r9": 0x2227,
        "r16": 0x2216,
        "r27": 0x2227,
    }, entry=0x10)

test_tpr_preserves_mmi_and_mic = require_registers(
    "tpr_preserves_mmi_and_mic", [
        (0x10, *movl_mlx(3, 0x12345678900100ff)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_cr_gr(31, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_TPR_MMI | 0xf0,
    }, entry=0x10)

test_tpr_mmi_masks_timer_until_cleared = require_registers(
    "tpr_mmi_masks_timer_until_cleared", [
        (0x10, *movl_mlx(3, IA64_TPR_MMI)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0x30, 0x00, adds(4, 0xef, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x00, nop_m(), adds(8, 0x2a, 0),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_TPR), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x63, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r8": 0x2a,
        "r31": 0x63,
    }, entry=0x10)

def sapic_nested_timer_priority_program(first_vector, second_vector):
    psr_ic_i = (1 << 13) | (1 << 14)

    return [
        (0x10, *movl_mlx(3, first_vector)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(4, 0x1000, 4), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, psr_ic_i)),
        (0x70, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR),
         adds(31, 1, 31), nop_i()),
        (0x3010, 0x00, nop_m(), cmp4_eq_imm(6, 7, 1, 31),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3100, qp=7)),
        (0x3030, *movl_mlx(3, second_vector)),
        (0x3040, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x3050, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x3060, 0x00, adds(4, 0x1000, 4), nop_i(),
         nop_i()),
        (0x3070, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x3080, *movl_mlx(19, psr_ic_i)),
        (0x3090, 0x08, mov_gr_psr_full(19), srlz_d(),
         nop_i()),
        (0x30a0, 0x10, nop_m(), nop_i(),
         br_cond(0x30a0, 0x30a0)),
        (0x3100, 0x00, nop_m(), adds(8, 0x5a, 0),
         nop_i()),
        (0x3110, 0x10, nop_m(), nop_i(),
         br_cond(0x3110, 0x3110)),
    ]

test_sapic_extint_masks_external_until_eoi = require_registers(
    "sapic_extint_masks_external_until_eoi",
    sapic_nested_timer_priority_program(0x00, 0xf0),
    {
        "ip": 0x30a0,
        "exception": IA64_EXCP_NONE,
        "r5": 0x00,
        "r8": 0,
        "r31": 1,
    }, entry=0x10)

test_sapic_same_class_higher_vector_preempts = require_registers(
    "sapic_same_class_higher_vector_preempts",
    sapic_nested_timer_priority_program(0xf0, 0xf1),
    {
        "ip": 0x3110,
        "exception": IA64_EXCP_NONE,
        "r5": 0xf1,
        "r8": 0x5a,
        "r31": 2,
    }, entry=0x10)

test_pal_halt_light_wakes_on_due_itm = require_registers(
    "pal_halt_light_wakes_on_due_itm", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x200000)),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(28, PAL_HALT_LIGHT)),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x10, mov_gr_psr_full(19), nop_i(),
         br_call(0, 0x70, PAL_PROC_ENTRY)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(),
         nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x5a, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r31": 0x5a,
    }, entry=0x10)

test_pal_halt_light_stops_at_pal_continuation = require_registers(
    "pal_halt_light_stops_at_pal_continuation", [
        (0x10, *movl_mlx(28, PAL_HALT_LIGHT)),
        (0x20, 0x10, nop_m(), nop_i(),
         br_call(0, 0x20, PAL_PROC_ENTRY)),
        (0x30, 0x00, nop_m(), adds(31, 0x5a, 0),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(),
         nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ], {
        "ip": PAL_PROC_ENTRY + 0x10,
        "halted": 1,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r31": 0,
    }, entry=0x10)

test_pal_halt_wakes_on_due_itm = require_registers(
    "pal_halt_wakes_on_due_itm", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, *movl_mlx(4, 0x200000)),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(28, PAL_HALT)),
        (0x60, 0x00, nop_m(), addl(29, 1, 0), addl(30, 0, 0)),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x80, 0x10, mov_gr_psr_full(19), addl(31, 0, 0),
         br_call(0, 0x80, PAL_PROC_ENTRY)),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(),
         nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x5a, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": 0,
        "r31": 0x5a,
    }, entry=0x10)

test_masked_itv_discards_due_timer = require_registers(
    "masked_itv_discards_due_timer", [
        (0x10, *movl_mlx(3, IA64_VECTOR_MASKED | 0xef)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(4, 0x1000)),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(8, 0x10000)),
        (0x70, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cloop(0x80, 0x80)),
        (0x90, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xc0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x64, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_invalid_itv_vector_is_ignored = require_registers(
    "invalid_itv_vector_is_ignored", [
        (0x10, *movl_mlx(3, 1)),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(4, 0x1000)),
        (0x50, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(8, 0x10000)),
        (0x70, 0x02, nop_m(), mov_lc_gr(8),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cloop(0x80, 0x80)),
        (0x90, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0xa0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x66, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0xb0,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_past_itm_does_not_fire = require_registers(
    "past_itm_does_not_fire", [
        (0x10, *movl_mlx(4, 0x200000)),
        (0x20, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x70, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x70, 0x80)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x3000, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x3000, 0x3000)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_past_rearmed_itm_does_not_interrupt = require_registers(
    "past_rearmed_itm_does_not_interrupt", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(0, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x60, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x3000, 0x00, mov_m_cr_gr(5, IA64_CR_SAPIC_IVR),
         adds(31, 1, 31),
         nop_i()),
        (0x3010, 0x00, nop_m(), cmp4_eq_imm(6, 7, 1, 31),
         nop_i()),
        (0x3020, 0x10, nop_m(), nop_i(),
         br_cond(0x3020, 0x3080, qp=7)),
        (0x3030, *movl_mlx(4, 0x200000)),
        (0x3040, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x3050, *movl_mlx(6, 0x100)),
        (0x3060, 0x00, mov_m_gr_cr(6, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x3070, 0x10, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI), nop_i(),
         rfi_b()),
        (0x3080, 0x00, mov_m_gr_cr(0, IA64_CR_SAPIC_EOI),
         adds(8, 0x2a, 0),
         nop_i()),
        (0x3090, 0x10, nop_m(), nop_i(),
         br_cond(0x3090, 0x3090)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_future_itm_rearm_preserves_pended_timer_irr = require_registers(
    "future_itm_rearm_preserves_pended_timer_irr", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(5, 0x100000000)),
        (0x60, 0x00, add(5, 4, 5), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(5, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x90, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), adds(8, 0x2a, 0),
         br_cond(0xa0, 0xa0)),
        (0x3000, 0x10, nop_m(), adds(31, 0x66, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x66,
    }, entry=0x10)

test_masking_itv_preserves_pended_timer_irr = require_registers(
    "masking_itv_preserves_pended_timer_irr", [
        (0x10, 0x00, adds(3, 0xef, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_ar(4, 44), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(4, IA64_CR_ITM), nop_i(),
         nop_i()),
        (0x50, *movl_mlx(3, IA64_VECTOR_MASKED | 0xef)),
        (0x60, 0x00, mov_m_gr_cr(3, IA64_CR_ITV), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(19, (1 << 13) | (1 << 14))),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), adds(8, 0x2a, 0),
         br_cond(0x90, 0x90)),
        (0x3000, 0x10, nop_m(), adds(31, 0x67, 0),
         br_cond(0x3000, 0x3010)),
        (0x3010, 0x10, nop_m(), nop_i(),
         br_cond(0x3010, 0x3010)),
    ], {
        "ip": 0x3010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x67,
    }, entry=0x10)

test_ptr_i_preserves_non_overlapping_itr = require_registers(
    "ptr_i_preserves_non_overlapping_itr", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 36) | (1 << 44))),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), adds(5, 0, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(3, 0x10000)),
        (0x80, 0x00, ptr_i(3, 7), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(20, HIGH_TR_BASE + 0x20000)),
        *rfi_to_gr(0xa0, 19, 20),
        (0x4000c00, 0x10, nop_m(), adds(31, 0x68, 0),
         br_cond(0x4000c00, 0x0c10)),
        (0x4000c10, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c10, 0x0c10)),
    ], {
        "ip": 0x0c10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x68,
    }, entry=0x10)

test_ptr_i_purges_matching_itr_by_address = require_registers(
    "ptr_i_purges_matching_itr_by_address", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 36) | (1 << 44))),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), adds(5, 0, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x10000)),
        (0x80, *movl_mlx(20, 0x10000)),
        (0x90, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0),
         nop_i()),
        (0xa0, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(3, 0x10000)),
        (0xc0, 0x00, ptr_i(3, 7), nop_i(),
         nop_i()),
        (0xd0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        *rfi_to_gr(0xe0, 19, 20),
        (0x4000c00, 0x10, nop_m(), adds(31, 0x69, 0),
         br_cond(0x4000c00, 0x0c10)),
        (0x4000c10, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c10, 0x0c10)),
        (0x4010000, 0x10, nop_m(), adds(31, 0x44, 0),
         br_cond(0x4010000, 0x10000)),
    ], {
        "ip": 0x0c10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x69,
    }, entry=0x10)

test_ptr_alt_decode = require_registers("ptr_alt_decode", [
    (0x10, 0x00, adds(2, 0x10000, 0), adds(3, LOW_VECTOR_ITIR, 0),
     nop_i()),
    (0x20, 0x00, ptr_d_alt(2, 3), nop_i(),
     nop_i()),
    (0x30, 0x00, ptr_i_alt(2, 3), nop_i(),
     nop_i()),
    (0x40, 0x10, nop_m(), adds(31, 0x6a, 0),
     br_cond(0x40, 0x50)),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {
    "ip": 0x50,
    "exception": IA64_EXCP_NONE,
    "r31": 0x6a,
}, entry=0x10)

test_alt_itlb_when_vhpt_disabled = require_registers(
    "alt_itlb_when_vhpt_disabled", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 36) | (1 << 44))),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(20, HIGH_TR_BASE + 0x20000)),
        *rfi_to_gr(0x80, 19, 20),
        (0x4000c00, 0x10, nop_m(), adds(31, 0x7d, 0),
         br_cond(0x4000c00, 0x0c10)),
        (0x4000c10, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c10, 0x0c10)),
    ], {
        "ip": 0x0c10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x7d,
    }, entry=0x10)

test_alt_dtlb_when_vhpt_disabled = require_registers(
    "alt_dtlb_when_vhpt_disabled", [
        (0x10, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 44))),
        (0x20, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, ld8(8, 2), nop_i(),
         nop_i()),
        (0x1000, 0x10, nop_m(), adds(31, 0x7e, 0),
         br_cond(0x1000, 0x1010)),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x7e,
    }, entry=0x10)

test_alt_dtlb_preserves_iha = require_registers(
    "alt_dtlb_preserves_iha", [
        (0x10, *movl_mlx(16, 0x123456789abc0000)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 44))),
        (0x30, *movl_mlx(2, HIGH_TR_BASE + 0x21000)),
        (0x40, 0x00, mov_m_gr_cr(16, 25), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8(8, 2), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 25), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x123456789abc0000,
        "r31": HIGH_TR_BASE + 0x21000,
    }, entry=0x10)

test_alt_itlb_preserves_iha = require_registers(
    "alt_itlb_preserves_iha", [
        (0x10, *movl_mlx(16, 0x123456789abc0000)),
        (0x20, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x30, *movl_mlx(19, (1 << 13) | (1 << 36) | (1 << 44))),
        (0x40, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
         nop_i()),
        (0x70, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(20, HIGH_TR_BASE + 0x22000)),
        (0x90, 0x00, mov_m_gr_cr(16, 25), mov_br_gr(7, 20),
         nop_i()),
        *rfi_to_gr(0xa0, 19, 20),
        (0x4000c00, 0x00, mov_m_cr_gr(30, 25), nop_i(),
         nop_i()),
        (0x4000c10, 0x00, mov_m_cr_gr(31, 20), nop_i(),
         nop_i()),
        (0x4000c20, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c20, 0x0c20)),
    ], {
        "ip": 0x0c20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x123456789abc0000,
        "r31": HIGH_TR_BASE + 0x22000,
    }, entry=0x10)

test_dtlb_miss_slot1_resumes_without_replaying_slot0 = require_registers(
    "dtlb_miss_slot1_resumes_without_replaying_slot0", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x20000)),
        (0x20, *movl_mlx(4, 0x12345678)),
        (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x40, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x50, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x60, 0x08, adds(16, 1, 16), st8(2, 4),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x1000, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(), nop_i()),
        (0x1010, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x1020, 0x00, itc_d(18), nop_i(), nop_i()),
        (0x1030, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r16": 1,
    }, entry=0x10)

test_dtlb_fault_itir_uses_region_rid = require_registers(
    "dtlb_fault_itir_uses_region_rid", [
        (0x10, *movl_mlx(17, 0xe000010000020000)),
        (0x20, *movl_mlx(18, (0x123 << 8) | (13 << 2))),
        (0x30, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x50, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8(8, 17), nop_i(),
         nop_i()),
        (0x1000, 0x10, mov_m_cr_gr(31, 21), nop_i(),
         br_cond(0x1000, 0x1010)),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r31": (0x123 << 8) | (13 << 2),
    }, entry=0x10)

test_alt_itlb_when_vhpt_ic_disabled = require_registers(
    "alt_itlb_when_vhpt_ic_disabled", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, HIGH_TR_BASE)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, (1 << 17) | (1 << 36) | (1 << 44))),
        (0x50, *movl_mlx(20, LOW_VECTOR_TR_PTE)),
        (0x60, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
         nop_i()),
        (0x90, 0x00, itr_i(5, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(20, HIGH_TR_BASE + 0x30000)),
        *rfi_to_gr(0xd0, 19, 20),
        (0x4000c00, 0x10, nop_m(), adds(31, 0x6c, 0),
         br_cond(0x4000c00, 0x0c10)),
        (0x4000c10, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c10, 0x0c10)),
    ], {
        "ip": 0x0c10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6c,
    }, entry=0x10)

test_data_nested_tlb_when_vhpt_ic_disabled = require_registers(
    "data_nested_tlb_when_vhpt_ic_disabled", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, HIGH_TR_BASE)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, (1 << 17) | (1 << 44))),
        (0x50, *movl_mlx(2, HIGH_TR_BASE + 0x40000)),
        (0x60, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x90, 0x08, ld8(8, 2), nop_i(),
         nop_i()),
        (0x1400, 0x10, nop_m(), adds(31, 0x6e, 0),
         br_cond(0x1400, 0x1410)),
        (0x1410, 0x10, nop_m(), nop_i(),
         br_cond(0x1410, 0x1410)),
    ], {
        "ip": 0x1410,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6e,
    }, entry=0x10)

test_ssm_ic_inflight_dtlb_sets_ni = require_registers(
    "ssm_ic_inflight_dtlb_sets_ni", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x50000)),
        (0x20, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x40, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8(8, 2), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(30, 1, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_ISR_R | IA64_ISR_NI,
    }, entry=0x10)

test_rsm_ic_inflight_dtlb_not_data_nested = require_registers(
    "rsm_ic_inflight_dtlb_not_data_nested", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x60000)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, rsm(1 << 13), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8(8, 2), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(31, 17), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(30, 1, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": IA64_ISR_R | IA64_ISR_NI,
    }, entry=0x10)

test_rsm_ic_serialized_data_nested_tlb = require_registers(
    "rsm_ic_serialized_data_nested_tlb", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x70000)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, rsm(1 << 13), nop_i(),
         nop_i()),
        (0x60, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x70, 0x00, ld8(8, 2), nop_i(),
         nop_i()),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(31, 0x6f, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
        (IA64_DATA_NESTED_TLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR + 0x10,
                 IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
    ], {
        "ip": IA64_DATA_NESTED_TLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6f,
    }, entry=0x10)

INTERRUPTION_PSR_INPUT = (
    IA64_PSR_UP | IA64_PSR_MFL | IA64_PSR_MFH |
    IA64_PSR_AC | IA64_PSR_IC | IA64_PSR_I | IA64_PSR_PK |
    IA64_PSR_DFL | IA64_PSR_DFH | IA64_PSR_SP |
    IA64_PSR_DI | IA64_PSR_SI | IA64_PSR_DT | IA64_PSR_RT |
    IA64_PSR_MC
)

INTERRUPTION_PSR_EXPECTED = (
    IA64_PSR_BE | IA64_PSR_UP | IA64_PSR_MFL | IA64_PSR_MFH |
    IA64_PSR_PK | IA64_PSR_DT | IA64_PSR_PP | IA64_PSR_RT |
    IA64_PSR_MC
)

test_exception_entry_initializes_psr = require_registers(
    "exception_entry_initializes_psr", [
        (0x10, *movl_mlx(16, IA64_DCR_BE | IA64_DCR_PP)),
        (0x20, *movl_mlx(19, INTERRUPTION_PSR_INPUT)),
        (0x30, 0x00, mov_m_gr_cr(16, 0), adds(31, 0x60, 0),
         nop_i()),
        *rfi_to_gr(0x40, 19, 31),
        (0x60, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x70, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_psr_gr(29), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(30, 16),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x20)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r29": INTERRUPTION_PSR_EXPECTED,
        "r30": INTERRUPTION_PSR_INPUT,
    }, entry=0x10)

test_exception_preserves_translation_bits = require_registers(
    "exception_preserves_translation_bits", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(19, (1 << 13) | (1 << 17) |
                         (1 << 27) | (1 << 36))),
        (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), adds(31, 0x80, 0),
         nop_i()),
        *rfi_to_gr(0x70, 19, 31),
        (0x4000080, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x4000000 + IA64_BREAK_VECTOR, 0x10, nop_m(), adds(31, 0x7c, 0),
         br_cond(IA64_BREAK_VECTOR, IA64_BREAK_VECTOR + 0x10)),
        (0x4000000 + IA64_BREAK_VECTOR + 0x10, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10,
                 IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x7c,
        "psr": (1 << 17) | (1 << 27) | (1 << 36),
    }, entry=0x10)

test_tpa_indexed_decode = require_registers("tpa_indexed_decode", [
    (0x10, *movl_mlx(18, 0x0010000004000661)),
    (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_m_gr_cr(7, 21), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_m_gr_cr(0, 20), adds(5, 5, 0),
     nop_i()),
    (0x50, 0x00, itr_d(5, 18), nop_i(),
     nop_i()),
    (0x60, 0x00, addl(2, 0x8430, 0), nop_i(),
     nop_i()),
    (0x70, 0x00, ssm(1 << 17), nop_i(),
     nop_i()),
    (0x80, 0x00, tpa(31, 2), nop_i(),
     nop_i()),
    (0x90, 0x10, nop_m(), nop_i(),
     br_cond(0x90, 0x90)),
], {"ip": 0x90, "exception": IA64_EXCP_NONE, "r31": 0x4008430}, entry=0x10)

test_itr_d_slot_uses_low_8_bits = require_registers(
    "itr_d_slot_uses_low_8_bits", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(5, 0x1234000000000005)),
        (0x30, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, addl(2, 0x8430, 0), nop_i(),
         nop_i()),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4008430,
    }, entry=0x10)

test_itr_d_reserved_slot_faults = require_exception(
    "itr_d_reserved_slot_faults", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, 0x00, adds(5, IA64_TR_COUNT, 0), nop_i(), nop_i()),
        (0x30, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x30, entry=0x10)

test_tpa_dt_disabled_uses_dtlb_entry = require_registers(
    "tpa_dt_disabled_uses_dtlb_entry", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, 0x00, adds(7, 0x68, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x50, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, addl(2, 0x8430, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4008430,
    }, entry=0x10)

test_tpa_region5_kernel_dtr_large_page = require_registers(
    "tpa_region5_kernel_dtr_large_page", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, HIGH_TR_BASE)),
        (0x30, *movl_mlx(20, KERNEL_REGION5_RR)),
        (0x40, 0x00, mov_rr_write(20, 19), nop_i(),
         nop_i()),
        (0x50, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x60, 0x00, adds(7, KERNEL_TR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x90, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(2, HIGH_TR_BASE + 0x12c0000)),
        (0xc0, *movl_mlx(21, IA64_PSR_DT)),
        (0xd0, 0x00, mov_gr_psr_full(21), nop_i(),
         nop_i()),
        (0xe0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xf0, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x100, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
    ], {
        "ip": 0x100,
        "exception": IA64_EXCP_NONE,
        "r31": 0x52c0000,
    }, entry=0x10)

test_tpa_dt_disabled_miss_raises_alt_dtlb = require_registers(
    "tpa_dt_disabled_miss_raises_alt_dtlb", [
        (0x10, *movl_mlx(2, HIGH_TR_BASE + 0x90000)),
        (0x20, *movl_mlx(19, 1 << 13)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x20,
                 IA64_ALT_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": HIGH_TR_BASE + 0x90000,
        "r31": IA64_ISR_NA,
    }, entry=0x10)

test_tpa_uses_short_vhpt_walk = require_registers(
    "tpa_uses_short_vhpt_walk", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x00, tak(30, 2), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4000430,
        "r30": 5,
    }, entry=0x10)

test_short_vhpt_walker_rejects_pending_table_purge = require_registers(
    "short_vhpt_walker_rejects_pending_table_purge", [
        (0x200, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x210, *movl_mlx(17, 0xa000000000000000)),
        (0x220, *movl_mlx(18, 0x539)),
        (0x230, *movl_mlx(19, 0xbffc000000000000)),
        (0x240, *movl_mlx(20, 0x0010000004009661)),
        (0x250, *movl_mlx(21, 0x0010000004000661)),
        (0x260, *movl_mlx(22, 0x4008000)),
        (0x270, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x280, *movl_mlx(23, 0x4000430)),
        (0x290, *movl_mlx(24, 0x1122334455667788)),
        (0x2a0, 0x00, st8(23, 24), nop_i(),
         nop_i()),
        (0x2b0, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0x2c0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x2d0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x2e0, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x2f0, 0x00, itc_d(20), nop_i(),
         nop_i()),
        (0x300, *movl_mlx(2, 0xa000000000000430)),
        (0x310, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x320, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x330, 0x00, ptr_d(19, 7), nop_i(),
         nop_i()),
        (0x340, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (0x350, 0x10, nop_m(), adds(28, 0x66, 0),
         br_cond(0x350, 0x350)),
        (0x000, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (0x010, 0x00, mov_m_cr_gr(31, 25),
         nop_i(), nop_i()),
        (0x020, 0x10, nop_m(), nop_i(),
         br_cond(0x020, 0x020)),
    ], {
        "ip": 0x020,
        "exception": IA64_EXCP_NONE,
        "r28": 0,
        "r29": 0,
        "r30": 0xa000000000000430,
        "r31": 0xbffc000000000000,
    }, entry=0x200)

test_short_vhpt_walk_uses_dcr_byte_order = require_registers(
    "short_vhpt_walk_uses_dcr_byte_order", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x6106000400001000)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, *movl_mlx(23, IA64_DCR_BE)),
        (0x90, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(23, 0), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xc0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xf0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0x100, *movl_mlx(2, 0xa000000000000430)),
        (0x110, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x120, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
    ], {
        "ip": 0x130,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4000430,
    }, entry=0x10)

test_short_vhpt_reserved_pte_aborts_to_dtlb_miss = require_registers(
    "short_vhpt_reserved_pte_aborts_to_dtlb_miss", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000663)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x20,
                 IA64_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": 0xbffc000000000000,
    }, entry=0x10)

test_short_vhpt_walker_ignores_uncacheable_mapping = require_registers(
    "short_vhpt_walker_ignores_uncacheable_mapping", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009671)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x20,
                 IA64_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": 0xbffc000000000000,
    }, entry=0x10)

test_tak_uses_short_vhpt_walk = require_registers(
    "tak_uses_short_vhpt_walk", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x00, tak(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r31": 5,
    }, entry=0x10)

test_short_vhpt_not_present_raises_page_fault = require_registers(
    "short_vhpt_not_present_raises_page_fault", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000660)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_R,
    }, entry=0x10)

def test_short_vhpt_not_present_entry_is_cached(qemu):
    result = run_program(qemu, [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000660)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], entry=0x10, expected={
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_R,
    }, name="short_vhpt_not_present_entry_is_cached")
    missing = []
    if not re.search(
        r"DTLB\[[0-9]+\] TC va=0xa000000000000000 .*"
        r"rid=0x000005 .* perm=0x0",
        result.register_output,
    ):
        missing.append("not-present VHPT entry was not installed as a data TC")
    if missing:
        raise RuntimeError(
            "short_vhpt_not_present_entry_is_cached failed: "
            f"{', '.join(missing)}\n{result.register_output}")

test_short_vhpt_entry_not_present_aborts_to_dtlb_miss = require_registers(
    "short_vhpt_entry_not_present_aborts_to_dtlb_miss", [
        (0x000, 0x10, nop_m(), adds(28, 0x55, 0),
         br_cond(0x000, 0x1f0)),
        (0x1f0, 0x10, nop_m(), nop_i(),
         br_cond(0x1f0, 0x1f0)),
        (0x200, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x210, *movl_mlx(17, 0xa000000000000000)),
        (0x220, *movl_mlx(18, 0x539)),
        (0x230, *movl_mlx(19, 0xbffc000000000000)),
        (0x240, *movl_mlx(20, 0x0010000004009660)),
        (0x250, *movl_mlx(2, 0xa000000000000430)),
        (0x260, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0x270, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x280, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x290, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x2a0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0x2b0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x2c0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x2d0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25),
         nop_i(), nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x00, mov_m_cr_gr(29, 17),
         nop_i(), nop_i()),
        (IA64_DTLB_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x30,
                 IA64_DTLB_VECTOR + 0x30)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r29": IA64_ISR_R,
        "r30": 0xa000000000000430,
        "r31": 0xbffc000000000000,
    }, entry=0x200)

test_ssm_ic_inflight_short_vhpt_entry_miss_raises_vhpt = require_registers(
    "ssm_ic_inflight_short_vhpt_entry_miss_raises_vhpt", [
        (0x000, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (0x010, 0x00, mov_m_cr_gr(31, 17), nop_i(),
         nop_i()),
        (0x020, 0x00, mov_m_cr_gr(28, 25), nop_i(),
         nop_i()),
        (0x030, 0x10, nop_m(), nop_i(),
         br_cond(0x030, 0x030)),
        (0x200, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x210, *movl_mlx(17, 0xa000000000000000)),
        (0x220, *movl_mlx(18, 0x539)),
        (0x230, *movl_mlx(2, 0xa000000000000430)),
        (0x240, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x250, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x260, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x270, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x280, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x290, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR, 0x10, nop_m(), adds(29, 0x55, 0),
         br_cond(IA64_DTLB_VECTOR, IA64_DTLB_VECTOR)),
    ], {
        "ip": 0x030,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_R | IA64_ISR_NI,
        "r28": 0xbffc000000000000,
    }, entry=0x200)

test_probe_fault_short_vhpt_not_present_raises_page_fault = require_registers(
    "probe_fault_short_vhpt_not_present_raises_page_fault", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000660)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x08, probe_w_fault(2, 3), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_NA | IA64_ISR_W | 5,
    }, entry=0x10)

test_short_vhpt_walker_reads_table_at_pl0 = require_registers(
    "short_vhpt_walker_reads_table_at_pl0", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x00100000040007e1)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xa000000000000430)),
        (0xf0, 0x00, nop_m(), mov_br_gr(7, 2),
         nop_i()),
        (0x100, *movl_mlx(19, (1 << 13) | (1 << 17) |
                          (1 << 36) | (3 << 32))),
        *rfi_to_gr(0x110, 19, 2),
        (0x4000430, 0x10, nop_m(), adds(31, 0x73, 0),
         br_cond(0x4000430, 0x4000440)),
        (0x4000440, 0x10, nop_m(), nop_i(),
         br_cond(0x4000440, 0x4000440)),
    ], {
        "ip": 0xa000000000000440,
        "exception": IA64_EXCP_NONE,
        "r31": 0x73,
    }, entry=0x10)

test_short_vhpt_ifetch_read_only_raises_inst_access = require_registers(
    "short_vhpt_ifetch_read_only_raises_inst_access", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x00100000040001e1)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, *movl_mlx(23, LOW_VECTOR_TR_PTE)),
        (0x90, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xe0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xf0, 0x00, adds(7, 16 << 2, 0), nop_i(),
         nop_i()),
        (0x100, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x110, 0x00, mov_m_gr_cr(0, 20), adds(5, 6, 0),
         nop_i()),
        (0x120, 0x00, itr_i(5, 23), nop_i(),
         nop_i()),
        (0x130, *movl_mlx(2, 0xa000000000000430)),
        (0x140, *movl_mlx(19, (1 << 13) | (1 << 17) |
                          (1 << 36) | (3 << 32))),
        (0x150, 0x00, nop_m(), mov_br_gr(7, 2),
         nop_i()),
        *rfi_to_gr(0x160, 19, 2),
        (0x4000000 + IA64_INST_ACCESS_VECTOR, 0x00,
         mov_m_cr_gr(30, 20), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_ACCESS_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_ACCESS_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_INST_ACCESS_VECTOR + 0x20,
                 IA64_INST_ACCESS_VECTOR + 0x20)),
    ], {
        "ip": IA64_INST_ACCESS_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_X,
    }, entry=0x10)

test_itr_i_clear_accessed_raises_inst_access_bit = require_registers(
    "itr_i_clear_accessed_raises_inst_access_bit", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(23, LOW_VECTOR_TR_PTE & ~PTE_ACCESSED)),
        (0x30, *movl_mlx(2, 0xa000000000000430)),
        (0x40, *movl_mlx(24, KERNEL_REGION5_RR)),
        (0x50, *movl_mlx(19, (1 << 13) | (1 << 36))),
        (0x60, 0x00, mov_rr_write(24, 2), nop_i(),
         nop_i()),
        (0x70, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(2, 20), adds(5, 6, 0),
         nop_i()),
        (0xc0, 0x00, itr_i(5, 23), nop_i(),
         nop_i()),
        (0xd0, 0x00, nop_m(), mov_br_gr(7, 2),
         nop_i()),
        *rfi_to_gr(0xe0, 19, 2),
        (0x4000000 + IA64_INST_ACCESS_BIT_VECTOR, 0x00,
         mov_m_cr_gr(30, 20), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_ACCESS_BIT_VECTOR + 0x10, 0x00,
         mov_m_cr_gr(31, 17), nop_i(), nop_i()),
        (0x4000000 + IA64_INST_ACCESS_BIT_VECTOR + 0x20, 0x10,
         nop_m(), nop_i(),
         br_cond(IA64_INST_ACCESS_BIT_VECTOR + 0x20,
                 IA64_INST_ACCESS_BIT_VECTOR + 0x20)),
        (0x4000430, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(0x4000430, 0x4000430)),
    ], {
        "ip": IA64_INST_ACCESS_BIT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0xa000000000000430,
        "r31": IA64_ISR_X,
    }, entry=0x10)

test_ifetch_page_not_present_after_branch_restarts_slot0 = require_registers(
    "ifetch_page_not_present_after_branch_restarts_slot0", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000660)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, *movl_mlx(23, LOW_VECTOR_TR_PTE)),
        (0x90, *movl_mlx(24, 0x00100000040007e1)),
        (0xa0, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xc0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xf0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0x100, 0x00, adds(7, 16 << 2, 0), nop_i(),
         nop_i()),
        (0x110, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x120, 0x00, mov_m_gr_cr(0, 20), adds(5, 6, 0),
         nop_i()),
        (0x130, 0x00, itr_i(5, 23), nop_i(),
         nop_i()),
        (0x140, *movl_mlx(2, 0xa000000000000430)),
        (0x150, *movl_mlx(19, (1 << 13) | (1 << 17) |
                          (1 << 36) | (3 << 32))),
        (0x160, 0x00, nop_m(), mov_br_gr(7, 2),
         nop_i()),
        *rfi_to_gr(0x170, 19, 2),
        (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR, 0x00,
         mov_m_cr_gr(25, 25), nop_i(), nop_i()),
        (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00,
         st8(25, 24), nop_i(), nop_i()),
        (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x00,
         itc_i(24), nop_i(), nop_i()),
        (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x30, 0x10,
         srlz_i(), nop_i(), rfi_b()),
        (0x4000430, 0x10, alloc_m(2, 8, 5, 0, 0), nop_i(),
         br_cond(0xa000000000000430, 0xa000000000000440)),
        (0x4000440, 0x10, nop_m(), nop_i(),
         br_cond(0xa000000000000440, 0xa000000000000440)),
    ], {
        "ip": 0xa000000000000440,
        "exception": IA64_EXCP_NONE,
        "cfm_sof": 8,
        "cfm_sol": 5,
    }, entry=0x10)

IFETCH_PNP_BASE = 0xa000000000000000
IFETCH_PNP_NEXT_PAGE = IFETCH_PNP_BASE + 0x2000
IFETCH_PNP_TARGET = IFETCH_PNP_BASE + 0x1ff0
IFETCH_PNP_CODE_PTE = 0x0010000004002660

test_ifetch_page_not_present_fallthrough_records_faulting_iip = \
    require_registers(
        "ifetch_page_not_present_fallthrough_records_faulting_iip", [
            (0x10, *movl_mlx(16, IFETCH_PNP_BASE)),
            (0x20, *movl_mlx(17, (5 << 8) | EIGHT_K_ITIR | 1)),
            (0x30, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
            (0x40, *movl_mlx(19, LOW_VECTOR_TR_PTE)),
            (0x50, *movl_mlx(20, IFETCH_PNP_CODE_PTE)),
            (0x60, *movl_mlx(21, IFETCH_PNP_BASE)),
            (0x70, *movl_mlx(22, IFETCH_PNP_NEXT_PAGE)),
            (0x80, *movl_mlx(23, IFETCH_PNP_TARGET)),
            (0x90, *movl_mlx(24, IA64_PSR_IC | IA64_PSR_IT)),
            (0xa0, 0x00, mov_rr_write(17, 16), adds(7, 16 << 2, 0),
             adds(5, 5, 0)),
            (0xb0, 0x00, mov_m_gr_cr(0, 20), nop_i(), nop_i()),
            (0xc0, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (0xd0, 0x00, itr_i(5, 18), nop_i(), nop_i()),
            (0xe0, 0x00, mov_m_gr_cr(21, 20), adds(7, 13 << 2, 0),
             adds(5, 6, 0)),
            (0xf0, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (0x100, 0x00, itr_i(5, 19), nop_i(), nop_i()),
            (0x110, 0x00, mov_m_gr_cr(22, 20), adds(7, 13 << 2, 0),
             adds(5, 7, 0)),
            (0x120, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (0x130, 0x00, itr_i(5, 20), adds(25, 0x150, 0), nop_i()),
            *rfi_to_gr(0x140, 24, 25),
            (0x4000150, 0x00, srlz_i(), nop_i(), nop_i()),
            (0x4000160, 0x00, nop_m(), mov_br_gr(7, 23), nop_i()),
            (0x4000170, 0x10, nop_m(), nop_i(), br_call_indirect(6, 7)),
            (0x4001ff0, 0x00, nop_m(), adds(28, 0x5a, 0), nop_i()),
            (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR, 0x00,
             mov_m_cr_gr(30, 19), nop_i(), nop_i()),
            (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00,
             mov_m_cr_gr(31, 20), nop_i(), nop_i()),
            (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x00,
             mov_m_cr_gr(29, 17), nop_i(), nop_i()),
            (0x4000000 + IA64_PAGE_NOT_PRESENT_VECTOR + 0x30, 0x10,
             nop_m(), nop_i(),
             br_cond(IA64_PAGE_NOT_PRESENT_VECTOR + 0x30,
                     IA64_PAGE_NOT_PRESENT_VECTOR + 0x30)),
        ], {
            "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x30,
            "exception": IA64_EXCP_NONE,
            "r28": 0x5a,
            "r29": IA64_ISR_X,
            "r30": IFETCH_PNP_NEXT_PAGE,
            "r31": IFETCH_PNP_NEXT_PAGE,
        }, entry=0x10)

test_speculative_load_walks_short_vhpt_with_ic_clear = require_registers(
    "speculative_load_walks_short_vhpt_with_ic_clear", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xbffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, *movl_mlx(23, 0x4000430)),
        (0xa0, *movl_mlx(24, 0x123456789abcdef0)),
        (0xb0, 0x00, st8(23, 24), nop_i(), nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xd0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xf0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0x100, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0x110, *movl_mlx(2, 0xa000000000000430)),
        (0x120, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x130, 0x00, ld8_s(31, 2), nop_i(),
         nop_i()),
        (0x140, 0x00, tak(30, 2), nop_i(),
         nop_i()),
        (0x150, 0x00, nop_m(), nop_i(), nop_i()),
        (0x160, 0x00, nop_m(), nop_i(), nop_i()),
        (0x170, 0x10, nop_m(), nop_i(),
         br_cond(0x170, 0x170)),
    ], {
        "ip": 0x170,
        "exception": IA64_EXCP_NONE,
        "r31": 0x123456789abcdef0,
        "r31_nat": 0,
        "r30": 5,
    }, entry=0x10)

test_speculative_load_defers_region6_vhpt_not_present = require_registers(
    "speculative_load_defers_region6_vhpt_not_present", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xc000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xdffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000660)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xc000000000000430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x00, ld8_s(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x00, nop_m(), nop_i(), nop_i()),
        (0x120, 0x00, nop_m(), nop_i(), nop_i()),
        (0x130, 0x10, nop_m(), nop_i(),
         br_cond(0x130, 0x130)),
    ], {
        "ip": 0x130,
        "exception": IA64_EXCP_NONE,
        "r31_nat": 1,
    }, entry=0x10)

test_region6_short_vhpt_controls_data_mapping = require_registers(
    "region6_short_vhpt_controls_data_mapping", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xc000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xdffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xc000000000000430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x08, ld8(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
        (0x430, 0x00, 0xfedcba9876543210, 0,
         0),
        (0x4000430, 0x00, 0x123456789a, 0,
         0),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r31": bundle_words(0x00, 0x123456789a, 0, 0)[0],
    }, entry=0x10)

test_region6_tpa_uses_short_vhpt_mapping = require_registers(
    "region6_tpa_uses_short_vhpt_mapping", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xc000000000000000)),
        (0x30, *movl_mlx(18, 0x539)),
        (0x40, *movl_mlx(19, 0xdffc000000000000)),
        (0x50, *movl_mlx(20, 0x0010000004009661)),
        (0x60, *movl_mlx(21, 0x0010000004000661)),
        (0x70, *movl_mlx(22, 0x4008000)),
        (0x80, 0x00, st8(22, 21), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(16, 8), adds(7, 0x38, 0),
         nop_i()),
        (0xa0, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0),
         nop_i()),
        (0xd0, 0x00, itr_d(5, 20), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0xc000000000000430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
    ], {
        "ip": 0x110,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4000430,
    }, entry=0x10)

test_translation_hash_m_unit_decode = require_registers(
    "translation_hash_m_unit_decode", [
        (0x10, *movl_mlx(16, 0x12345000)),
        (0x20, 0x00, tak(17, 16), nop_i(),
         nop_i()),
        (0x30, 0x00, thash(18, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, ttag(19, 16), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "r17": 1,
        "r18": 0x12345000,
        "r19": 0x12345,
    }, entry=0x10)

test_translation_hash_m46_ignored_bits_decode = require_registers(
    "translation_hash_m46_ignored_bits_decode", [
        (0x10, *movl_mlx(16, 0x12345000)),
        (0x20, 0x00, tak(17, 16, bit36=1, ignored=0x0b), nop_i(),
         nop_i()),
        (0x30, 0x00, thash(18, 16, bit36=1, ignored=0x01), nop_i(),
         nop_i()),
        (0x40, 0x00, ttag(19, 16, bit36=1, ignored=0x01), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "exception": IA64_EXCP_NONE,
        "r17": 1,
        "r18": 0x12345000,
        "r19": 0x12345,
    }, entry=0x10)

test_translation_hash_ops_clear_dest_nat = require_registers(
    "translation_hash_ops_clear_dest_nat", [
        (0x10, *movl_mlx(16, IA64_PSR_ED)),
        (0x20, *movl_mlx(17, 0x12345000)),
        (0x30, 0x00, mov_gr_psr_full(16), addl(3, 0x100, 0),
         nop_i()),
        (0x40, 0x00, ld8_s(20, 3), nop_i(),
         nop_i()),
        (0x50, 0x00, ld8_s(21, 3), nop_i(),
         nop_i()),
        (0x60, 0x00, ld8_s(22, 3), nop_i(),
         nop_i()),
        (0x70, 0x00, tak(20, 17), nop_i(),
         nop_i()),
        (0x80, 0x00, thash(21, 17), nop_i(),
         nop_i()),
        (0x90, 0x00, ttag(22, 17), nop_i(),
         nop_i()),
        (0xa0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xe0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xf0, 0x00, nop_m(), nop_i(), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
    ], {
        "ip": 0x100,
        "exception": IA64_EXCP_NONE,
        "r20_nat": 0,
        "r21_nat": 0,
        "r22_nat": 0,
    }, entry=0x10)

test_translation_hash_nat_source_rules = require_registers(
    "translation_hash_nat_source_rules", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, thash(17, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, ttag(18, 16), nop_i(),
         nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x00, nop_m(), nop_i(), nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r17_nat": 1,
        "r18_nat": 1,
    }, entry=0x10)

test_tak_nat_source_consumes_non_access = require_registers(
    "tak_nat_source_consumes_non_access", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, tak(17, 16), nop_i(),
         nop_i()),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x5620,
        "exception": IA64_EXCP_NONE,
        "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_NA | 3,
    }, entry=0x10)

test_tpa_nat_source_consumes_non_access = require_registers(
    "tpa_nat_source_consumes_non_access", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, ssm(1 << 13), nop_i(),
         nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x50, 0x00, tpa(17, 16), nop_i(),
         nop_i()),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x5620,
        "exception": IA64_EXCP_NONE,
        "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | IA64_ISR_NA,
    }, entry=0x10)

def register_nat_consumption_test(name, fault_bundle, expected_isr=0,
                                  enable_ic=True):
    bundles = [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
    ]
    fault_ip = 0x30
    if enable_ic:
        bundles.extend([
            (0x30, 0x00, ssm(1 << 13), nop_i(),
             nop_i()),
            (0x40, 0x00, srlz_d(), nop_i(),
             nop_i()),
        ])
        fault_ip = 0x50
    bundles.extend([
        (fault_ip, *fault_bundle),
        (0x5600, 0x00, mov_m_cr_gr(14, 20), nop_i(),
         nop_i()),
        (0x5610, 0x00, mov_m_cr_gr(15, 17), nop_i(),
         nop_i()),
        (0x5620, 0x10, nop_m(), nop_i(),
         br_cond(0x5620, 0x5620)),
        (0x200, 0x00, 0, 0,
         0),
    ])
    return require_registers(name, bundles, {
        "ip": 0x5620,
        "exception": IA64_EXCP_NONE,
        "r14": 0,
        "r15": IA64_ISR_CODE_REG_NAT | expected_isr,
    }, entry=0x10)

test_mov_ar_nat_source_consumes = register_nat_consumption_test(
    "mov_ar_nat_source_consumes",
    (0x00, mov_m_gr_ar(16, 65), nop_i(), nop_i()),
    1 << IA64_ISR_EI_SHIFT)

test_mov_br_nat_source_consumes = register_nat_consumption_test(
    "mov_br_nat_source_consumes",
    (0x09, nop_m(), nop_m(), mov_b_gr(0, 16)),
    2 << IA64_ISR_EI_SHIFT)

test_mov_pr_nat_source_consumes = register_nat_consumption_test(
    "mov_pr_nat_source_consumes",
    (0x00,
     bitfield(3, 33, 3) | bitfield(16, 13, 7) | bitfield(0x7f, 6, 7),
     nop_i(), nop_i()))

test_mov_cr_nat_source_consumes = register_nat_consumption_test(
    "mov_cr_nat_source_consumes",
    (0x00, mov_m_gr_cr(16, 0), nop_i(), nop_i()))

test_mov_psr_nat_source_consumes = register_nat_consumption_test(
    "mov_psr_nat_source_consumes",
    (0x00, mov_m_gr_psrl(16), nop_i(), nop_i()))

test_mov_um_nat_source_consumes = register_nat_consumption_test(
    "mov_um_nat_source_consumes",
    (0x00, mov_m_gr_psr_um(16), nop_i(), nop_i()))

test_mov_rr_nat_index_consumes = register_nat_consumption_test(
    "mov_rr_nat_index_consumes",
    (0x00, mov_rr_read(17, 16), nop_i(), nop_i()))

test_mov_pkr_nat_index_consumes = register_nat_consumption_test(
    "mov_pkr_nat_index_consumes",
    (0x00, mov_pkr_indexed(16, 17, bit36=1), nop_i(), nop_i()))

test_mov_pmc_nat_value_consumes = register_nat_consumption_test(
    "mov_pmc_nat_value_consumes",
    (0x00, mov_grpmc_indexed(3, 16), nop_i(), nop_i()))

test_mov_cpuid_nat_index_consumes = register_nat_consumption_test(
    "mov_cpuid_nat_index_consumes",
    (0x00, mov_cpuid(17, 16), nop_i(), nop_i()))

test_itc_d_nat_pte_consumes = register_nat_consumption_test(
    "itc_d_nat_pte_consumes",
    (0x00, itc_d(16), nop_i(), nop_i()),
    IA64_ISR_NI, enable_ic=False)

test_itr_d_nat_slot_consumes = register_nat_consumption_test(
    "itr_d_nat_slot_consumes",
    (0x00, itr_d(16, 17), nop_i(), nop_i()),
    IA64_ISR_NI, enable_ic=False)

test_ptc_l_nat_addr_consumes = register_nat_consumption_test(
    "ptc_l_nat_addr_consumes",
    (0x00, ptc_l(16, 17), nop_i(), nop_i()))

test_ptr_d_nat_size_consumes = register_nat_consumption_test(
    "ptr_d_nat_size_consumes",
    (0x00, ptr_d(17, 16), nop_i(), nop_i()))

test_ptc_e_nat_addr_consumes = register_nat_consumption_test(
    "ptc_e_nat_addr_consumes",
    (0x00, ptc_e(16), nop_i(), nop_i()))

test_fc_nat_source_consumes_non_access = register_nat_consumption_test(
    "fc_nat_source_consumes_non_access",
    (0x00, fc_i(16), nop_i(), nop_i()),
    IA64_ISR_NA | IA64_ISR_R | 1)

test_setf_nat_source_sets_fr_natval = require_registers(
    "setf_nat_source_sets_fr_natval", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(16, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x00, setf_sig(7, 16), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), nop_b()),
        (0x50, 0x02, nop_m(), nop_i(), nop_i()),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "f7": ExpectedFP(0, 0x1fffe, nat=True),
    }, entry=0x10)

test_short_vhpt_thash_decode = require_registers(
    "short_vhpt_thash_decode", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c9)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(19, 0xa0007fffff90c010)),
        (0x40, 0x00, mov_m_gr_cr(16, 8), adds(18, 0x539, 0),
         nop_i()),
        (0x50, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x60, 0x00, thash(20, 19), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r20": 0xbffc000ffffff218,
    }, entry=0x10)

test_thash_uses_pta_with_walker_disabled = require_registers(
    "thash_uses_pta_with_walker_disabled", [
        (0x10, *movl_mlx(16, 0x1ffc0000000000c8)),
        (0x20, *movl_mlx(17, 0xa000000000000000)),
        (0x30, *movl_mlx(19, 0xa0007fffff90c010)),
        (0x40, 0x00, mov_m_gr_cr(16, 8), adds(18, 0x539, 0),
         nop_i()),
        (0x50, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x60, 0x00, thash(20, 19), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "r20": 0xbffc000ffffff218,
    }, entry=0x10)

test_short_vhpt_thash_uses_implemented_va_bits = require_registers(
    "short_vhpt_thash_uses_implemented_va_bits", [
        (0x10, *movl_mlx(16, 0x1ffffe00000000d1)),
        (0x20, *movl_mlx(17, 0xe000000000000000)),
        (0x30, *movl_mlx(18, 0x135)),
        (0x40, *movl_mlx(19, 0xfffffe00003fe800)),
        (0x50, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x70, 0x00, thash(20, 19), nop_i(),
         nop_i()),
        (0x80, 0x00, ttag(21, 19), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r20": 0xfff7ffff80000ff8,
        "r21": 0x1fffff00001ff,
    }, entry=0x10)

test_short_vhpt_thash_high_region_self_map = require_registers(
    "short_vhpt_thash_high_region_self_map", [
        (0x10, *movl_mlx(16, 0x1ffff000000000b1)),
        (0x20, *movl_mlx(17, 0xe000000000000000)),
        (0x30, *movl_mlx(18, 0x135)),
        (0x40, *movl_mlx(19, 0xfffffffc00000ff8)),
        (0x50, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x70, 0x00, thash(20, 19), nop_i(),
         nop_i()),
        (0x80, 0x00, ttag(21, 19), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "r20": 0xffffffffff000000,
        "r21": 0x1ffffffe00000,
    }, entry=0x10)

test_long_vhpt_walk_uses_standard_entry_layout = require_registers(
    "long_vhpt_walk_uses_standard_entry_layout", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0x0010000004000661)),
        (0x40, *movl_mlx(19, 0x230)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x60, *movl_mlx(21, 0x100040)),
        (0x70, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x80, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(2, 0x430)),
        (0xd0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0xe0, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0xf0, 0x00, tak(30, 2), nop_i(),
         nop_i()),
        (0x100, 0x10, nop_m(), nop_i(),
         br_cond(0x100, 0x100)),
    ], {
        "ip": 0x100,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4000430,
        "r30": 2,
    }, entry=0x10)

test_long_vhpt_walk_uses_dcr_byte_order = require_registers(
    "long_vhpt_walk_uses_dcr_byte_order", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0x6106000400001000)),
        (0x40, *movl_mlx(19, 0x3002000000000000)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG_BYTE_SWAPPED)),
        (0x60, *movl_mlx(21, 0x100040)),
        (0x70, *movl_mlx(22, IA64_DCR_BE)),
        (0x80, 0x00, st8(21, 18), adds(23, 8, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 19), adds(24, 16, 21),
         nop_i()),
        (0xa0, 0x00, st8(24, 20), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(22, 0), nop_i(),
         nop_i()),
        (0xc0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xd0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(2, 0x430)),
        (0xf0, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x100, 0x00, tpa(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x00, tak(30, 2), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r31": 0x4000430,
        "r30": 2,
    }, entry=0x10)

LONG_VHPT_RID1_DATA_BUNDLE = (0x4000430, 0x00, 0x1111222233334444, 0, 0)
LONG_VHPT_RID2_DATA_BUNDLE = (0x4010430, 0x00, 0x5555666677778888, 0, 0)
LONG_VHPT_RID1_DATA_LOW, _ = bundle_words(*LONG_VHPT_RID1_DATA_BUNDLE[1:])
LONG_VHPT_RID2_DATA_LOW, _ = bundle_words(*LONG_VHPT_RID2_DATA_BUNDLE[1:])

test_long_vhpt_same_va_different_rids_refills = require_registers(
    "long_vhpt_same_va_different_rids_refills", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x131)),
        (0x30, *movl_mlx(18, 0x231)),
        (0x40, *movl_mlx(19, 0x0010000004000661)),
        (0x50, *movl_mlx(20, 0x0010000004010661)),
        (0x60, *movl_mlx(21, 0x230)),
        (0x70, *movl_mlx(22, LONG_VHPT_RID1_TAG)),
        (0x80, *movl_mlx(23, LONG_VHPT_RID2_TAG)),
        (0x90, *movl_mlx(24, 0x100020)),
        (0xa0, *movl_mlx(25, 0x100040)),
        (0xb0, 0x00, st8(24, 19), adds(26, 8, 24),
         nop_i()),
        (0xc0, 0x00, st8(26, 21), adds(27, 16, 24),
         nop_i()),
        (0xd0, 0x00, st8(27, 22), nop_i(),
         nop_i()),
        (0xe0, 0x00, st8(25, 20), adds(26, 8, 25),
         nop_i()),
        (0xf0, 0x00, st8(26, 21), adds(27, 16, 25),
         nop_i()),
        (0x100, 0x00, st8(27, 23), nop_i(),
         nop_i()),
        (0x110, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x120, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0x130, *movl_mlx(2, 0x430)),
        (0x140, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x150, 0x00, ld8(28, 2), nop_i(),
         nop_i()),
        (0x160, 0x00, mov_rr_write(18, 0), nop_i(),
         nop_i()),
        (0x170, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x180, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (0x190, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0x1a0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x1b0, 0x00, ld8(30, 2), nop_i(),
         nop_i()),
        (0x1c0, 0x10, nop_m(), nop_i(),
         br_cond(0x1c0, 0x1c0)),
        LONG_VHPT_RID1_DATA_BUNDLE,
        LONG_VHPT_RID2_DATA_BUNDLE,
    ], {
        "ip": 0x1c0,
        "exception": IA64_EXCP_NONE,
        "r28": LONG_VHPT_RID1_DATA_LOW,
        "r29": LONG_VHPT_RID2_DATA_LOW,
        "r30": LONG_VHPT_RID1_DATA_LOW,
    }, entry=0x10)

test_long_vhpt_not_present_ignores_software_fields = require_registers(
    "long_vhpt_not_present_ignores_software_fields", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0xfffffffffffffffe)),
        (0x40, *movl_mlx(19, 0xdeadbeef00000030)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x60, *movl_mlx(21, 0x100040)),
        (0x70, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x80, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(2, 0x430)),
        (0xd0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0xe0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xf0, 0x00, ld8(29, 2), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_PAGE_NOT_PRESENT_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_PAGE_NOT_PRESENT_VECTOR,
                 IA64_PAGE_NOT_PRESENT_VECTOR)),
    ], {
        "ip": IA64_PAGE_NOT_PRESENT_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x430,
        "r31": IA64_ISR_R,
    }, entry=0x10)

test_long_vhpt_unsupported_page_size_aborts_to_dtlb_miss = require_registers(
    "long_vhpt_unsupported_page_size_aborts_to_dtlb_miss", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0x0010000004000661)),
        (0x40, *movl_mlx(19, 0x23c)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x60, *movl_mlx(21, 0x100040)),
        (0x70, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x80, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(2, 0x430)),
        (0xd0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0xe0, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x20,
                 IA64_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x430,
        "r31": 0x100040,
    }, entry=0x10)

test_long_vhpt_walker_does_not_search_collision_chain = require_registers(
    "long_vhpt_walker_does_not_search_collision_chain", [
        (0x10, *movl_mlx(16, 0x10013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0x0010000004000661)),
        (0x40, *movl_mlx(19, 0x230)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x60, *movl_mlx(21, 0x100060)),
        (0x70, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x80, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(2, 0x430)),
        (0xd0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0xe0, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25), nop_i(),
         nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x20,
                 IA64_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x430,
        "r31": 0x100040,
    }, entry=0x10)

# The long-format table lives at an unmapped region 6 address, so the
# walker's own reference to the VHPT misses the TLB and raises a VHPT
# Translation fault (the handler at offset 0 records IFA and IHA).
test_long_vhpt_table_tlb_miss_raises_vhpt_translation = require_registers(
    "long_vhpt_table_tlb_miss_raises_vhpt_translation", [
        (0x000, 0x00, mov_m_cr_gr(30, 20), nop_i(),
         nop_i()),
        (0x010, 0x00, mov_m_cr_gr(31, 25), nop_i(),
         nop_i()),
        (0x020, 0x10, nop_m(), nop_i(),
         br_cond(0x020, 0x020)),
        (0x200, *movl_mlx(16, 0xc00000000010013d)),
        (0x210, *movl_mlx(17, 0x231)),
        (0x220, *movl_mlx(18, 0x0010000004000661)),
        (0x230, *movl_mlx(19, 0x230)),
        (0x240, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x250, *movl_mlx(21, 0x100040)),
        (0x260, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x270, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x280, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0x290, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x2a0, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0x2b0, *movl_mlx(2, 0x430)),
        (0x2c0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x2d0, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0x2e0, 0x10, nop_m(), nop_i(),
         br_cond(0x2e0, 0x2e0)),
        (IA64_DTLB_VECTOR, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR, IA64_DTLB_VECTOR)),
    ], {
        "ip": 0x020,
        "exception": IA64_EXCP_NONE,
        "r30": 0x430,
        "r31": 0xc000000000100040,
    }, entry=0x200)

# When the table itself is reachable only through a non-cacheable
# translation, the VHPT is not referenced at all and the walker aborts to a
# Data TLB Miss fault instead of raising a VHPT Translation fault.
test_long_vhpt_uncacheable_table_aborts_to_dtlb_miss = require_registers(
    "long_vhpt_uncacheable_table_aborts_to_dtlb_miss", [
        (0x10, *movl_mlx(16, 0xc00000000010013d)),
        (0x20, *movl_mlx(17, 0x231)),
        (0x30, *movl_mlx(18, 0x0010000004000661)),
        (0x40, *movl_mlx(19, 0x230)),
        (0x50, *movl_mlx(20, LONG_VHPT_RID2_TAG)),
        (0x60, *movl_mlx(21, 0x100040)),
        (0x70, 0x00, st8(21, 18), adds(22, 8, 21),
         nop_i()),
        (0x80, 0x00, st8(22, 19), adds(23, 16, 21),
         nop_i()),
        (0x90, 0x00, st8(23, 20), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(24, 0xc000000000100000)),
        (0xb0, *movl_mlx(25, 0x100671)),
        (0xc0, 0x00, adds(7, 0x38, 0), nop_i(),
         nop_i()),
        (0xd0, 0x00, mov_m_gr_cr(24, 20), nop_i(),
         nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0xf0, 0x00, itc_d(25), nop_i(),
         nop_i()),
        (0x100, 0x00, mov_m_gr_cr(16, 8), nop_i(),
         nop_i()),
        (0x110, 0x00, mov_rr_write(17, 0), nop_i(),
         nop_i()),
        (0x120, *movl_mlx(2, 0x430)),
        (0x130, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0x140, 0x00, tpa(29, 2), nop_i(),
         nop_i()),
        (0x150, 0x10, nop_m(), nop_i(),
         br_cond(0x150, 0x150)),
        (IA64_DTLB_VECTOR, 0x00, mov_m_cr_gr(30, 20),
         nop_i(), nop_i()),
        (IA64_DTLB_VECTOR + 0x10, 0x00, mov_m_cr_gr(31, 25),
         nop_i(), nop_i()),
        (IA64_DTLB_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DTLB_VECTOR + 0x20,
                 IA64_DTLB_VECTOR + 0x20)),
    ], {
        "ip": IA64_DTLB_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r30": 0x430,
        "r31": 0xc000000000100040,
    }, entry=0x10)

test_itr_d_uses_slot_register_value = require_registers(
    "itr_d_uses_slot_register_value", [
        (0x10, *movl_mlx(18, 0x0010000004000661)),
        (0x20, *movl_mlx(19, 0x4000000)),
        (0x30, 0x00, mov_m_gr_cr(19, 20), adds(21, 0x58, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(21, 21), adds(10, 7, 0),
         nop_i()),
        (0x50, 0x00, itr_d(10, 18, bit36=1), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(18, 0x0010000001000661)),
        (0x70, *movl_mlx(19, 0xe000000081000000)),
        (0x80, 0x00, mov_m_gr_cr(19, 20), adds(21, 0x60, 0),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(21, 21), adds(10, 2, 0),
         nop_i()),
        (0xa0, 0x00, itr_d(10, 18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(2, 0x4092158)),
        (0xc0, 0x00, ssm(1 << 17), adds(27, 1, 0),
         nop_i()),
        (0xd0, 0x10, st4(2, 27), nop_i(),
         br_cond(0xd0, 0xe0)),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0xe0)),
    ], {"ip": 0xe0, "exception": IA64_EXCP_NONE}, entry=0x10)

test_itr_d_slot_replacement_keeps_old_translation_cached = require_registers(
    "itr_d_slot_replacement_keeps_old_translation_cached", [
        (0x10, *movl_mlx(18, 0x4009661)),
        (0x20, *movl_mlx(19, 0x4010661)),
        (0x30, *movl_mlx(20, 0x9000)),
        (0x40, *movl_mlx(21, 0x20000)),
        (0x50, 0x00, adds(7, 0x38, 0), adds(10, 4, 0),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(20, 20), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x80, 0x00, itr_d(10, 18), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(21, 20), nop_i(), nop_i()),
        (0xa0, 0x00, itr_d(10, 19), nop_i(), nop_i()),
        (0xb0, *movl_mlx(22, (1 << 13) | (1 << 17))),
        (0xc0, 0x00, mov_gr_psr_full(22), nop_i(), nop_i()),
        (0xd0, 0x00, ld8(31, 20), nop_i(), nop_i()),
        (0xe0, 0x00, ld8(30, 21), nop_i(), nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(), br_cond(0xf0, 0xf0)),
        ITC_DATA_BUNDLE,
        PTC_SURVIVOR_BUNDLE,
    ], {
        "ip": 0xf0,
        "exception": IA64_EXCP_NONE,
        "r30": PTC_SURVIVOR_LOW,
        "r31": ITC_DATA_LOW,
    }, entry=0x10)

test_itr_d_cached_translation_survives_region_register_write = \
    require_registers(
        "itr_d_cached_translation_survives_region_register_write", [
            (0x10, *movl_mlx(18, 0x4009661)),
            (0x20, *movl_mlx(19, 0x4010661)),
            (0x30, *movl_mlx(20, 0x9000)),
            (0x40, *movl_mlx(21, 0x20000)),
            (0x50, *movl_mlx(23, (0x12345 << 8) | LOW_VECTOR_ITIR)),
            (0x60, 0x00, mov_rr_write(23, 0), adds(7, LOW_VECTOR_ITIR, 0),
             adds(10, 4, 0)),
            (0x70, 0x00, mov_m_gr_cr(20, 20), nop_i(), nop_i()),
            (0x80, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
            (0x90, 0x00, itr_d(10, 18), nop_i(), nop_i()),
            (0xa0, 0x00, mov_m_gr_cr(21, 20), nop_i(), nop_i()),
            (0xb0, 0x00, itr_d(10, 19), nop_i(), nop_i()),
            (0xc0, 0x00, mov_rr_write(23, 0), nop_i(), nop_i()),
            (0xd0, 0x00, srlz_d(), nop_i(), nop_i()),
            (0xe0, *movl_mlx(22, (1 << 13) | (1 << 17))),
            (0xf0, 0x00, mov_gr_psr_full(22), nop_i(), nop_i()),
            (0x100, 0x00, ld8(31, 20), nop_i(), nop_i()),
            (0x110, 0x00, ld8(30, 21), nop_i(), nop_i()),
            (0x120, 0x10, nop_m(), nop_i(), br_cond(0x120, 0x120)),
            ITC_DATA_BUNDLE,
            PTC_SURVIVOR_BUNDLE,
        ], {
            "ip": 0x120,
            "exception": IA64_EXCP_NONE,
            "r30": PTC_SURVIVOR_LOW,
            "r31": ITC_DATA_LOW,
        }, entry=0x10)

test_ptr_d_purge_completes_on_srlz_d = require_registers(
    "ptr_d_purge_completes_on_srlz_d", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(3, HIGH_TR_BASE)),
        (0x90, 0x00, ptr_d(3, 7), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(2, HIGH_TR_BASE + 0x9000)),
        (0xb0, 0x00, ssm((1 << 13) | (1 << 17)), nop_i(),
         nop_i()),
        (0xc0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xd0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xe0, 0x00, ld8(30, 2), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(29, 0x72, 0),
         br_cond(IA64_ALT_DTLB_VECTOR,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r29": 0x72,
        "r31": ITC_DATA_LOW,
    }, entry=0x10)

test_ptr_d_purge_invalidates_advanced_load = require_registers(
    "ptr_d_purge_invalidates_advanced_load", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(2, HIGH_TR_BASE + 0x9000)),
        (0x90, *movl_mlx(3, HIGH_TR_BASE)),
        (0xa0, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0xb0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xc0, 0x00, ld8_a(31, 2), nop_i(),
         nop_i()),
        (0xd0, *movl_mlx(31, 0x55)),
        (0xe0, 0x00, ptr_d(3, 7), nop_i(),
         nop_i()),
        (0xf0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x100, 0x00, ld8_c_clr(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), nop_i(),
         br_cond(0x110, 0x110)),
        (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(29, 0x73, 0),
         br_cond(IA64_ALT_DTLB_VECTOR,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r29": 0x73,
    }, entry=0x10)

test_interruption_serializes_pending_ptr_d = require_registers(
    "interruption_serializes_pending_ptr_d", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(2, HIGH_TR_BASE + 0x9000)),
        (0x90, *movl_mlx(3, HIGH_TR_BASE)),
        (0xa0, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0xb0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xc0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xd0, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0xe0, 0x00, ptr_d(3, 7), nop_i(),
         nop_i()),
        (0xf0, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR, 0x00, ld8(30, 2), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), adds(29, 0x74, 0),
         br_cond(IA64_BREAK_VECTOR + 0x10,
                 IA64_BREAK_VECTOR + 0x10)),
        (IA64_DATA_NESTED_TLB_VECTOR, 0x10, nop_m(), adds(29, 0x75, 0),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR,
                 IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
        (IA64_DATA_NESTED_TLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_NESTED_TLB_VECTOR + 0x10,
                 IA64_DATA_NESTED_TLB_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_DATA_NESTED_TLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r29": 0x75,
        "r31": ITC_DATA_LOW,
    }, entry=0x10)

test_rfi_serializes_pending_ptr_d = require_registers(
    "rfi_serializes_pending_ptr_d", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(20, HIGH_TR_BASE)),
        (0x30, 0x00, adds(7, 0x68, 0), adds(5, 5, 0),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_d(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x80, *movl_mlx(2, HIGH_TR_BASE + 0x9000)),
        (0x90, *movl_mlx(3, HIGH_TR_BASE)),
        (0xa0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xb0, *movl_mlx(21, 0x100)),
        (0xc0, 0x00, ptr_d(3, 7), nop_i(),
         nop_i()),
        *rfi_to_gr(0xd0, 19, 21),
        (0x100, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0x110, 0x10, nop_m(), adds(29, 0x76, 0),
         br_cond(0x110, 0x120)),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(29, 0x77, 0),
         br_cond(IA64_ALT_DTLB_VECTOR,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        ITC_DATA_BUNDLE,
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r29": 0x77,
    }, entry=0x10)

test_rfi_serializes_pending_ptr_i = require_registers(
    "rfi_serializes_pending_ptr_i", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_IT | IA64_PSR_BN)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), adds(5, 0, 0),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(0, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(18, LOW_VECTOR_TR_PTE + 0x10000)),
        (0x80, *movl_mlx(20, 0x10000)),
        (0x90, 0x00, mov_m_gr_cr(20, 20), adds(5, 5, 0),
         nop_i()),
        (0xa0, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(3, 0x10000)),
        (0xc0, 0x00, ptr_i(3, 7), nop_i(),
         nop_i()),
        *rfi_to_gr(0xd0, 19, 20),
        (0x4000c00, 0x10, nop_m(), adds(31, 0x78, 0),
         br_cond(0x4000c00, 0x0c10)),
        (0x4000c10, 0x10, nop_m(), nop_i(),
         br_cond(0x4000c10, 0x0c10)),
        (0x4010000, 0x10, nop_m(), adds(31, 0x44, 0),
         br_cond(0x4010000, 0x10010)),
        (0x4010010, 0x10, nop_m(), nop_i(),
         br_cond(0x4010010, 0x10010)),
    ], {
        "ip": 0x0c10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x78,
    }, entry=0x10)

test_mov_pkr_indexed_decode = require_registers("mov_pkr_indexed_decode", [
    (0x10, 0x00, addl(2, 0x5501, 0), adds(3, 0x103, 0),
     nop_i()),
    (0x20, 0x00, mov_pkr_indexed(3, 2, bit36=1), nop_i(),
     nop_i()),
    (0x30, 0x09, mov_m_cr_gr(4, 19), mov_pkr_indexed_read(5, 3, bit36=1),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "exception": IA64_EXCP_NONE,
    "r4": 0,
    "r5": 0x5501,
}, entry=0x10)

test_mov_pkr_does_not_alias_interruption_crs = require_registers(
    "mov_pkr_does_not_alias_interruption_crs", [
        (0x10, 0x00, addl(2, 0x1234, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_cr(2, 19), nop_i(),
         nop_i()),
        (0x30, 0x00, addl(3, 0x103, 0), addl(4, 0x5601, 0),
         nop_i()),
        (0x40, 0x00, mov_pkr_indexed(3, 4, bit36=1), nop_i(),
         nop_i()),
        (0x50, 0x09, mov_m_cr_gr(5, 19), mov_pkr_indexed_read(6, 3, bit36=1),
         nop_i()),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
    ], {
        "ip": 0x60,
        "exception": IA64_EXCP_NONE,
        "r5": 0x1234,
        "r6": 0x5601,
    }, entry=0x10)

test_mov_pkr_duplicate_key_invalidates_old_slot = require_registers(
    "mov_pkr_duplicate_key_invalidates_old_slot", [
        (0x10, 0x00, addl(2, 0x101, 0), addl(3, 0x101, 0),
         nop_i()),
        (0x20, 0x00, mov_pkr_indexed(3, 2, bit36=1), nop_i(),
         nop_i()),
        (0x30, 0x00, addl(3, 0x102, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_pkr_indexed(3, 2, bit36=1), nop_i(),
         nop_i()),
        (0x50, 0x00, addl(3, 0x101, 0), nop_i(),
         nop_i()),
        (0x60, 0x09, mov_pkr_indexed_read(5, 3, bit36=1), addl(3, 0x102, 0),
         nop_i()),
        (0x70, 0x09, mov_pkr_indexed_read(6, 3, bit36=1), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r5": 0x100,
        "r6": 0x101,
    }, entry=0x10)

REGION7_DATA = bundle_words(0x00, 0x123456789a, 0, 0)[0]
FW_IDENTITY_DATA = bundle_words(0x00, 0x1122334455667788, 0, 0)[0]
REGION7_SCRATCH_DATA = 0x1122334455667788

test_region7_untranslated_data_faults = require_registers(
    "region7_untranslated_data_faults", [
    (0x10, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
    (0x20, *movl_mlx(3, 0xe000000000000300)),
    (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
     nop_i()),
    (0x40, 0x08, ld8(31, 3), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
    (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(31, 0x68, 0),
     br_cond(IA64_ALT_DTLB_VECTOR,
             IA64_ALT_DTLB_VECTOR + 0x10)),
    (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
     br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
             IA64_ALT_DTLB_VECTOR + 0x10)),
    (0x300, 0x00, 0x123456789a, 0,
     0),
], {
    "ip": IA64_ALT_DTLB_VECTOR + 0x10,
    "exception": IA64_EXCP_NONE,
    "r31": 0x68,
}, entry=0x10)

test_region7_untranslated_user_data_faults = require_registers(
    "region7_untranslated_user_data_faults", [
        (0x10, *movl_mlx(19, (1 << 13) | (1 << 17) |
                         (3 << 32) | (1 << 44))),
        (0x20, *movl_mlx(3, 0xe000000000000300)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x08, ld8(31, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x1000, 0x10, nop_m(), adds(31, 0x6e, 0),
         br_cond(0x1000, 0x1010)),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
        (0x300, 0x00, 0x123456789a, 0,
         0),
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6e,
    }, entry=0x10)

test_region7_loader_scratch_store_load = require_registers("region7_loader_scratch_store_load", [
    *dtr_setup_bundles(0x10, REGION7_SCRATCH_VA, REGION7_SCRATCH_PA),
    (0x70, *movl_mlx(3, REGION7_SCRATCH_VA)),
    (0x80, *movl_mlx(4, REGION7_SCRATCH_DATA)),
    (0x90, 0x00, ssm(1 << 17), nop_i(),
     nop_i()),
    (0xa0, 0x08, st8(3, 4), ld8(31, 3),
     nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "exception": IA64_EXCP_NONE,
    "r31": REGION7_SCRATCH_DATA,
}, entry=0x10)

test_region7_dtr_controls_data_mapping = require_registers(
    "region7_dtr_controls_data_mapping", [
        *dtr_setup_bundles(0x10, 0xe000000081000430, 0x1000430,
                           page_shift=22, slot=2),
        (0x70, *movl_mlx(3, 0xe000000081000430)),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x08, ld8(31, 3), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (0x1000430, 0x00, 0x123456789abcdef0, 0,
         0),
        (0x81000430, 0x00, 0xfedcba9876543210, 0,
         0),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r31": bundle_words(0x00, 0x123456789abcdef0, 0, 0)[0],
    }, entry=0x10)

test_region7_nonzero_rid_requires_translation = require_registers(
    "region7_nonzero_rid_requires_translation", [
        (0x10, *movl_mlx(17, 0xe000000000000300)),
        (0x20, *movl_mlx(18, (1 << 8) | (13 << 2))),
        (0x30, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x50, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x60, 0x08, ld8(31, 17), nop_i(),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x1000, 0x10, mov_m_cr_gr(31, 21), nop_i(),
         br_cond(0x1000, 0x1010)),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
        (0x300, 0x00, 0x123456789a, 0,
         0),
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r31": (1 << 8) | (13 << 2),
    }, entry=0x10)

test_sal_boot_identity_handles_nonzero_region7_rid = require_registers(
    "sal_boot_identity_handles_nonzero_region7_rid", [
        (0x10, *movl_mlx(17, 0xe000000000000300)),
        (0x20, *movl_mlx(18, (1 << 8) | (13 << 2))),
        (0x30, *movl_mlx(2, IA64_FIRMWARE_IVT_BASE)),
        (0x40, 0x00, mov_m_gr_cr(2, 2), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x70, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x80, 0x08, ld8(31, 17), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x300, 0x00, 0x123456789a, 0,
         0),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r31": REGION7_DATA,
    }, entry=0x10)

# Region-7 boot accesses above the 0x8000_0000 direct-map base resolve to
# physical memory biased down by that base: VA 0xe000_0000_8000_1240 (region-7
# offset 0x8000_1240) must read PA 0x1240, not the unbiased identity alias
# 0x8000_1240.  The IA-64 loaders rely on this to reach top-of-RAM free-memory
# descriptors that no explicit TR covers; without the bias those pages alias
# unbacked physical memory 0x8000_0000 too high (see IA64_FW_REGION7_-
# DIRECTMAP_BASE) and the loader's free list reads back a NULL link.
REGION7_DIRECTMAP_DATA = bundle_words(0x00, 0x00c0ffee1234abcd, 0, 0)[0]
test_sal_boot_identity_region7_directmap_bias = require_registers(
    "sal_boot_identity_region7_directmap_bias", [
        (0x10, *movl_mlx(17, 0xe000000080001240)),
        (0x20, *movl_mlx(18, (1 << 8) | (13 << 2))),
        (0x30, *movl_mlx(2, IA64_FIRMWARE_IVT_BASE)),
        (0x40, 0x00, mov_m_gr_cr(2, 2), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x70, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x80, 0x08, ld8(31, 17), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x1240, 0x00, 0x00c0ffee1234abcd, 0,
         0),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r31": REGION7_DIRECTMAP_DATA,
    }, entry=0x10)

# The region-7 KSEG physical alias (VA = PA + 0x8000_0000) must persist after
# the SAL boot environment ends (cr.iva != the firmware IVT): the early kernel
# reaches loader-built structures near the top of RAM through it before its
# self-mapped page tables are active.  Here cr.iva is a non-firmware (kernel)
# IVT, so ia64_sal_boot_environment_active() is false, yet the region-7 offset
# 0x8000_1240 must still resolve to PA 0x1240.  Bounded to backed RAM
# (region7_directmap_limit), so it is a no-op outside physical memory.
test_region7_kseg_alias_persists_without_sal = require_registers(
    "region7_kseg_alias_persists_without_sal", [
        (0x10, *movl_mlx(17, 0xe000000080001240)),
        (0x20, *movl_mlx(18, (1 << 8) | (13 << 2))),
        (0x30, *movl_mlx(2, 0x100000)),
        (0x40, 0x00, mov_m_gr_cr(2, 2), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_rr_write(18, 17), nop_i(),
         nop_i()),
        (0x60, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0x70, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x80, 0x08, ld8(31, 17), nop_i(),
         nop_i()),
        (0x90, 0x10, nop_m(), nop_i(),
         br_cond(0x90, 0x90)),
        (0x1240, 0x00, 0x00c0ffee1234abcd, 0,
         0),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "r31": REGION7_DIRECTMAP_DATA,
    }, entry=0x10)

test_sal_boot_identity_does_not_override_explicit_rid_miss = \
    require_registers(
        "sal_boot_identity_does_not_override_explicit_rid_miss", [
            (0x10, *movl_mlx(17, 0xe000000083009af8)),
            (0x20, *movl_mlx(18, (1 << 8) | (24 << 2))),
            (0x30, 0x00, mov_rr_write(18, 17), nop_i(),
             nop_i()),
            *dtr_setup_bundles(0x40, 0xe000000083000000,
                               0x03000000, page_shift=24, slot=1),
            (0xa0, *movl_mlx(18, 0x100730)),
            (0xb0, *movl_mlx(2, IA64_FIRMWARE_IVT_BASE)),
            (0xc0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
            (0xd0, 0x00, mov_m_gr_cr(2, 2), nop_i(),
             nop_i()),
            (0xe0, 0x00, mov_rr_write(18, 17), nop_i(),
             nop_i()),
            (0xf0, 0x00, mov_gr_psr_full(19), nop_i(),
             nop_i()),
            (0x100, 0x08, ld8(31, 17), nop_i(),
             nop_i()),
            (0x110, 0x10, nop_m(), nop_i(),
             br_cond(0x110, 0x110)),
            (IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR, 0x10,
             nop_m(), adds(31, 0x6f, 0),
             br_cond(IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR,
                     IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR + 0x10)),
            (IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR + 0x10, 0x10,
             nop_m(), nop_i(),
             br_cond(IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR + 0x10,
                     IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR + 0x10)),
        ], {
            "ip": IA64_FIRMWARE_IVT_BASE + IA64_ALT_DTLB_VECTOR + 0x10,
            "exception": IA64_EXCP_NONE,
            "r31": 0x6f,
        }, entry=0x10)

test_region7_untranslated_high_va_faults = require_registers(
    "region7_untranslated_high_va_faults", [
    (0x10, *movl_mlx(19, (1 << 13) | (1 << 17) | (1 << 44))),
    (0x20, *movl_mlx(3, 0xfffffffffffc0000)),
    (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
     nop_i()),
    (0x40, 0x08, ld8(31, 3), nop_i(),
     nop_i()),
    (0x1000, 0x10, nop_m(), adds(31, 0x6d, 0),
     br_cond(0x1000, 0x1010)),
    (0x1010, 0x10, nop_m(), nop_i(),
     br_cond(0x1010, 0x1010)),
], {
    "ip": 0x1010,
    "exception": IA64_EXCP_NONE,
    "r31": 0x6d,
}, entry=0x10)

test_region6_untranslated_data_faults = require_registers(
    "region6_untranslated_data_faults", [
    (0x10, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
    (0x20, *movl_mlx(3, 0xc000000000000300)),
    (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
     nop_i()),
    (0x40, 0x08, ld8(31, 3), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
    (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(31, 0x69, 0),
     br_cond(IA64_ALT_DTLB_VECTOR,
             IA64_ALT_DTLB_VECTOR + 0x10)),
    (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
     br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
             IA64_ALT_DTLB_VECTOR + 0x10)),
    (0x300, 0x00, 0x123456789a, 0,
     0),
], {
    "ip": IA64_ALT_DTLB_VECTOR + 0x10,
    "exception": IA64_EXCP_NONE,
    "r31": 0x69,
}, entry=0x10)

test_region6_untranslated_user_data_faults = require_registers(
    "region6_untranslated_user_data_faults", [
        (0x10, *movl_mlx(19, (1 << 13) | (1 << 17) |
                         (3 << 32) | (1 << 44))),
        (0x20, *movl_mlx(3, 0xc000000000000300)),
        (0x30, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x40, 0x08, ld8(31, 3), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x1000, 0x10, nop_m(), adds(31, 0x6f, 0),
         br_cond(0x1000, 0x1010)),
        (0x1010, 0x10, nop_m(), nop_i(),
         br_cond(0x1010, 0x1010)),
        (0x300, 0x00, 0x123456789a, 0,
         0),
    ], {
        "ip": 0x1010,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6f,
    }, entry=0x10)

test_region6_high_dtr_tpa_decode = require_registers(
    "region6_high_dtr_tpa_decode", [
        *dtr_setup_bundles(0x10, 0xc00080000ff280a1, 0x5080a1),
        (0x70, *movl_mlx(3, 0xc00080000ff280a1)),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x00, tpa(31, 3, bit36=1), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r31": 0x5080a1,
    }, entry=0x10)

test_region6_local_sapic_store = require_registers("region6_local_sapic_store", [
    *dtr_setup_bundles(0x10, 0xc0000000fee00000, 0xfee00000,
                       pte_flags=DTR_PTE_UC),
    (0x70, *movl_mlx(3, 0xc0000000fee00000)),
    (0x80, *movl_mlx(4, 0xef)),
    (0x90, 0x10, ssm(1 << 17), nop_i(),
     br_cond(0x90, 0xa0)),
    (0xa0, 0x00, st8(3, 4), nop_i(),
     nop_i()),
    (0xb0, 0x00, mov_m_cr_gr(30, IA64_CR_SAPIC_IRR3), nop_i(),
     nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(),
     br_cond(0xc0, 0xc0)),
], {
    "ip": 0xc0,
    "exception": IA64_EXCP_NONE,
    "r30": 1 << 47,
}, entry=0x10)

test_region6_processor_interrupt_block_inta_read = require_registers(
    "region6_processor_interrupt_block_inta_read", [
        *dtr_setup_bundles(0x10, 0xc0000000fefe0000, 0xfefe0000,
                           pte_flags=DTR_PTE_UC),
        (0x70, *movl_mlx(3, 0xc0000000fefe0000)),
        (0x80, 0x10, ssm(1 << 17), nop_i(),
         br_cond(0x80, 0x90)),
        (0x90, 0x00, ld1(31, 3), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r31": 0,
    }, entry=0x10)

test_region6_processor_interrupt_block_xtp_store = require_registers(
    "region6_processor_interrupt_block_xtp_store", [
        *dtr_setup_bundles(0x10, 0xc0000000fefe0008, 0xfefe0008,
                           pte_flags=DTR_PTE_UC),
        (0x70, *movl_mlx(3, 0xc0000000fefe0008)),
        (0x80, *movl_mlx(4, 0xd0)),
        (0x90, 0x10, ssm(1 << 17), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, st1_postinc(3, 4, 0), nop_i(),
         nop_i()),
        (0xb0, 0x00, mov_m_cr_gr(30, IA64_CR_SAPIC_IRR3), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0xc0)),
    ], {
        "ip": 0xc0,
        "exception": IA64_EXCP_NONE,
        "r30": 0,
    }, entry=0x10)

test_firmware_identity_under_translation = require_registers(
    "firmware_identity_under_translation", [
        (0x10, *movl_mlx(2, 0x130000)),
        (0x20, *movl_mlx(3, IA64_FIRMWARE_IVT_BASE)),
        (0x30, 0x00, mov_m_gr_cr(3, 2), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(19, (1 << 17) | (1 << 36))),
        (0x50, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x50, 0x100000)),
        (0x100000, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0x100010, 0x10, nop_m(), nop_i(),
         br_cond(0x100010, 0x100010)),
        (0x130000, 0x00, 0x1122334455667788, 0,
         0),
    ], {
        "ip": 0x100010,
        "exception": IA64_EXCP_NONE,
        "r31": FW_IDENTITY_DATA,
    }, entry=0x10)

test_firmware_identity_ends_after_iva_handoff = require_registers(
    "firmware_identity_ends_after_iva_handoff", [
        *dtr_setup_bundles(0x10, 0x130000, 0x4130000),
        (0x70, *movl_mlx(3, 0x130000)),
        (0x80, 0x00, ssm(1 << 17), nop_i(),
         nop_i()),
        (0x90, 0x08, ld8(30, 3), nop_i(),
         nop_i()),
        (0xa0, *movl_mlx(2, 0x4000000)),
        (0xb0, 0x00, mov_m_gr_cr(2, 2), nop_i(),
         nop_i()),
        (0xc0, 0x08, ld8(31, 3), nop_i(),
         nop_i()),
        (0xd0, 0x10, nop_m(), nop_i(),
         br_cond(0xd0, 0xd0)),
        (0x130000, 0x00, 0x1122334455667788, 0,
         0),
        (0x4130000, 0x00, 0x8877665544332211, 0,
         0),
    ], {
        "ip": 0xd0,
        "exception": IA64_EXCP_NONE,
        "r30": bundle_words(0x00, 0x1122334455667788, 0, 0)[0],
        "r31": bundle_words(0x00, 0x8877665544332211, 0, 0)[0],
    }, entry=0x10)

test_firmware_runtime_identity_after_iva_handoff = require_registers(
    "firmware_runtime_identity_after_iva_handoff", [
        (0x10, *movl_mlx(2, 0x130000)),
        (0x20, *movl_mlx(3, 0x4000000)),
        (0x30, 0x00, mov_m_gr_cr(3, 2), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(19, (1 << 17) | (1 << 36))),
        (0x50, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x50, 0x100000)),
        (0x100000, 0x00, ld8(31, 2), nop_i(),
         nop_i()),
        (0x100010, 0x10, nop_m(), nop_i(),
         br_cond(0x100010, 0x100010)),
        (0x130000, 0x00, 0x1122334455667788, 0,
         0),
    ], {
        "ip": 0x100010,
        "exception": IA64_EXCP_NONE,
        "r31": FW_IDENTITY_DATA,
    }, entry=0x10)

test_firmware_identity_does_not_override_user_mapping = require_registers(
    "firmware_identity_does_not_override_user_mapping", [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE | (3 << 7))),
        (0x20, *movl_mlx(19, (1 << 36) | IA64_PSR_CPL3)),
        (0x30, *movl_mlx(20, IA64_FW_IDENTITY_BASE)),
        (0x40, *movl_mlx(21, 0x4000000)),
        (0x50, 0x00, adds(7, LOW_VECTOR_ITIR, 0), adds(5, 5, 0),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x80, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(21, 2), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        *rfi_to_gr(0xb0, 19, 20),
        (IA64_FW_IDENTITY_BASE, 0x10, nop_m(), adds(31, 0x66, 0),
         br_cond(IA64_FW_IDENTITY_BASE,
                 IA64_FW_IDENTITY_BASE + 0x10)),
        (IA64_FW_IDENTITY_BASE + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FW_IDENTITY_BASE + 0x10,
                 IA64_FW_IDENTITY_BASE + 0x10)),
        (0x4000000, 0x10, nop_m(), adds(31, 0x55, 0),
         br_cond(IA64_FW_IDENTITY_BASE,
                 IA64_FW_IDENTITY_BASE + 0x10)),
        (0x4000010, 0x10, nop_m(), nop_i(),
         br_cond(IA64_FW_IDENTITY_BASE + 0x10,
                 IA64_FW_IDENTITY_BASE + 0x10)),
    ], {
        "ip": IA64_FW_IDENTITY_BASE + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x55,
    }, entry=0x10)


test_rfi_restores_translation_bits = require_registers(
    "rfi_restores_translation_bits", [
        (0x10, *movl_mlx(19, (1 << 17) | (1 << 27) | (1 << 36))),
        (0x20, *movl_mlx(20, 0x70)),
        (0x30, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x30, 0x100000)),
        (0x100000, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (0x100010, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x100020, 0x10, mov_m_gr_cr(0, 23), nop_i(),
         rfi_b()),
        (0x70, 0x00, mov_m_psr_gr(31), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "exception": IA64_EXCP_NONE, "r31": 0}, entry=0x10)

test_rfi_resumes_at_ipsr_ri_slot = require_registers(
    "rfi_resumes_at_ipsr_ri_slot", [
        (0x10, *movl_mlx(19, 1 << 41)),
        (0x20, *movl_mlx(20, 0x60)),
        (0x30, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x00, mov_m_psr_gr(29), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], {
        "ip": 0x80,
        "exception": IA64_EXCP_NONE,
        "r29": 0,
        "r30": 0,
        "r31": 0x22,
    }, entry=0x10)

test_mov_from_psr_does_not_copy_execution_slot_to_rfi = require_registers(
    "mov_from_psr_does_not_copy_execution_slot_to_rfi", [
        (0x10, *movl_mlx(20, 0x60)),
        (0x20, 0x08, nop_m(), mov_m_psr_gr(19), nop_i()),
        (0x30, 0x08, mov_m_gr_cr(19, 16), mov_m_gr_cr(20, 19),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r19": 0,
        "r30": 0x11,
        "r31": 0x22,
    }, entry=0x10)

test_rfi_ignores_iip_low_bits = require_registers(
    "rfi_ignores_iip_low_bits", [
        (0x10, *movl_mlx(19, 1 << 41)),
        (0x20, *movl_mlx(20, 0x6f)),
        (0x30, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x60, 0x10, adds(30, 0x11, 0), adds(31, 0x22, 0),
         br_cond(0x60, 0x70)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r30": 0,
        "r31": 0x22,
    }, entry=0x10)

test_czx1_r_zero_index = require_registers("czx1_r_zero_index", [
    (0x10, *movl_mlx(3, 0x8877665500332211)),
    (0x20, 0x00, nop_m(), czx1_r(31, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 3}, entry=0x10)

test_czx1_r_no_zero = require_registers("czx1_r_no_zero", [
    (0x10, *movl_mlx(3, 0x3d6365766863616d)),
    (0x20, 0x00, nop_m(), czx1_r(31, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 8}, entry=0x10)

test_czx1_l_zero_index = require_registers("czx1_l_zero_index", [
    (0x10, *movl_mlx(3, 0x8877665500332211)),
    (0x20, 0x00, nop_m(), czx1_l(31, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 4}, entry=0x10)

test_czx2_r_zero_index = require_registers("czx2_r_zero_index", [
    (0x10, *movl_mlx(3, 0x3333000022221111)),
    (0x20, 0x00, nop_m(), czx2_r(31, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 2}, entry=0x10)

test_czx2_r_ignored_r2_decode = require_registers("czx2_r_ignored_r2_decode", [
    (0x10, *movl_mlx(3, 0x3333000022221111)),
    (0x20, 0x00, nop_m(), czx2_r(31, 3) | bitfield(6, 13, 7),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 2}, entry=0x10)

test_czx2_l_zero_index = require_registers("czx2_l_zero_index", [
    (0x10, *movl_mlx(3, 0x3333000022221111)),
    (0x20, 0x00, nop_m(), czx2_l(31, 3),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "exception": IA64_EXCP_NONE, "r31": 1}, entry=0x10)

test_mov_rr_indexed_decode = require_registers("mov_rr_indexed_decode", [
    (0x10, *movl_mlx(17, 0xa000000000000000)),
    (0x20, 0x00, adds(16, 0x539, 0), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_rr_write(16, 17, ignored36=1), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_rr_read(29, 17, ignored36=1), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r29": 0x539}, entry=0x10)

test_mov_cpuid_indexed_decode = require_registers("mov_cpuid_indexed_decode", [
    (0x10, 0x00, nop_m(), addl(31, 3, 0),
     nop_i()),
    (0x20, 0x00, mov_cpuid(29, 31, bit36=1), nop_i(),
     nop_i()),
    (0x30, 0x00, nop_m(), addl(31, 4, 0),
     nop_i()),
    (0x40, 0x00, mov_cpuid(28, 31, bit36=1), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_cpuid(30, 0), nop_i(),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r28": 0x0000000000000005,
    "r29": 0x0000000020000704,
    "r30": 0x49656e69756e6547,
}, entry=0x10)

test_mov_cpuid_madison_model = require_registers(
    "mov_cpuid_madison_model", [
        (0x10, 0x00, nop_m(), addl(31, 3, 0), nop_i()),
        (0x20, 0x00, mov_cpuid(29, 31), addl(31, 4, 0), nop_i()),
        (0x30, 0x00, mov_cpuid(28, 31), nop_i(), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r28": 0x0000000000000001,
        "r29": 0x000000001f010504,
    }, entry=0x10, cpu="madison")

test_mov_dahr_indexed_decode = require_registers("mov_dahr_indexed_decode", [
    (0x10, 0x00, addl(18, 2, 0), addl(29, 0x55, 0),
     nop_i()),
    (0x20, 0x00, mov_dahr_read(29, 18, bit36=1, ignored=0x7b),
     nop_i(), nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {
    "ip": 0x30,
    "exception": IA64_EXCP_NONE,
    "r29": 0,
}, entry=0x10)

test_mov_msr_indexed_decode = require_registers("mov_msr_indexed_decode", [
    (0x10, 0x00, addl(2, 66, 0), addl(3, 0x1234, 0),
     nop_i()),
    (0x20, 0x00, mov_msr_write(2, 3, bit36=1), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_msr_read(31, 2, bit36=1), nop_i(),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "exception": IA64_EXCP_NONE,
    "r31": 0x1234,
}, entry=0x10)

test_mov_dbr_ibr_indexed_decode = require_registers("mov_dbr_ibr_indexed_decode", [
    (0x10, 0x00, addl(2, 10, 0), addl(3, 0x66, 0),
     nop_i()),
    (0x20, 0x00, addl(4, 0x77, 0), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_dbr_indexed_write(2, 3), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_ibr_indexed_write(2, 4), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_dbr_indexed_read(29, 2), nop_i(),
     nop_i()),
    (0x60, 0x00, mov_ibr_indexed_read(30, 2, bit36=1), nop_i(),
     nop_i()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
], {
    "ip": 0x70,
    "exception": IA64_EXCP_NONE,
    "r29": 0x66,
    "r30": 0x77,
}, entry=0x10)

test_mov_br_hint_decode = require_registers("mov_br_hint_decode", [
    (0x10, 0x00, addl(3, 0x1234, 0), nop_i(),
     nop_i()),
    (0x20, 0x09, nop_m(), nop_m(),
     mov_b_gr(0, 3, x6=2)),
    (0x30, 0x00, nop_m(), mov_gr_b(29, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r29": 0x1234}, entry=0x10)

test_ssm_rsm_decode = require_registers("ssm_rsm_decode", [
    (0x10, 0x00, ssm(0x4000), nop_i(),
     nop_i()),
    (0x20, 0x00, mov_m_psr_gr(29), nop_i(),
     nop_i()),
    (0x30, 0x00, rsm(0x4000), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_m_psr_gr(30), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r29": 0x4000, "r30": 0}, entry=0x10)

test_sum_um_rum_decode = require_registers("sum_um_rum_decode", [
    (0x10, 0x00, rsm(0x8), nop_i(),
     nop_i()),
    (0x20, 0x00, sum_um(0x8), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_m_psr_gr(29), nop_i(),
     nop_i()),
    (0x40, 0x00, rum(0x8), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_m_psr_gr(30), nop_i(),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {"ip": 0x60, "r29": 0x8, "r30": 0}, entry=0x10)

test_psr_high_mask_and_um_decode = require_registers("psr_high_mask_and_um_decode", [
    (0x10, 0x00, addl(18, 0x1a, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, mov_m_gr_psr_um(18), nop_i(),
     nop_i()),
    (0x30, 0x00, mov_m_psr_um_gr(29), nop_i(),
     nop_i()),
    (0x40, 0x00, ssm(0x682008), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_m_psr_gr(30), nop_i(),
     nop_i()),
    (0x60, 0x00, rsm(0x682008), nop_i(),
     nop_i()),
    (0x70, 0x00, mov_m_psr_gr(31), nop_i(),
     nop_i()),
    (0x80, 0x00, ssm(IA64_PSR_SP), nop_i(),
     nop_i()),
    (0x90, 0x00, sum_um(0x4), nop_i(),
     nop_i()),
    (0xa0, 0x00, mov_m_psr_gr(28), nop_i(),
     nop_i()),
    (0xb0, 0x10, nop_m(), nop_i(),
     br_cond(0xb0, 0xb0)),
], {
    "ip": 0xb0,
    "exception": IA64_EXCP_NONE,
    "r28": IA64_PSR_SP | 0x12,
    "r29": 0x1a,
    "r30": 0x68201a,
    "r31": 0x12,
}, entry=0x10)

test_mov_psr_um_reserved_bit_fault = require_exception(
    "mov_psr_um_reserved_bit_fault", [
        (0x10, 0x00, addl(18, 0x40, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, mov_m_gr_psr_um(18), nop_i(),
         nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x20)

test_ptc_e_purges_data_tc_on_srlz_i = require_registers(
    "ptc_e_purges_data_tc_on_srlz_i", [
        (0x10, *movl_mlx(17, PERCPU_ADDR)),
        (0x20, *movl_mlx(18, 0x00100000052c0661)),
        (0x30, *movl_mlx(19, REGION7_GRANULE_RR)),
        (0x40, 0x00, mov_rr_write(19, 17), nop_i(),
         nop_i()),
        (0x50, 0x00, adds(7, PERCPU_ITIR, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_gr_cr(17, 20), nop_i(),
         nop_i()),
        (0x80, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0x90, 0x00, ptc_e(17), nop_i(),
         nop_i()),
        (0xa0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xb0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xc0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0xd0, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0xe0, 0x00, ld8(31, 17), nop_i(),
         nop_i()),
        (0xf0, 0x10, nop_m(), nop_i(),
         br_cond(0xf0, 0xf0)),
        (IA64_ALT_DTLB_VECTOR, 0x10, nop_m(), adds(31, 0x6e, 0),
         br_cond(IA64_ALT_DTLB_VECTOR,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
        (0x52c0000, 0x00, 0x123456789abcdef0, 0,
         0),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x6e,
    }, entry=0x10)

test_percpu_alt_dtlb_uses_updated_kr3_after_ptc_e = require_registers(
    "percpu_alt_dtlb_uses_updated_kr3_after_ptc_e", [
        (0x10, *movl_mlx(17, PERCPU_ADDR + 0x4b8)),
        (0x20, *movl_mlx(18, 0x00100000052c0661)),
        (0x30, *movl_mlx(19, REGION7_GRANULE_RR)),
        (0x40, 0x00, mov_rr_write(19, 17), nop_i(),
         nop_i()),
        (0x50, 0x00, adds(7, PERCPU_ITIR, 0), nop_i(),
         nop_i()),
        (0x60, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x70, *movl_mlx(16, PERCPU_ADDR)),
        (0x80, 0x00, mov_m_gr_cr(16, 20), nop_i(),
         nop_i()),
        (0x90, 0x00, itc_d(18), nop_i(),
         nop_i()),
        (0xa0, 0x00, ptc_e(17), nop_i(),
         nop_i()),
        (0xb0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xc0, *movl_mlx(20, 0x1140000)),
        (0xd0, 0x00, mov_m_gr_ar(20, 3), nop_i(),
         nop_i()),
        (0xe0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xf0, 0x00, mov_gr_psr_full(19), nop_i(),
         nop_i()),
        (0x100, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x110, 0x00, ld8(31, 17), nop_i(),
         nop_i()),
        (0x120, 0x10, nop_m(), nop_i(),
         br_cond(0x120, 0x120)),
        (IA64_ALT_DTLB_VECTOR, 0x00, mov_m_cr_gr(16, 20), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x00, mov_m_ar_gr(19, 3), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x20, *movl_mlx(26, 0x40000)),
        (IA64_ALT_DTLB_VECTOR + 0x30, 0x00, sub_reg(19, 19, 26), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x40, 0x00, adds(21, 0x661, 0), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x50, 0x00, or_reg(19, 19, 21), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x60, 0x00, adds(25, PERCPU_ITIR, 0),
         nop_i(), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x70, 0x00, mov_m_gr_cr(25, 21), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x80, 0x00, itc_d(19), nop_i(),
         nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x90, 0x10, nop_m(), nop_i(),
         rfi_b()),
        (0x52c04b8, 0x00, 0x1111111111111111, 0,
         0),
        (0x11004b8, 0x00, PERCPU_NEW_DATA, 0,
         0),
    ], {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r31": PERCPU_NEW_DATA_LOW,
    }, entry=0x10)

test_shr_u_imm_decode = require_registers("shr_u_imm_decode", [
    (0x10, 0x00, addl(3, 0x80, 0), nop_i(),
     nop_i()),
    (0x20, 0x02, nop_m(), shr_u_imm(4, 3, 4),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 8}, entry=0x10)

test_shrp_imm_decode = require_registers("shrp_imm_decode", [
    (0x10, 0x00, addl(2, 0x1234, 0), addl(3, 0x5678, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), shrp_imm(4, 2, 3, 16),
     shrp_imm(5, 2, 3, 0, ignored=1)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r4": 0x1234000000000000, "r5": 0x5678}, entry=0x10)

test_reserved_a1_x4_5_x2b_1_illegal = require_exception(
    "reserved_a1_x4_5_x2b_1_illegal",
    [(0x10, 0x00, nop_m(), reserved_a1_x4_5_x2b_1(1, 2, 3), nop_i())],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_mux1_rev_decode = require_registers("mux1_rev_decode", [
    (0x10, *movl_mlx(28, 0x1122334455667788)),
    (0x20, 0x02, nop_m(), mux1_rev(16, 28),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r16": 0x8877665544332211}, entry=0x10)

test_mux2_imm_decode = require_registers("mux2_imm_decode", [
    (0x10, *movl_mlx(31, 0x1122334455667788)),
    (0x20, 0x02, nop_m(), mux2(28, 31, 0x05),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r28": 0x7788778855665566}, entry=0x10)

test_pcmp1_eq_decode = require_registers("pcmp1_eq_decode", [
    (0x10, *movl_mlx(2, 0x0102030405060708)),
    (0x20, *movl_mlx(3, 0x0102030005060008)),
    (0x30, 0x02, nop_m(), pcmp1_eq(17, 2, 3),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r17": 0xffffff00ffff00ff}, entry=0x10)

test_pcmp1_eq_m_slot_decode = require_registers("pcmp1_eq_m_slot_decode", [
    (0x10, *movl_mlx(2, 0xff02030405060708)),
    (0x20, *movl_mlx(3, 0xff00030400060700)),
    (0x30, 0x02, pcmp1_eq(16, 2, 3), nop_i(),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r16": 0xff00ffff00ffff00}, entry=0x10)

test_pavg_decode = require_registers("pavg_decode", [
    (0x10, *movl_mlx(20, 0x0001020304050607)),
    (0x20, *movl_mlx(21, 0x0000000100020003)),
    (0x30, *movl_mlx(22, 0x0101010101010101)),
    (0x40, *movl_mlx(23, 0x0001000100010001)),
    (0x50, 0x02, nop_m(), pavg(4, 20, 0, 1),
     pavg(5, 20, 0, 1, raz=True)),
    (0x60, 0x02, nop_m(), pavg(6, 21, 0, 2),
     pavg(7, 21, 0, 2, raz=True)),
    (0x70, 0x02, nop_m(), pavgsub(8, 0, 22, 1),
     pavgsub(9, 0, 23, 2)),
    (0x80, 0x10, nop_m(), nop_i(),
     br_cond(0x80, 0x80)),
], {
    "ip": 0x80,
    "r4": 0x0001010102030303,
    "r5": 0x0001010202030304,
    "r6": 0x0000000100010001,
    "r7": 0x0000000100010002,
    "r8": 0xffffffffffffffff,
    "r9": 0xffffffffffffffff,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_pminmax_pack_decode = require_registers("pminmax_pack_decode", [
    (0x10, *movl_mlx(20, 0x10ff80017fff0002)),
    (0x20, *movl_mlx(21, 0x20017f02ff000003)),
    (0x30, *movl_mlx(22, 0x80017fff0002ffff)),
    (0x40, *movl_mlx(23, 0x7fff800000030001)),
    (0x50, 0x02, nop_m(), pmax1_u(4, 20, 21),
     pmin1_u(5, 20, 21)),
    (0x60, 0x02, nop_m(), pmax2(6, 22, 23),
     pmin2(7, 22, 23)),
    (0x70, *movl_mlx(24, 0x0080ff800080007f)),
    (0x80, *movl_mlx(25, 0x800001000001ffff)),
    (0x90, 0x02, nop_m(), pack2_sss(8, 24, 25),
     pack2_uss(9, 24, 25)),
    (0xa0, *movl_mlx(26, 0x0000800000007fff)),
    (0xb0, *movl_mlx(27, 0x00010000ffff8000)),
    (0xc0, 0x02, nop_m(), pack4_sss(10, 26, 27),
     nop_i()),
    (0xd0, 0x10, nop_m(), nop_i(),
     br_cond(0xd0, 0xd0)),
], {
    "ip": 0xd0,
    "r4": 0x20ff8002ffff0003,
    "r5": 0x10017f017f000002,
    "r6": 0x7fff7fff00030001,
    "r7": 0x800180000002ffff,
    "r8": 0x807f01ff7f807f7f,
    "r9": 0x00ff01008000807f,
    "r10": 0x7fff80007fff7fff,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_psad1_decode = require_registers("psad1_decode", [
    (0x10, *movl_mlx(20, 0x0102030405060708)),
    (0x20, *movl_mlx(21, 0x0806040200060a08)),
    (0x30, 0x02, nop_m(), psad1(4, 20, 21),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {
    "ip": 0x40,
    "r4": 0x16,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_fc_i_sync_i_decode = require_registers("fc_i_sync_i_decode", [
    (0x10, *movl_mlx(30, 0x200)),
    (0x20, 0x10, fc_i(30), adds(30, 32, 30),
     br_cond(0x20, 0x30)),
    (0x30, 0x08, sync_i(), adds(31, 1, 0),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "exception": IA64_EXCP_NONE, "r30": 0x220,
    "r31": 1}, entry=0x10)

test_srlz_sync_ignored_bit_decode = require_registers(
    "srlz_sync_ignored_bit_decode", [
        (0x10, 0x00, srlz_d(ignored36=1), adds(20, 1, 0),
         nop_i()),
        (0x20, 0x00, srlz_i(ignored36=1), adds(21, 2, 0),
         nop_i()),
        (0x30, 0x00, sync_i(ignored36=1), adds(22, 3, 0),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "exception": IA64_EXCP_NONE,
        "r20": 1,
        "r21": 2,
        "r22": 3,
    }, entry=0x10)

def test_srlz_i_without_pending_itlb_change_keeps_tb_cache(qemu):
    stats, output = run_program_jit(qemu, [
        (0x10, 0x10, nop_m(), srlz_i(),
         br_cond(0x10, 0x10)),
    ], entry=0x10)
    if stats.get("TB count", 0) < 1:
        raise AssertionError(f"missing translated TB:\n{output}")
    if stats.get("TB flush count") != 0:
        raise AssertionError(f"srlz.i caused TB flush:\n{output}")


def test_itlb_mapping_change_keeps_reusable_tb_cache(qemu):
    stats, output = run_program_jit(qemu, [
        (0x10, *movl_mlx(18, LOW_VECTOR_TR_PTE)),
        (0x20, *movl_mlx(19, 0x8000)),
        (0x30, 0x00, adds(7, LOW_VECTOR_ITIR, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(),
         nop_i()),
        (0x50, 0x00, mov_m_gr_cr(19, 20), nop_i(),
         nop_i()),
        (0x60, 0x00, itr_i(5, 18), nop_i(),
         nop_i()),
        (0x70, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
    ], entry=0x10)
    if stats.get("TB count", 0) < 1:
        raise AssertionError(f"missing translated TB:\n{output}")
    if stats.get("TB flush count") != 0:
        raise AssertionError(
            f"instruction mapping change discarded reusable TBs:\n{output}")


test_fwb_decode = require_registers("fwb_decode", [
    (0x10, 0x00, fwb(ignored36=1, ignored=0x73963), adds(23, 4, 0),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {
    "ip": 0x20,
    "exception": IA64_EXCP_NONE,
    "r23": 4,
}, entry=0x10)

test_mf_ignored_bit_decode = require_registers("mf_ignored_bit_decode", [
    (0x10, 0x00, mf(ignored36=1, ignored=0x150bd), adds(24, 5, 0),
     nop_i()),
    (0x20, 0x00, mf(advanced=True, ignored36=1, ignored=0x4a319),
     adds(25, 6, 0), nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {
    "ip": 0x30,
    "exception": IA64_EXCP_NONE,
    "r24": 5,
    "r25": 6,
}, entry=0x10)

_fc_patch_low, _fc_patch_high = bundle_words(
    0x11, nop_m(), adds(31, 2, 0), br_cond(0x100, 0x150)
)

test_fc_i_invalidates_translated_target = require_registers(
    "fc_i_invalidates_translated_target", [
        (0x10, 0x10, nop_m(), nop_i(),
         br_cond(0x10, 0x100)),
        (0x40, *movl_mlx(16, 0x100)),
        (0x50, *movl_mlx(17, _fc_patch_low)),
        (0x60, *movl_mlx(18, _fc_patch_high)),
        (0x70, 0x00, st8(16, 17), adds(19, 8, 16),
         nop_i()),
        (0x80, 0x00, st8(19, 18), nop_i(),
         nop_i()),
        (0x90, 0x10, fc_i(16), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, sync_i(), nop_i(),
         nop_i()),
        (0xb0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xc0, 0x10, nop_m(), nop_i(),
         br_cond(0xc0, 0x100)),
        (0x100, 0x11, nop_m(), adds(30, 1, 0),
         br_cond(0x100, 0x40)),
        (0x150, 0x10, nop_m(), nop_i(),
         br_cond(0x150, 0x150)),
    ], {
        "ip": 0x150,
        "exception": IA64_EXCP_NONE,
        "r30": 1,
        "r31": 2,
    }, entry=0x10)

_fc_line_patch_low, _fc_line_patch_high = bundle_words(
    0x11, nop_m(), adds(31, 2, 0), br_cond(0x120, 0x180)
)

test_fc_i_invalidates_translated_cache_line = require_registers(
    "fc_i_invalidates_translated_cache_line", [
        (0x10, 0x10, nop_m(), nop_i(),
         br_cond(0x10, 0x120)),
        (0x40, *movl_mlx(16, 0x120)),
        (0x50, *movl_mlx(17, _fc_line_patch_low)),
        (0x60, *movl_mlx(18, _fc_line_patch_high)),
        (0x70, *movl_mlx(20, 0x100)),
        (0x80, 0x00, cmp4_eq_imm(6, 7, 1, 30), nop_i(),
         br_cond(0x80, 0x190, qp=7)),
        (0x90, 0x00, st8(16, 17), adds(19, 8, 16),
         nop_i()),
        (0xa0, 0x00, st8(19, 18), nop_i(),
         nop_i()),
        (0xb0, 0x10, fc_i(20), nop_i(),
         br_cond(0xb0, 0xc0)),
        (0xc0, 0x00, sync_i(), nop_i(),
         nop_i()),
        (0xd0, 0x00, srlz_i(), nop_i(),
         nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(),
         br_cond(0xe0, 0x120)),
        (0x120, 0x11, nop_m(), adds(30, 1, 30),
         br_cond(0x120, 0x40)),
        (0x180, 0x10, nop_m(), nop_i(),
         br_cond(0x180, 0x180)),
        (0x190, 0x10, nop_m(), nop_i(),
         br_cond(0x190, 0x190)),
    ], {
        "ip": 0x180,
        "exception": IA64_EXCP_NONE,
        "r30": 1,
        "r31": 2,
    }, entry=0x10)

_pal_cache_flush_patch_low, _pal_cache_flush_patch_high = bundle_words(
    0x11, nop_m(), adds(21, 2, 0), br_cond(0x120, 0x180)
)

test_pal_cache_flush_invalidates_translated_target = require_registers(
    "pal_cache_flush_invalidates_translated_target", [
        (0x10, 0x10, nop_m(), nop_i(),
         br_cond(0x10, 0x120)),
        (0x40, *movl_mlx(16, 0x120)),
        (0x50, *movl_mlx(17, _pal_cache_flush_patch_low)),
        (0x60, *movl_mlx(18, _pal_cache_flush_patch_high)),
        (0x70, 0x00, st8(16, 17), adds(19, 8, 16),
         nop_i()),
        (0x80, 0x00, st8(19, 18), addl(28, PAL_CACHE_FLUSH, 0),
         nop_i()),
        (0x90, 0x00, nop_m(), addl(29, 4, 0),
         addl(30, 3, 0)),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_call(0, 0xa0, PAL_PROC_ENTRY)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0x120)),
        (0x120, 0x11, nop_m(), adds(20, 1, 20),
         br_cond(0x120, 0x40)),
        (0x180, 0x10, nop_m(), nop_i(),
         br_cond(0x180, 0x180)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {
        "ip": 0x180,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r20": 1,
        "r21": 2,
    }, entry=0x10)

test_shladdp4_decode = require_registers("shladdp4_decode", [
    (0x10, 0x00, addl(29, 3, 0), addl(28, 1, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), shladdp4(9, 29, 2, 0),
     shladd(10, 29, 4, 28)),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r9": 12, "r10": 49}, entry=0x10)

test_padd1_decode = require_registers("padd1_decode", [
    (0x10, 0x00, addl(3, 0x010203, 0), addl(4, 0x010101, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), padd1(5, 3, 4),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r5": 0x020304}, entry=0x10)

test_psub1_uuu_decode = require_registers("psub1_uuu_decode", [
    (0x10, *movl_mlx(3, 0x000102ff000102ff)),
    (0x20, *movl_mlx(4, 0x0101010101010101)),
    (0x30, 0x02, nop_m(), psub1_uuu(5, 3, 4),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r5": 0x000001fe000001fe}, entry=0x10)

test_pshladd2_decode = require_registers("pshladd2_decode", [
    (0x10, *movl_mlx(3, 0x7fff40000001ffff)),
    (0x20, *movl_mlx(4, 0x00010001ffff0001)),
    (0x30, 0x02, nop_m(), pshladd2(5, 3, 4, 4),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r5": 0x7fff7fff000ffff1}, entry=0x10)

test_pshradd2_decode = require_registers("pshradd2_decode", [
    (0x10, *movl_mlx(3, 0x80007fff0004fffc)),
    (0x20, *movl_mlx(4, 0x000100017fff8000)),
    (0x30, 0x02, nop_m(), pshradd2(5, 3, 1, 4),
     nop_i()),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r5": 0xc00140007fff8000}, entry=0x10)

test_shl_var_ignored_bit_decode = require_registers(
    "shl_var_ignored_bit_decode", [
        (0x10, 0x00, addl(8, 0x12, 0), addl(9, 4, 0),
         nop_i()),
        (0x20, 0x02, nop_m(), shl_var(10, 8, 9, ignored=1),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r10": 0x120}, entry=0x10)

test_mpy4_decode = require_registers("mpy4_decode", [
    (0x10, *movl_mlx(8, 0x00000000ffffffff)),
    (0x20, 0x00, nop_m(), addl(9, 2, 0),
     nop_i()),
    (0x30, 0x00, nop_m(), nop_i(),
     mpy4(10, 8, 9, ignored=1)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r10": 0x00000001fffffffe}, entry=0x10)

test_mpyshl4_decode = require_registers("mpyshl4_decode", [
    (0x10, *movl_mlx(8, 0x00000002000000ff)),
    (0x20, *movl_mlx(9, 0xffff000000000003)),
    (0x30, 0x00, nop_m(), nop_i(),
     mpyshl4(10, 8, 9, ignored=1)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r10": 0x0000000600000000}, entry=0x10)

test_pshr_decode = require_registers("pshr_decode", [
    (0x10, *movl_mlx(24, 0x800000007fffffff)),
    (0x20, *movl_mlx(25, 0x80017fff0001ffff)),
    (0x30, 0x00, addl(26, 4, 0), addl(27, 40, 0),
     nop_i()),
    (0x40, 0x00, nop_m(), pshr4(28, 24, 12, ignored=7),
     pshr4(29, 24, 27, unsigned=True, variable=True)),
    (0x50, 0x00, nop_m(), pshr2(30, 25, 26, variable=True),
     pshr2(31, 25, 16, unsigned=True, ignored=5)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r28": 0xfff800000007ffff,
    "r29": 0,
    "r30": 0xf80007ff0000ffff,
    "r31": 0,
}, entry=0x10)

test_pshl_decode = require_registers("pshl_decode", [
    (0x10, *movl_mlx(24, 0x0001000200030004)),
    (0x20, *movl_mlx(25, 0x0000000100000002)),
    (0x30, 0x00, addl(26, 4, 0), addl(27, 8, 0),
     nop_i()),
    (0x40, 0x00, nop_m(), pshl2(28, 24, 26, ignored=1),
     pshl4(29, 25, 27, ignored=1)),
    (0x50, 0x00, nop_m(), pshl2_fixed(30, 24, 16),
     pshl4_fixed(31, 24, 31)),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r28": 0x0010002000300040,
    "r29": 0x0000010000000200,
    "r30": 0,
    "r31": 0,
}, entry=0x10)

test_pshl_fixed_complement_count_decode = require_registers(
    "pshl_fixed_complement_count_decode", [
        (0x10, *movl_mlx(8, 0x0000000000000080)),
        (0x20, *movl_mlx(9, 0x0000000000000080)),
        (0x30, 0x01, nop_m(), pshl4_fixed(8, 8, 24),
         pshl2_fixed(9, 9, 8)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "r8": 0x0000000080000000,
        "r9": 0x0000000000008000,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_simd_helper_nat_propagates = require_registers("simd_helper_nat_propagates", [
    (0x10, 0x00, mov_m_imm_ar(36, 1), addl(4, 0x200, 0),
     nop_i()),
    (0x20, 0x08, ld8_fill_postinc(5, 4, 0), nop_i(),
     nop_i()),
    (0x30, *movl_mlx(6, 0x0001000200030004)),
    (0x40, 0x02, nop_m(), pmpy2(7, 5, 6),
     mux1_rev(8, 5)),
    (0x50, 0x02, nop_m(), czx1_r(9, 5),
     pack2_sss(10, 5, 6)),
    (0x60, 0x00, nop_m(), nop_i(), nop_i()),
    (0x70, 0x00, nop_m(), nop_i(), nop_i()),
    (0x80, 0x00, nop_m(), nop_i(), nop_i()),
    (0x90, 0x00, nop_m(), nop_i(), nop_i()),
    (0xa0, 0x10, nop_m(), nop_i(),
     br_cond(0xa0, 0xa0)),
    (0x200, 0x00, 0, 0,
     0),
], {
    "ip": 0xa0,
    "r7_nat": 1,
    "r8_nat": 1,
    "r9_nat": 1,
    "r10_nat": 1,
}, entry=0x10)

test_pshr_nat_propagates = require_registers("pshr_nat_propagates", [
    (0x10, 0x00, mov_m_imm_ar(36, 1), addl(4, 0x200, 0),
     nop_i()),
    (0x20, 0x08, ld8_fill_postinc(5, 4, 0), nop_i(),
     nop_i()),
    (0x30, 0x00, nop_m(), pshr4(6, 5, 1),
     pshr2(7, 0, 5, variable=True)),
    (0x40, 0x00, nop_m(), nop_i(), nop_i()),
    (0x50, 0x00, nop_m(), nop_i(), nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
    (0x200, 0x00, 0, 0,
     0),
], {
    "ip": 0x60,
    "r6_nat": 1,
    "r7_nat": 1,
}, entry=0x10)

test_pshl_nat_propagates = require_registers("pshl_nat_propagates", [
    (0x10, 0x00, mov_m_imm_ar(36, 1), addl(4, 0x200, 0),
     nop_i()),
    (0x20, 0x08, ld8_fill_postinc(5, 4, 0), nop_i(),
     nop_i()),
    (0x30, 0x00, addl(6, 4, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, nop_m(), pshl4(7, 5, 6),
     pshl2(8, 0, 5)),
    (0x50, 0x00, nop_m(), nop_i(), nop_i()),
    (0x60, 0x00, nop_m(), nop_i(), nop_i()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
    (0x200, 0x00, 0, 0,
     0),
], {
    "ip": 0x70,
    "r7_nat": 1,
    "r8_nat": 1,
}, entry=0x10)

test_addp4_decode = require_registers("addp4_decode", [
    (0x10, 0x00, addl(3, 0x5a4d, 0), addl(4, 0x1000, 0),
     nop_i()),
    (0x20, 0x02, nop_m(), addl(6, 3, 0),
     nop_i()),
    (0x30, 0x02, nop_m(), dep(4, 6, 4, 30, 2),
     nop_i()),
    (0x40, 0x02, nop_m(), addp4(5, 3, 4),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r5": 0x60000000c0006a4d}, entry=0x10)

test_addp4_imm_negative_decode = require_registers("addp4_imm_negative_decode", [
    (0x10, 0x02, nop_m(), addp4_imm(16, -1, 0),
     nop_i()),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {"ip": 0x20, "r16": 0xffffffff}, entry=0x10)

test_addp4_imm_a4_decode = require_registers("addp4_imm_a4_decode", [
    (0x10, 0x02, nop_m(), addp4_imm(24, -2048, 0),
     addp4_imm(14, -256, 0)),
    (0x20, 0x10, nop_m(), nop_i(),
     br_cond(0x20, 0x20)),
], {
    "ip": 0x20,
    "r24": 0xfffff800,
    "r14": 0xffffff00,
}, entry=0x10)

test_addp4_imm_positive_decode = require_registers(
    "addp4_imm_positive_decode", [
        (0x10, 0x02, nop_m(), addp4_imm(24, 1, 0), nop_i()),
        (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
    ], {
        "ip": 0x20,
        "r24": 1,
    }, entry=0x10)

test_cdboot_word_add_cloop_decode = require_registers(
    "cdboot_word_add_cloop_decode",
    [
        (0x10, 0x00, alloc(32, 8, 0, 0, 0), nop_i(),
         nop_i()),
        (0x20, *movl_mlx(32, 0x8000)),
        (0x30, *movl_mlx(33, 0x9000)),
        (0x40, *movl_mlx(34, 0xa000)),
        (0x50, *movl_mlx(16, 0xffffffff)),
        (0x60, *movl_mlx(17, 0x00000001)),
        (0x70, 0x08, st4_postinc(33, 16, 4),
         st4_postinc(34, 17, 4), nop_i()),
        (0x80, *movl_mlx(16, 0x00000000)),
        (0x90, *movl_mlx(17, 0xffffffff)),
        (0xa0, 0x08, st4_postinc(33, 16, 4),
         st4_postinc(34, 17, 4), nop_i()),
        (0xb0, *movl_mlx(16, 0xffffffff)),
        (0xc0, *movl_mlx(17, 0x00000001)),
        (0xd0, 0x08, st4_postinc(33, 16, 4),
         st4_postinc(34, 17, 4), nop_i()),
        (0xe0, *movl_mlx(16, 0x00000001)),
        (0xf0, *movl_mlx(17, 0x00000002)),
        (0x100, 0x08, st4_postinc(33, 16, 4),
         st4_postinc(34, 17, 4), nop_i()),
        (0x110, *movl_mlx(32, 0x8000)),
        (0x120, *movl_mlx(33, 0x9000)),
        (0x130, *movl_mlx(34, 0xa000)),
        (0x140, 0x00, nop_m(), adds(8, 0, 0),
         adds(35, 4, 0)),
        (0x150, 0x02, nop_m(), mov_lc_imm(7),
         nop_i()),
        (0x160, 0x00, nop_m(), cmp4_ltu_unc(0, 15, 0, 35),
         mov_i_ar_gr(26, 65)),
        (0x170, 0x10, nop_m(), addp4(31, 35, 0),
         br_cond(0x170, 0x300, qp=15)),
        (0x180, 0x00, nop_m(), adds(30, -1, 31),
         nop_i()),
        (0x190, 0x02, nop_m(), mov_lc_gr(30),
         nop_i()),
        (0x1a0, 0x08, ld4_postinc(31, 33, 4),
         ld4_postinc(30, 34, 4), addp4(29, 8, 0)),
        (0x1b0, 0x00, nop_m(), add(28, 30, 31),
         add(27, 28, 29)),
        (0x1c0, 0x10, st4_postinc(32, 27, 4),
         shr_u_imm(8, 27, 32), br_cloop(0x1c0, 0x1a0)),
        (0x1d0, 0x02, nop_m(), mov_lc_gr(26),
         nop_i()),
        (0x1e0, *movl_mlx(3, 0x8000)),
        (0x1f0, 0x08, ld4_postinc(10, 3, 4), nop_m(),
         nop_i()),
        (0x200, 0x08, ld4_postinc(11, 3, 4), nop_m(),
         nop_i()),
        (0x210, 0x08, ld4_postinc(12, 3, 4), nop_m(),
         nop_i()),
        (0x220, 0x08, ld4_postinc(13, 3, 4), nop_m(),
         mov_ar_lc(9)),
        (0x230, 0x10, nop_m(), nop_i(),
         br_cond(0x230, 0x230)),
        (0x300, 0x10, nop_m(), nop_i(),
         br_cond(0x300, 0x300)),
    ],
    {
        "ip": 0x230,
        "r8": 0,
        "r9": 7,
        "r10": 0,
        "r11": 0,
        "r12": 1,
        "r13": 4,
        "r32": 0x8010,
        "r33": 0x9010,
        "r34": 0xa010,
    },
    entry=0x10,
)

test_sync_i_ignored_fields_do_not_write_gr = require_registers(
    "sync_i_ignored_fields_do_not_write_gr", [
        (0x10, 0x00, nop_m(), adds(5, 0x55, 0), nop_i()),
        (0x20, 0x00, sync_i(ignored=5), nop_i(), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(), br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "r5": 0x55,
    }, entry=0x10)



# ── PAL tests ──

test_pal_version = require_registers("pal_version",
    pal_call_program(PAL_VERSION), {"ip": 0x30, "r28": PAL_VERSION, "r8": 0,
    "r9": PAL_VERSION_VALUE, "r10": PAL_VERSION_VALUE}, entry=0x10)

test_pal_version_reserved_arg = require_registers("pal_version_reserved_arg",
    pal_call_program(PAL_VERSION, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VERSION,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_rse_info = require_registers("pal_rse_info",
    pal_call_program(PAL_RSE_INFO),
    {"ip": 0x30, "r28": PAL_RSE_INFO, "r8": 0, "r9": 96, "r10": 16},
    entry=0x10)

test_pal_rse_info_reserved_arg = require_registers("pal_rse_info_reserved_arg",
    pal_call_program(PAL_RSE_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_RSE_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_vm_summary = require_registers("pal_vm_summary",
    pal_call_program(PAL_VM_SUMMARY),
    {"ip": 0x30, "r28": PAL_VM_SUMMARY, "r8": 0,
    "r9": PAL_VM_SUMMARY_INFO_1, "r10": PAL_VM_SUMMARY_INFO_2}, entry=0x10)

test_pal_vm_summary_reserved_arg = require_registers(
    "pal_vm_summary_reserved_arg",
    pal_call_program(PAL_VM_SUMMARY, [(29, 0), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_VM_SUMMARY,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_summary = require_registers("pal_cache_summary",
    pal_call_program(PAL_CACHE_SUMMARY),
    {"ip": 0x30, "r28": PAL_CACHE_SUMMARY, "r8": 0,
    "r9": 3, "r10": 5}, entry=0x10)

test_pal_cache_summary_madison = require_registers(
    "pal_cache_summary_madison",
    pal_call_program(PAL_CACHE_SUMMARY),
    {"ip": 0x30, "r28": PAL_CACHE_SUMMARY, "r8": 0,
     "r9": 3, "r10": 4}, entry=0x10, cpu="madison")

test_pal_cache_summary_reserved_arg = require_registers(
    "pal_cache_summary_reserved_arg",
    pal_call_program(PAL_CACHE_SUMMARY, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_SUMMARY,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_info = require_registers("pal_cache_info",
    pal_call_program(PAL_CACHE_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO, "r8": 0,
     "r9": PAL_CACHE_INFO_L0_I_1, "r10": PAL_CACHE_INFO_L0_2,
     "r11": 0}, entry=0x10)

test_pal_cache_info_l0_data = require_registers("pal_cache_info_l0_data",
    pal_call_program(PAL_CACHE_INFO, [(29, 0), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO, "r8": 0,
     "r9": PAL_CACHE_INFO_L0_D_1, "r10": PAL_CACHE_INFO_L0_2,
     "r11": 0}, entry=0x10)

test_pal_cache_info_l1_data = require_registers(
    "pal_cache_info_l1_data",
    pal_call_program(PAL_CACHE_INFO, [(29, 1), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO, "r8": 0,
     "r9": PAL_CACHE_INFO_L1_D_1, "r10": PAL_CACHE_INFO_L1_D_2,
     "r11": 0}, entry=0x10)

test_pal_cache_info_l1_instruction = require_registers(
    "pal_cache_info_l1_instruction",
    pal_call_program(PAL_CACHE_INFO, [(29, 1), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO, "r8": 0,
     "r9": PAL_CACHE_INFO_L1_I_1, "r10": PAL_CACHE_INFO_L1_I_2,
     "r11": 0}, entry=0x10)

test_pal_cache_info_l2_unified = require_registers(
    "pal_cache_info_l2_unified",
    pal_call_program(PAL_CACHE_INFO, [(29, 2), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO, "r8": 0,
     "r9": PAL_CACHE_INFO_L2_U_1, "r10": PAL_CACHE_INFO_L2_U_2,
     "r11": 0}, entry=0x10)

test_pal_cache_info_invalid = require_registers("pal_cache_info_invalid",
    pal_call_program(PAL_CACHE_INFO, [(29, 3), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_info_l2_unified_bad_type = require_registers(
    "pal_cache_info_l2_unified_bad_type",
    pal_call_program(PAL_CACHE_INFO, [(29, 2), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_freq_base = require_registers("pal_freq_base",
    pal_call_program(PAL_FREQ_BASE),
    {"ip": 0x30, "r28": PAL_FREQ_BASE, "r8": 0,
    "r9": 100000000, "r10": 0, "r11": 0}, entry=0x10)

test_pal_freq_base_reserved_arg = require_registers(
    "pal_freq_base_reserved_arg",
    pal_call_program(PAL_FREQ_BASE, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_FREQ_BASE,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_freq_ratios = require_registers("pal_freq_ratios",
    pal_call_program(PAL_FREQ_RATIOS),
    {"ip": 0x30, "r28": PAL_FREQ_RATIOS, "r8": 0,
    "r9": PAL_RATIO_16_1, "r10": PAL_RATIO_16_3,
    "r11": PAL_RATIO_2_1}, entry=0x10)

test_pal_freq_ratios_madison = require_registers(
    "pal_freq_ratios_madison", pal_call_program(PAL_FREQ_RATIOS),
    {"ip": 0x30, "r28": PAL_FREQ_RATIOS, "r8": 0,
     "r9": PAL_RATIO_16_1, "r10": PAL_RATIO_4_1,
     "r11": PAL_RATIO_2_1}, entry=0x10, cpu="madison")

test_pal_freq_ratios_reserved_arg = require_registers(
    "pal_freq_ratios_reserved_arg",
    pal_call_program(PAL_FREQ_RATIOS, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_FREQ_RATIOS,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

# --- Merced (original Itanium) model-differentiated PAL responses (P1.2) ---
# 800 MHz core / 133.33 MHz bus / 200 MHz ITC (249634-002 datasheet).
test_pal_freq_ratios_merced = require_registers(
    "pal_freq_ratios_merced", pal_call_program(PAL_FREQ_RATIOS),
    {"ip": 0x30, "r28": PAL_FREQ_RATIOS, "r8": 0,
     "r9": PAL_RATIO_8_1, "r10": PAL_RATIO_4_3,
     "r11": PAL_RATIO_2_1}, entry=0x10, cpu="merced")

# PAL_FREQ_BASE base clock is the same 100 MHz for merced.
test_pal_freq_base_merced = require_registers(
    "pal_freq_base_merced", pal_call_program(PAL_FREQ_BASE),
    {"ip": 0x30, "r28": PAL_FREQ_BASE, "r8": 0,
     "r9": 100000000, "r10": 0, "r11": 0}, entry=0x10, cpu="merced")

# PAL_VM_SUMMARY reports the asymmetric 8 ITR / 48 DTR file.
test_pal_vm_summary_merced = require_registers(
    "pal_vm_summary_merced", pal_call_program(PAL_VM_SUMMARY),
    {"ip": 0x30, "r28": PAL_VM_SUMMARY, "r8": 0,
     "r9": PAL_VM_SUMMARY_INFO_1_MERCED, "r10": PAL_VM_SUMMARY_INFO_2},
    entry=0x10, cpu="merced")

# Procedures that post-date Merced return NOT_IMPLEMENTED on the merced model.
test_pal_prefetch_vis_merced_unimplemented = require_registers(
    "pal_prefetch_vis_merced_unimplemented",
    pal_call_program(PAL_PREFETCH_VIS),
    {"ip": 0x30, "r28": PAL_PREFETCH_VIS,
     "r8": (-1 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="merced")

test_pal_cache_shared_info_merced_unimplemented = require_registers(
    "pal_cache_shared_info_merced_unimplemented",
    pal_call_program(PAL_CACHE_SHARED_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_SHARED_INFO,
     "r8": (-1 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="merced")

test_pal_brand_info_merced_unimplemented = require_registers(
    "pal_brand_info_merced_unimplemented",
    pal_stacked_call_program(PAL_BRAND_INFO, [18, 0, 0]),
    {"ip": 0x80, "r28": PAL_BRAND_INFO,
     "r8": (-1 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="merced")

# logical_to_physical is already montecito-only; confirm merced too is
# NOT_IMPLEMENTED (mirrors pal_logical_to_physical_madison_unimplemented).
test_pal_logical_to_physical_merced_unimplemented = require_registers(
    "pal_logical_to_physical_merced_unimplemented",
    pal_call_program(PAL_LOGICAL_TO_PHYSICAL,
                     [(29, 0xffffffffffffffff), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_LOGICAL_TO_PHYSICAL,
     "r8": (-1 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="merced")

# Regression: a PAL procedure returns its status in GR8; on hardware that
# register write clears the NaT bit.  r8-r11 are PAL *output* registers, so a
# caller may leave one NaT before the call -- the result must not come back NaT.
# (XP's SETUPLDR wedged on exactly this: a `st8 [r30]=r8` of the still-NaT PAL
# status raised NaT Consumption.)  Here r8 is forced NaT with an ld8.fill under
# ar.unat, then PAL_VERSION is called; r8 must be non-NaT afterwards.
test_pal_call_clears_return_reg_nat = require_registers(
    "pal_call_clears_return_reg_nat", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0), nop_i()),
        (0x20, 0x08, ld8_fill_postinc(8, 6, 0), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), addl(28, PAL_VERSION, 0), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_call(0, 0x40, PAL_PROC_ENTRY)),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
        (0x200, 0x00, 0, 0, 0),
    ], {
        "ip": 0x50,
        "r8": 0,
        "r8_nat": 0,
        "r9": PAL_VERSION_VALUE,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

# CPUID identity on merced: CPUID[3] = family 0x07, model 0, rev 8 (C2 stepping)
# = 0x0000000007000804 (249720-009); CPUID[4] = 0, i.e. brl NOT implemented
# (245319-002 brl page) -- the bit Windows keys KF_BRL off.
test_cpuid_merced = require_registers(
    "cpuid_merced", [
        (0x10, 0x00, nop_m(), addl(31, 3, 0), nop_i()),
        (0x20, 0x00, mov_cpuid(29, 31), nop_i(), nop_i()),
        (0x30, 0x00, nop_m(), addl(30, 4, 0), nop_i()),
        (0x40, 0x00, mov_cpuid(28, 30), nop_i(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "r29": 0x0000000007000804,
        "r28": 0x0000000000000000,
    }, entry=0x10, cpu="merced")

test_pal_vm_page_size = require_registers("pal_vm_page_size",
    pal_call_program(PAL_VM_PAGE_SIZE),
    {"ip": 0x30, "r28": PAL_VM_PAGE_SIZE, "r8": 0,
    "r9": PAL_INSERTABLE_PAGE_SIZE_MASK, "r10": PAL_PURGE_PAGE_SIZE_MASK},
    entry=0x10)

test_pal_vm_page_size_reserved_arg = require_registers(
    "pal_vm_page_size_reserved_arg",
    pal_call_program(PAL_VM_PAGE_SIZE, [(29, 0), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_VM_PAGE_SIZE,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_ptce_info = require_registers("pal_ptce_info",
    pal_call_program(PAL_PTCE_INFO),
    {"ip": 0x30, "r28": PAL_PTCE_INFO, "r8": 0,
     "r9": 0, "r10": (1 << 32) | 1,
     "r11": 0}, entry=0x10)

test_pal_ptce_info_reserved_arg = require_registers(
    "pal_ptce_info_reserved_arg",
    pal_call_program(PAL_PTCE_INFO, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PTCE_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_vm_info = require_registers("pal_vm_info",
    pal_call_program(PAL_VM_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO, "r8": 0,
     "r9": PAL_VM_INFO_L0, "r10": 1 << 12,
     "r11": 0}, entry=0x10)

test_pal_vm_info_l0_data = require_registers("pal_vm_info_l0_data",
    pal_call_program(PAL_VM_INFO, [(29, 0), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO, "r8": 0,
     "r9": PAL_VM_INFO_L0, "r10": 1 << 12,
     "r11": 0}, entry=0x10)

test_pal_vm_info_l1_data = require_registers("pal_vm_info_l1_data",
    pal_call_program(PAL_VM_INFO, [(29, 1), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO, "r8": 0,
     "r9": PAL_VM_INFO_L1, "r10": PAL_INSERTABLE_PAGE_SIZE_MASK,
     "r11": 0}, entry=0x10)

test_pal_vm_info_l1_instruction = require_registers(
    "pal_vm_info_l1_instruction",
    pal_call_program(PAL_VM_INFO, [(29, 1), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO, "r8": 0,
     "r9": PAL_VM_INFO_L1, "r10": PAL_INSERTABLE_PAGE_SIZE_MASK,
     "r11": 0}, entry=0x10)

test_pal_vm_info_l2_invalid = require_registers("pal_vm_info_l2_invalid",
    pal_call_program(PAL_VM_INFO, [(29, 2), (30, 2), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO,
     "r8": -2 & 0xffffffffffffffff, "r9": 0, "r10": 0,
     "r11": 0}, entry=0x10)

test_pal_vm_info_invalid = require_registers("pal_vm_info_invalid",
    pal_call_program(PAL_VM_INFO, [(29, 0), (30, 4), (31, 0)]),
    {"ip": 0x60, "r28": PAL_VM_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_vm_tr_read_dtr = require_registers("pal_vm_tr_read_dtr", [
    (0x10, *movl_mlx(18, PAL_TR_TEST_PTE)),
    (0x20, 0x00, nop_m(), addl(19, PAL_TR_TEST_IFA & ~0xfff, 0),
     nop_i()),
    (0x30, 0x00, nop_m(), addl(7, PAL_TR_TEST_ITIR, 0), addl(5, 5, 0)),
    (0x40, 0x00, mov_m_gr_cr(19, 20), nop_i(), nop_i()),
    (0x50, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
    (0x60, 0x00, itr_d(5, 18), nop_i(), nop_i()),
    (0x70, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
    (0x80, *movl_mlx(28, PAL_VM_TR_READ)),
    (0x90, *movl_mlx(32, PAL_VM_TR_READ)),
    (0xa0, 0x00, nop_m(), addl(33, 5, 0), addl(34, 1, 0)),
    (0xb0, 0x00, nop_m(), addl(35, 0x2000, 0), nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(), br_call(0, 0xc0, PAL_PROC_ENTRY)),
    (0xd0, 0x00, nop_m(), addl(2, 0x2000, 0), nop_i()),
    (0xe0, 0x00, ld8(20, 2), adds(2, 8, 2), nop_i()),
    (0xf0, 0x00, ld8(21, 2), adds(2, 8, 2), nop_i()),
    (0x100, 0x00, ld8(22, 2), adds(2, 8, 2), nop_i()),
    (0x110, 0x00, ld8(23, 2), nop_i(), nop_i()),
    (0x120, 0x10, nop_m(), nop_i(), br_cond(0x120, 0x120)),
    (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
    (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
], {"ip": 0x120, "r28": PAL_VM_TR_READ, "r8": 0,
    "r9": PAL_TR_VALID_ALL, "r10": 0, "r11": 0,
    "r20": PAL_TR_TEST_PTE, "r21": PAL_TR_TEST_ITIR,
    "r22": PAL_TR_TEST_IFA, "r23": PAL_TR_TEST_ITIR}, entry=0x10)

test_pal_vm_tr_read_max_dtr = require_registers("pal_vm_tr_read_max_dtr", [
        (0x10, *movl_mlx(18, PAL_TR_TEST_PTE)),
        (0x20, 0x00, nop_m(), addl(19, PAL_TR_TEST_IFA & ~0xfff, 0),
         nop_i()),
        (0x30, 0x00, mov_m_gr_cr(19, 20),
         addl(5, IA64_TR_COUNT - 1, 0), addl(7, PAL_TR_TEST_ITIR, 0)),
        (0x40, 0x00, mov_m_gr_cr(7, 21), nop_i(), nop_i()),
        (0x50, 0x00, itr_d(5, 18), nop_i(), nop_i()),
        (0x60, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
        (0x70, *movl_mlx(28, PAL_VM_TR_READ)),
        (0x80, *movl_mlx(32, PAL_VM_TR_READ)),
        (0x90, 0x00, nop_m(),
         addl(33, IA64_TR_COUNT - 1, 0), addl(34, 1, 0)),
        (0xa0, 0x00, nop_m(), addl(35, 0x2000, 0), nop_i()),
        (0xb0, 0x10, nop_m(), nop_i(), br_call(0, 0xb0, PAL_PROC_ENTRY)),
        (0xc0, 0x00, nop_m(), addl(2, 0x2000, 0), nop_i()),
        (0xd0, 0x00, ld8(20, 2), adds(2, 8, 2), nop_i()),
        (0xe0, 0x00, ld8(21, 2), adds(2, 8, 2), nop_i()),
        (0xf0, 0x00, ld8(22, 2), adds(2, 8, 2), nop_i()),
        (0x100, 0x00, ld8(23, 2), nop_i(), nop_i()),
        (0x110, 0x10, nop_m(), nop_i(), br_cond(0x110, 0x110)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {"ip": 0x110, "r28": PAL_VM_TR_READ, "r8": 0,
        "r9": PAL_TR_VALID_ALL, "r10": 0, "r11": 0,
        "r20": PAL_TR_TEST_PTE, "r21": PAL_TR_TEST_ITIR,
        "r22": PAL_TR_TEST_IFA, "r23": PAL_TR_TEST_ITIR}, entry=0x10)

test_pal_vm_tr_read_empty = require_registers("pal_vm_tr_read_empty",
    pal_stacked_call_program(PAL_VM_TR_READ, [4, 1, 0x2000]),
    {"ip": 0x80, "r28": PAL_VM_TR_READ, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_vm_tr_read_rejects_first_non_tr = require_registers(
    "pal_vm_tr_read_rejects_first_non_tr",
    pal_stacked_call_program(PAL_VM_TR_READ, [IA64_TR_COUNT, 1, 0x2000]),
    {"ip": 0x80, "r28": PAL_VM_TR_READ,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_vm_tr_read_invalid = require_registers("pal_vm_tr_read_invalid",
    pal_stacked_call_program(PAL_VM_TR_READ, [0, 2, 0x2000]),
    {"ip": 0x80, "r28": PAL_VM_TR_READ,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_vm_tr_read_misaligned_buffer = require_registers(
    "pal_vm_tr_read_misaligned_buffer",
    pal_stacked_call_program(PAL_VM_TR_READ, [0, 1, 0x2004]),
    {"ip": 0x80, "r28": PAL_VM_TR_READ,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_proc_entry_virtual_itr = require_registers(
    "pal_proc_entry_virtual_itr", [
        (0x10, *movl_mlx(18, PAL_VIRTUAL_CODE_PTE)),
        (0x20, *movl_mlx(22, PAL_VIRTUAL_PROC_PTE)),
        (0x30, *movl_mlx(20, PAL_VIRTUAL_CODE_BASE)),
        (0x40, *movl_mlx(21, PAL_VIRTUAL_PROC_BASE)),
        (0x50, *movl_mlx(25, PAL_VIRTUAL_RR)),
        (0x60, 0x00, mov_rr_write(25, 21), nop_i(), nop_i()),
        (0x70, 0x00, srlz_i(), nop_i(), nop_i()),
        (0x80, 0x00, mov_m_gr_cr(20, 20), adds(7, PAL_VIRTUAL_ITIR, 0),
         nop_i()),
        (0x90, 0x00, mov_m_gr_cr(7, 21), adds(5, 5, 0), nop_i()),
        (0xa0, 0x00, itr_i(5, 18), nop_i(), nop_i()),
        (0xb0, 0x00, mov_m_gr_cr(21, 20), adds(6, 6, 0), nop_i()),
        (0xc0, 0x00, itr_i(6, 22), nop_i(), nop_i()),
        (0xd0, *movl_mlx(23, PAL_VIRTUAL_CODE_ENTRY)),
        (0xe0, *movl_mlx(24, PAL_VIRTUAL_PROC_ENTRY)),
        (0xf0, *movl_mlx(19, PAL_VIRTUAL_PSR)),
        (0x100, 0x00, nop_m(), mov_b_gr(7, 23), nop_i()),
        *rfi_to_gr(0x110, 19, 23),
        (PAL_VIRTUAL_CODE_ENTRY_PA, *movl_mlx(28, PAL_VERSION)),
        (PAL_VIRTUAL_CODE_ENTRY_PA + 0x10, 0x00, nop_m(), mov_b_gr(7, 24),
         nop_i()),
        (PAL_VIRTUAL_CODE_ENTRY_PA + 0x20, 0x10, nop_m(), nop_i(),
         br_call_indirect(0, 7)),
        (PAL_VIRTUAL_CODE_ENTRY_PA + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(PAL_VIRTUAL_CODE_ENTRY + 0x30,
                 PAL_VIRTUAL_CODE_ENTRY + 0x30)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {
        "ip": PAL_VIRTUAL_CODE_ENTRY + 0x30,
        "r28": PAL_VERSION,
        "r8": 0,
        "r9": PAL_VERSION_VALUE,
        "r10": PAL_VERSION_VALUE,
        "r11": 0,
    }, entry=0x10)

test_pal_prefetch_vis = require_registers("pal_prefetch_vis",
    pal_call_program(PAL_PREFETCH_VIS),
    {"ip": 0x30, "r28": PAL_PREFETCH_VIS, "r8": 0,
     "r9": ((1 << 0) | (1 << 1)), "r10": 0}, entry=0x10)

test_pal_prefetch_vis_reserved_arg = require_registers(
    "pal_prefetch_vis_reserved_arg",
    pal_call_program(PAL_PREFETCH_VIS, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PREFETCH_VIS,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_flush = require_registers("pal_cache_flush",
    pal_call_program(PAL_CACHE_FLUSH, [(29, 3), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_FLUSH, "r8": 0, "r9": 0, "r10": 0},
    entry=0x10)

test_pal_cache_flush_coherent_icache = require_registers(
    "pal_cache_flush_coherent_icache",
    pal_call_program(PAL_CACHE_FLUSH, [(29, 4), (30, 3), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_FLUSH, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_cache_flush_bad_type = require_registers(
    "pal_cache_flush_bad_type",
    pal_call_program(PAL_CACHE_FLUSH, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_FLUSH,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_flush_bad_operation = require_registers(
    "pal_cache_flush_bad_operation",
    pal_call_program(PAL_CACHE_FLUSH, [(29, 3), (30, 4), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_FLUSH,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_init = require_registers("pal_cache_init",
    pal_call_program(PAL_CACHE_INIT, [(29, 0), (30, 3), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_INIT, "r8": 0, "r9": 0, "r10": 0,
     "r11": 0}, entry=0x10)

test_pal_cache_init_invalid = require_registers("pal_cache_init_invalid",
    pal_call_program(PAL_CACHE_INIT, [(29, 0), (30, 3), (31, 2)]),
    {"ip": 0x60, "r28": PAL_CACHE_INIT,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_prot_info = require_registers("pal_cache_prot_info",
    pal_call_program(PAL_CACHE_PROT_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_PROT_INFO, "r8": 0,
     "r9": PAL_CACHE_PROT_DATA_NONE | (PAL_CACHE_PROT_TAG_NONE_L0 << 32),
     "r10": 0, "r11": 0}, entry=0x10)

test_pal_cache_prot_info_invalid = require_registers(
    "pal_cache_prot_info_invalid",
    pal_call_program(PAL_CACHE_PROT_INFO, [(29, 0), (30, 3), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_PROT_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_cache_prot_info_unified_bad_type = require_registers(
    "pal_cache_prot_info_unified_bad_type",
    pal_call_program(PAL_CACHE_PROT_INFO, [(29, 2), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_PROT_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mem_attrib = require_registers("pal_mem_attrib",
    pal_call_program(PAL_MEM_ATTRIB),
    {"ip": 0x30, "r28": PAL_MEM_ATTRIB, "r8": 0,
     "r9": PAL_MEM_ATTRIB_WB_UC, "r10": 0, "r11": 0}, entry=0x10)

test_pal_mem_attrib_reserved_arg = require_registers(
    "pal_mem_attrib_reserved_arg",
    pal_call_program(PAL_MEM_ATTRIB, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MEM_ATTRIB,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_bus_get_features = require_registers("pal_bus_get_features",
    pal_call_program(PAL_BUS_GET_FEATURES),
    {"ip": 0x30, "r28": PAL_BUS_GET_FEATURES, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_bus_get_features_reserved_arg = require_registers(
    "pal_bus_get_features_reserved_arg",
    pal_call_program(PAL_BUS_GET_FEATURES, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_BUS_GET_FEATURES,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_bus_set_features = require_registers("pal_bus_set_features",
    pal_call_program(PAL_BUS_SET_FEATURES, [(29, 0x1234), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_BUS_SET_FEATURES, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_bus_set_features_invalid = require_registers(
    "pal_bus_set_features_invalid",
    pal_call_program(PAL_BUS_SET_FEATURES, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_BUS_SET_FEATURES,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_proc_set_features = require_registers("pal_proc_set_features",
    pal_call_program(PAL_PROC_SET_FEATURES, [(29, 0x55), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PROC_SET_FEATURES, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_proc_set_features_invalid = require_registers(
    "pal_proc_set_features_invalid",
    pal_call_program(PAL_PROC_SET_FEATURES, [(29, 0), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_PROC_SET_FEATURES,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_proc_get_features = require_registers("pal_proc_get_features",
    pal_call_program(PAL_PROC_GET_FEATURES),
    {"ip": 0x30, "r28": PAL_PROC_GET_FEATURES, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_proc_get_features_reserved_arg = require_registers(
    "pal_proc_get_features_reserved_arg",
    pal_call_program(PAL_PROC_GET_FEATURES, [(29, 0), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_PROC_GET_FEATURES,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_proc_get_features_montecito_next_set = require_registers(
    "pal_proc_get_features_montecito_next_set",
    pal_call_program(PAL_PROC_GET_FEATURES, [(29, 0), (30, 16), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PROC_GET_FEATURES,
     "r8": 1, "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_proc_get_features_montecito_set18 = require_registers(
    "pal_proc_get_features_montecito_set18",
    pal_call_program(PAL_PROC_GET_FEATURES, [(29, 0), (30, 18), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PROC_GET_FEATURES,
     "r8": 0, "r9": 1 << 18, "r10": 1 << 18, "r11": 0}, entry=0x10)

test_pal_proc_get_features_montecito_beyond_max = require_registers(
    "pal_proc_get_features_montecito_beyond_max",
    pal_call_program(PAL_PROC_GET_FEATURES, [(29, 0), (30, 19), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PROC_GET_FEATURES,
     "r8": (-8 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_proc_get_features_madison_beyond_max = require_registers(
    "pal_proc_get_features_madison_beyond_max",
    pal_call_program(PAL_PROC_GET_FEATURES, [(29, 0), (30, 16), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PROC_GET_FEATURES,
     "r8": (-8 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="madison")

test_pal_logical_to_physical_current = require_registers(
    "pal_logical_to_physical_current",
    pal_call_program(PAL_LOGICAL_TO_PHYSICAL,
                     [(29, 0xffffffffffffffff), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_LOGICAL_TO_PHYSICAL, "r8": 0,
     "r9": 1 | (1 << 16) | (1 << 32), "r10": 0, "r11": 0},
    entry=0x10)

test_pal_logical_to_physical_multicore_thread = require_registers(
    "pal_logical_to_physical_multicore_thread",
    pal_call_program(PAL_LOGICAL_TO_PHYSICAL,
                     [(29, 3), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_LOGICAL_TO_PHYSICAL, "r8": 0,
     "r9": 4 | (2 << 16) | (2 << 32),
     "r10": 1 | (1 << 32), "r11": 3},
    entry=0x10, alat=None, smp="4,sockets=1,cores=2,threads=2")

test_pal_logical_to_physical_madison_unimplemented = require_registers(
    "pal_logical_to_physical_madison_unimplemented",
    pal_call_program(PAL_LOGICAL_TO_PHYSICAL,
                     [(29, 0xffffffffffffffff), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_LOGICAL_TO_PHYSICAL,
     "r8": (-1 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10, cpu="madison")

test_pal_cache_shared_info_single_thread = require_registers(
    "pal_cache_shared_info_single_thread",
    pal_call_program(PAL_CACHE_SHARED_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_SHARED_INFO, "r8": 0,
     "r9": 1, "r10": 0, "r11": 0}, entry=0x10)

test_pal_cache_shared_info_sibling_thread = require_registers(
    "pal_cache_shared_info_sibling_thread",
    pal_call_program(PAL_CACHE_SHARED_INFO, [(29, 2), (30, 2), (31, 1)]),
    {"ip": 0x60, "r28": PAL_CACHE_SHARED_INFO, "r8": 0,
     "r9": 2, "r10": 1, "r11": 1},
    entry=0x10, alat=None, smp="4,sockets=1,cores=2,threads=2")

test_pal_brand_info_string = require_registers(
    "pal_brand_info_string", [
        (0x10, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
        (0x20, *movl_mlx(28, PAL_BRAND_INFO)),
        (0x30, *movl_mlx(32, PAL_BRAND_INFO)),
        (0x40, *movl_mlx(33, 0)),
        (0x50, *movl_mlx(34, PAL_BRAND_BUFFER)),
        (0x60, *movl_mlx(35, 0)),
        (0x70, 0x10, nop_m(), nop_i(), br_call(0, 0x70, PAL_PROC_ENTRY)),
        (0x80, *movl_mlx(2, PAL_BRAND_BUFFER)),
        (0x90, 0x00, ld8(20, 2), nop_i(), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(), br_cond(0xa0, 0xa0)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {"ip": 0xa0, "r28": PAL_BRAND_INFO, "r8": 0,
        "r9": len("QEMU Montecito-compatible IA-64 CPU 1.60GHz 24MB"),
        "r10": 0, "r11": 0,
        "r20": int.from_bytes(b"QEMU Mon", "little")}, entry=0x10)

test_pal_brand_info_frequency = require_registers(
    "pal_brand_info_frequency",
    pal_stacked_call_program(PAL_BRAND_INFO, [16, 0, 0]),
    {"ip": 0x80, "r28": PAL_BRAND_INFO, "r8": 0,
     "r9": 1600000000, "r10": 0, "r11": 0}, entry=0x10)

test_pal_brand_info_cache = require_registers(
    "pal_brand_info_cache",
    pal_stacked_call_program(PAL_BRAND_INFO, [17, 0, 0]),
    {"ip": 0x80, "r28": PAL_BRAND_INFO, "r8": 0,
     "r9": 24 * 1024 * 1024, "r10": 0, "r11": 0}, entry=0x10)

test_pal_brand_info_bus = require_registers(
    "pal_brand_info_bus",
    pal_stacked_call_program(PAL_BRAND_INFO, [18, 0, 0]),
    {"ip": 0x80, "r28": PAL_BRAND_INFO, "r8": 0,
     "r9": 533333333, "r10": 0, "r11": 0}, entry=0x10)

test_pal_debug_info = require_registers("pal_debug_info",
    pal_call_program(PAL_DEBUG_INFO),
    {"ip": 0x30, "r28": PAL_DEBUG_INFO, "r8": 0,
     "r9": 4, "r10": 4, "r11": 0}, entry=0x10)

test_pal_debug_info_reserved_arg = require_registers(
    "pal_debug_info_reserved_arg",
    pal_call_program(PAL_DEBUG_INFO, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_DEBUG_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_register_info_application_implemented = require_registers(
    "pal_register_info_application_implemented",
    pal_call_program(PAL_REGISTER_INFO, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO, "r8": 0,
     "r9": PAL_AR_IMPLEMENTED_LOW, "r10": PAL_AR_IMPLEMENTED_HIGH,
     "r11": 0}, entry=0x10)

test_pal_register_info_application_side_effects = require_registers(
    "pal_register_info_application_side_effects",
    pal_call_program(PAL_REGISTER_INFO, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_register_info_control_implemented = require_registers(
    "pal_register_info_control_implemented",
    pal_call_program(PAL_REGISTER_INFO, [(29, 2), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO, "r8": 0,
     "r9": PAL_CR_IMPLEMENTED_LOW, "r10": PAL_CR_IMPLEMENTED_HIGH,
     "r11": 0}, entry=0x10)

test_pal_register_info_control_side_effects = require_registers(
    "pal_register_info_control_side_effects",
    pal_call_program(PAL_REGISTER_INFO, [(29, 3), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO, "r8": 0,
     "r9": 0, "r10": PAL_CR_READ_SIDE_EFFECT_HIGH, "r11": 0},
    entry=0x10)

test_pal_register_info_invalid_request = require_registers(
    "pal_register_info_invalid_request",
    pal_call_program(PAL_REGISTER_INFO, [(29, 4), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_register_info_reserved_arg = require_registers(
    "pal_register_info_reserved_arg",
    pal_call_program(PAL_REGISTER_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_REGISTER_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_perf_mon_info = require_registers("pal_perf_mon_info", [
    (0x10, *movl_mlx(29, PAL_PERF_BUFFER)),
    (0x20, 0x00, nop_m(), addl(30, 0, 0), addl(31, 0, 0)),
    (0x30, 0x00, nop_m(), addl(28, PAL_PERF_MON_INFO, 0), nop_i()),
    (0x40, 0x10, nop_m(), nop_i(), br_call(0, 0x40, PAL_PROC_ENTRY)),
    (0x50, *movl_mlx(2, PAL_PERF_BUFFER)),
    (0x60, 0x00, ld8(20, 2), adds(2, 8, 2), nop_i()),
    (0x70, 0x00, ld8(21, 2), adds(2, 0x18, 2), nop_i()),
    (0x80, 0x00, ld8(22, 2), adds(2, 8, 2), nop_i()),
    (0x90, 0x00, ld8(23, 2), adds(2, 0x18, 2), nop_i()),
    (0xa0, 0x00, ld8(24, 2), adds(2, 0x20, 2), nop_i()),
    (0xb0, 0x00, ld8(25, 2), nop_i(), nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(), br_cond(0xc0, 0xc0)),
    (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
    (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
], {"ip": 0xc0, "r28": PAL_PERF_MON_INFO, "r8": 0,
    "r9": 0x08123004, "r10": 0, "r11": 0,
    "r20": 0x3fff, "r21": 0, "r22": 0x3ffff, "r23": 0,
    "r24": 0xf0, "r25": 0xf0},
    entry=0x10)

test_pal_perf_mon_info_bad_buffer = require_registers(
    "pal_perf_mon_info_bad_buffer",
    pal_call_program(PAL_PERF_MON_INFO,
                     [(29, PAL_PERF_BUFFER + 4), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PERF_MON_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_perf_mon_info_reserved_arg = require_registers(
    "pal_perf_mon_info_reserved_arg",
    pal_call_program(PAL_PERF_MON_INFO,
                     [(29, PAL_PERF_BUFFER), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PERF_MON_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_fixed_addr = require_registers("pal_fixed_addr",
    pal_call_program(PAL_FIXED_ADDR),
    {"ip": 0x30, "r28": PAL_FIXED_ADDR, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_fixed_addr_reserved_arg = require_registers(
    "pal_fixed_addr_reserved_arg",
    pal_call_program(PAL_FIXED_ADDR, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_FIXED_ADDR,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_platform_addr_interrupt = require_registers(
    "pal_platform_addr_interrupt",
    pal_call_program(PAL_PLATFORM_ADDR,
                     [(29, PAL_PLATFORM_INTERRUPT_BLOCK),
                      (30, PAL_INTERRUPT_BLOCK_DEFAULT), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PLATFORM_ADDR, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_platform_addr_ignores_bit63 = require_registers(
    "pal_platform_addr_ignores_bit63",
    pal_call_program(PAL_PLATFORM_ADDR,
                     [(29, PAL_PLATFORM_INTERRUPT_BLOCK),
                      (30, PAL_INTERRUPT_BLOCK_DEFAULT | (1 << 63)),
                      (31, 0)]),
    {"ip": 0x60, "r28": PAL_PLATFORM_ADDR, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_platform_addr_io = require_registers(
    "pal_platform_addr_io",
    pal_call_program(PAL_PLATFORM_ADDR,
                     [(29, PAL_PLATFORM_IO_BLOCK),
                      (30, PAL_IO_BLOCK_DEFAULT), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PLATFORM_ADDR, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_platform_addr_bad_type = require_registers(
    "pal_platform_addr_bad_type",
    pal_call_program(PAL_PLATFORM_ADDR,
                     [(29, 2), (30, PAL_INTERRUPT_BLOCK_DEFAULT), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PLATFORM_ADDR,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_platform_addr_unmapped = require_registers(
    "pal_platform_addr_unmapped",
    pal_call_program(PAL_PLATFORM_ADDR,
                     [(29, PAL_PLATFORM_INTERRUPT_BLOCK),
                      (30, 0x200000), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PLATFORM_ADDR,
     "r8": (-3 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_clear_log = require_registers("pal_mc_clear_log",
    pal_call_program(PAL_MC_CLEAR_LOG, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_CLEAR_LOG, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_copy_info = require_registers("pal_copy_info",
    pal_call_program(PAL_COPY_INFO, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_COPY_INFO, "r8": 0,
     "r9": PAL_COPY_BUFFER_SIZE, "r10": PAL_COPY_BUFFER_ALIGN, "r11": 0},
    entry=0x10)

test_pal_copy_info_bad_type = require_registers("pal_copy_info_bad_type",
    pal_call_program(PAL_COPY_INFO, [(29, 2), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_COPY_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_copy_info_ia32_unsupported = require_registers(
    "pal_copy_info_ia32_unsupported",
    pal_call_program(PAL_COPY_INFO, [(29, 1), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_COPY_INFO,
     "r8": (-3 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_copy_info_platform_for_ia64 = require_registers(
    "pal_copy_info_platform_for_ia64",
    pal_call_program(PAL_COPY_INFO, [(29, 0), (30, 1), (31, 0)]),
    {"ip": 0x60, "r28": PAL_COPY_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_copy_pal_entry_callable = require_registers(
    "pal_copy_pal_entry_callable", [
        (0x10, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
        (0x20, *movl_mlx(28, PAL_COPY_PAL)),
        (0x30, *movl_mlx(32, PAL_COPY_PAL)),
        (0x40, *movl_mlx(33, PAL_COPY_TARGET | (1 << 63))),
        (0x50, *movl_mlx(34, PAL_COPY_BUFFER_SIZE)),
        (0x60, *movl_mlx(35, 0)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, PAL_PROC_ENTRY)),
        (0x80, *movl_mlx(28, PAL_VERSION)),
        (0x90, 0x00, nop_m(), addl(29, 0, 0), addl(30, 0, 0)),
        (0xa0, 0x10, nop_m(), addl(31, 0, 0),
         br_call(0, 0xa0, PAL_COPY_TARGET)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ],
    {"ip": 0xb0, "r28": PAL_VERSION, "r8": 0,
     "r9": PAL_VERSION_VALUE, "r10": PAL_VERSION_VALUE, "r11": 0},
    entry=0x10)

test_pal_copy_pal_ap_entry_callable = require_registers(
    "pal_copy_pal_ap_entry_callable", [
        (0x10, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
        (0x20, *movl_mlx(28, PAL_COPY_PAL)),
        (0x30, *movl_mlx(32, PAL_COPY_PAL)),
        (0x40, *movl_mlx(33, PAL_COPY_TARGET | (1 << 63))),
        (0x50, *movl_mlx(34, PAL_COPY_BUFFER_SIZE)),
        (0x60, *movl_mlx(35, 1)),
        (0x70, 0x10, nop_m(), nop_i(),
         br_call(0, 0x70, PAL_PROC_ENTRY)),
        (0x80, *movl_mlx(28, PAL_VERSION)),
        (0x90, 0x00, nop_m(), addl(29, 0, 0), addl(30, 0, 0)),
        (0xa0, 0x10, nop_m(), addl(31, 0, 0),
         br_call(0, 0xa0, PAL_COPY_TARGET)),
        (0xb0, 0x10, nop_m(), nop_i(),
         br_cond(0xb0, 0xb0)),
        (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
        (PAL_COPY_TARGET, 0x0a, pal_break(), nop_m(), nop_i()),
        (PAL_COPY_TARGET + 0x10, 0x10, nop_m(), nop_i(),
         br_ret(0)),
    ],
    {"ip": 0xb0, "r28": PAL_VERSION, "r8": 0,
     "r9": PAL_VERSION_VALUE, "r10": PAL_VERSION_VALUE, "r11": 0},
    entry=0x10)

test_pal_copy_pal_bad_alloc = require_registers("pal_copy_pal_bad_alloc",
    pal_stacked_call_program(PAL_COPY_PAL,
                             [PAL_COPY_TARGET, PAL_COPY_BUFFER_SIZE - 1, 0]),
    {"ip": 0x80, "r28": PAL_COPY_PAL,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_copy_pal_bad_alignment = require_registers(
    "pal_copy_pal_bad_alignment",
    pal_stacked_call_program(PAL_COPY_PAL,
                             [PAL_COPY_TARGET + 0x20,
                              PAL_COPY_BUFFER_SIZE, 0]),
    {"ip": 0x80, "r28": PAL_COPY_PAL,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_copy_pal_bad_processor = require_registers(
    "pal_copy_pal_bad_processor",
    pal_stacked_call_program(PAL_COPY_PAL,
                             [PAL_COPY_TARGET, PAL_COPY_BUFFER_SIZE, 2]),
    {"ip": 0x80, "r28": PAL_COPY_PAL,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_halt_info = require_registers("pal_halt_info", [
    (0x10, 0x00, nop_m(), alloc(2, 4, 0, 0, 0), nop_i()),
    (0x20, *movl_mlx(28, PAL_HALT_INFO)),
    (0x30, *movl_mlx(32, PAL_HALT_INFO)),
    (0x40, *movl_mlx(33, PAL_HALT_INFO_BUFFER)),
    (0x50, *movl_mlx(34, 0)),
    (0x60, *movl_mlx(35, 0)),
    (0x70, 0x10, nop_m(), nop_i(), br_call(0, 0x70, PAL_PROC_ENTRY)),
    (0x80, *movl_mlx(2, PAL_HALT_INFO_BUFFER)),
    (0x90, 0x00, ld8(20, 2), adds(2, 8, 2), nop_i()),
    (0xa0, 0x00, ld8(21, 2), adds(2, 0x30, 2), nop_i()),
    (0xb0, 0x00, ld8(22, 2), nop_i(), nop_i()),
    (0xc0, 0x10, nop_m(), nop_i(), br_cond(0xc0, 0xc0)),
    (PAL_PROC_ENTRY, 0x0a, pal_break(), nop_m(), nop_i()),
    (PAL_PROC_ENTRY + 0x10, 0x10, nop_m(), nop_i(), br_ret(0)),
], {"ip": 0xc0, "r28": PAL_HALT_INFO, "r8": 0,
    "r9": 0, "r10": 0, "r11": 0,
    "r20": PAL_HALT_LIGHT_INFO, "r21": PAL_HALT_STATE1_INFO, "r22": 0},
    entry=0x10)

test_pal_halt_invalid_state = require_registers("pal_halt_invalid_state",
    pal_call_program(PAL_HALT, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_HALT,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_halt_reserved_arg = require_registers("pal_halt_reserved_arg",
    pal_call_program(PAL_HALT, [(29, 1), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_HALT,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_halt_info_bad_buffer = require_registers(
    "pal_halt_info_bad_buffer",
    pal_stacked_call_program(PAL_HALT_INFO,
                             [PAL_HALT_INFO_BUFFER + 4, 0, 0]),
    {"ip": 0x80, "r28": PAL_HALT_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_halt_info_reserved_arg = require_registers(
    "pal_halt_info_reserved_arg",
    pal_stacked_call_program(PAL_HALT_INFO, [PAL_HALT_INFO_BUFFER, 1, 0]),
    {"ip": 0x80, "r28": PAL_HALT_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_drain = require_registers("pal_mc_drain",
    pal_call_program(PAL_MC_DRAIN),
    {"ip": 0x30, "r28": PAL_MC_DRAIN, "r8": 0, "r9": 0, "r10": 0},
    entry=0x10)

test_pal_mc_drain_reserved_arg = require_registers(
    "pal_mc_drain_reserved_arg",
    pal_call_program(PAL_MC_DRAIN, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_DRAIN,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_expected = require_registers("pal_mc_expected",
    pal_call_program(PAL_MC_EXPECTED, [(29, 1), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_EXPECTED, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_mc_dynamic_state_empty = require_registers(
    "pal_mc_dynamic_state_empty",
    pal_call_program(PAL_MC_DYNAMIC_STATE, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_DYNAMIC_STATE, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_mc_dynamic_state_empty_aligned_offset = require_registers(
    "pal_mc_dynamic_state_empty_aligned_offset",
    pal_call_program(PAL_MC_DYNAMIC_STATE, [(29, 8), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_DYNAMIC_STATE, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_mc_dynamic_state_bad_offset = require_registers(
    "pal_mc_dynamic_state_bad_offset",
    pal_call_program(PAL_MC_DYNAMIC_STATE, [(29, 4), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_DYNAMIC_STATE,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_dynamic_state_reserved_arg = require_registers(
    "pal_mc_dynamic_state_reserved_arg",
    pal_call_program(PAL_MC_DYNAMIC_STATE, [(29, 0), (30, 0), (31, 1)]),
    {"ip": 0x60, "r28": PAL_MC_DYNAMIC_STATE,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_error_info_map_empty = require_registers(
    "pal_mc_error_info_map_empty",
    pal_call_program(PAL_MC_ERROR_INFO, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_ERROR_INFO,
     "r8": (-6 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_error_info_structure_empty = require_registers(
    "pal_mc_error_info_structure_empty",
    pal_call_program(PAL_MC_ERROR_INFO, [(29, 2), (30, 1 << 8), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_ERROR_INFO,
     "r8": (-6 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_error_info_bad_index = require_registers(
    "pal_mc_error_info_bad_index",
    pal_call_program(PAL_MC_ERROR_INFO, [(29, 3), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_ERROR_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_error_info_bad_level = require_registers(
    "pal_mc_error_info_bad_level",
    pal_call_program(PAL_MC_ERROR_INFO, [(29, 2), (30, 0x300), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_ERROR_INFO,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_resume_no_context = require_registers(
    "pal_mc_resume_no_context",
    pal_call_program(PAL_MC_RESUME, [(29, 0), (30, 0x2000), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_RESUME,
     "r8": (-3 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_resume_new_context_no_context = require_registers(
    "pal_mc_resume_new_context_no_context",
    pal_call_program(PAL_MC_RESUME, [(29, 1), (30, 0x2000), (31, 1)]),
    {"ip": 0x60, "r28": PAL_MC_RESUME,
     "r8": (-3 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_resume_bad_args = require_registers(
    "pal_mc_resume_bad_args",
    pal_call_program(PAL_MC_RESUME, [(29, 2), (30, 0x2000), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_RESUME,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_resume_bad_save_ptr = require_registers(
    "pal_mc_resume_bad_save_ptr",
    pal_call_program(PAL_MC_RESUME, [(29, 0), (30, 0x2100), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_RESUME,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_mc_register_mem = require_registers("pal_mc_register_mem",
    pal_call_program(PAL_MC_REGISTER_MEM, [(29, 0x2000), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MC_REGISTER_MEM, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_cache_line_init = require_registers("pal_cache_line_init",
    pal_call_program(PAL_CACHE_LINE_INIT,
                     [(29, 0x4000), (30, 0x1234), (31, 0)]),
    {"ip": 0x60, "r28": PAL_CACHE_LINE_INIT, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_pmi_entrypoint = require_registers("pal_pmi_entrypoint",
    pal_call_program(PAL_PMI_ENTRYPOINT, [(29, 0x5000), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_PMI_ENTRYPOINT, "r8": 0,
     "r9": 0, "r10": 0, "r11": 0}, entry=0x10)

test_pal_mem_for_test = require_registers("pal_mem_for_test",
    pal_call_program(PAL_MEM_FOR_TEST, [(29, 0), (30, 0), (31, 0)]),
    {"ip": 0x60, "r28": PAL_MEM_FOR_TEST, "r8": 0,
     "r9": 0, "r10": 1, "r11": 0}, entry=0x10)

test_pal_test_proc_healthy = require_registers("pal_test_proc_healthy",
    pal_stacked_call_program(PAL_TEST_PROC, [0x2000, 0, 1]),
    {"ip": 0x80, "r28": PAL_TEST_PROC, "r8": 0,
     "r9": PAL_SELF_TEST_STATE_TESTED, "r10": 0, "r11": 0}, entry=0x10)

test_pal_test_proc_missing_cacheable_attr = require_registers(
    "pal_test_proc_missing_cacheable_attr",
    pal_stacked_call_program(PAL_TEST_PROC, [0x2000, 0, 0]),
    {"ip": 0x80, "r28": PAL_TEST_PROC,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_test_proc_bad_address = require_registers(
    "pal_test_proc_bad_address",
    pal_stacked_call_program(PAL_TEST_PROC, [1 << 63, 0, 1]),
    {"ip": 0x80, "r28": PAL_TEST_PROC,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_test_proc_bad_attributes = require_registers(
    "pal_test_proc_bad_attributes",
    pal_stacked_call_program(PAL_TEST_PROC, [0x2000, 0, 1 << 16]),
    {"ip": 0x80, "r28": PAL_TEST_PROC,
     "r8": (-2 & 0xffffffffffffffff), "r9": 0, "r10": 0, "r11": 0},
    entry=0x10)

test_pal_unknown = require_registers("pal_unknown",
    pal_call_program(0xffff),
    {"ip": 0x30, "r28": 0xffff, "r8": (-1 & 0xffffffffffffffff)},
    entry=0x10)

# ── Exception tests ──

test_exception_break = require_exception("exception_break", [
    (0x10, 0x11, nop_m(), break_m(0x42), nop_m()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x42)

test_exception_syscall_break = require_exception("exception_syscall_break", [
    (0x10, 0x11, nop_m(), pal_break(), nop_m()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x100000)

test_exception_break_f = require_exception("exception_break_f", [
    (0x10, 0x0d, nop_m(), break_f(0x42), nop_i()),
], IA64_EXCP_BREAK, fault_ip=0x10, fault_imm=0x42)

test_exception_break_x = require_registers("exception_break_x", [
    (0x100000, *movl_mlx(2, 1 << 13)),
    (0x100010, 0x10, mov_gr_psr_full(2), nop_i(),
     br_cond(0x100010, 0x10)),
    (0x10, *break_x_mlx(0x34b630b4b820032b)),
    (IA64_BREAK_VECTOR, 0x00, nop_m(), nop_i(), nop_i()),
    (IA64_BREAK_VECTOR + 0x10, 0x00, nop_m(), nop_i(), nop_i()),
    (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
     br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x20)),
], {
    "ip": IA64_BREAK_VECTOR + 0x20,
    "exception": IA64_EXCP_NONE,
    "fault_ip": 0x10,
    "fault_imm": 0x34b630b4b820032b,
}, entry=0x100000)

test_nop_f_decode = require_exception("nop_f_decode", [
    (0x10, 0x0d, nop_m(), nop_f(0x42), nop_i()),
    (0x20, 0x11, nop_m(), nop_i(), break_b()),
], IA64_EXCP_BREAK, fault_ip=0x20)

test_exception_records_slot_ri = require_registers(
    "exception_records_slot_ri", [
        (0x10, *movl_mlx(19, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(19), nop_i(),
         br_cond(0x20, 0x30)),
        (0x30, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(16, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(17, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_psr_gr(18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r16": (1 << 13) | (1 << 41),
        "r17": (1 << 41),
        "r18": 0,
    }, entry=0x10)

test_break_preserves_ifa_and_records_iim_isr = require_registers(
    "break_preserves_ifa_and_records_iim_isr", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(20, 0x1111222233334444)),
        (0x30, 0x00, mov_m_gr_cr(20, 20), nop_i(),
         nop_i()),
        (0x40, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x40, 0x50)),
        (0x50, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x60, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 20), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 24), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_cr_gr(10, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0x1111222233334444,
        "r9": 0x42,
        "r10": (1 << 41),
    }, entry=0x10)

test_iipa_reports_previous_successful_bundle_for_slot0_fault = require_registers(
    "iipa_reports_previous_successful_bundle_for_slot0_fault", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, break_m(0x42), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_iipa_reports_current_bundle_after_prior_slot_success = require_registers(
    "iipa_reports_current_bundle_after_prior_slot_success", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 22), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_iipa_preserved_for_rfi_to_fault = require_registers(
    "iipa_preserved_for_rfi_to_fault", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x90, 0x00, break_m(0x43), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(9, 24), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x00,
         cmp4_eq_unc_imm(6, 7, 0x42, 9), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x50, qp=6)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_cr_gr(8, 22), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x40, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x50, *movl_mlx(19, 1 << 13)),
        (IA64_BREAK_VECTOR + 0x60, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(19, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x40,
        "exception": IA64_EXCP_NONE,
        "r8": 0x40,
    }, entry=0x10)

test_exception_clears_ifs_keeps_cfm = require_registers(
    "exception_clears_ifs_keeps_cfm", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x50, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x10)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "cfm_sof": 7,
        "cfm_sol": 4,
    }, entry=0x10)

test_cover_saves_interrupted_cfm_to_ifs = require_registers(
    "cover_saves_interrupted_cfm_to_ifs", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x50, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x00, mov_m_cr_gr(8, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_cr_gr(9, 23), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x30)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": 0,
        "r9": (1 << 63) | 0x207,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_rfi_restores_interrupted_bsp_after_cover = require_registers(
    "rfi_restores_interrupted_bsp_after_cover", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x40)),
        (0x40, *movl_mlx(3, 0x100000)),
        (0x50, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x60, 0x00, alloc(38, 7, 4, 0, 0), nop_i(),
         nop_i()),
        (0x70, 0x00, mov_m_ar_gr(8, 17), nop_i(),
         nop_i()),
        (0x80, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x90, 0x00, mov_m_ar_gr(9, 17), nop_i(),
         nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(),
         br_cond(0xa0, 0xa0)),
        (IA64_BREAK_VECTOR, 0x10, nop_m(), nop_i(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x100000,
        "r9": 0x100000,
        "cfm_sof": 7,
        "cfm_sol": 4,
    }, entry=0x10)

test_cover_rfi_rebases_rotating_floating_registers = require_registers(
    "cover_rfi_rebases_rotating_floating_registers", [
        (0x10, *movl_mlx(2, IA64_PSR_IC)),
        (0x20, *movl_mlx(3, 0x12345678)),
        (0x30, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x40, 0x01, setf_sig(32, 3), mov_i_imm_ar(66, 1), nop_i()),
        (0x50, 0x13, nop_m(), nop_b(), br_ctop_many(0x50, 0x50)),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x80, 0x00, nop_m(), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), br_cond(0x90, 0x90)),
        (IA64_BREAK_VECTOR, 0x10, nop_m(), nop_i(), cover_b()),
        (IA64_BREAK_VECTOR + 0x10, 0x00, nop_m(), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x20, *movl_mlx(20, 0x80)),
        (IA64_BREAK_VECTOR + 0x30, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x40, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0x90,
        "exception": IA64_EXCP_NONE,
        "f33": ExpectedFP(0x12345678, 0x1003e),
        "cfm_rrb_fr": 95,
    }, entry=0x10)

test_cover_rfi_rebases_rotating_general_registers = require_registers(
    "cover_rfi_rebases_rotating_general_registers", [
        (0x10, *movl_mlx(2, IA64_PSR_IC)),
        (0x20, *movl_mlx(3, 0x123456789abcdef0)),
        (0x30, 0x00, alloc(4, 32, 2, 4, 0), nop_i(), nop_i()),
        (0x40, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), adds(32, 0, 3), mov_i_imm_ar(66, 1)),
        (0x60, 0x13, nop_m(), nop_b(), br_ctop_many(0x60, 0x60)),
        (0x70, 0x00, nop_m(), adds(8, 0, 33), nop_i()),
        (0x80, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x90, 0x00, nop_m(), adds(9, 0, 33), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(), br_cond(0xa0, 0xa0)),
        (IA64_BREAK_VECTOR, 0x10, nop_m(), nop_i(), cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(20, 0x90)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(20, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(), rfi_b()),
    ], {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r8": 0x123456789abcdef0,
        "r9": 0x123456789abcdef0,
        "cfm_rrb_gr": 31,
    }, entry=0x10)

test_br_call_ret_rebases_rotating_floating_registers = require_registers(
    "br_call_ret_rebases_rotating_floating_registers", [
        (0x10, *movl_mlx(3, 0x12345678)),
        (0x20, 0x01, setf_sig(32, 3), mov_i_imm_ar(66, 1), nop_i()),
        (0x30, 0x13, nop_m(), nop_b(), br_ctop_many(0x30, 0x30)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), nop_i(), nop_i()),
        (0x110, 0x10, nop_m(), nop_i(), br_ret(0)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "f33": ExpectedFP(0x12345678, 0x1003e),
        "cfm_rrb_fr": 95,
    }, entry=0x10)

test_clrrrb_rebases_rotating_floating_registers = require_registers(
    "clrrrb_rebases_rotating_floating_registers", [
        (0x10, *movl_mlx(3, 0x12345678)),
        (0x20, 0x01, setf_sig(32, 3), mov_i_imm_ar(66, 1), nop_i()),
        (0x30, 0x13, nop_m(), nop_b(), br_ctop_many(0x30, 0x30)),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x13, nop_m(), nop_b(), clrrrb_b()),
        (0x60, 0x00, nop_m(), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "f32": ExpectedFP(0x12345678, 0x1003e),
        "cfm_rrb_fr": 0,
    }, entry=0x10)

test_nested_exception_keeps_handler_return_state = require_registers(
    "nested_exception_keeps_handler_return_state", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(3, IA64_BREAK_VECTOR + 0x50)),
        (0x30, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x30, 0x40)),
        (0x40, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x08, nop_m(), cmp4_eq_imm(1, 2, 0, 6),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x30, qp=1)),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x70, qp=2)),
        (IA64_BREAK_VECTOR + 0x30, 0x10, mov_gr_psr_full(2), adds(6, 1, 0),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x40, 0x11, nop_m(), break_m(0x43), nop_m()),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_m_cr_gr(4, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, mov_m_cr_gr(5, 19), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x60, IA64_BREAK_VECTOR + 0xa0)),
        (IA64_BREAK_VECTOR + 0xa0, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0xa0, IA64_BREAK_VECTOR + 0xa0)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x80, 0x00, mov_m_gr_cr(3, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": IA64_BREAK_VECTOR + 0xa0,
        "exception": IA64_EXCP_NONE,
        "r4": 0,
        "r5": IA64_BREAK_VECTOR + 0x50,
        "r6": 1,
    }, entry=0x10)

test_nested_exception_keeps_handler_interruption_state = require_registers(
    "nested_exception_keeps_handler_interruption_state", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, *movl_mlx(3, IA64_BREAK_VECTOR + 0x180)),
        (0x30, *movl_mlx(20, 1 << 41)),
        (0x40, 0x00, mov_m_gr_cr(20, 17), nop_i(), nop_i()),
        (0x50, *movl_mlx(20, 0x12345600 | (16 << 2))),
        (0x60, 0x00, mov_m_gr_cr(20, 21), nop_i(), nop_i()),
        (0x70, *movl_mlx(20, 0x9999aaaabbbbcccc)),
        (0x80, 0x00, mov_m_gr_cr(20, 25), nop_i(), nop_i()),
        (0x90, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x90, 0xa0)),
        (0xa0, 0x00, srlz_d(), nop_i(), nop_i()),
        (0xb0, 0x11, nop_m(), break_m(0x42), nop_m()),
        (IA64_BREAK_VECTOR, 0x08, nop_m(), cmp4_eq_imm(1, 2, 0, 31),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10, IA64_BREAK_VECTOR + 0x30, qp=1)),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20, IA64_BREAK_VECTOR + 0x100, qp=2)),
        (IA64_BREAK_VECTOR + 0x30, 0x10, mov_gr_psr_full(2), adds(31, 1, 0),
         br_cond(IA64_BREAK_VECTOR + 0x30, IA64_BREAK_VECTOR + 0x40)),
        (IA64_BREAK_VECTOR + 0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x50, 0x11, nop_m(), break_m(0x43), nop_m()),
        (IA64_BREAK_VECTOR + 0x100, *movl_mlx(20, 1 << 42)),
        (IA64_BREAK_VECTOR + 0x110, 0x00, mov_m_gr_cr(20, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x120,
         *movl_mlx(20, 0x87654300 | (20 << 2))),
        (IA64_BREAK_VECTOR + 0x130, 0x00, mov_m_gr_cr(20, 21), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x140, *movl_mlx(20, 0xdeadbeef10002500)),
        (IA64_BREAK_VECTOR + 0x150, 0x00, mov_m_gr_cr(20, 25), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x160, 0x00, mov_m_gr_cr(0, 16), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x170, 0x10, mov_m_gr_cr(3, 19), nop_i(),
         rfi_b()),
        (IA64_BREAK_VECTOR + 0x180, 0x00, mov_m_cr_gr(4, 17), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x190, 0x00, mov_m_cr_gr(5, 21), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x1a0, 0x00, mov_m_cr_gr(6, 25), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x1b0, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x1b0, IA64_BREAK_VECTOR + 0x1b0)),
    ], {
        "ip": IA64_BREAK_VECTOR + 0x1b0,
        "exception": IA64_EXCP_NONE,
        "r4": (1 << 42),
        "r5": 0x87654300 | (20 << 2),
        "r6": 0xdeadbeef10002500,
    }, entry=0x10)

test_rse_rfi_selects_matching_outer_exception_frame = require_registers(
    "rse_rfi_selects_matching_outer_exception_frame", [
        (0x10, *movl_mlx(2, IA64_PSR_IC)),
        (0x20, *movl_mlx(3, 0x100000)),
        (0x30, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (0x40, *movl_mlx(1, 0x123456789abcdef0)),
        (0x50, 0x10, mov_gr_psr_full(2), nop_i(),
         br_call(0, 0x50, 0x100)),
        (0x60, 0x00, nop_m(), adds(9, 0, 1),
         nop_i()),
        (0x70, 0x10, nop_m(), nop_i(),
         br_cond(0x70, 0x70)),
        (0x100, 0x00, nop_m(), alloc(33, 4, 3, 0, 0),
         nop_i()),
        (0x110, 0x00, nop_m(), mov_gr_b(32, 0),
         adds(34, 0, 1)),
        (0x120, 0x00, break_m(0x42), nop_i(),
         nop_i()),
        (0x130, 0x00, nop_m(), adds(1, 0, 34),
         adds(8, 0, 34)),
        (0x140, 0x00, nop_m(), mov_m_ar_gr(33, 64),
         mov_b_gr(0, 32)),
        (0x150, 0x10, nop_m(), nop_i(), br_ret(0)),
        (IA64_BREAK_VECTOR, 0x08, nop_m(), cmp4_eq_imm(1, 2, 0, 6),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x10,
                 IA64_BREAK_VECTOR + 0x30, qp=1)),
        (IA64_BREAK_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x20,
                 IA64_BREAK_VECTOR + 0x90, qp=2)),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         cover_b()),
        (IA64_BREAK_VECTOR + 0x40, *movl_mlx(3, 0x200000)),
        (IA64_BREAK_VECTOR + 0x50, 0x00, mov_ar(3, 18), adds(6, 1, 0),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x60, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(IA64_BREAK_VECTOR + 0x60, IA64_BREAK_VECTOR + 0x70)),
        (IA64_BREAK_VECTOR + 0x70, 0x00, break_m(0x43), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x90, 0x00, nop_m(), alloc(34, 4, 3, 0, 0),
         nop_i()),
        (IA64_BREAK_VECTOR + 0xa0, *movl_mlx(34, 0x0badf00ddeadbeef)),
        (IA64_BREAK_VECTOR + 0xb0, *movl_mlx(3, 0x100000)),
        (IA64_BREAK_VECTOR + 0xc0, 0x00, mov_ar(3, 18), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0xd0, *movl_mlx(20, IA64_PSR_IC)),
        (IA64_BREAK_VECTOR + 0xe0, 0x00, mov_m_gr_cr(20, 16),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0xf0, *movl_mlx(20, 0x130)),
        (IA64_BREAK_VECTOR + 0x100, 0x00, mov_m_gr_cr(20, 19),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x110,
         *movl_mlx(20, (1 << 63) | 4 | (3 << 7))),
        (IA64_BREAK_VECTOR + 0x120, 0x00, mov_m_gr_cr(20, 23),
         nop_i(), nop_i()),
        (IA64_BREAK_VECTOR + 0x130, 0x10, nop_m(), nop_i(),
         rfi_b()),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
        "r1": 0x123456789abcdef0,
        "r8": 0x123456789abcdef0,
        "r9": 0x123456789abcdef0,
        "r10": 0,
        "cfm_sof": 0,
        "cfm_sol": 0,
    }, entry=0x10)

test_disabled_fp_high_fault = require_registers(
    "disabled_fp_high_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DFH)),
        (0x20, *movl_mlx(3, 0x1234)),
        (0x30, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, setf_sig(40, 3), nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR, 0x00, mov_m_cr_gr(8, 19),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DISABLED_FP_VECTOR + 0x20,
                 IA64_DISABLED_FP_VECTOR + 0x20)),
    ], {
        "ip": IA64_DISABLED_FP_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r8": 0x50,
        "r9": 2,
    }, entry=0x10)

test_disabled_fp_low_fault = require_registers(
    "disabled_fp_low_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DFL)),
        (0x20, *movl_mlx(3, 0x1234)),
        (0x30, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x40, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x50, 0x00, setf_sig(8, 3), nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR, 0x00, mov_m_cr_gr(8, 19),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DISABLED_FP_VECTOR + 0x20,
                 IA64_DISABLED_FP_VECTOR + 0x20)),
    ], {
        "ip": IA64_DISABLED_FP_VECTOR + 0x20,
        "exception": IA64_EXCP_NONE,
        "r8": 0x50,
        "r9": 1,
    }, entry=0x10)

test_disabled_fp_load_sets_isr_r = require_registers(
    "disabled_fp_load_sets_isr_r", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DFH)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x00, ldf8(40, 3), nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DISABLED_FP_VECTOR + 0x10,
                 IA64_DISABLED_FP_VECTOR + 0x10)),
    ], {
        "ip": IA64_DISABLED_FP_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r9": IA64_ISR_R | 2,
    }, entry=0x10)

test_disabled_fp_store_sets_isr_w = require_registers(
    "disabled_fp_store_sets_isr_w", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DFH)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x00, stfe(3, 40), nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DISABLED_FP_VECTOR + 0x10,
                 IA64_DISABLED_FP_VECTOR + 0x10)),
    ], {
        "ip": IA64_DISABLED_FP_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r9": IA64_ISR_W | 2,
    }, entry=0x10)

test_disabled_fp_mixed_sets_reports_both = require_registers(
    "disabled_fp_mixed_sets_reports_both", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DFL |
                         IA64_PSR_DFH)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x0d, nop_m(), fmerge_ns(40, 8, 0), nop_i()),
        (IA64_DISABLED_FP_VECTOR, 0x00, mov_m_cr_gr(9, 17),
         nop_i(), nop_i()),
        (IA64_DISABLED_FP_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DISABLED_FP_VECTOR + 0x10,
                 IA64_DISABLED_FP_VECTOR + 0x10)),
    ], {
        "ip": IA64_DISABLED_FP_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r9": 3 | (1 << IA64_ISR_EI_SHIFT),
    }, entry=0x10)

test_fp_writes_set_psr_mfl_mfh = require_registers(
    "fp_writes_set_psr_mfl_mfh", [
        (0x10, *movl_mlx(2, 0x1234)),
        (0x20, 0x00, setf_sig(8, 2), nop_i(), nop_i()),
        (0x30, 0x00, setf_sig(40, 2), nop_i(), nop_i()),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "exception": IA64_EXCP_NONE,
        "psr": ExpectedBits(mask=IA64_PSR_MFL | IA64_PSR_MFH,
                            value=IA64_PSR_MFL | IA64_PSR_MFH),
        "f8": ExpectedFP(0x1234, 0x1003e),
        "f40": ExpectedFP(0x1234, 0x1003e),
        "ar_fpsr": DEFAULT_FPSR,
    }, entry=0x10)

test_predicated_off_disabled_fp_does_not_fault = require_registers(
    "predicated_off_disabled_fp_does_not_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_DFH)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, setf_sig(40, 2, qp=1), nop_i(), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "exception": IA64_EXCP_NONE,
        "psr": IA64_PSR_DFH,
        "f40": ExpectedFP(0, 0),
        "ar_fpsr": DEFAULT_FPSR,
    }, entry=0x10)

test_exception_illegal = require_exception("exception_illegal", [
    (0x10, 0x11, nop_m(),
     illegal_m(), nop_m()),
], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_exception_illegal_enters_general_vector = require_registers(
        "exception_illegal_enters_general_vector", [
        (0x10, *movl_mlx(2, 1 << 13)),
        (0x20, 0x10, mov_gr_psr_full(2), nop_i(),
         br_cond(0x20, 0x30)),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x11, nop_m(), illegal_m(), nop_m()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x10,
                 IA64_GENERAL_VECTOR + 0x10)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r8": (1 << 41),
    }, entry=0x10)

test_private_extension_opcode_illegal = require_exception(
    "private_extension_opcode_illegal",
    [
        (0x10, 0x11, nop_m(),
         op(0xf) | bitfield(1, 26, 1) | bitfield(0, 27, 6),
         nop_b()),
    ],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_exception_reserved_template = require_exception(
    "exception_reserved_template",
    [(0x10, 0x1f, nop_m(), nop_m(), nop_m())],
    IA64_EXCP_RESERVED_TEMPLATE, fault_ip=0x10,
)

test_exception_unaligned = require_exception(
    "exception_unaligned",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ld8(4, 3), nop_i(), nop_i()),
    ],
    IA64_EXCP_UNALIGNED, fault_ip=0x20,
)

test_exception_unaligned_sets_ifa_isr = require_registers(
    "exception_unaligned_sets_ifa_isr",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x00, ld8(4, 3), nop_i(), nop_i()),
        (0x5a00, 0x00, mov_m_cr_gr(14, 20), nop_i(), nop_i()),
        (0x5a10, 0x00, mov_m_cr_gr(15, 17), nop_i(), nop_i()),
        (0x5a20, 0x10, nop_m(), nop_i(), br_cond(0x5a20, 0x5a20)),
    ],
    {"ip": 0x5a20, "r14": 0xff9, "r15": IA64_ISR_R},
)

test_exception_unaligned_slot1_uses_psr_ri = require_registers(
    "exception_unaligned_slot1_uses_psr_ri",
    [
        (0x10, 0x00, nop_m(), adds(3, 0xff9, 0), nop_i()),
        (0x20, 0x00, ssm(1 << 13), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x08, nop_m(), ld8(4, 3), nop_i()),
        (IA64_UNALIGNED_VECTOR, 0x00, mov_m_cr_gr(14, 20),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x10, 0x00, mov_m_cr_gr(15, 17),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x20, 0x00, mov_m_cr_gr(16, 19),
         nop_i(), nop_i()),
        (IA64_UNALIGNED_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_UNALIGNED_VECTOR + 0x30,
                 IA64_UNALIGNED_VECTOR + 0x30)),
    ],
    {
        "ip": IA64_UNALIGNED_VECTOR + 0x30,
        "r14": 0xff9,
        "r15": IA64_ISR_R | (1 << IA64_ISR_EI_SHIFT),
        "r16": 0x40,
    },
)

test_no_ic_data_access_enters_vector_with_ni = require_registers(
    "no_ic_data_access_enters_vector_with_ni",
    [
        (0x10, *movl_mlx(16, 0x40000)),
        (0x20, *movl_mlx(17, 12 << 2)),
        (0x30, *movl_mlx(18, 0x40201)),
        (0x40, *movl_mlx(20, 0x1111222233334444)),
        (0x50, *movl_mlx(21, 0x5555666677778888)),
        (0x60, 0x00, mov_m_gr_cr(16, 20), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(17, 21), adds(5, 0, 0), nop_i()),
        (0x80, 0x00, itr_d(5, 18), nop_i(), nop_i()),
        (0x90, 0x00, mov_m_gr_cr(20, 19), nop_i(), nop_i()),
        (0xa0, 0x00, mov_m_gr_cr(21, 20), nop_i(), nop_i()),
        (0xb0, 0x00, ssm(1 << 17), nop_i(), nop_i()),
        (0xc0, 0x00, st8(16, 0), nop_i(), nop_i()),
        (IA64_DATA_ACCESS_VECTOR, 0x00, mov_m_cr_gr(8, 17), nop_i(),
         nop_i()),
        (IA64_DATA_ACCESS_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 19),
         nop_i(), nop_i()),
        (IA64_DATA_ACCESS_VECTOR + 0x20, 0x00, mov_m_cr_gr(10, 20),
         nop_i(), nop_i()),
        (IA64_DATA_ACCESS_VECTOR + 0x30, 0x10, nop_m(), nop_i(),
         br_cond(IA64_DATA_ACCESS_VECTOR + 0x30,
                 IA64_DATA_ACCESS_VECTOR + 0x30)),
    ],
    {
        "ip": IA64_DATA_ACCESS_VECTOR + 0x30,
        "exception": IA64_EXCP_NONE,
        "r8": IA64_ISR_W | IA64_ISR_NI,
        "r9": 0x1111222233334444,
        "r10": 0x5555666677778888,
    },
)

test_firmware_unaligned_load_assist = require_registers(
    "firmware_unaligned_load_assist",
    [
        (0x10, *movl_mlx(20, 0x1122334455667788)),
        (0x20, *movl_mlx(21, 0x99aabbccddeeff00)),
        (0x30, 0x00, addl(3, 0x100, 0), nop_i(), nop_i()),
        (0x40, 0x0a, st8(3, 20), adds(3, 8, 3), nop_i()),
        (0x50, 0x0a, st8(3, 21), adds(3, -4, 3), nop_i()),
        (0x60, 0x00, addl(2, 0x10000, 0), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 2), nop_i(), nop_i()),
        (0x80, 0x00, ssm((1 << 13) | (1 << 3)), nop_i(), nop_i()),
        (0x90, 0x0a, ld8(22, 3), adds(23, 1, 0), nop_i()),
        (0xa0, 0x10, nop_m(), nop_i(), br_cond(0xa0, 0xa0)),
    ],
    {
        "ip": 0xa0,
        "exception": IA64_EXCP_NONE,
        "r22": 0xddeeff0011223344,
        "r23": 1,
    },
)

test_firmware_unaligned_store_assist = require_registers(
    "firmware_unaligned_store_assist",
    [
        (0x10, *movl_mlx(20, 0x1122334455667788)),
        (0x20, *movl_mlx(21, 0x99aabbccddeeff00)),
        (0x30, *movl_mlx(24, 0xaabbccddeeff0011)),
        (0x40, 0x00, addl(3, 0x100, 0), nop_i(), nop_i()),
        (0x50, 0x0a, st8(3, 20), adds(3, 8, 3), nop_i()),
        (0x60, 0x0a, st8(3, 21), adds(3, -4, 3), nop_i()),
        (0x70, 0x00, addl(2, 0x10000, 0), nop_i(), nop_i()),
        (0x80, 0x00, mov_m_gr_cr(2, 2), nop_i(), nop_i()),
        (0x90, 0x00, ssm((1 << 13) | (1 << 3)), nop_i(), nop_i()),
        (0xa0, 0x0a, st8(3, 24), adds(25, 1, 0), nop_i()),
        (0xb0, 0x00, adds(3, -4, 3), nop_i(), nop_i()),
        (0xc0, 0x0a, ld8(26, 3), adds(3, 8, 3), nop_i()),
        (0xd0, 0x00, ld8(27, 3), nop_i(), nop_i()),
        (0xe0, 0x10, nop_m(), nop_i(), br_cond(0xe0, 0xe0)),
    ],
    {
        "ip": 0xe0,
        "exception": IA64_EXCP_NONE,
        "r25": 1,
        "r26": 0xeeff001155667788,
        "r27": 0x99aabbccaabbccdd,
    },
)

test_firmware_unaligned_speculative_load_assist = require_registers(
    "firmware_unaligned_speculative_load_assist",
    [
        (0x10, *movl_mlx(20, 0x1122334455667788)),
        (0x20, *movl_mlx(21, 0x99aabbccddeeff00)),
        (0x30, 0x00, addl(3, 0x300, 0), addl(5, 0x304, 0),
         nop_i()),
        (0x40, 0x0a, st8(3, 20), adds(3, 8, 3), nop_i()),
        (0x50, 0x0a, st8(3, 21), adds(3, -8, 3), nop_i()),
        (0x60, 0x00, addl(2, 0x10000, 0), nop_i(), nop_i()),
        (0x70, 0x00, mov_m_gr_cr(2, 2), nop_i(), nop_i()),
        (0x80, 0x00, ssm((1 << 13) | (1 << 3)), nop_i(), nop_i()),
        (0x90, 0x00, ld8_s(4, 5), nop_i(), nop_i()),
        (0xa0, 0x00, nop_m(), adds(8, 0, 4), nop_i()),
        (0xb0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xc0, 0x00, nop_m(), nop_i(), nop_i()),
        (0xd0, 0x00, ld8_a(6, 3), nop_i(), nop_i()),
        (0xe0, 0x00, nop_m(), addl(6, 0x55, 0), nop_i()),
        (0xf0, 0x00, ld8_a(6, 5), nop_i(), nop_i()),
        (0x100, 0x00, nop_m(), adds(11, 0, 6), nop_i()),
        (0x110, 0x00, nop_m(), addl(6, 0x77, 0), nop_i()),
        (0x120, 0x00, ld8_c_nc(6, 3), nop_i(), nop_i()),
        (0x130, 0x00, ld8_a(7, 3), nop_i(), nop_i()),
        (0x140, 0x00, nop_m(), addl(7, 0x66, 0), nop_i()),
        (0x150, 0x00, ld8_sa(7, 5), nop_i(), nop_i()),
        (0x160, 0x00, nop_m(), adds(12, 0, 7), nop_i()),
        (0x170, 0x00, nop_m(), nop_i(), nop_i()),
        (0x180, 0x00, nop_m(), nop_i(), nop_i()),
        (0x190, 0x00, nop_m(), addl(7, 0x88, 0), nop_i()),
        (0x1a0, 0x00, ld8_c_nc(7, 3), nop_i(), nop_i()),
        (0x1b0, 0x10, nop_m(), nop_i(), br_cond(0x1b0, 0x1b0)),
    ],
    {
        "ip": 0x1b0,
        "exception": IA64_EXCP_NONE,
        "r6": 0x1122334455667788,
        "r7": 0x1122334455667788,
        "r8": 0xddeeff0011223344,
        "r8_nat": 0,
        "r11": 0x55,
        "r12": 0x66,
        "r12_nat": 0,
    },
)

test_firmware_unaligned_virtual_load_assist = require_registers(
    "firmware_unaligned_virtual_load_assist",
    [
        (0x10, *movl_mlx(20, 0x1122334455667788)),
        (0x20, *movl_mlx(21, 0x99aabbccddeeff00)),
        (0x30, 0x00, addl(3, 0x300, 0), nop_i(), nop_i()),
        (0x40, 0x0a, st8(3, 20), adds(3, 8, 3), nop_i()),
        (0x50, 0x00, st8(3, 21), nop_i(), nop_i()),
        *dtr_setup_bundles(0x60, 0xe000000000000304, 0x304),
        (0xc0, *movl_mlx(5, 0xe000000000000304)),
        (0xd0, 0x00, addl(2, 0x10000, 0), nop_i(), nop_i()),
        (0xe0, 0x00, mov_m_gr_cr(2, 2), nop_i(), nop_i()),
        (0xf0, 0x00, ssm((1 << 17) | (1 << 13) | (1 << 3)),
         nop_i(), nop_i()),
        (0x100, 0x00, ld8_s(22, 5), nop_i(), nop_i()),
        (0x110, 0x00, nop_m(), adds(23, 1, 0), nop_i()),
        (0x120, 0x10, nop_m(), nop_i(), br_cond(0x120, 0x120)),
    ],
    {
        "ip": 0x120,
        "exception": IA64_EXCP_NONE,
        "r22": 0xddeeff0011223344,
        "r22_nat": 0,
        "r23": 1,
    },
)

test_speculative_unaligned_defers = require_registers(
    "speculative_unaligned_defers",
    [
        (0x10, 0x00, nop_m(), addl(3, 0x104, 0), nop_i()),
        (0x20, 0x00, sum_um(0x8), nop_i(), nop_i()),
        (0x30, 0x00, ld8_s(4, 3), nop_i(), nop_i()),
        (0x40, 0x00, nop_m(), nop_i(), nop_i()),
        (0x50, 0x00, nop_m(), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ],
    {"ip": 0x60, "r4_nat": 1},
)

test_clrrrb_b_decode = require_exception("clrrrb_b_decode", [
    (0x10, 0x13, nop_m(), nop_b(), clrrrb_b()),
    (0x20, 0x11, nop_m(), nop_i(), break_b()),
], IA64_EXCP_BREAK, fault_ip=0x20)

test_clrrrb_pr_b_decode = require_exception("clrrrb_pr_b_decode", [
    (0x10, 0x11, nop_m(), nop_i(),
     clrrrb_pr_b(qp=1, ignored=0x1965d4)),
    (0x20, 0x11, nop_m(), nop_i(), break_b()),
], IA64_EXCP_BREAK, fault_ip=0x20)

test_br_ctop_many_decode = require_exception("br_ctop_many_decode", [
    (0x10, 0x00, nop_m(), addl(8, 1, 0), nop_i()),
    (0x20, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
    (0x30, 0x13, nop_m(), nop_b(), br_ctop_many(0x30, 0x30)),
    (0x40, 0x11, nop_m(), nop_i(), break_b()),
], IA64_EXCP_BREAK, fault_ip=0x40)

test_br_cloop_requires_slot2 = require_exception(
    "br_cloop_requires_slot2", [
        (0x10, 0x12, nop_m(), br_cloop(0x10, 0x10), nop_b()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_cover_requires_group_stop = require_exception(
    "cover_requires_group_stop", [
        (0x10, 0x18, nop_m(), nop_m(), int(cover_b())),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_alloc_requires_group_start = require_exception(
    "alloc_requires_group_start", [
        (0x10, 0x00, nop_m(), nop_i(), nop_i()),
        (0x20, 0x00, alloc_m(1, 1, 0, 0, 0), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x20)

test_loadrs_rejects_nonzero_rsc_mode = require_exception(
    "loadrs_rejects_nonzero_rsc_mode", [
        (0x10, 0x01, nop_m(), adds(3, 1, 0), nop_i()),
        (0x20, 0x03, mov_m_gr_ar(3, 16), nop_i(), nop_i()),
        (0x30, 0x01, loadrs_enc(), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x30)

test_reserved_application_register_is_illegal = require_exception(
    "reserved_application_register_is_illegal", [
        (0x10, 0x00, mov_m_ar_gr(8, 8), nop_i(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_rsc_reserved_field_fault = require_exception(
    "rsc_reserved_field_fault", [
        (0x10, *movl_mlx(3, 1 << 63)),
        (0x20, 0x00, mov_m_gr_ar(3, 16), nop_i(), nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x20)

test_ssm_reserved_mask_field_fault = require_exception(
    "ssm_reserved_mask_field_fault", [
        (0x10, 0x00, ssm(1), nop_i(), nop_i()),
    ], IA64_EXCP_RESERVED_REG_FIELD, fault_ip=0x10)

test_privileged_instruction_rejected_at_cpl3 = require_registers(
    "privileged_instruction_rejected_at_cpl3", [
        (0x10, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_CPL3)),
        (0x20, 0x00, nop_m(), adds(31, 0x50, 0), nop_i()),
        *rfi_to_gr(0x30, 19, 31),
        (0x50, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x60, 0x00, ssm(IA64_PSR_I), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(31, 17),
         nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x10,
                 IA64_GENERAL_VECTOR + 0x10)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 0x10,
    }, entry=0x10)

test_predicated_off_privileged_instruction_does_not_fault = require_registers(
    "predicated_off_privileged_instruction_does_not_fault", [
        (0x10, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_CPL3)),
        (0x20, 0x00, nop_m(), adds(31, 0x50, 0), nop_i()),
        *rfi_to_gr(0x30, 19, 31),
        (0x50, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x60, 0x00, ssm(IA64_PSR_I, qp=1), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
    ], {
        "ip": 0x70,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_stacked_gr_destination_out_of_frame = require_exception(
    "stacked_gr_destination_out_of_frame", [
        (0x10, 0x00, nop_m(), adds(32, 1, 0), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_predicated_off_stacked_gr_destination_does_not_fault = require_registers(
    "predicated_off_stacked_gr_destination_does_not_fault", [
        (0x10, 0x00, nop_m(), adds(32, 1, 0, qp=1), nop_i()),
        (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
    ], {
        "ip": 0x20,
        "exception": IA64_EXCP_NONE,
        "r32": 0,
    }, entry=0x10)

test_postincrement_base_out_of_frame = require_exception(
    "postincrement_base_out_of_frame", [
        (0x10, 0x08, lfetch_postinc(32, 8), nop_m(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_ldfp_requires_opposite_register_banks = require_exception(
    "ldfp_requires_opposite_register_banks", [
        (0x10, 0x08, ldfp8_postinc(2, 4, 3), nop_m(), nop_i()),
    ], IA64_EXCP_ILLEGAL, fault_ip=0x10)

test_br_ctop_self_loop_budgeted = require_registers(
    "br_ctop_self_loop_budgeted", [
        (0x10, 0x00, nop_m(), addl(8, 5000, 0), nop_i()),
        (0x20, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0x30, 0x10, nop_m(), adds(4, 1, 4),
         br_ctop_many(0x30, 0x30)),
        (0x40, 0x02, nop_m(), mov_ar_lc(5), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {
        "ip": 0x50,
        "r4": 5001,
        "r5": 0,
    }, entry=0x10)

test_counted_self_loop_fault_has_slot1_ri = require_registers(
    "counted_self_loop_fault_has_slot1_ri", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(3, HIGH_TR_BASE + 0xfff8)),
        (0x80, 0x00, adds(8, 1, 0), nop_i(), nop_i()),
        (0x90, 0x02, nop_m(), mov_lc_gr(8), nop_i()),
        (0xa0, *movl_mlx(19, IA64_PSR_IC | IA64_PSR_DT)),
        (0xb0, 0x00, mov_gr_psr_full(19), nop_i(), nop_i()),
        (0xc0, 0x19, nop_m(), st8_postinc(3, 0, 8),
         br_cloop(0xc0, 0xc0)),
        (IA64_ALT_DTLB_VECTOR, 0x02, mov_m_cr_gr(31, 16),
         extr_u(31, 31, 41, 2), nop_i()),
        (IA64_ALT_DTLB_VECTOR + 0x10, 0x10, nop_m(), nop_i(),
         br_cond(IA64_ALT_DTLB_VECTOR + 0x10,
                 IA64_ALT_DTLB_VECTOR + 0x10)),
    ], {
        "ip": IA64_ALT_DTLB_VECTOR + 0x10,
        "exception": IA64_EXCP_NONE,
        "r31": 1,
    }, entry=0x10)

test_brl_call_mlx_decode = require_registers("brl_call_mlx_decode", [
    (0x10, *brl_call_mlx(6, 0x10, 0x40)),
    (0x20, 0x00, adds(8, 1, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, adds(8, 0x5a, 0), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r8": 0x5a}, entry=0x10)

test_brl_call_mlx_no_stop_decode = require_registers(
    "brl_call_mlx_no_stop_decode", [
        (0x10, *brl_call_mlx(6, 0x10, 0x40, template=0x04)),
        (0x20, 0x00, adds(8, 1, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(8, 0x5c, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {"ip": 0x50, "r8": 0x5c}, entry=0x10)

test_brl_call_mlx_negative_lslot_decode = require_registers(
    "brl_call_mlx_negative_lslot_decode", [
        (0x07000030, *brl_call_mlx(6, 0x07000030, 0x010000d0,
                                   ignored_l=0x3)),
        (0x010000d0, 0x00, adds(8, 0x66, 0), nop_i(), nop_i()),
        (0x010000e0, 0x10, nop_m(), nop_i(),
         br_cond(0x010000e0, 0x010000e0)),
    ], {"ip": 0x010000e0, "r8": 0x66}, entry=0x07000030)

test_brl_cond_mlx_decode = require_registers("brl_cond_mlx_decode", [
    (0x10, *brl_cond_mlx(0x10, 0x40)),
    (0x20, 0x00, adds(8, 1, 0), nop_i(),
     nop_i()),
    (0x40, 0x00, adds(8, 0x5b, 0), nop_i(),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r8": 0x5b}, entry=0x10)

test_brl_cond_mlx_no_stop_decode = require_registers(
    "brl_cond_mlx_no_stop_decode", [
        (0x10, *brl_cond_mlx(0x10, 0x40, template=0x04)),
        (0x20, 0x00, adds(8, 1, 0), nop_i(),
         nop_i()),
        (0x40, 0x00, adds(8, 0x5d, 0), nop_i(),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
    ], {"ip": 0x50, "r8": 0x5d}, entry=0x10)

test_hint_x_mlx_decode = require_registers("hint_x_mlx_decode", [
    (0x10, *hint_x_mlx(0x3456789abcde)),
    (0x20, 0x00, adds(8, 0x5c, 0), nop_i(),
     nop_i()),
    (0x30, 0x10, nop_m(), nop_i(),
     br_cond(0x30, 0x30)),
], {"ip": 0x30, "r8": 0x5c, "exception": IA64_EXCP_NONE}, entry=0x10)

test_br_call_indirect_completers_decode = require_registers(
    "br_call_indirect_completers_decode", [
        (0x10, 0x01, addl(8, 0x70, 0), nop_i(),
         nop_i()),
        (0x20, 0x00, nop_m(), mov_br_gr(7, 8),
         nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_call_indirect(6, 7, wh=7, many=True, ignored=0xf2f5,
                          bit36=1)),
        (0x40, 0x10, adds(5, 0x33, 0), nop_i(),
         br_call_indirect(6, 7, wh=3, clear=True, ignored=0xd71e, qp=6)),
        (0x50, 0x10, nop_m(), nop_i(),
         br_cond(0x50, 0x50)),
        (0x70, 0x10, adds(4, 0x5a, 0), nop_i(),
         br_ret(6)),
    ], {"ip": 0x50, "r4": 0x5a, "r5": 0x33}, entry=0x10)

test_br_indirect_ignores_low_bits = require_registers(
    "br_indirect_ignores_low_bits", [
        (0x10, *movl_mlx(8, 0x6f)),
        (0x20, 0x00, nop_m(), mov_br_gr(7, 8), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(),
         br_indirect(7, wh=3, many=True, clear=True, bit36=1)),
        (0x40, 0x00, adds(4, 0x11, 0), nop_i(), nop_i()),
        (0x60, 0x00, adds(4, 0x5a, 0), nop_i(), nop_i()),
        (0x70, 0x10, nop_m(), nop_i(), br_cond(0x70, 0x70)),
    ], {"ip": 0x70, "r4": 0x5a}, entry=0x10)

test_br_indirect_predicate_false_falls_through = require_registers(
    "br_indirect_predicate_false_falls_through", [
        (0x10, *movl_mlx(8, 0x60)),
        (0x20, 0x00, nop_m(), mov_br_gr(7, 8), nop_i()),
        (0x30, 0x10, nop_m(), nop_i(), br_indirect(7, qp=6)),
        (0x40, 0x00, adds(4, 0x33, 0), nop_i(), nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        (0x60, 0x00, adds(4, 0x5a, 0), nop_i(), nop_i()),
    ], {"ip": 0x50, "r4": 0x33}, entry=0x10)

test_br_ia_nonzero_qp_illegal = require_exception(
    "br_ia_nonzero_qp_illegal",
    [(0x10, 0x10, nop_m(), nop_i(), br_indirect(7, btype=1, qp=1))],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_br_ia_bspstore_mismatch_illegal = require_exception(
    "br_ia_bspstore_mismatch_illegal", [
        (0x10, 0x00, alloc_m(2, 8, 4, 0, 0), nop_i(),
         nop_i()),
        (0x20, 0x10, nop_m(), nop_i(),
         br_call(0, 0x20, 0x40)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_indirect(7, btype=1)),
    ],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x40,
)

test_br_ia_psr_di_disabled_transition_fault = require_registers(
    "br_ia_psr_di_disabled_transition_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IC | IA64_PSR_DI)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(),
         nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(),
         nop_i()),
        (0x40, 0x10, nop_m(), nop_i(),
         br_indirect(7, btype=1)),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x20,
                 IA64_GENERAL_VECTOR + 0x20)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x20,
        "r8": 0x40,
        "r9": 0x40 | (2 << IA64_ISR_EI_SHIFT),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_br_ia_montecito_native_ia32_disabled_fault = require_registers(
    "br_ia_montecito_native_ia32_disabled_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IC)),
        (0x20, 0x00, mov_gr_psr_full(2), nop_i(), nop_i()),
        (0x30, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_indirect(7, btype=1)),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x20,
                 IA64_GENERAL_VECTOR + 0x20)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x20,
        "r8": 0x40,
        "r9": 0x40 | (2 << IA64_ISR_EI_SHIFT),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_rfi_montecito_native_ia32_disabled_fault = require_registers(
    "rfi_montecito_native_ia32_disabled_fault", [
        (0x10, *movl_mlx(2, IA64_PSR_IS)),
        (0x20, *movl_mlx(3, 0x1234567800000045)),
        (0x30, 0x00, mov_m_gr_cr(2, 16), nop_i(), nop_i()),
        (0x40, 0x00, mov_m_gr_cr(3, 19), nop_i(), nop_i()),
        (0x50, *movl_mlx(4, IA64_PSR_IC)),
        (0x60, 0x00, mov_gr_psr_full(4), nop_i(), nop_i()),
        (0x70, 0x00, srlz_d(), nop_i(), nop_i()),
        (0x80, 0x11, nop_m(), nop_i(), rfi_b()),
        (IA64_GENERAL_VECTOR, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
        (IA64_GENERAL_VECTOR + 0x10, 0x00, mov_m_cr_gr(9, 17), nop_i(),
         nop_i()),
        (IA64_GENERAL_VECTOR + 0x20, 0x10, nop_m(), nop_i(),
         br_cond(IA64_GENERAL_VECTOR + 0x20,
                 IA64_GENERAL_VECTOR + 0x20)),
    ], {
        "ip": IA64_GENERAL_VECTOR + 0x20,
        "r8": 0x80,
        "r9": 0x40 | (2 << IA64_ISR_EI_SHIFT),
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)

test_rfi_montecito_uncollected_transition_preserves_target = \
    require_registers(
        "rfi_montecito_uncollected_transition_preserves_target", [
            (0x10, *movl_mlx(5, 0x10000)),
            (0x20, 0x00, mov_m_gr_cr(5, 2), nop_i(), nop_i()),
            (0x30, *movl_mlx(2, IA64_PSR_IS)),
            (0x40, *movl_mlx(3, 0x1234567800000045)),
            (0x50, 0x00, mov_m_gr_cr(2, 16), nop_i(), nop_i()),
            (0x60, 0x00, mov_m_gr_cr(3, 19), nop_i(), nop_i()),
            (0x70, 0x11, nop_m(), nop_i(), rfi_b()),
            (0x15400, 0x00, mov_m_cr_gr(8, 19), nop_i(), nop_i()),
            (0x15410, 0x00, mov_m_cr_gr(9, 16), nop_i(), nop_i()),
            (0x15420, 0x00, mov_m_cr_gr(10, 17), nop_i(), nop_i()),
            (0x15430, 0x10, nop_m(), nop_i(), br_cond(0x15430, 0x15430)),
        ], {
            "ip": 0x15430,
            "r8": 0x1234567800000045,
            "r9": IA64_PSR_IS,
            "r10": 0x40 | IA64_ISR_NI | (2 << IA64_ISR_EI_SHIFT),
            "fault_code": IA64_EXCP_DISABLED_ISA_TRANSITION,
            "fault_ip": 0x70,
            "exception": IA64_EXCP_NONE,
        }, entry=0x10)

test_reserved_indirect_branch_btype_illegal = require_exception(
    "reserved_indirect_branch_btype_illegal",
    [(0x10, 0x10, nop_m(), nop_i(), br_indirect(7, btype=2))],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_reserved_ip_relative_branch_btype_illegal = require_exception(
    "reserved_ip_relative_branch_btype_illegal",
    [(0x10, 0x10, nop_m(), nop_i(),
      ip_relative_branch_btype(1, 0x10, 0x20))],
    IA64_EXCP_ILLEGAL,
    fault_ip=0x10,
)

test_br_cloop_decrements_lc = require_registers("br_cloop_decrements_lc", [
    (0x10, 0x00, nop_m(), adds(4, 0, 0), nop_i()),
    (0x20, 0x02, nop_m(), mov_lc_imm(2), nop_i()),
    (0x30, 0x10, nop_m(), adds(4, 1, 4),
     br_cloop(0x30, 0x30)),
    (0x40, 0x02, nop_m(), mov_ar_lc(5), nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": 3, "r5": 0}, entry=0x10)

test_br_ctop_rotating_pipeline = require_registers("br_ctop_rotating_pipeline", [
    (0x10, 0x00, alloc_m(9, 35, 35, 4, 0),
     mov_i_imm_ar(66, 25), mov_lc_imm(0)),
    (0x20, 0x00, nop_m(), mov_pr_rot_imm(0x10000), nop_i()),
    (0x30, 0x00, nop_m(), adds(32, 0x5a, 0, qp=16),
     adds(8, 0, 56, qp=40)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_ctop_many(0x40, 0x30)),
    (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x50)),
], {"ip": 0x50, "exception": IA64_EXCP_NONE, "r8": 0x5a}, entry=0x10)

test_br_ctop_long_rotating_pipeline = require_registers(
    "br_ctop_long_rotating_pipeline", [
        # alloc must start an instruction group.  Use MLX;; here so this
        # setup instruction cannot silently leave a pending illegal fault.
        (0x10, 0x05, *movl_mlx(5, 130)[1:]),
        (0x20, 0x00, alloc_m(9, 32, 32, 4, 0),
         mov_i_imm_ar(66, 1), mov_lc_gr(5)),
        (0x30, 0x00, nop_m(), mov_pr_rot_imm(0x10000), adds(4, 1, 0)),
        (0x40, 0x00, nop_m(), adds(32, 0, 4, qp=16), adds(4, 1, 4)),
        (0x50, 0x10, nop_m(), adds(8, 0, 34, qp=18),
         br_ctop_many(0x50, 0x40)),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
    ], {"ip": 0x60, "exception": IA64_EXCP_NONE,
        "r4": 132, "r8": 129}, entry=0x10)

_br_ctop_spec_data = [i + 1 for i in range(131)] + [0]
test_br_ctop_long_speculative_load_pipeline = require_registers(
    "br_ctop_long_speculative_load_pipeline", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(20, HIGH_TR_BASE + 0x8000)),
        (0x80, *movl_mlx(5, 130)),
        (0x90, 0x01, nop_m(), nop_i(), nop_i()),
        (0xa0, 0x00, alloc_m(9, 32, 32, 4, 0),
         mov_i_imm_ar(66, 1), mov_lc_gr(5)),
        (0xb0, *movl_mlx(19, (1 << 13) | (1 << 17))),
        (0xc0, 0x08, mov_gr_psr_full(19), srlz_d(), nop_i()),
        (0xd0, 0x00, nop_m(), mov_pr_rot_imm(0x10000), nop_i()),
        (0xe0, 0x00, ld8_s_postinc(32, 20, 8, qp=16), nop_i(), nop_i()),
        (0xf0, 0x10, nop_m(), adds(8, 0, 34, qp=18),
         br_ctop_many(0xf0, 0xe0)),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x100)),
        *(raw_bundle(0x408000 + i * 8, _br_ctop_spec_data[i],
                     _br_ctop_spec_data[i + 1])
          for i in range(0, len(_br_ctop_spec_data), 2)),
    ], {"exception": IA64_EXCP_NONE, "ip": 0x100,
        "r8": 129, "r20": HIGH_TR_BASE + 0x8418}, entry=0x10)

_strcpy_pipeline_data = [0x6d6e6f7071727374] * 126 + [0, 0]
test_br_ctop_strcpy_pipeline_stops_on_first_zero_word = require_registers(
    "br_ctop_strcpy_pipeline_stops_on_first_zero_word", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(20, HIGH_TR_BASE + 0x8000)),
        (0x80, *movl_mlx(19, HIGH_TR_BASE + 0xc000)),
        (0x90, *movl_mlx(21, HIGH_TR_BASE + 0xc000 + 1000)),
        (0xa0, *movl_mlx(5, -1)),
        (0xb0, *movl_mlx(17, (1 << 13) | (1 << 17))),
        (0xc0, 0x08, mov_gr_psr_full(17), srlz_d(), nop_i()),
        (0xd0, 0x00, alloc(2, 32, 2, 4, 0), mov_lc_imm(-1), nop_i()),
        # Enter through a taken branch, as optimized library routines do.
        # This also prevents a fall-through TB from executing the first loop
        # iteration while it still contains the pipeline setup.
        (0xe0, 0x11, nop_m(), mov_pr_rot_imm(0x10000),
         br_cond(0xe0, 0xf0)),
        # This is the three-stage software pipeline used by an IA-64
        # word-at-a-time string copy: speculative load, check/zero search,
        # then store.  The stop after slot 1 in the second bundle is
        # intentional and matches the compare-to-branch dependency group.
        (0xf0, 0x00, ld8_s_postinc(32, 20, 8, qp=16),
         chk_s_i(34, 0xf0, 0x200, qp=18), nop_i()),
        (0x100, 0x02, adds(31, 0, 34, qp=18),
         czx1_r(24, 34, qp=18), cmp_eq_imm(0, 7, 8, 24, qp=18)),
        (0x110, 0x10, nop_m(), nop_i(), br_cond(0x110, 0x140, qp=7)),
        (0x120, 0x11, st8_postinc(19, 34, 8, qp=18), nop_i(),
         br_ctop_few(0x120, 0xf0)),
        # Match the byte tail as well as the pipelined word loop.  Merely
        # checking the last bulk store leaves an early exit undetected when
        # the untouched destination bytes happen to be zero.
        (0x140, 0x00, nop_m(), mov_lc_gr(24), nop_i()),
        (0x150, 0x01, nop_m(), extr_u(27, 31, 0, 8),
         shr_u_imm(31, 31, 8)),
        (0x160, 0x11, st1_postinc(19, 27, 1), nop_i(),
         br_cloop(0x160, 0x150)),
        (0x170, 0x00, ld8_postinc(9, 21, 8), nop_i(), nop_i()),
        (0x180, 0x00, ld1(10, 21), adds(8, 0, 19), nop_i()),
        (0x190, 0x10, nop_m(), nop_i(), br_cond(0x190, 0x190)),
        (0x200, 0x10, nop_m(), nop_i(), br_cond(0x200, 0x200)),
        *(raw_bundle(0x408000 + i * 8, _strcpy_pipeline_data[i],
                     _strcpy_pipeline_data[i + 1])
          for i in range(0, len(_strcpy_pipeline_data), 2)),
        *(raw_bundle(0x40c000 + i * 16, 0x5a5a5a5a5a5a5a5a,
                     0x5a5a5a5a5a5a5a5a)
          for i in range(64)),
    ], {"exception": IA64_EXCP_NONE, "ip": 0x190,
        "r8": HIGH_TR_BASE + 0xc000 + 1009,
        "r9": 0x6d6e6f7071727374, "r10": 0}, entry=0x10)

test_br_ctop_strcpy_pipeline_survives_cover_rfi = require_registers(
    "br_ctop_strcpy_pipeline_survives_cover_rfi", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(20, HIGH_TR_BASE + 0x8000)),
        (0x80, *movl_mlx(19, HIGH_TR_BASE + 0xc000)),
        (0x90, *movl_mlx(21, HIGH_TR_BASE + 0xc000 + 1000)),
        (0xa0, *movl_mlx(5, -1)),
        (0xb0, *movl_mlx(17, (1 << 13) | (1 << 17) | (1 << 44))),
        (0xc0, 0x08, mov_gr_psr_full(17), srlz_d(), nop_i()),
        (0xd0, 0x00, alloc(2, 32, 2, 4, 0), mov_lc_gr(5), nop_i()),
        (0xe0, 0x00, nop_m(), mov_pr_rot_imm(0x10000), nop_i()),
        (0xf0, 0x00, ld8_s_postinc(32, 20, 8, qp=16),
         chk_s_i(34, 0xf0, 0x250, qp=18), nop_i()),
        (0x100, 0x02, adds(31, 0, 34, qp=18),
         czx1_r(24, 34, qp=18), cmp_eq_imm(0, 7, 8, 24, qp=18)),
        (0x110, 0x00, nop_m(), adds(30, 1, 30),
         cmp4_eq_imm(6, 0, 129, 30)),
        (0x120, 0x10, nop_m(), nop_i(), br_cond(0x120, 0x200, qp=6)),
        (0x130, 0x10, nop_m(), nop_i(), br_cond(0x130, 0x160, qp=7)),
        (0x140, 0x11, st8_postinc(19, 34, 8, qp=18), nop_i(),
         br_ctop_few(0x140, 0xf0)),
        (0x160, 0x00, ld8_postinc(9, 21, 8), nop_i(), nop_i()),
        (0x170, 0x00, ld8(10, 21), adds(8, 0, 19), nop_i()),
        (0x180, 0x10, nop_m(), nop_i(), br_cond(0x180, 0x180)),
        (0x200, 0x00, break_m(0x42), nop_i(), nop_i()),
        (0x250, 0x10, nop_m(), nop_i(), br_cond(0x250, 0x250)),
        (IA64_BREAK_VECTOR, 0x10, nop_m(), nop_i(), cover_b()),
        (IA64_BREAK_VECTOR + 0x10, *movl_mlx(14, 0x130)),
        (IA64_BREAK_VECTOR + 0x20, 0x00, mov_m_gr_cr(14, 19), nop_i(),
         nop_i()),
        (IA64_BREAK_VECTOR + 0x30, 0x10, nop_m(), nop_i(), rfi_b()),
        *(raw_bundle(0x408000 + i * 8, _strcpy_pipeline_data[i],
                     _strcpy_pipeline_data[i + 1])
          for i in range(0, len(_strcpy_pipeline_data), 2)),
    ], {"exception": IA64_EXCP_NONE, "ip": 0x180,
        "r8": HIGH_TR_BASE + 0xc000 + 1008,
        "r9": 0x6d6e6f7071727374, "r10": 0,
        "r30": 129}, entry=0x10)

test_br_call_ret_strcpy_pipeline_stops_on_first_zero_word = require_registers(
    "br_call_ret_strcpy_pipeline_stops_on_first_zero_word", [
        *dtr_setup_bundles(0x10, HIGH_TR_BASE, 0x400000),
        (0x70, *movl_mlx(17, (1 << 13) | (1 << 17))),
        (0x80, 0x08, mov_gr_psr_full(17), srlz_d(), nop_i()),
        (0x90, 0x00, nop_m(), alloc(2, 3, 1, 0, 0), nop_i()),
        (0xa0, *movl_mlx(33, HIGH_TR_BASE + 0xc000)),
        (0xb0, *movl_mlx(34, HIGH_TR_BASE + 0x8000)),
        (0xc0, 0x10, nop_m(), nop_i(), br_call(0, 0xc0, 0x200)),
        (0xd0, *movl_mlx(21, HIGH_TR_BASE + 0xc000 + 1000)),
        (0xe0, 0x00, ld8_postinc(9, 21, 8), nop_i(), nop_i()),
        (0xf0, 0x00, ld8(10, 21), nop_i(), nop_i()),
        (0x100, 0x10, nop_m(), nop_i(), br_cond(0x100, 0x100)),
        (0x200, 0x00, nop_m(), alloc(2, 32, 2, 4, 0), nop_i()),
        (0x210, 0x00, nop_m(), adds(19, 0, 32), adds(20, 0, 33)),
        (0x220, 0x00, nop_m(), adds(8, 0, 32), nop_i()),
        (0x230, *movl_mlx(5, -1)),
        (0x240, 0x00, nop_m(), mov_lc_gr(5), nop_i()),
        (0x250, 0x00, nop_m(), mov_pr_rot_imm(0x10000), nop_i()),
        (0x260, 0x00, ld8_s_postinc(32, 20, 8, qp=16),
         chk_s_i(34, 0x260, 0x2f0, qp=18), nop_i()),
        (0x270, 0x02, adds(31, 0, 34, qp=18),
         czx1_r(24, 34, qp=18), cmp_eq_imm(0, 7, 8, 24, qp=18)),
        (0x280, 0x10, nop_m(), nop_i(), br_cond(0x280, 0x2c0, qp=7)),
        (0x290, 0x11, st8_postinc(19, 34, 8, qp=18), nop_i(),
         br_ctop_few(0x290, 0x260)),
        (0x2c0, 0x10, nop_m(), nop_i(), br_ret(0)),
        (0x2f0, 0x10, nop_m(), nop_i(), br_cond(0x2f0, 0x2f0)),
        *(raw_bundle(0x408000 + i * 8, _strcpy_pipeline_data[i],
                     _strcpy_pipeline_data[i + 1])
          for i in range(0, len(_strcpy_pipeline_data), 2)),
    ], {"exception": IA64_EXCP_NONE, "ip": 0x100,
        "r8": HIGH_TR_BASE + 0xc000,
        "r9": 0x6d6e6f7071727374, "r10": 0}, entry=0x10)

test_br_ctop_rotates_floating_registers = require_registers(
    "br_ctop_rotates_floating_registers", [
        (0x10, *movl_mlx(2, 0x12345678)),
        # LC=95 plus the one epilog stage executes exactly 96 rotations.
        # The complete rotating FR bank must return to its original mapping.
        (0x20, 0x01, setf_sig(32, 2), mov_lc_imm(95),
         mov_i_imm_ar(66, 1)),
        (0x30, 0x13, nop_m(), nop_b(), br_ctop_many(0x30, 0x30)),
        (0x40, 0x10, nop_m(), nop_i(),
         br_cond(0x40, 0x40)),
    ], {
        "ip": 0x40,
        "f32": ExpectedFP(0x12345678, 0x1003e),
        "cfm_rrb_fr": 0,
    }, entry=0x10)

test_br_wtop_false_predicate_drains_epilog = require_registers(
    "br_wtop_false_predicate_drains_epilog", [
        (0x10, 0x00, nop_m(), mov_i_imm_ar(66, 2), nop_i()),
        (0x20, 0x13, nop_m(), nop_b(), br_wtop(0x20, 0x50, qp=16)),
        (0x30, 0x00, adds(4, 0x11, 0), nop_i(), nop_i()),
        (0x40, 0x10, nop_m(), nop_i(), br_cond(0x40, 0x80)),
        (0x50, 0x00, adds(4, 0x5a, 0), nop_i(), nop_i()),
        (0x60, 0x13, nop_m(), nop_b(), br_wtop(0x60, 0x50, qp=16)),
        (0x70, 0x00, nop_m(), mov_i_ar_gr(5, 66), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r4": 0x5a, "r5": 0}, entry=0x10)

test_br_wexit_false_predicate_drains_epilog = require_registers(
    "br_wexit_false_predicate_drains_epilog", [
        (0x10, 0x00, nop_m(), mov_i_imm_ar(66, 2), nop_i()),
        (0x20, 0x13, nop_m(), nop_b(), br_wexit(0x20, 0x70, qp=16)),
        (0x30, 0x00, nop_m(), mov_i_ar_gr(4, 66), nop_i()),
        (0x40, 0x13, nop_m(), nop_b(), br_wexit(0x40, 0x70, qp=16)),
        (0x50, 0x00, adds(6, 0x11, 0), nop_i(), nop_i()),
        (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x80)),
        (0x70, 0x00, nop_m(), mov_i_ar_gr(5, 66), nop_i()),
        (0x80, 0x10, nop_m(), nop_i(), br_cond(0x80, 0x80)),
    ], {"ip": 0x80, "r4": 1, "r5": 0, "r6": 0}, entry=0x10)

test_pmc_pmd_registers_are_independent = require_registers("pmc_pmd_registers_are_independent", [
    (0x10, 0x00, adds(9, 1, 0), adds(20, 0x77, 0),
     nop_i()),
    (0x20, 0x00, mov_grpmc_indexed(9, 20), adds(21, 0x55, 0),
     nop_i()),
    (0x30, 0x00, mov_grpmd_indexed(9, 21), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_pmcgr_indexed(30, 9), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_pmdgr_indexed(31, 9), nop_i(),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "exception": IA64_EXCP_NONE,
    "r30": 0x77,
    "r31": 0x55,
}, entry=0x10)

test_pmc_pmd_indexed_decode = require_registers("pmc_pmd_indexed_decode", [
    (0x10, 0x00, adds(9, 1, 0), adds(10, 0x77, 0),
     nop_i()),
    (0x20, 0x00, adds(11, 2, 0), adds(12, 0x55, 0),
     nop_i()),
    (0x30, 0x00, mov_grpmc_indexed(9, 10, bit36=1), nop_i(),
     nop_i()),
    (0x40, 0x00, mov_grpmd_indexed(11, 12, bit36=1), nop_i(),
     nop_i()),
    (0x50, 0x00, mov_pmcgr_indexed(30, 9, bit36=1), nop_i(),
     nop_i()),
    (0x60, 0x00, mov_pmdgr_indexed(31, 11, bit36=1), nop_i(),
     nop_i()),
    (0x70, 0x10, nop_m(), nop_i(),
     br_cond(0x70, 0x70)),
], {
    "ip": 0x70,
    "exception": IA64_EXCP_NONE,
    "r30": 0x77,
    "r31": 0x55,
}, entry=0x10)

# cmp.ge.or: compare r3 >= 0 (signed), OR into predicates.
# r39 = 5 (positive), so GE 0 is true → p13 OR'd with 1 → p13=1.
# r39 is then set to 0 which equals 0, so GE 0 is still true → p14 OR'd → p14=1.
test_cmp_ge_or_decode = require_registers("cmp_ge_or_decode", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(13, 14, 0, 16),
     nop_i()),
    (0x20, 0x00, adds(29, 5, 0), cmp_ge_or(13, 14, 29),
     nop_i()),
    (0x30, 0x00, adds(29, 0, 0), cmp_ge_or(14, 13, 29),
     nop_i()),
    (0x40, 0x02, nop_m(), adds(4, 1, 0, qp=13),
     adds(5, 1, 0, qp=14)),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": 1, "r5": 1}, entry=0x10)

test_cmp_ge_or_issue_raw_decode = require_registers("cmp_ge_or_issue_raw_decode", [
    (0x10, 0x00, adds(16, 1, 0), cmp_ltu_unc(13, 14, 0, 16),
     nop_i()),
    (0x20, 0x00, adds(27, -5, 0), adds(28, -1, 0),
     nop_i()),
    (0x30, 0x00, nop_m(), cmp_ge_or_issue_raw(7, 50, 28, 0x57, qp=13),
     nop_i()),
    (0x40, 0x02, nop_m(), adds(4, 1, 0, qp=7),
     nop_i()),
    (0x50, 0x10, nop_m(), nop_i(),
     br_cond(0x50, 0x50)),
], {"ip": 0x50, "r4": 1}, entry=0x10)

test_cmp_ge_and_decode = require_registers("cmp_ge_and_decode", [
    (0x10, 0x00, cmp4_eq_imm(6, 7, 0, 0), nop_i(),
     nop_i()),
    (0x20, 0x00, adds(3, -1, 0), cmp_ge_and(6, 7, 3, ignored=0x48),
     nop_i()),
    (0x30, 0x02, nop_m(), adds(4, 1, 0, qp=6),
     adds(5, 1, 0, qp=7)),
    (0x40, 0x10, nop_m(), nop_i(),
     br_cond(0x40, 0x40)),
], {"ip": 0x40, "r4": 1, "r5": 0}, entry=0x10)

test_cmp_ge_or_andcm_issue_raw_decode = require_registers(
    "cmp_ge_or_andcm_issue_raw_decode", [
        (0x10, 0x00, adds(3, -1, 0),
         cmp_ge_or_andcm_issue_raw(6, 7, 3, ignored=0x19),
         nop_i()),
        (0x20, 0x02, nop_m(), adds(4, 1, 0, qp=6),
         adds(5, 1, 0, qp=7)),
        (0x30, 0x10, nop_m(), nop_i(),
         br_cond(0x30, 0x30)),
    ], {"ip": 0x30, "r4": 1, "r5": 0}, entry=0x10)

# fselect: f1 = (f3 AND f2) OR (f4 AND NOT f2)
# f2 (mask) = 0xFF00, f3 = 0x1234, f4 = 0x5678
# result = (0x1234 & 0xFF00) | (0x5678 & ~0xFF00)
#        = 0x1200 | 0x0078 = 0x1278
test_fselect_decode = require_registers("fselect_decode", [
    (0x10, 0x00, addl(24, 0xFF00 & 0x1FFFFF, 0),
     addl(25, 0x1234, 0), nop_i()),
    (0x20, 0x00, addl(26, 0x5678, 0), nop_i(),
     nop_i()),
    (0x30, 0x09, setf_sig(6, 24), setf_sig(7, 25),
     nop_i()),
    (0x40, 0x09, setf_sig(8, 26), nop_m(),
     nop_i()),
    (0x50, 0x0d, nop_m(), fselect(10, 6, 7, 8),
     nop_i()),
    (0x60, 0x10, nop_m(), nop_i(),
     br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "f10": ExpectedFP(0x1278, 0x1003e),
    "ar_fpsr": DEFAULT_FPSR,
}, entry=0x10)

test_fselect_natval_propagates = require_registers(
    "fselect_natval_propagates", [
        (0x10, 0x00, mov_m_imm_ar(36, 1), addl(6, 0x200, 0),
         nop_i()),
        (0x20, 0x08, ld8_fill_postinc(3, 6, 0), nop_i(),
         nop_i()),
        (0x30, 0x09, ldf8_s(7, 3), setf_sig(8, 0),
         nop_i()),
        (0x40, 0x0d, nop_m(), fselect(10, 8, 7, 8),
         nop_i()),
        (0x50, 0x10, nop_m(), nop_i(), br_cond(0x50, 0x80)),
        (0x60, 0x10, nop_m(), nop_i(),
         br_cond(0x60, 0x60)),
        (0x80, 0x10, nop_m(), nop_i(),
         br_cond(0x80, 0x80)),
        (0x200, 0x00, 0, 0,
         0),
    ], {
        "ip": 0x80,
        "f10": ExpectedFP(0, 0x1fffe, nat=True),
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    },
    entry=0x10)


test_mux1_brcst_decode = require_registers("mux1_brcst_decode", [
    (0x10, 0x00, nop_m(), adds(14, 0x5a, 0), mux1(1, 14, 0)),
    (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
], {
    "ip": 0x20,
    "r1": 0x5a5a5a5a5a5a5a5a,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_scalar_shift_count_64 = require_registers("scalar_shift_count_64", [
    (0x10, *movl_mlx(14, UINT64_MAX)),
    (0x20, 0x00, nop_m(), adds(15, 64, 0), adds(16, 1, 0)),
    (0x30, 0x00, nop_m(), adds(17, -16, 0), shr_u_var(1, 14, 15)),
    (0x40, 0x00, nop_m(), shl_var(2, 16, 15), shr_var(3, 17, 15)),
    (0x50, 0x00, nop_m(), shr_var(4, 16, 15), nop_i()),
    (0x60, 0x10, nop_m(), nop_i(), br_cond(0x60, 0x60)),
], {
    "ip": 0x60,
    "r1": 0,
    "r2": 0,
    "r3": UINT64_MAX,
    "r4": 0,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_mov_ip_current_bundle = require_registers("mov_ip_current_bundle", [
    (0x10, 0x00, nop_m(), mov_ip(1), mov_ip(2)),
    (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
], {
    "ip": 0x20,
    "r1": 0x10,
    "r2": 0x10,
    "exception": IA64_EXCP_NONE,
}, entry=0x10)

test_brp_loop_imp_decode = require_registers("brp_loop_imp_decode", [
    (0x10, 0x10, nop_m(), adds(1, 1, 0), brp_loop_imp()),
    (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
], {"ip": 0x20, "r1": 1, "exception": IA64_EXCP_NONE}, entry=0x10)

test_brp_sptk_decode = require_registers("brp_sptk_decode", [
    (0x10, 0x10, nop_m(), adds(1, 1, 0), brp_sptk()),
    (0x20, 0x10, nop_m(), nop_i(), br_cond(0x20, 0x20)),
], {"ip": 0x20, "r1": 1, "exception": IA64_EXCP_NONE}, entry=0x10)

test_predicate_register_roundtrip = require_registers(
    "predicate_register_roundtrip", [
        (0x10, 0x00, nop_m(), adds(1, 0xa, 0), mov_gr_pr(1, 0xe)),
        (0x20, 0x00, nop_m(), mov_pr_gr(4), mov_gr_pr(4, -2)),
        (0x30, 0x10, nop_m(), nop_i(), br_cond(0x30, 0x30)),
    ], {
        "ip": 0x30,
        "r4": 0xb,
        "pr_mask": 0xb,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)


def _fp_representation_case(name, value, width, model):
    if width == 32:
        value &= 0xffffffff
        integer_store, fp_load = st4, ldfs
        fp_set, fp_get, fp_store, integer_load = setf_s, getf_s, stfs, ld4
        spill_to_binary = spill_to_binary32
    elif width == 64:
        value &= UINT64_MAX
        integer_store, fp_load = st8, ldfd
        fp_set, fp_get, fp_store, integer_load = setf_d, getf_d, stfd, ld8
        spill_to_binary = spill_to_binary64
    else:
        raise ValueError("FP representation width must be 32 or 64")

    low, high = model(value)
    memory_value = spill_to_binary(low, high)
    case = require_registers(name, [
        (0x10, *movl_mlx(2, value)),
        (0x20, 0x00, addl(3, 0x200, 0), addl(4, 0x210, 0), nop_i()),
        (0x30, 0x00, integer_store(3, 2), nop_i(), nop_i()),
        (0x40, 0x00, fp_load(6, 3), nop_i(), nop_i()),
        (0x50, 0x00, fp_set(7, 2), nop_i(), nop_i()),
        (0x60, 0x00, fp_get(5, 6), nop_i(), nop_i()),
        (0x70, 0x00, fp_store(4, 7), nop_i(), nop_i()),
        (0x80, 0x00, integer_load(8, 4), nop_i(), nop_i()),
        (0x90, 0x10, nop_m(), nop_i(), br_cond(0x90, 0x90)),
    ], {
        "ip": 0x90,
        "f6": ExpectedFP(low, high),
        "f7": ExpectedFP(low, high),
        "r5": memory_value,
        "r8": memory_value,
        "ar_fpsr": DEFAULT_FPSR,
        "exception": IA64_EXCP_NONE,
    }, entry=0x10)
    case.__name__ = "test_" + name
    return case


FP_REPRESENTATION_CASES = {}
for _width, _vectors, _model in (
        (32, BINARY32_EDGE_VECTORS + deterministic_words(32, 12),
         binary32_to_spill),
        (64, BINARY64_EDGE_VECTORS + deterministic_words(64, 12),
         binary64_to_spill)):
    for _index, _value in enumerate(_vectors):
        _name = f"fpmodel_binary{_width}_{_index:02d}"
        FP_REPRESENTATION_CASES[_name] = _fp_representation_case(
            _name, _value, _width, _model)


TEST_NAMES = {
    "pmc_pmd_registers_are_independent": test_pmc_pmd_registers_are_independent,
    "pmc_pmd_indexed_decode": test_pmc_pmd_indexed_decode,
    "gcc_alloc_and_ar_lc": test_gcc_alloc_and_ar_lc,
    "chk_s_m_branches_on_nat": test_chk_s_m_branches_on_nat,
    "chk_s_f_decode": test_chk_s_f_decode,
    "chk_a_nc_m_decode": test_chk_a_nc_m_decode,
    "mlx_chk_a_clr_nop_x_decode": test_mlx_chk_a_clr_nop_x_decode,
    "mlx_false_predicate_long_nop_decode":
        test_mlx_false_predicate_long_nop_decode,
    "mlx_long_nop_x_imm_decode": test_mlx_long_nop_x_imm_decode,
    "chk_a_m_branches_on_miss": test_chk_a_m_branches_on_miss,
    "chk_a_clr_removes_entry": test_chk_a_clr_removes_entry,
    "invala_e_gr_invalidates_selected_register":
        test_invala_e_gr_invalidates_selected_register,
    "alat_reloading_register_does_not_leave_duplicate":
        test_alat_reloading_register_does_not_leave_duplicate,
    "invala_clears_all_alat_entries": test_invala_clears_all_alat_entries,
    "ld8_c_nc_address_mismatch_reloads":
        test_ld8_c_nc_address_mismatch_reloads,
    "ld8_c_clr_address_mismatch_reloads":
        test_ld8_c_clr_address_mismatch_reloads,
    "cmp4_lt_unc_decode": test_cmp4_lt_unc_decode,
    "cmp4_eq_imm_decode": test_cmp4_eq_imm_decode,
    "cmp4_eq_unc_imm_p0_decode": test_cmp4_eq_unc_imm_p0_decode,
    "cmp_ltu_unc_p0_decode": test_cmp_ltu_unc_p0_decode,
    "cmp4_ltu_unc_p0_register_decode":
        test_cmp4_ltu_unc_p0_register_decode,
    "cmp_ltu_imm_negative_decode": test_cmp_ltu_imm_negative_decode,
    "cmp4_ltu_imm_negative_decode": test_cmp4_ltu_imm_negative_decode,
    "cmp_unc_pred_false_clears": test_cmp_unc_pred_false_clears,
    "cmp4_ltu_unc_imm_pred_false_clears": test_cmp4_ltu_unc_imm_pred_false_clears,
    "cmp_unc_self_predicate_reads_old_qp": test_cmp_unc_self_predicate_reads_old_qp,
    "tbit_unc_pred_false_clears": test_tbit_unc_pred_false_clears,
    "cmp_same_pred_illegal": test_cmp_same_pred_illegal,
    "cmp_unc_same_pred_pred_false_illegal":
        test_cmp_unc_same_pred_pred_false_illegal,
    "tbit_same_pred_illegal": test_tbit_same_pred_illegal,
    "tnat_unc_same_pred_pred_false_illegal":
        test_tnat_unc_same_pred_pred_false_illegal,
    "tnat_nz_or_decode": test_tnat_nz_or_decode,
    "tnat_nz_and_ignored_bits_decode":
        test_tnat_nz_and_ignored_bits_decode,
    "tf_feature_predicate_updates": test_tf_feature_predicate_updates,
    "tf_upper_cpuid_feature_bits": test_tf_upper_cpuid_feature_bits,
    "tf_same_pred_illegal": test_tf_same_pred_illegal,
    "tf_unc_same_pred_pred_false_illegal":
        test_tf_unc_same_pred_pred_false_illegal,
    "cmp_eq_and_decode": test_cmp_eq_and_decode,
    "cmp_ne_and_parallel_semantics": test_cmp_ne_and_parallel_semantics,
    "ws2003_compare_update_decode": test_ws2003_compare_update_decode,
    "cmp4_ge_or_andcm_decode": test_cmp4_ge_or_andcm_decode,
    "cmp_ne_or_andcm_decode": test_cmp_ne_or_andcm_decode,
    "cmp_ne_or_andcm_imm_negative_decode": test_cmp_ne_or_andcm_imm_negative_decode,
    "cmp4_ne_or_andcm_decode": test_cmp4_ne_or_andcm_decode,
    "cmp4_eq_ne_or_decode": test_cmp4_eq_ne_or_decode,
    "cmp_imm_update_decode": test_cmp_imm_update_decode,
    "cmp_lt_unc_imm_decode": test_cmp_lt_unc_imm_decode,
    "dep_decode": test_dep_decode,
    "extr_u_ignored_bit36_decode": test_extr_u_ignored_bit36_decode,
    "extr_signed_truncates_overlong_field":
        test_extr_signed_truncates_overlong_field,
    "dep_source_alias_decode": test_dep_source_alias_decode,
    "page_frame_record_address_arithmetic":
        test_page_frame_record_address_arithmetic,
    "page_table_pointer_dep_cascade": test_page_table_pointer_dep_cascade,
    "high_ram_above_4g_physical_and_translated_access":
        test_high_ram_above_4g_physical_and_translated_access,
    "long_vhpt_large_page_high_ram_subword_remap":
        test_long_vhpt_large_page_high_ram_subword_remap,
    "st4_variants_preserve_adjacent_halfword":
        test_st4_variants_preserve_adjacent_halfword,
    "load_x6_18_reserved_illegal_operation":
        test_load_x6_18_reserved_illegal_operation,
    "load_x6_19_reserved_illegal_operation":
        test_load_x6_19_reserved_illegal_operation,
    "load_x6_1a_reserved_illegal_operation":
        test_load_x6_1a_reserved_illegal_operation,
    "load_postinc_x6_18_reserved_illegal_operation":
        test_load_postinc_x6_18_reserved_illegal_operation,
    "load_postinc_x6_19_reserved_illegal_operation":
        test_load_postinc_x6_19_reserved_illegal_operation,
    "load_postinc_x6_1a_reserved_illegal_operation":
        test_load_postinc_x6_1a_reserved_illegal_operation,
    "store_x6_38_reserved_illegal_operation":
        test_store_x6_38_reserved_illegal_operation,
    "store_x6_39_reserved_illegal_operation":
        test_store_x6_39_reserved_illegal_operation,
    "store_x6_3a_reserved_illegal_operation":
        test_store_x6_3a_reserved_illegal_operation,
    "store_postinc_x6_38_reserved_illegal_operation":
        test_store_postinc_x6_38_reserved_illegal_operation,
    "store_postinc_x6_39_reserved_illegal_operation":
        test_store_postinc_x6_39_reserved_illegal_operation,
    "store_postinc_x6_3a_reserved_illegal_operation":
        test_store_postinc_x6_3a_reserved_illegal_operation,
    "depz_decode": test_depz_decode,
    "depz_len64_decode": test_depz_len64_decode,
    "ld1_acq_decode": test_ld1_acq_decode,
    "ld4_bias_decode": test_ld4_bias_decode,
    "ld8_c_nc_hit_preserves_target": test_ld8_c_nc_hit_preserves_target,
    "ld8_c_nc_hit_consumes_nat_base": test_ld8_c_nc_hit_consumes_nat_base,
    "ld8_c_clr_hit_clears_entry": test_ld8_c_clr_hit_clears_entry,
    "ld4_c_clr_hit_clears_entry": test_ld4_c_clr_hit_clears_entry,
    "zero_alat_check_load_always_reloads":
        test_zero_alat_check_load_always_reloads,
    "zero_alat_chk_a_always_branches": test_zero_alat_chk_a_always_branches,
    "ld8_sa_failure_invalidates_old_entry": test_ld8_sa_failure_invalidates_old_entry,
    "ld8_a_uc_zeroes_target_and_skips_alat":
        test_ld8_a_uc_zeroes_target_and_skips_alat,
    "ld8_s_uc_defers": test_ld8_s_uc_defers,
    "ld16_loads_gr_and_csd": test_ld16_loads_gr_and_csd,
    "ld16_acq_hint_decode": test_ld16_acq_hint_decode,
    "ld16_uc_unsupported_data_reference":
        test_ld16_uc_unsupported_data_reference,
    "st16_stores_gr_and_csd": test_st16_stores_gr_and_csd,
    "st16_rel_stores_gr_and_csd": test_st16_rel_stores_gr_and_csd,
    "st16_uc_unsupported_data_reference":
        test_st16_uc_unsupported_data_reference,
    "cmp8xchg16_uc_unsupported_data_reference":
        test_cmp8xchg16_uc_unsupported_data_reference,
    "ld16_madison_illegal_operation": test_ld16_madison_illegal_operation,
    "st16_madison_illegal_operation": test_st16_madison_illegal_operation,
    "cmp8xchg16_madison_illegal_operation":
        test_cmp8xchg16_madison_illegal_operation,
    "memory_order_completers_decode": test_memory_order_completers_decode,
    "data_big_endian_load_store": test_data_big_endian_load_store,
    "data_big_endian_cmpxchg4": test_data_big_endian_cmpxchg4,
    "data_big_endian_stf_spill_ldf_fill":
        test_data_big_endian_stf_spill_ldf_fill,
    "data_big_endian_ldfe_stfe": test_data_big_endian_ldfe_stfe,
    "ldfs_expands_single_memory_format":
        test_ldfs_expands_single_memory_format,
    "ldfs_preserves_single_nan_payload":
        test_ldfs_preserves_single_nan_payload,
    "ldfps_expands_both_single_values":
        test_ldfps_expands_both_single_values,
    "stfs_stfd_convert_register_format":
        test_stfs_stfd_convert_register_format,
    "getf_exact_register_format_translation":
        test_getf_exact_register_format_translation,
    "stf8_stfe_convert_register_format":
        test_stf8_stfe_convert_register_format,
    "stfs_natval_consumption": test_stfs_natval_consumption,
    "stfd_natval_consumption": test_stfd_natval_consumption,
    "stf8_natval_consumption": test_stf8_natval_consumption,
    "stfe_natval_consumption": test_stfe_natval_consumption,
    "stf_spill_preserves_natval": test_stf_spill_preserves_natval,
    "store_invalidates_advanced_load": test_store_invalidates_advanced_load,
    "rse_call_invalidates_stacked_alat": test_rse_call_invalidates_stacked_alat,
    "semaphore_ops_invalidate_advanced_loads": test_semaphore_ops_invalidate_advanced_loads,
    "xchg4_result_base_alias_invalidates_alat":
        test_xchg4_result_base_alias_invalidates_alat,
    "fetchadd4_result_base_alias_invalidates_alat":
        test_fetchadd4_result_base_alias_invalidates_alat,
    "cmpxchg4_result_base_alias_success_invalidates_alat":
        test_cmpxchg4_result_base_alias_success_invalidates_alat,
    "cmpxchg4_result_base_alias_failure_keeps_alat":
        test_cmpxchg4_result_base_alias_failure_keeps_alat,
    "cmpxchg4_full_ar_ccv_compare": test_cmpxchg4_full_ar_ccv_compare,
    "semaphore_ops_clear_result_nat": test_semaphore_ops_clear_result_nat,
    "fetchadd4_alt_dtlb_sets_read_write_isr":
        test_fetchadd4_alt_dtlb_sets_read_write_isr,
    "fetchadd4_unaligned_sets_read_write_isr":
        test_fetchadd4_unaligned_sets_read_write_isr,
    "fetchadd4_nat_base_sets_read_write_isr":
        test_fetchadd4_nat_base_sets_read_write_isr,
    "normal_load_clears_stale_nat": test_normal_load_clears_stale_nat,
    "integer_nat_propagates_and_clears": test_integer_nat_propagates_and_clears,
    "integer_compare_nat_source_rules": test_integer_compare_nat_source_rules,
    "tbit_nat_source_rules": test_tbit_nat_source_rules,
    "normal_load_consumes_nat_base": test_normal_load_consumes_nat_base,
    "nat_consumption_sets_ifa_isr": test_nat_consumption_sets_ifa_isr,
    "nat_store_data_consumption_is_access": test_nat_store_data_consumption_is_access,
    "speculative_load_defers_nat_base": test_speculative_load_defers_nat_base,
    "speculative_load_defers_psr_ed": test_speculative_load_defers_psr_ed,
    "speculative_load_no_recovery_tlb_miss_faults":
        test_speculative_load_no_recovery_tlb_miss_faults,
    "speculative_load_defers_via_dcr_without_ed":
        test_speculative_load_defers_via_dcr_without_ed,
    "speculative_load_handler_psr_ed_defers_retry":
        test_speculative_load_handler_psr_ed_defers_retry,
    "speculative_unaligned_no_recovery_faults":
        test_speculative_unaligned_no_recovery_faults,
    "speculative_unimplemented_physical_unaligned_defers":
        test_speculative_unimplemented_physical_unaligned_defers,
    "unimplemented_physical_load_faults":
        test_unimplemented_physical_load_faults,
    "unimplemented_physical_precludes_unaligned":
        test_unimplemented_physical_precludes_unaligned,
    "unimplemented_physical_instruction_traps":
        test_unimplemented_physical_instruction_traps,
    "speculative_recovery_dcr_dm_defers_tlb_miss":
        test_speculative_recovery_dcr_dm_defers_tlb_miss,
    "speculative_recovery_dcr_da_defers_access_bit":
        test_speculative_recovery_dcr_da_defers_access_bit,
    "speculative_recovery_dcr_dk_defers_key_miss":
        test_speculative_recovery_dcr_dk_defers_key_miss,
    "speculative_recovery_unaligned_defers":
        test_speculative_recovery_unaligned_defers,
    "ws2003_cmd646_unaligned_check_load_sets_ed":
        test_ws2003_cmd646_unaligned_check_load_sets_ed,
    "ld8_s_d2_hint_decode": test_ld8_s_d2_hint_decode,
    "mov_crgr_clears_stale_nat": test_mov_crgr_clears_stale_nat,
    "lfetch_decode": test_lfetch_decode,
    "lfetch_nonfault_suppresses_translation_fault":
        test_lfetch_nonfault_suppresses_translation_fault,
    "lfetch_fault_checks_translation":
        test_lfetch_fault_checks_translation,
    "hint_m_decode": test_hint_m_decode,
    "hint_i_decode": test_hint_i_decode,
    "xma_h_decode": test_xma_h_decode,
    "xma_hu_decode": test_xma_hu_decode,
    "xma_natval_propagates": test_xma_natval_propagates,
    "fnorm_normalizes_setf_sig_payload": test_fnorm_normalizes_setf_sig_payload,
    "getf_exp_after_fnorm_sig": test_getf_exp_after_fnorm_sig,
    "fpabs_fpneg_decode": test_fpabs_fpneg_decode,
    "fmerge_forms_decode": test_fmerge_forms_decode,
    "fmerge_natval_propagates": test_fmerge_natval_propagates,
    "fminmax_scalar_decode": test_fminmax_scalar_decode,
    "fminmax_scalar_tie_uses_f3": test_fminmax_scalar_tie_uses_f3,
    "fp_logical_and_swap_decode": test_fp_logical_and_swap_decode,
    "fp_logical_swap_natval_propagates": test_fp_logical_swap_natval_propagates,
    "fp_mix_sign_extend_decode": test_fp_mix_sign_extend_decode,
    "fp_mix_sign_extend_natval_propagates": test_fp_mix_sign_extend_natval_propagates,
    "fpsr_status_field_controls": test_fpsr_status_field_controls,
    "fpsr_td_suppresses_fp_fault": test_fpsr_td_suppresses_fp_fault,
    "fsetc_sf0_td_reserved_field_fault":
        test_fsetc_sf0_td_reserved_field_fault,
    "fsetc_pc1_reserved_field_fault": test_fsetc_pc1_reserved_field_fault,
    "fsetc_fclrf_ignored_bit36_decode":
        test_fsetc_fclrf_ignored_bit36_decode,
    "fchkf_no_branch_when_flags_committed": test_fchkf_no_branch_when_flags_committed,
    "fchkf_branches_on_uncommitted_flag": test_fchkf_branches_on_uncommitted_flag,
    "fchkf_positive_target_ignores_bit26":
        test_fchkf_positive_target_ignores_bit26,
    "fchkf_negative_target_uses_bit36":
        test_fchkf_negative_target_uses_bit36,
    "fcmp_invalid_fault_restores_predicates":
        test_fcmp_invalid_fault_restores_predicates,
    "fcmp_p2_high_bit_not_fchkfs": test_fcmp_p2_high_bit_not_fchkfs,
    "fpmerge_parallel_forms_decode": test_fpmerge_parallel_forms_decode,
    "fpminmax_parallel_decode": test_fpminmax_parallel_decode,
    "fpminmax_simd_high_lane_fault_isr":
        test_fpminmax_simd_high_lane_fault_isr,
    "fpminmax_nan_invalid_fault":
        test_fpminmax_nan_invalid_fault,
    "fpcmp_parallel_decode": test_fpcmp_parallel_decode,
    "fpcmp_simd_high_lane_fault_isr":
        test_fpcmp_simd_high_lane_fault_isr,
    "fp_parallel_natval_propagates": test_fp_parallel_natval_propagates,
    "fpcvt_parallel_decode": test_fpcvt_parallel_decode,
    "fpcvt_parallel_natval_propagates": test_fpcvt_parallel_natval_propagates,
    "fpcvt_simd_high_lane_fault_isr":
        test_fpcvt_simd_high_lane_fault_isr,
    "fpma_parallel_decode": test_fpma_parallel_decode,
    "fpma_parallel_natval_propagates": test_fpma_parallel_natval_propagates,
    "fpma_simd_high_lane_fault_isr":
        test_fpma_simd_high_lane_fault_isr,
    "fp_unary_natval_propagates": test_fp_unary_natval_propagates,
    "fp_arithmetic_natval_propagates": test_fp_arithmetic_natval_propagates,
    "getf_natval_sets_gr_nat": test_getf_natval_sets_gr_nat,
    "fpack_decode": test_fpack_decode,
    "frsqrta_decode": test_frsqrta_decode,
    "frsqrta_pred_false_clears": test_frsqrta_pred_false_clears,
    "frsqrta_special_returns_operand": test_frsqrta_special_returns_operand,
    "frsqrta_swa_fault_discards_result":
        test_frsqrta_swa_fault_discards_result,
    "fprsqrta_decode": test_fprsqrta_decode,
    "fprsqrta_simd_high_lane_fault_isr":
        test_fprsqrta_simd_high_lane_fault_isr,
    "setf_exp_decode": test_setf_exp_decode,
    "setf_sig_ignored_bits_decode": test_setf_sig_ignored_bits_decode,
    "getf_sig_ignored_bits_decode": test_getf_sig_ignored_bits_decode,
    "w2k_fp_s1_pred_false_decode": test_w2k_fp_s1_pred_false_decode,
    "fma_d_s0_decode": test_fma_d_s0_decode,
    "fnmpy_s_s1_decode": test_fnmpy_s_s1_decode,
    "fsub_d_s0_decode": test_fsub_d_s0_decode,
    "fmpy_s0_decode": test_fmpy_s0_decode,
    "fmpy_s_s1_decode": test_fmpy_s_s1_decode,
    "fms_s3_decode": test_fms_s3_decode,
    "fnma_d_s1_decode": test_fnma_d_s1_decode,
    "fclass_m_decode": test_fclass_m_decode,
    "fclass_m_ignored_bits_decode": test_fclass_m_ignored_bits_decode,
    "fclass_same_pred_pred_false_noop":
        test_fclass_same_pred_pred_false_noop,
    "fcmp_natval_clears_predicates": test_fcmp_natval_clears_predicates,
    "fcmp_status_field_decode": test_fcmp_status_field_decode,
    "fcmp_same_pred_illegal": test_fcmp_same_pred_illegal,
    "fclass_unc_same_pred_pred_false_illegal":
        test_fclass_unc_same_pred_pred_false_illegal,
    "fcvt_fxu_double_to_uint": test_fcvt_fxu_double_to_uint,
    "fcvt_fxu_rounds_sf0": test_fcvt_fxu_rounds_sf0,
    "fcvt_fx_signed_trunc": test_fcvt_fx_signed_trunc,
    "fcvt_fxu_preserves_sig_payload": test_fcvt_fxu_preserves_sig_payload,
    "fcvt_xf_signed_sig_to_float": test_fcvt_xf_signed_sig_to_float,
    "fcvt_xf_ignores_prior_precision": test_fcvt_xf_ignores_prior_precision,
    "fcvt_xf_reads_register_significand":
        test_fcvt_xf_reads_register_significand,
    "fcvt_xf_extreme_signed_round_trip":
        test_fcvt_xf_extreme_signed_round_trip,
    "fcvt_xf_natval_propagates": test_fcvt_xf_natval_propagates,
    "umodsi3_hash_remainder": test_umodsi3_hash_remainder,
    "setf_sig_direct_scalar_operand": test_setf_sig_direct_scalar_operand,
    "fr1_is_read_only_one": test_fr1_is_read_only_one,
    "w2k_frcpa_capacity_calc": test_w2k_frcpa_capacity_calc,
    "coreutils_hash_bucket_float_division":
        test_coreutils_hash_bucket_float_division,
    "ws2003_vga_frcpa_integer_division":
        test_ws2003_vga_frcpa_integer_division,
    "frcpa_setf_sig_high_integer_remainder":
        test_frcpa_setf_sig_high_integer_remainder,
    "frcpa_double_normal_reciprocal": test_frcpa_double_normal_reciprocal,
    "frcpa_swa_fault_discards_result":
        test_frcpa_swa_fault_discards_result,
    "frcpa_special_quotient": test_frcpa_special_quotient,
    "frcpa_pred_false_clears": test_frcpa_pred_false_clears,
    "frcpa_p2_high_bits_decode": test_frcpa_p2_high_bits_decode,
    "frcpa_natval_propagates": test_frcpa_natval_propagates,
    "fprcpa_decode": test_fprcpa_decode,
    "fprcpa_simd_high_lane_fault_isr":
        test_fprcpa_simd_high_lane_fault_isr,
    "ld1_postinc_decode": test_ld1_postinc_decode,
    "ld1_reg_postinc_decode": test_ld1_reg_postinc_decode,
    "ld1_reg_postinc_uses_old_increment": test_ld1_reg_postinc_uses_old_increment,
    "ld_reg_postinc_same_target_illegal":
        test_ld_reg_postinc_same_target_illegal,
    "ld_imm_postinc_same_target_illegal":
        test_ld_imm_postinc_same_target_illegal,
    "ld_postinc_same_target_predicated_false":
        test_ld_postinc_same_target_predicated_false,
    "ld1_sa_postinc_decode": test_ld1_sa_postinc_decode,
    "ld8_nt1_postinc_decode": test_ld8_nt1_postinc_decode,
    "memory_cache_hints_decode": test_memory_cache_hints_decode,
    "ld8_fill_st8_spill_postinc_decode": test_ld8_fill_st8_spill_postinc_decode,
    "ld8_fill_restores_unat_bit": test_ld8_fill_restores_unat_bit,
    "st8_spill_updates_unat_bit": test_st8_spill_updates_unat_bit,
    "integer_postinc_imm9_decode": test_integer_postinc_imm9_decode,
    "ldf8_decode": test_ldf8_decode,
    "ldfd_loads_double_memory_format": test_ldfd_loads_double_memory_format,
    "ldf8_s_chk_s_f_defers_nat_base": test_ldf8_s_chk_s_f_defers_nat_base,
    "ldf8_a_chk_a_f_hit": test_ldf8_a_chk_a_f_hit,
    "ldf8_c_nc_hit_preserves_target": test_ldf8_c_nc_hit_preserves_target,
    "ldf8_c_nc_hit_consumes_nat_base": test_ldf8_c_nc_hit_consumes_nat_base,
    "ldf8_a_uc_zeroes_target_and_skips_alat":
        test_ldf8_a_uc_zeroes_target_and_skips_alat,
    "fp_alat_does_not_satisfy_gr_check_load": test_fp_alat_does_not_satisfy_gr_check_load,
    "invala_e_fp_invalidates_selected_register":
        test_invala_e_fp_invalidates_selected_register,
    "ldfp8_postinc_decode": test_ldfp8_postinc_decode,
    "ldf_fill_postinc_decode": test_ldf_fill_postinc_decode,
    "ldf8_loads_integer_register_format": test_ldf8_loads_integer_register_format,
    "ldf8_f1_does_not_change_fixed_register":
        test_ldf8_f1_does_not_change_fixed_register,
    "stf_spill_ldf_fill_preserves_sig": test_stf_spill_ldf_fill_preserves_sig,
    "st1_postinc_decode": test_st1_postinc_decode,
    "st8_postinc_same_base_value_uses_old_base":
        test_st8_postinc_same_base_value_uses_old_base,
    "cmpxchg4_uses_ar_ccv": test_cmpxchg4_uses_ar_ccv,
    "xchg4_decode": test_xchg4_decode,
    "cmpxchg4_repeated_word_updates": test_cmpxchg4_repeated_word_updates,
    "cmpxchg4_region7_store": test_cmpxchg4_region7_store,
    "cmp8xchg16_acq_stores_pair": test_cmp8xchg16_acq_stores_pair,
    "cmp8xchg16_rel_mismatch_keeps_pair":
        test_cmp8xchg16_rel_mismatch_keeps_pair,
    "cmp8xchg16_unaligned": test_cmp8xchg16_unaligned,
    "natpage_load_raises_nat_consumption":
        test_natpage_load_raises_nat_consumption,
    "natpage_store_raises_nat_consumption":
        test_natpage_store_raises_nat_consumption,
    "natpage_xchg_raises_nat_consumption":
        test_natpage_xchg_raises_nat_consumption,
    "natpage_unaligned_store_outranks_unaligned":
        test_natpage_unaligned_store_outranks_unaligned,
    "unaligned_store_reports_unaligned_when_mapped":
        test_unaligned_store_reports_unaligned_when_mapped,
    "natpage_speculative_load_defers":
        test_natpage_speculative_load_defers,
    "natpage_short_vhpt_load_raises_nat_consumption":
        test_natpage_short_vhpt_load_raises_nat_consumption,
    "natpage_instruction_fetch_raises_nat_consumption":
        test_natpage_instruction_fetch_raises_nat_consumption,
    "cmp8xchg16_natpage_consumption":
        test_cmp8xchg16_natpage_consumption,
    "cmpxchg4_acq_region7_store": test_cmpxchg4_acq_region7_store,
    "andcm_imm_negative_mask_round_trip": test_andcm_imm_negative_mask_round_trip,
    "stf_spill_postinc_decode": test_stf_spill_postinc_decode,
    "stf8_postinc_imm9_decode": test_stf8_postinc_imm9_decode,
    "stf8_postinc_stores_setf_sig": test_stf8_postinc_stores_setf_sig,
    "stfe_stores_extended_float": test_stfe_stores_extended_float,
    "ldfe_stfe_preserves_extended_payload":
        test_ldfe_stfe_preserves_extended_payload,
    "fma_preserves_extended_precision":
        test_fma_preserves_extended_precision,
    "fp_divzero_fault_discards_result":
        test_fp_divzero_fault_discards_result,
    "fp_inexact_trap_commits_result":
        test_fp_inexact_trap_commits_result,
    "probe_r_fault_ignored_fields_decode":
        test_probe_r_fault_ignored_fields_decode,
    "probe_w_imm_decode": test_probe_w_imm_decode,
    "probe_result_clears_destination_nat":
        test_probe_result_clears_destination_nat,
    "probe_stacked_result_survives_call_return":
        test_probe_stacked_result_survives_call_return,
    "probe_r_register_level_nat_consumption":
        test_probe_r_register_level_nat_consumption,
    "probe_w_register_level_nat_consumption":
        test_probe_w_register_level_nat_consumption,
    "probe_w_dt_disabled_miss_raises_alt_dtlb":
        test_probe_w_dt_disabled_miss_raises_alt_dtlb,
    "probe_w_dt_disabled_ic_clear_miss_raises_data_nested_tlb":
        test_probe_w_dt_disabled_ic_clear_miss_raises_data_nested_tlb,
    "probe_w_dt_enabled_miss_raises_alt_dtlb":
        test_probe_w_dt_enabled_miss_raises_alt_dtlb,
    "probe_w_clean_page_dirty_bit_not_checked":
        test_probe_w_clean_page_dirty_bit_not_checked,
    "probe_r_insufficient_privilege_returns_zero":
        test_probe_r_insufficient_privilege_returns_zero,
    "probe_natpage_outranks_key_miss":
        test_probe_natpage_outranks_key_miss,
    "probe_natpage_outranks_access_rights":
        test_probe_natpage_outranks_access_rights,
    "probe_natpage_outranks_access_bit":
        test_probe_natpage_outranks_access_bit,
    "probe_natpage_outranks_dirty_bit":
        test_probe_natpage_outranks_dirty_bit,
    "probe_natpage_reports_isr_ed_zero":
        test_probe_natpage_reports_isr_ed_zero,
    "probe_not_present_outranks_natpage":
        test_probe_not_present_outranks_natpage,
    "probe_r_fault_natpage_isr_code":
        test_probe_r_fault_natpage_isr_code,
    "probe_rw_fault_natpage_isr_code":
        test_probe_rw_fault_natpage_isr_code,
    "lfetch_fault_natpage_isr_code":
        test_lfetch_fault_natpage_isr_code,
    "load_reg_postinc_x6_18_reserved_illegal_operation":
        test_load_reg_postinc_x6_18_reserved_illegal_operation,
    "load_reg_postinc_x6_19_reserved_illegal_operation":
        test_load_reg_postinc_x6_19_reserved_illegal_operation,
    "load_reg_postinc_x6_1a_reserved_illegal_operation":
        test_load_reg_postinc_x6_1a_reserved_illegal_operation,
    "probe_r_natpage_dtr_raises_nat_consumption":
        test_probe_r_natpage_dtr_raises_nat_consumption,
    "probe_r_fault_natpage_raises_nat_consumption":
        test_probe_r_fault_natpage_raises_nat_consumption,
    "probe_w_natpage_short_vhpt_walk_raises_nat_consumption":
        test_probe_w_natpage_short_vhpt_walk_raises_nat_consumption,
    "probe_r_dt_disabled_natpage_raises_nat_consumption":
        test_probe_r_dt_disabled_natpage_raises_nat_consumption,
    "probe_dt_disabled_maintenance_bits_grant":
        test_probe_dt_disabled_maintenance_bits_grant,
    "probe_w_dt_disabled_key_miss_raises_data_key_miss":
        test_probe_w_dt_disabled_key_miss_raises_data_key_miss,
    "probe_r_dt_disabled_key_read_disable_returns_zero":
        test_probe_r_dt_disabled_key_read_disable_returns_zero,
    "probe_w_dt_disabled_key_write_disable_returns_zero":
        test_probe_w_dt_disabled_key_write_disable_returns_zero,
    "sxt1_decode": test_sxt1_decode,
    "mov_lc_imm_decode": test_mov_lc_imm_decode,
    "mov_lc_negative_imm_sign_extends":
        test_mov_lc_negative_imm_sign_extends,
    "mov_br_hint_decode": test_mov_br_hint_decode,
    "mov_m_imm_ar_decode": test_mov_m_imm_ar_decode,
    "mov_m_negative_imm_ar_sign_extends":
        test_mov_m_negative_imm_ar_sign_extends,
    "mov_m_cr_gr_decode": test_mov_m_cr_gr_decode,
    "itr_i_indexed_decode": test_itr_i_indexed_decode,
    "itr_i_slot_uses_low_8_bits": test_itr_i_slot_uses_low_8_bits,
    "itr_i_reserved_slot_faults": test_itr_i_reserved_slot_faults,
    "itr_i_resumes_next_slot_after_tb_exit":
        test_itr_i_resumes_next_slot_after_tb_exit,
    "itr_i_8k_translation_uses_unrounded_paddr":
        test_itr_i_8k_translation_uses_unrounded_paddr,
    "it_only_keeps_data_physical": test_it_only_keeps_data_physical,
    "data_physical_uc_bit_aliases_wbl_space":
        test_data_physical_uc_bit_aliases_wbl_space,
    "itr_i_uses_region_rid": test_itr_i_uses_region_rid,
    "itc_d_uses_source_pte_and_cr_ifa": test_itc_d_uses_source_pte_and_cr_ifa,
    "itc_d_pl0_user_read_faults": test_itc_d_pl0_user_read_faults,
    "br_ret_cpl_change_does_not_reuse_kernel_tlb":
        test_br_ret_cpl_change_does_not_reuse_kernel_tlb,
    "itc_d_replaces_full_tc": test_itc_d_replaces_full_tc,
    "itc_d_full_tc_replacement_rotates": test_itc_d_full_tc_replacement_rotates,
    "itc_d_evicted_refill_flushes_host_tlb":
        test_itc_d_evicted_refill_flushes_host_tlb,
    "itr_d_all_tr_slots_survive_tc_churn":
        test_itr_d_all_tr_slots_survive_tc_churn,
    "itc_d_preserves_24bit_key": test_itc_d_preserves_24bit_key,
    "itc_d_4g_page_size_reserved_field_fault":
        test_itc_d_4g_page_size_reserved_field_fault,
    "itr_d_4g_page_size_reserved_field_fault":
        test_itr_d_4g_page_size_reserved_field_fault,
    "itc_d_present_reserved_pte_field_fault":
        test_itc_d_present_reserved_pte_field_fault,
    "itc_i_present_reserved_pte_field_fault":
        test_itc_i_present_reserved_pte_field_fault,
    "itc_d_present_reserved_itir_field_fault":
        test_itc_d_present_reserved_itir_field_fault,
    "itc_d_present_reserved_ma_field_fault":
        test_itc_d_present_reserved_ma_field_fault,
    "itc_d_not_present_rejects_low_itir_reserved_field":
        test_itc_d_not_present_rejects_low_itir_reserved_field,
    "itc_d_not_present_raises_page_fault":
        test_itc_d_not_present_raises_page_fault,
    "tak_not_present_dtlb_returns_one":
        test_tak_not_present_dtlb_returns_one,
    "itc_d_clear_accessed_raises_data_access_bit":
        test_itc_d_clear_accessed_raises_data_access_bit,
    "itc_d_clear_dirty_raises_dirty_bit":
        test_itc_d_clear_dirty_raises_dirty_bit,
    "itc_d_clean_page_read_fill_store_raises_dirty_bit":
        test_itc_d_clean_page_read_fill_store_raises_dirty_bit,
    "data_dirty_rfi_retries_word_store_once":
        test_data_dirty_rfi_retries_word_store_once,
    "data_dirty_rfi_preserves_bank1_word_store":
        test_data_dirty_rfi_preserves_bank1_word_store,
    "itc_d_clear_accessed_store_precedes_access_bit":
        test_itc_d_clear_accessed_store_precedes_access_bit,
    "itc_d_psr_da_suppresses_one_data_access_bit":
        test_itc_d_psr_da_suppresses_one_data_access_bit,
    "itc_d_data_key_miss_raises_key_vector":
        test_itc_d_data_key_miss_raises_key_vector,
    "itc_d_key_permission_store_raises_permission_vector":
        test_itc_d_key_permission_store_raises_permission_vector,
    "itc_d_matching_pkr_allows_keyed_load":
        test_itc_d_matching_pkr_allows_keyed_load,
    "ssm_pk_invalidates_cached_keyless_access":
        test_ssm_pk_invalidates_cached_keyless_access,
    "tpa_key_miss_raises_data_key_miss":
        test_tpa_key_miss_raises_data_key_miss,
    "probe_w_key_miss_raises_data_key_miss":
        test_probe_w_key_miss_raises_data_key_miss,
    "itr_i_instruction_key_miss_raises_key_vector":
        test_itr_i_instruction_key_miss_raises_key_vector,
    "itc_i_m_unit_decode": test_itc_i_m_unit_decode,
    "itc_i_resumes_next_slot_after_tb_exit":
        test_itc_i_resumes_next_slot_after_tb_exit,
    "ptc_l_4g_page_size_is_purgeable":
        test_ptc_l_4g_page_size_is_purgeable,
    "ptc_l_keeps_nonoverlapping_tc": test_ptc_l_keeps_nonoverlapping_tc,
    "ptc_l_does_not_clear_local_alat":
        test_ptc_l_does_not_clear_local_alat,
    "ar_itc_advances_in_guest_loop": test_ar_itc_advances_in_guest_loop,
    "cloop_zero_st1_timer_interrupts_batched_loop":
        test_cloop_zero_st1_timer_interrupts_batched_loop,
    "cloop_zero_st1_invalidates_alat_range":
        test_cloop_zero_st1_invalidates_alat_range,
    "cloop_zero_st1_clears_cross_page_range":
        test_cloop_zero_st1_clears_cross_page_range,
    "mov_to_ivr_illegal": test_mov_to_ivr_illegal,
    "mov_to_irr_illegal": test_mov_to_irr_illegal,
    "mov_to_read_only_cr_predicate_false":
        test_mov_to_read_only_cr_predicate_false,
    "async_timer_interrupt_enters_ivt": test_async_timer_interrupt_enters_ivt,
    "async_timer_interrupt_records_boundary_ri": test_async_timer_interrupt_records_boundary_ri,
    "async_timer_interrupt_never_resumes_mlx_slot2":
        test_async_timer_interrupt_never_resumes_mlx_slot2,
    "repeated_timer_rfi_preserves_word_rmw":
        test_repeated_timer_rfi_preserves_word_rmw,
    "timer_interrupt_preserves_banked_word_rmw":
        test_timer_interrupt_preserves_banked_word_rmw,
    "timer_cover_rfi_preserves_large_frame_halfword_rmw":
        test_timer_cover_rfi_preserves_large_frame_halfword_rmw,
    "ld2_bias_st2_raw_large_frame_sequence":
        test_ld2_bias_st2_raw_large_frame_sequence,
    "rse_small_kernel_frame_preserves_counter_across_spill_calls":
        test_rse_small_kernel_frame_preserves_counter_across_spill_calls,
    "rse_large_frame_timer_rfi_preserves_high_caller_local":
        test_rse_large_frame_timer_rfi_preserves_high_caller_local,
    "rse_seventy_output_handoff_preserves_kernel_locals":
        test_rse_seventy_output_handoff_preserves_kernel_locals,
    "timer_interrupt_exits_chained_loop_after_virtual_deadline":
        test_timer_interrupt_exits_chained_loop_after_virtual_deadline,
    "async_timer_interrupt_preserves_bank1_grs": test_async_timer_interrupt_preserves_bank1_grs,
    "tpr_preserves_mmi_and_mic": test_tpr_preserves_mmi_and_mic,
    "tpr_mmi_masks_timer_until_cleared": test_tpr_mmi_masks_timer_until_cleared,
    "sapic_extint_masks_external_until_eoi":
        test_sapic_extint_masks_external_until_eoi,
    "sapic_same_class_higher_vector_preempts":
        test_sapic_same_class_higher_vector_preempts,
    "pal_halt_light_stops_at_pal_continuation":
        test_pal_halt_light_stops_at_pal_continuation,
    "pal_halt_light_wakes_on_due_itm": test_pal_halt_light_wakes_on_due_itm,
    "pal_halt_wakes_on_due_itm": test_pal_halt_wakes_on_due_itm,
    "masked_itv_discards_due_timer": test_masked_itv_discards_due_timer,
    "invalid_itv_vector_is_ignored": test_invalid_itv_vector_is_ignored,
    "past_itm_does_not_fire": test_past_itm_does_not_fire,
    "past_rearmed_itm_does_not_interrupt":
        test_past_rearmed_itm_does_not_interrupt,
    "ptr_i_preserves_non_overlapping_itr": test_ptr_i_preserves_non_overlapping_itr,
    "ptr_i_purges_matching_itr_by_address": test_ptr_i_purges_matching_itr_by_address,
    "ptr_alt_decode": test_ptr_alt_decode,
    "alt_itlb_when_vhpt_disabled": test_alt_itlb_when_vhpt_disabled,
    "alt_dtlb_when_vhpt_disabled": test_alt_dtlb_when_vhpt_disabled,
    "alt_dtlb_preserves_iha": test_alt_dtlb_preserves_iha,
    "alt_itlb_preserves_iha": test_alt_itlb_preserves_iha,
    "dtlb_miss_slot1_resumes_without_replaying_slot0":
        test_dtlb_miss_slot1_resumes_without_replaying_slot0,
    "dtlb_fault_itir_uses_region_rid": test_dtlb_fault_itir_uses_region_rid,
    "itr_i_survives_region_register_write": test_itr_i_survives_region_register_write,
    "itr_i_match_ignores_vrn": test_itr_i_match_ignores_vrn,
    "itr_i_cached_translation_survives_region_register_write":
        test_itr_i_cached_translation_survives_region_register_write,
    "dtr_match_ignores_vrn": test_dtr_match_ignores_vrn,
    "alt_itlb_when_vhpt_ic_disabled": test_alt_itlb_when_vhpt_ic_disabled,
    "data_nested_tlb_when_vhpt_ic_disabled": test_data_nested_tlb_when_vhpt_ic_disabled,
    "ssm_ic_inflight_dtlb_sets_ni": test_ssm_ic_inflight_dtlb_sets_ni,
    "rsm_ic_inflight_dtlb_not_data_nested":
        test_rsm_ic_inflight_dtlb_not_data_nested,
    "rsm_ic_serialized_data_nested_tlb":
        test_rsm_ic_serialized_data_nested_tlb,
    "exception_entry_initializes_psr": test_exception_entry_initializes_psr,
    "exception_preserves_translation_bits": test_exception_preserves_translation_bits,
    "tpa_indexed_decode": test_tpa_indexed_decode,
    "itr_d_slot_uses_low_8_bits": test_itr_d_slot_uses_low_8_bits,
    "itr_d_reserved_slot_faults": test_itr_d_reserved_slot_faults,
    "tpa_dt_disabled_uses_dtlb_entry":
        test_tpa_dt_disabled_uses_dtlb_entry,
    "tpa_region5_kernel_dtr_large_page":
        test_tpa_region5_kernel_dtr_large_page,
    "tpa_dt_disabled_miss_raises_alt_dtlb":
        test_tpa_dt_disabled_miss_raises_alt_dtlb,
    "tpa_uses_short_vhpt_walk": test_tpa_uses_short_vhpt_walk,
    "short_vhpt_walker_rejects_pending_table_purge":
        test_short_vhpt_walker_rejects_pending_table_purge,
    "short_vhpt_walk_uses_dcr_byte_order":
        test_short_vhpt_walk_uses_dcr_byte_order,
    "short_vhpt_reserved_pte_aborts_to_dtlb_miss":
        test_short_vhpt_reserved_pte_aborts_to_dtlb_miss,
    "short_vhpt_walker_ignores_uncacheable_mapping":
        test_short_vhpt_walker_ignores_uncacheable_mapping,
    "tak_uses_short_vhpt_walk": test_tak_uses_short_vhpt_walk,
    "short_vhpt_not_present_raises_page_fault":
        test_short_vhpt_not_present_raises_page_fault,
    "short_vhpt_not_present_entry_is_cached":
        test_short_vhpt_not_present_entry_is_cached,
    "short_vhpt_entry_not_present_aborts_to_dtlb_miss":
        test_short_vhpt_entry_not_present_aborts_to_dtlb_miss,
    "ssm_ic_inflight_short_vhpt_entry_miss_raises_vhpt":
        test_ssm_ic_inflight_short_vhpt_entry_miss_raises_vhpt,
    "probe_fault_short_vhpt_not_present_raises_page_fault":
        test_probe_fault_short_vhpt_not_present_raises_page_fault,
    "short_vhpt_walker_reads_table_at_pl0":
        test_short_vhpt_walker_reads_table_at_pl0,
    "short_vhpt_ifetch_read_only_raises_inst_access":
        test_short_vhpt_ifetch_read_only_raises_inst_access,
    "itr_i_clear_accessed_raises_inst_access_bit":
        test_itr_i_clear_accessed_raises_inst_access_bit,
    "ifetch_page_not_present_after_branch_restarts_slot0":
        test_ifetch_page_not_present_after_branch_restarts_slot0,
    "ifetch_page_not_present_fallthrough_records_faulting_iip":
        test_ifetch_page_not_present_fallthrough_records_faulting_iip,
    "speculative_load_walks_short_vhpt_with_ic_clear":
        test_speculative_load_walks_short_vhpt_with_ic_clear,
    "speculative_load_defers_region6_vhpt_not_present":
        test_speculative_load_defers_region6_vhpt_not_present,
    "region6_short_vhpt_controls_data_mapping":
        test_region6_short_vhpt_controls_data_mapping,
    "region6_tpa_uses_short_vhpt_mapping":
        test_region6_tpa_uses_short_vhpt_mapping,
    "translation_hash_m_unit_decode": test_translation_hash_m_unit_decode,
    "translation_hash_m46_ignored_bits_decode":
        test_translation_hash_m46_ignored_bits_decode,
    "translation_hash_ops_clear_dest_nat":
        test_translation_hash_ops_clear_dest_nat,
    "translation_hash_nat_source_rules":
        test_translation_hash_nat_source_rules,
    "tak_nat_source_consumes_non_access":
        test_tak_nat_source_consumes_non_access,
    "tpa_nat_source_consumes_non_access":
        test_tpa_nat_source_consumes_non_access,
    "mov_ar_nat_source_consumes": test_mov_ar_nat_source_consumes,
    "mov_br_nat_source_consumes": test_mov_br_nat_source_consumes,
    "mov_pr_nat_source_consumes": test_mov_pr_nat_source_consumes,
    "mov_cr_nat_source_consumes": test_mov_cr_nat_source_consumes,
    "mov_psr_nat_source_consumes": test_mov_psr_nat_source_consumes,
    "mov_um_nat_source_consumes": test_mov_um_nat_source_consumes,
    "mov_rr_nat_index_consumes": test_mov_rr_nat_index_consumes,
    "mov_pkr_nat_index_consumes": test_mov_pkr_nat_index_consumes,
    "mov_pmc_nat_value_consumes": test_mov_pmc_nat_value_consumes,
    "mov_cpuid_nat_index_consumes": test_mov_cpuid_nat_index_consumes,
    "itc_d_nat_pte_consumes": test_itc_d_nat_pte_consumes,
    "itr_d_nat_slot_consumes": test_itr_d_nat_slot_consumes,
    "ptc_l_nat_addr_consumes": test_ptc_l_nat_addr_consumes,
    "ptr_d_nat_size_consumes": test_ptr_d_nat_size_consumes,
    "ptc_e_nat_addr_consumes": test_ptc_e_nat_addr_consumes,
    "fc_nat_source_consumes_non_access":
        test_fc_nat_source_consumes_non_access,
    "setf_nat_source_sets_fr_natval":
        test_setf_nat_source_sets_fr_natval,
    "short_vhpt_thash_decode": test_short_vhpt_thash_decode,
    "thash_uses_pta_with_walker_disabled":
        test_thash_uses_pta_with_walker_disabled,
    "short_vhpt_thash_uses_implemented_va_bits":
        test_short_vhpt_thash_uses_implemented_va_bits,
    "short_vhpt_thash_high_region_self_map":
        test_short_vhpt_thash_high_region_self_map,
    "long_vhpt_walk_uses_standard_entry_layout":
        test_long_vhpt_walk_uses_standard_entry_layout,
    "long_vhpt_walk_uses_dcr_byte_order":
        test_long_vhpt_walk_uses_dcr_byte_order,
    "long_vhpt_same_va_different_rids_refills":
        test_long_vhpt_same_va_different_rids_refills,
    "long_vhpt_not_present_ignores_software_fields":
        test_long_vhpt_not_present_ignores_software_fields,
    "long_vhpt_unsupported_page_size_aborts_to_dtlb_miss":
        test_long_vhpt_unsupported_page_size_aborts_to_dtlb_miss,
    "long_vhpt_walker_does_not_search_collision_chain":
        test_long_vhpt_walker_does_not_search_collision_chain,
    "long_vhpt_table_tlb_miss_raises_vhpt_translation":
        test_long_vhpt_table_tlb_miss_raises_vhpt_translation,
    "long_vhpt_uncacheable_table_aborts_to_dtlb_miss":
        test_long_vhpt_uncacheable_table_aborts_to_dtlb_miss,
    "itr_d_not_present_raises_page_fault":
        test_itr_d_not_present_raises_page_fault,
    "itr_d_8k_translation_uses_unrounded_paddr":
        test_itr_d_8k_translation_uses_unrounded_paddr,
    "itr_d_8k_odd_subpage_store_visible_across_call":
        test_itr_d_8k_odd_subpage_store_visible_across_call,
    "itc_d_virtual_stack_local_passed_as_high_sol_output":
        test_itc_d_virtual_stack_local_passed_as_high_sol_output,
    "itr_d_uses_slot_register_value": test_itr_d_uses_slot_register_value,
    "itr_d_slot_replacement_keeps_old_translation_cached":
        test_itr_d_slot_replacement_keeps_old_translation_cached,
    "itr_d_cached_translation_survives_region_register_write":
        test_itr_d_cached_translation_survives_region_register_write,
    "ptr_d_purge_completes_on_srlz_d": test_ptr_d_purge_completes_on_srlz_d,
    "ptr_d_purge_invalidates_advanced_load":
        test_ptr_d_purge_invalidates_advanced_load,
    "interruption_serializes_pending_ptr_d":
        test_interruption_serializes_pending_ptr_d,
    "region7_untranslated_data_faults": test_region7_untranslated_data_faults,
    "region7_untranslated_user_data_faults":
        test_region7_untranslated_user_data_faults,
    "region7_loader_scratch_store_load": test_region7_loader_scratch_store_load,
    "region7_dtr_controls_data_mapping":
        test_region7_dtr_controls_data_mapping,
    "region7_nonzero_rid_requires_translation":
        test_region7_nonzero_rid_requires_translation,
    "sal_boot_identity_handles_nonzero_region7_rid":
        test_sal_boot_identity_handles_nonzero_region7_rid,
    "sal_boot_identity_does_not_override_explicit_rid_miss":
        test_sal_boot_identity_does_not_override_explicit_rid_miss,
    "sal_boot_identity_region7_directmap_bias":
        test_sal_boot_identity_region7_directmap_bias,
    "region7_kseg_alias_persists_without_sal":
        test_region7_kseg_alias_persists_without_sal,
    "region7_untranslated_high_va_faults":
        test_region7_untranslated_high_va_faults,
    "region6_untranslated_data_faults": test_region6_untranslated_data_faults,
    "region6_untranslated_user_data_faults":
        test_region6_untranslated_user_data_faults,
    "region6_high_dtr_tpa_decode": test_region6_high_dtr_tpa_decode,
    "region6_local_sapic_store": test_region6_local_sapic_store,
    "region6_processor_interrupt_block_inta_read":
        test_region6_processor_interrupt_block_inta_read,
    "region6_processor_interrupt_block_xtp_store":
        test_region6_processor_interrupt_block_xtp_store,
    "firmware_identity_under_translation": test_firmware_identity_under_translation,
    "firmware_identity_ends_after_iva_handoff":
        test_firmware_identity_ends_after_iva_handoff,
    "firmware_identity_does_not_override_user_mapping":
        test_firmware_identity_does_not_override_user_mapping,
    "firmware_runtime_identity_after_iva_handoff":
        test_firmware_runtime_identity_after_iva_handoff,
    "rfi_restores_translation_bits": test_rfi_restores_translation_bits,
    "rfi_serializes_pending_ptr_d": test_rfi_serializes_pending_ptr_d,
    "rfi_serializes_pending_ptr_i": test_rfi_serializes_pending_ptr_i,
    "rfi_resumes_at_ipsr_ri_slot": test_rfi_resumes_at_ipsr_ri_slot,
    "mov_from_psr_does_not_copy_execution_slot_to_rfi":
        test_mov_from_psr_does_not_copy_execution_slot_to_rfi,
    "rfi_ignores_iip_low_bits": test_rfi_ignores_iip_low_bits,
    "czx1_r_zero_index": test_czx1_r_zero_index,
    "czx1_r_no_zero": test_czx1_r_no_zero,
    "czx1_l_zero_index": test_czx1_l_zero_index,
    "czx2_r_zero_index": test_czx2_r_zero_index,
    "czx2_r_ignored_r2_decode": test_czx2_r_ignored_r2_decode,
    "czx2_l_zero_index": test_czx2_l_zero_index,
    "mov_rr_indexed_decode": test_mov_rr_indexed_decode,
    "mov_cpuid_indexed_decode": test_mov_cpuid_indexed_decode,
    "mov_cpuid_madison_model": test_mov_cpuid_madison_model,
    "mov_dahr_indexed_decode": test_mov_dahr_indexed_decode,
    "mov_pkr_indexed_decode": test_mov_pkr_indexed_decode,
    "mov_pkr_does_not_alias_interruption_crs":
        test_mov_pkr_does_not_alias_interruption_crs,
    "mov_pkr_duplicate_key_invalidates_old_slot":
        test_mov_pkr_duplicate_key_invalidates_old_slot,
    "mov_m_psr_gr_decode": test_mov_m_psr_gr_decode,
    "mov_m_gr_psrl_decode": test_mov_m_gr_psrl_decode,
    "cover_b_ignored_fields_decode": test_cover_b_ignored_fields_decode,
    "epc_b_ignored_fields_decode": test_epc_b_ignored_fields_decode,
    "bsw0_clears_bn_bit": test_bsw0_clears_bn_bit,
    "bsw0_in_b_slot_falls_through": test_bsw0_in_b_slot_falls_through,
    "bsw1_sets_bn_bit": test_bsw1_sets_bn_bit,
    "vmsw1_montecito_virtualization_fault":
        test_vmsw1_montecito_virtualization_fault,
    "vmsw0_montecito_virtualization_fault":
        test_vmsw0_montecito_virtualization_fault,
    "vmsw1_madison_illegal_operation": test_vmsw1_madison_illegal_operation,
    "vmsw0_madison_illegal_operation": test_vmsw0_madison_illegal_operation,
    "vmsw_cpl3_montecito_privileged_operation":
        test_vmsw_cpl3_montecito_privileged_operation,
    "vmsw_cpl3_madison_illegal_operation":
        test_vmsw_cpl3_madison_illegal_operation,
    "bsw_switches_r16_r31_bank": test_bsw_switches_r16_r31_bank,
    "bsw_restores_banked_nat": test_bsw_restores_banked_nat,
    "mov_msr_indexed_decode": test_mov_msr_indexed_decode,
    "mov_dbr_ibr_indexed_decode": test_mov_dbr_ibr_indexed_decode,
    "ssm_rsm_decode": test_ssm_rsm_decode,
    "sum_um_rum_decode": test_sum_um_rum_decode,
    "psr_high_mask_and_um_decode": test_psr_high_mask_and_um_decode,
    "mov_psr_um_reserved_bit_fault": test_mov_psr_um_reserved_bit_fault,
    "ptc_e_purges_data_tc_on_srlz_i":
        test_ptc_e_purges_data_tc_on_srlz_i,
    "percpu_alt_dtlb_uses_updated_kr3_after_ptc_e":
        test_percpu_alt_dtlb_uses_updated_kr3_after_ptc_e,
    "br_cloop_decrements_lc": test_br_cloop_decrements_lc,
    "shr_u_imm_decode": test_shr_u_imm_decode,
    "shrp_imm_decode": test_shrp_imm_decode,
    "reserved_a1_x4_5_x2b_1_illegal": test_reserved_a1_x4_5_x2b_1_illegal,
    "mux1_rev_decode": test_mux1_rev_decode,
    "mux2_imm_decode": test_mux2_imm_decode,
    "pcmp1_eq_decode": test_pcmp1_eq_decode,
    "pcmp1_eq_m_slot_decode": test_pcmp1_eq_m_slot_decode,
    "pavg_decode": test_pavg_decode,
    "pminmax_pack_decode": test_pminmax_pack_decode,
    "psad1_decode": test_psad1_decode,
    "fc_i_sync_i_decode": test_fc_i_sync_i_decode,
    "fc_i_invalidates_translated_target": test_fc_i_invalidates_translated_target,
    "fc_i_invalidates_translated_cache_line":
        test_fc_i_invalidates_translated_cache_line,
    "pal_cache_flush_invalidates_translated_target":
        test_pal_cache_flush_invalidates_translated_target,
    "shladdp4_decode": test_shladdp4_decode,
    "padd1_decode": test_padd1_decode,
    "psub1_uuu_decode": test_psub1_uuu_decode,
    "pshladd2_decode": test_pshladd2_decode,
    "pshradd2_decode": test_pshradd2_decode,
    "shl_var_ignored_bit_decode": test_shl_var_ignored_bit_decode,
    "mpy4_decode": test_mpy4_decode,
    "mpyshl4_decode": test_mpyshl4_decode,
    "pshr_decode": test_pshr_decode,
    "pshl_decode": test_pshl_decode,
    "pshl_fixed_complement_count_decode":
        test_pshl_fixed_complement_count_decode,
    "simd_helper_nat_propagates": test_simd_helper_nat_propagates,
    "pshr_nat_propagates": test_pshr_nat_propagates,
    "pshl_nat_propagates": test_pshl_nat_propagates,
    "private_extension_opcode_illegal":
        test_private_extension_opcode_illegal,
    "addp4_decode": test_addp4_decode,
    "addp4_imm_negative_decode": test_addp4_imm_negative_decode,
    "addp4_imm_a4_decode": test_addp4_imm_a4_decode,
    "addp4_imm_positive_decode": test_addp4_imm_positive_decode,
    "cdboot_word_add_cloop_decode": test_cdboot_word_add_cloop_decode,
    "sync_i_ignored_fields_do_not_write_gr":
        test_sync_i_ignored_fields_do_not_write_gr,
    "alloc_m34_ignored_bits_decode": test_alloc_m34_ignored_bits_decode,
    "alloc_predicated_illegal": test_alloc_predicated_illegal,
    "srlz_i_without_pending_itlb_change_keeps_tb_cache":
        test_srlz_i_without_pending_itlb_change_keeps_tb_cache,
    "itlb_mapping_change_keeps_reusable_tb_cache":
        test_itlb_mapping_change_keeps_reusable_tb_cache,
    "srlz_sync_ignored_bit_decode": test_srlz_sync_ignored_bit_decode,
    "fwb_decode": test_fwb_decode,
    "mf_ignored_bit_decode": test_mf_ignored_bit_decode,
    "rse_alloc_call_ret": test_rse_alloc_call_ret,
    "rse_call_sets_callee_input_frame": test_rse_call_sets_callee_input_frame,
    "rse_nested_alloc_call_preserves_output_arg": test_rse_nested_alloc_call_preserves_output_arg,
    "rse_call_uses_high_sol_output_arg": test_rse_call_uses_high_sol_output_arg,
    "rse_call_maps_all_high_output_args":
        test_rse_call_maps_all_high_output_args,
    "rse_call_moves_output_nat_across_word_boundary":
        test_rse_call_moves_output_nat_across_word_boundary,
    "rse_callee_alloc_stores_input_arg": test_rse_callee_alloc_stores_input_arg,
    "rse_alloc_preserves_ar_pfs": test_rse_alloc_preserves_ar_pfs,
    "alloc_clears_destination_nat": test_alloc_clears_destination_nat,
    "br_call_ret_preserves_ec": test_br_call_ret_preserves_ec,
    "rse_bsp_is_current_frame_base": test_rse_bsp_is_current_frame_base,
    "rse_call_ret_updates_bsp_base": test_rse_call_ret_updates_bsp_base,
    "rse_call_ret_preserves_caller_local": test_rse_call_ret_preserves_caller_local,
    "rse_large_callee_preserves_high_caller_local":
        test_rse_large_callee_preserves_high_caller_local,
    "rse_parent_spill_keeps_call_snapshot":
        test_rse_parent_spill_keeps_call_snapshot,
    "rse_call_preserves_same_bundle_local_write":
        test_rse_call_preserves_same_bundle_local_write,
    "rse_cover_skips_trailing_rnat_slot": test_rse_cover_skips_trailing_rnat_slot,
    "rse_bspstore_preserves_dirty_partition_across_rnat":
        test_rse_bspstore_preserves_dirty_partition_across_rnat,
    "rse_loadrs_bspstore_return_uses_covered_frame": test_rse_loadrs_bspstore_return_uses_covered_frame,
    "rse_loadrs_zero_current_frame_invalidates_parents": test_rse_loadrs_zero_current_frame_invalidates_parents,
    "rse_call_ret_preserves_region7_bsp": test_rse_call_ret_preserves_region7_bsp,
    "rse_flushrs_clears_stale_rnat": test_rse_flushrs_clears_stale_rnat,
    "rse_cover_flushrs_spills_covered_frame": test_rse_cover_flushrs_spills_covered_frame,
    "rse_tracked_return_redirties_reused_frame": test_rse_tracked_return_redirties_reused_frame,
    "rse_nested_return_restores_bspstore_base":
        test_rse_nested_return_restores_bspstore_base,
    "rse_deep_call_chain_spills_parent_frames": test_rse_deep_call_chain_spills_parent_frames,
    "rse_evict_parent_frames_preserves_caller_local":
        test_rse_evict_parent_frames_preserves_caller_local,
    "rse_untracked_return_uses_each_rnat_collection":
        test_rse_untracked_return_uses_each_rnat_collection,
    "rse_return_reclaims_clean_keeps_unreached_rnat":
        test_rse_return_reclaims_clean_keeps_unreached_rnat,
    "rse_untracked_return_resyncs_trimmed_rnat":
        test_rse_untracked_return_resyncs_trimmed_rnat,
    "rse_bspstore_keeps_saved_frame": test_rse_bspstore_keeps_saved_frame,
    "rse_firmware_unmatched_return_restores_matching_frame": test_rse_firmware_unmatched_return_restores_matching_frame,
    "rse_untracked_return_redirties_restored_frame": test_rse_untracked_return_redirties_restored_frame,
    "rse_untracked_return_restores_high_caller_local": test_rse_untracked_return_restores_high_caller_local,
    "rse_loadrs_cover_span_restores_embedded_frame": test_rse_loadrs_cover_span_restores_embedded_frame,
    "rse_loadrs_cover_span_uses_preserved_sol":
        test_rse_loadrs_cover_span_uses_preserved_sol,
    "rse_zero_sol_cover_return_restores_bsp_base": test_rse_zero_sol_cover_return_restores_bsp_base,
    "rse_loadrs_zero_sol_return_keeps_bsp_without_cover":
        test_rse_loadrs_zero_sol_return_keeps_bsp_without_cover,
    "rsc_write_clips_pl_to_cpl": test_rsc_write_clips_pl_to_cpl,
    "rse_uses_rsc_pl_for_access_rights": test_rse_uses_rsc_pl_for_access_rights,
    "rse_rt_enables_protection_key_checks":
        test_rse_rt_enables_protection_key_checks,
    "rse_big_endian_backing_store": test_rse_big_endian_backing_store,
    "rse_big_endian_rnat_collection": test_rse_big_endian_rnat_collection,
    "rse_spill_fault_sets_isr_rs": test_rse_spill_fault_sets_isr_rs,
    "rfi_target_rse_fill_fault_uses_restored_psr":
        test_rfi_target_rse_fill_fault_uses_restored_psr,
    "rfi_retries_interrupted_current_frame_fill":
        test_rfi_retries_interrupted_current_frame_fill,
    "rse_rt_translates_with_dt_disabled": test_rse_rt_translates_with_dt_disabled,
    "rse_flushrs_crosses_reverse_mapped_virtual_pages":
        test_rse_flushrs_crosses_reverse_mapped_virtual_pages,
    "rse_bspstore_rewrite_reloads_spilled_frame": test_rse_bspstore_rewrite_reloads_spilled_frame,
    "rse_bspstore_physical_alias_survives_rt_disable": test_rse_bspstore_physical_alias_survives_rt_disable,
    "rse_bspstore_dtlb_miss_retries_spill": test_rse_bspstore_dtlb_miss_retries_spill,
    "rse_br_ret_fill_dtlb_miss_retries_atomically": test_rse_br_ret_fill_dtlb_miss_retries_atomically,
    "rse_rfi_bspstore_rebase_preserves_interrupted_call": test_rse_rfi_bspstore_rebase_preserves_interrupted_call,
    "rse_rfi_same_iip_preserves_interrupted_call_nat":
        test_rse_rfi_same_iip_preserves_interrupted_call_nat,
    "rse_rfi_bspstore_advanced_iip_spills_parent_frame": test_rse_rfi_bspstore_advanced_iip_spills_parent_frame,
    "rse_rfi_does_not_spill_dirty_frame_rnat":
        test_rse_rfi_does_not_spill_dirty_frame_rnat,
    "rse_rfi_does_not_overwrite_trailing_rnat":
        test_rse_rfi_does_not_overwrite_trailing_rnat,
    "rse_rfi_advanced_iip_uses_covered_current_frame": test_rse_rfi_advanced_iip_uses_covered_current_frame,
    "rse_rfi_repeated_cover_uses_latest_current_frame":
        test_rse_rfi_repeated_cover_uses_latest_current_frame,
    "rse_rfi_repeated_cover_preserves_latest_dirty_partition":
        test_rse_rfi_repeated_cover_preserves_latest_dirty_partition,
    "rse_rfi_advanced_iip_bspstore_switch_loads_external_frame":
        test_rse_rfi_advanced_iip_bspstore_switch_loads_external_frame,
    "rse_rfi_advanced_iip_preserves_nested_call_locals": test_rse_rfi_advanced_iip_preserves_nested_call_locals,
    "rse_rfi_bypassed_call_drops_returned_frame":
        test_rse_rfi_bypassed_call_drops_returned_frame,
    "rse_manual_rfi_loadrs_restores_current_frame_base": test_rse_manual_rfi_loadrs_restores_current_frame_base,
    "rse_manual_rfi_smaller_frame_restores_current_frame_base":
        test_rse_manual_rfi_smaller_frame_restores_current_frame_base,
    "rse_rfi_user_context_preserves_loadrs_dirty_partition":
        test_rse_rfi_user_context_preserves_loadrs_dirty_partition,
    "rse_rfi_loadrs_preserves_high_sol_caller_local": test_rse_rfi_loadrs_preserves_high_sol_caller_local,
    "rse_rfi_loadrs_preserves_low_sol_caller_local": test_rse_rfi_loadrs_preserves_low_sol_caller_local,
    "rse_rfi_loadrs_preserves_caller_locals_after_nested_return": test_rse_rfi_loadrs_preserves_caller_locals_after_nested_return,
    "rse_rfi_loadrs_preserves_caller_locals_after_syscall_error": test_rse_rfi_loadrs_preserves_caller_locals_after_syscall_error,
    "rse_rfi_loadrs_preserves_gp_save_after_syscall_error": test_rse_rfi_loadrs_preserves_gp_save_after_syscall_error,
    "rse_exception_loadrs_preserves_interrupted_call": test_rse_exception_loadrs_preserves_interrupted_call,
    "rse_rfi_flushed_interrupted_frame_reads_backing_store":
        test_rse_rfi_flushed_interrupted_frame_reads_backing_store,
    "rse_rfi_flushed_same_iip_uses_interrupted_frame":
        test_rse_rfi_flushed_same_iip_uses_interrupted_frame,
    "rse_rfi_nested_handler_preserves_faulting_frame":
        test_rse_rfi_nested_handler_preserves_faulting_frame,
    "rse_postinc_after_flushrs_preserves_register_value":
        test_rse_postinc_after_flushrs_preserves_register_value,
    "rse_rfi_invalid_ifs_unchanged_stack_restores_call":
        test_rse_rfi_invalid_ifs_unchanged_stack_restores_call,
    "rse_exception_restores_snapshot_arrays": test_rse_exception_restores_snapshot_arrays,
    "rse_exception_flushrs_preserves_high_local": test_rse_exception_flushrs_preserves_high_local,
    "rse_exception_bspstore_restore_skips_unrelated_frame": test_rse_exception_bspstore_restore_skips_unrelated_frame,
    "rse_rfi_context_switch_drops_empty_frame_snapshots": test_rse_rfi_context_switch_drops_empty_frame_snapshots,
    "rse_rfi_invalid_ifs_context_switch_drops_snapshot": test_rse_rfi_invalid_ifs_context_switch_drops_snapshot,
    "rse_rfi_invalid_ifs_same_bspstore_keeps_guest_gr":
        test_rse_rfi_invalid_ifs_same_bspstore_keeps_guest_gr,
    "rse_rfi_invalid_ifs_exact_iip_keeps_guest_gr":
        test_rse_rfi_invalid_ifs_exact_iip_keeps_guest_gr,
    "rse_rfi_unmatched_context_keeps_guest_interruption_resources":
        test_rfi_unmatched_context_keeps_interruption_resources,
    "rse_rfi_cross_region_context_ignores_stale_exception_frame":
        test_rfi_cross_region_context_ignores_stale_exception_frame,
    "rse_rfi_backward_context_ignores_stale_exception_frame":
        test_rfi_backward_context_ignores_stale_exception_frame,
    "rse_loadrs_clamps_stacked_grs": test_rse_loadrs_clamps_stacked_grs,
    "rse_loadrs_sets_tear_point": test_rse_loadrs_sets_tear_point,
    "rse_loadrs_preserves_clean_partial_rnat_collection":
        test_rse_loadrs_preserves_clean_partial_rnat_collection,
    "rse_loadrs_reloads_same_collection_rnat":
        test_rse_loadrs_reloads_same_collection_rnat,
    "rse_return_growth_keeps_dirty_bsp_distance":
        test_rse_return_growth_keeps_dirty_bsp_distance,
    "rse_bspstore_write_rebases_dirty_partition": test_rse_bspstore_write_rebases_dirty_partition,
    "rse_bspstore_rebase_preserves_dirty_cover_prefix":
        test_rse_bspstore_rebase_preserves_dirty_cover_prefix,
    "rse_bspstore_rebase_writes_no_memory":
        test_rse_bspstore_rebase_writes_no_memory,
    "rse_br_ret_fill_ignores_rsc_mode": test_rse_br_ret_fill_ignores_rsc_mode,
    "pal_version": test_pal_version,
    "pal_version_reserved_arg": test_pal_version_reserved_arg,
    "pal_rse_info": test_pal_rse_info,
    "pal_rse_info_reserved_arg": test_pal_rse_info_reserved_arg,
    "pal_vm_summary": test_pal_vm_summary,
    "pal_vm_summary_reserved_arg": test_pal_vm_summary_reserved_arg,
    "pal_cache_summary": test_pal_cache_summary,
    "pal_cache_summary_madison": test_pal_cache_summary_madison,
    "pal_cache_summary_reserved_arg": test_pal_cache_summary_reserved_arg,
    "pal_freq_base": test_pal_freq_base,
    "pal_freq_base_reserved_arg": test_pal_freq_base_reserved_arg,
    "pal_freq_ratios": test_pal_freq_ratios,
    "pal_freq_ratios_madison": test_pal_freq_ratios_madison,
    "pal_freq_ratios_reserved_arg": test_pal_freq_ratios_reserved_arg,
    "pal_freq_ratios_merced": test_pal_freq_ratios_merced,
    "pal_freq_base_merced": test_pal_freq_base_merced,
    "pal_vm_summary_merced": test_pal_vm_summary_merced,
    "pal_prefetch_vis_merced_unimplemented":
        test_pal_prefetch_vis_merced_unimplemented,
    "pal_cache_shared_info_merced_unimplemented":
        test_pal_cache_shared_info_merced_unimplemented,
    "pal_brand_info_merced_unimplemented":
        test_pal_brand_info_merced_unimplemented,
    "pal_logical_to_physical_merced_unimplemented":
        test_pal_logical_to_physical_merced_unimplemented,
    "pal_call_clears_return_reg_nat": test_pal_call_clears_return_reg_nat,
    "cpuid_merced": test_cpuid_merced,
    "pal_vm_page_size": test_pal_vm_page_size,
    "pal_vm_page_size_reserved_arg": test_pal_vm_page_size_reserved_arg,
    "pal_ptce_info": test_pal_ptce_info,
    "pal_ptce_info_reserved_arg": test_pal_ptce_info_reserved_arg,
    "pal_vm_info": test_pal_vm_info,
    "pal_vm_info_l0_data": test_pal_vm_info_l0_data,
    "pal_vm_info_l1_data": test_pal_vm_info_l1_data,
    "pal_vm_info_l1_instruction": test_pal_vm_info_l1_instruction,
    "pal_vm_info_l2_invalid": test_pal_vm_info_l2_invalid,
    "pal_vm_info_invalid": test_pal_vm_info_invalid,
    "pal_vm_tr_read_dtr": test_pal_vm_tr_read_dtr,
    "pal_vm_tr_read_max_dtr": test_pal_vm_tr_read_max_dtr,
    "pal_vm_tr_read_empty": test_pal_vm_tr_read_empty,
    "pal_vm_tr_read_rejects_first_non_tr":
        test_pal_vm_tr_read_rejects_first_non_tr,
    "pal_vm_tr_read_invalid": test_pal_vm_tr_read_invalid,
    "pal_vm_tr_read_misaligned_buffer": test_pal_vm_tr_read_misaligned_buffer,
    "pal_proc_entry_virtual_itr": test_pal_proc_entry_virtual_itr,
    "pal_prefetch_vis": test_pal_prefetch_vis,
    "pal_prefetch_vis_reserved_arg": test_pal_prefetch_vis_reserved_arg,
    "pal_cache_flush": test_pal_cache_flush,
    "pal_cache_flush_coherent_icache": test_pal_cache_flush_coherent_icache,
    "pal_cache_flush_bad_type": test_pal_cache_flush_bad_type,
    "pal_cache_flush_bad_operation": test_pal_cache_flush_bad_operation,
    "pal_cache_init": test_pal_cache_init,
    "pal_cache_init_invalid": test_pal_cache_init_invalid,
    "pal_cache_info": test_pal_cache_info,
    "pal_cache_info_l0_data": test_pal_cache_info_l0_data,
    "pal_cache_info_l1_data": test_pal_cache_info_l1_data,
    "pal_cache_info_l1_instruction": test_pal_cache_info_l1_instruction,
    "pal_cache_info_l2_unified": test_pal_cache_info_l2_unified,
    "pal_cache_info_invalid": test_pal_cache_info_invalid,
    "pal_cache_info_l2_unified_bad_type":
        test_pal_cache_info_l2_unified_bad_type,
    "pal_cache_prot_info": test_pal_cache_prot_info,
    "pal_cache_prot_info_invalid": test_pal_cache_prot_info_invalid,
    "pal_cache_prot_info_unified_bad_type":
        test_pal_cache_prot_info_unified_bad_type,
    "pal_mem_attrib": test_pal_mem_attrib,
    "pal_mem_attrib_reserved_arg": test_pal_mem_attrib_reserved_arg,
    "pal_bus_get_features": test_pal_bus_get_features,
    "pal_bus_get_features_reserved_arg":
        test_pal_bus_get_features_reserved_arg,
    "pal_bus_set_features": test_pal_bus_set_features,
    "pal_bus_set_features_invalid": test_pal_bus_set_features_invalid,
    "pal_proc_set_features": test_pal_proc_set_features,
    "pal_proc_set_features_invalid": test_pal_proc_set_features_invalid,
    "pal_proc_get_features": test_pal_proc_get_features,
    "pal_proc_get_features_montecito_next_set":
        test_pal_proc_get_features_montecito_next_set,
    "pal_proc_get_features_montecito_set18":
        test_pal_proc_get_features_montecito_set18,
    "pal_proc_get_features_montecito_beyond_max":
        test_pal_proc_get_features_montecito_beyond_max,
    "pal_proc_get_features_madison_beyond_max":
        test_pal_proc_get_features_madison_beyond_max,
    "pal_proc_get_features_reserved_arg":
        test_pal_proc_get_features_reserved_arg,
    "pal_logical_to_physical_current":
        test_pal_logical_to_physical_current,
    "pal_logical_to_physical_multicore_thread":
        test_pal_logical_to_physical_multicore_thread,
    "pal_logical_to_physical_madison_unimplemented":
        test_pal_logical_to_physical_madison_unimplemented,
    "pal_cache_shared_info_single_thread":
        test_pal_cache_shared_info_single_thread,
    "pal_cache_shared_info_sibling_thread":
        test_pal_cache_shared_info_sibling_thread,
    "pal_brand_info_string": test_pal_brand_info_string,
    "pal_brand_info_frequency": test_pal_brand_info_frequency,
    "pal_brand_info_cache": test_pal_brand_info_cache,
    "pal_brand_info_bus": test_pal_brand_info_bus,
    "pal_debug_info": test_pal_debug_info,
    "pal_debug_info_reserved_arg": test_pal_debug_info_reserved_arg,
    "pal_register_info_application_implemented":
        test_pal_register_info_application_implemented,
    "pal_register_info_application_side_effects":
        test_pal_register_info_application_side_effects,
    "pal_register_info_control_implemented":
        test_pal_register_info_control_implemented,
    "pal_register_info_control_side_effects":
        test_pal_register_info_control_side_effects,
    "pal_register_info_invalid_request":
        test_pal_register_info_invalid_request,
    "pal_register_info_reserved_arg": test_pal_register_info_reserved_arg,
    "pal_perf_mon_info": test_pal_perf_mon_info,
    "pal_perf_mon_info_bad_buffer": test_pal_perf_mon_info_bad_buffer,
    "pal_perf_mon_info_reserved_arg": test_pal_perf_mon_info_reserved_arg,
    "pal_fixed_addr": test_pal_fixed_addr,
    "pal_fixed_addr_reserved_arg": test_pal_fixed_addr_reserved_arg,
    "pal_platform_addr_interrupt": test_pal_platform_addr_interrupt,
    "pal_platform_addr_ignores_bit63": test_pal_platform_addr_ignores_bit63,
    "pal_platform_addr_io": test_pal_platform_addr_io,
    "pal_platform_addr_bad_type": test_pal_platform_addr_bad_type,
    "pal_platform_addr_unmapped": test_pal_platform_addr_unmapped,
    "pal_mc_clear_log": test_pal_mc_clear_log,
    "pal_copy_info": test_pal_copy_info,
    "pal_copy_info_bad_type": test_pal_copy_info_bad_type,
    "pal_copy_info_ia32_unsupported": test_pal_copy_info_ia32_unsupported,
    "pal_copy_info_platform_for_ia64": test_pal_copy_info_platform_for_ia64,
    "pal_copy_pal_entry_callable": test_pal_copy_pal_entry_callable,
    "pal_copy_pal_ap_entry_callable": test_pal_copy_pal_ap_entry_callable,
    "pal_copy_pal_bad_alloc": test_pal_copy_pal_bad_alloc,
    "pal_copy_pal_bad_alignment": test_pal_copy_pal_bad_alignment,
    "pal_copy_pal_bad_processor": test_pal_copy_pal_bad_processor,
    "pal_halt_info": test_pal_halt_info,
    "pal_halt_invalid_state": test_pal_halt_invalid_state,
    "pal_halt_reserved_arg": test_pal_halt_reserved_arg,
    "pal_halt_info_bad_buffer": test_pal_halt_info_bad_buffer,
    "pal_halt_info_reserved_arg": test_pal_halt_info_reserved_arg,
    "pal_mc_drain": test_pal_mc_drain,
    "pal_mc_drain_reserved_arg": test_pal_mc_drain_reserved_arg,
    "pal_mc_expected": test_pal_mc_expected,
    "pal_mc_dynamic_state_empty": test_pal_mc_dynamic_state_empty,
    "pal_mc_dynamic_state_empty_aligned_offset":
        test_pal_mc_dynamic_state_empty_aligned_offset,
    "pal_mc_dynamic_state_bad_offset": test_pal_mc_dynamic_state_bad_offset,
    "pal_mc_dynamic_state_reserved_arg":
        test_pal_mc_dynamic_state_reserved_arg,
    "pal_mc_error_info_map_empty": test_pal_mc_error_info_map_empty,
    "pal_mc_error_info_structure_empty": test_pal_mc_error_info_structure_empty,
    "pal_mc_error_info_bad_index": test_pal_mc_error_info_bad_index,
    "pal_mc_error_info_bad_level": test_pal_mc_error_info_bad_level,
    "pal_mc_resume_no_context": test_pal_mc_resume_no_context,
    "pal_mc_resume_new_context_no_context":
        test_pal_mc_resume_new_context_no_context,
    "pal_mc_resume_bad_args": test_pal_mc_resume_bad_args,
    "pal_mc_resume_bad_save_ptr": test_pal_mc_resume_bad_save_ptr,
    "pal_mc_register_mem": test_pal_mc_register_mem,
    "pal_cache_line_init": test_pal_cache_line_init,
    "pal_pmi_entrypoint": test_pal_pmi_entrypoint,
    "pal_mem_for_test": test_pal_mem_for_test,
    "pal_test_proc_healthy": test_pal_test_proc_healthy,
    "pal_test_proc_missing_cacheable_attr":
        test_pal_test_proc_missing_cacheable_attr,
    "pal_test_proc_bad_address": test_pal_test_proc_bad_address,
    "pal_test_proc_bad_attributes": test_pal_test_proc_bad_attributes,
    "pal_unknown": test_pal_unknown,
    "popcnt_decode": test_popcnt_decode,
    "clz_decode": test_clz_decode,
    "pmpy2_decode": test_pmpy2_decode,
    "mix_decode": test_mix_decode,
    "unpack2_l_decode": test_unpack2_l_decode,
    "pmpyshr2_decode": test_pmpyshr2_decode,
    "clrrrb_b_decode": test_clrrrb_b_decode,
    "clrrrb_pr_b_decode": test_clrrrb_pr_b_decode,
    "br_ctop_many_decode": test_br_ctop_many_decode,
    "br_cloop_requires_slot2": test_br_cloop_requires_slot2,
    "cover_requires_group_stop": test_cover_requires_group_stop,
    "alloc_requires_group_start": test_alloc_requires_group_start,
    "loadrs_rejects_nonzero_rsc_mode":
        test_loadrs_rejects_nonzero_rsc_mode,
    "reserved_application_register_is_illegal":
        test_reserved_application_register_is_illegal,
    "rsc_reserved_field_fault": test_rsc_reserved_field_fault,
    "ssm_reserved_mask_field_fault": test_ssm_reserved_mask_field_fault,
    "privileged_instruction_rejected_at_cpl3":
        test_privileged_instruction_rejected_at_cpl3,
    "predicated_off_privileged_instruction_does_not_fault":
        test_predicated_off_privileged_instruction_does_not_fault,
    "stacked_gr_destination_out_of_frame":
        test_stacked_gr_destination_out_of_frame,
    "predicated_off_stacked_gr_destination_does_not_fault":
        test_predicated_off_stacked_gr_destination_does_not_fault,
    "postincrement_base_out_of_frame":
        test_postincrement_base_out_of_frame,
    "ldfp_requires_opposite_register_banks":
        test_ldfp_requires_opposite_register_banks,
    "br_ctop_self_loop_budgeted": test_br_ctop_self_loop_budgeted,
    "counted_self_loop_fault_has_slot1_ri":
        test_counted_self_loop_fault_has_slot1_ri,
    "brl_call_mlx_decode": test_brl_call_mlx_decode,
    "brl_call_mlx_no_stop_decode": test_brl_call_mlx_no_stop_decode,
    "brl_call_mlx_negative_lslot_decode":
        test_brl_call_mlx_negative_lslot_decode,
    "brl_cond_mlx_decode": test_brl_cond_mlx_decode,
    "brl_cond_mlx_no_stop_decode": test_brl_cond_mlx_no_stop_decode,
    "hint_x_mlx_decode": test_hint_x_mlx_decode,
    "br_call_indirect_completers_decode":
        test_br_call_indirect_completers_decode,
    "br_indirect_ignores_low_bits": test_br_indirect_ignores_low_bits,
    "br_indirect_predicate_false_falls_through":
        test_br_indirect_predicate_false_falls_through,
    "br_ia_nonzero_qp_illegal": test_br_ia_nonzero_qp_illegal,
    "br_ia_bspstore_mismatch_illegal":
        test_br_ia_bspstore_mismatch_illegal,
    "br_ia_psr_di_disabled_transition_fault":
        test_br_ia_psr_di_disabled_transition_fault,
    "br_ia_montecito_native_ia32_disabled_fault":
        test_br_ia_montecito_native_ia32_disabled_fault,
    "rfi_montecito_native_ia32_disabled_fault":
        test_rfi_montecito_native_ia32_disabled_fault,
    "rfi_montecito_uncollected_transition_preserves_target":
        test_rfi_montecito_uncollected_transition_preserves_target,
    "reserved_indirect_branch_btype_illegal":
        test_reserved_indirect_branch_btype_illegal,
    "reserved_ip_relative_branch_btype_illegal":
        test_reserved_ip_relative_branch_btype_illegal,
    "br_ctop_rotating_pipeline": test_br_ctop_rotating_pipeline,
    "br_ctop_long_rotating_pipeline": test_br_ctop_long_rotating_pipeline,
    "br_ctop_long_speculative_load_pipeline":
        test_br_ctop_long_speculative_load_pipeline,
    "br_ctop_strcpy_pipeline_stops_on_first_zero_word":
        test_br_ctop_strcpy_pipeline_stops_on_first_zero_word,
    "br_ctop_strcpy_pipeline_survives_cover_rfi":
        test_br_ctop_strcpy_pipeline_survives_cover_rfi,
    "br_call_ret_strcpy_pipeline_stops_on_first_zero_word":
        test_br_call_ret_strcpy_pipeline_stops_on_first_zero_word,
    "br_ctop_rotates_floating_registers": test_br_ctop_rotates_floating_registers,
    "br_wtop_false_predicate_drains_epilog":
        test_br_wtop_false_predicate_drains_epilog,
    "br_wexit_false_predicate_drains_epilog":
        test_br_wexit_false_predicate_drains_epilog,
    "future_itm_rearm_preserves_pended_timer_irr":
        test_future_itm_rearm_preserves_pended_timer_irr,
    "masking_itv_preserves_pended_timer_irr":
        test_masking_itv_preserves_pended_timer_irr,
    "exception_break": test_exception_break,
    "exception_break_f": test_exception_break_f,
    "exception_break_x": test_exception_break_x,
    "exception_syscall_break": test_exception_syscall_break,
    "nop_f_decode": test_nop_f_decode,
    "exception_records_slot_ri": test_exception_records_slot_ri,
    "break_preserves_ifa_and_records_iim_isr":
        test_break_preserves_ifa_and_records_iim_isr,
    "iipa_reports_previous_successful_bundle_for_slot0_fault":
        test_iipa_reports_previous_successful_bundle_for_slot0_fault,
    "iipa_reports_current_bundle_after_prior_slot_success":
        test_iipa_reports_current_bundle_after_prior_slot_success,
    "iipa_preserved_for_rfi_to_fault":
        test_iipa_preserved_for_rfi_to_fault,
    "exception_clears_ifs_keeps_cfm": test_exception_clears_ifs_keeps_cfm,
    "disabled_fp_high_fault": test_disabled_fp_high_fault,
    "disabled_fp_low_fault": test_disabled_fp_low_fault,
    "disabled_fp_load_sets_isr_r": test_disabled_fp_load_sets_isr_r,
    "disabled_fp_store_sets_isr_w": test_disabled_fp_store_sets_isr_w,
    "disabled_fp_mixed_sets_reports_both":
        test_disabled_fp_mixed_sets_reports_both,
    "fp_writes_set_psr_mfl_mfh": test_fp_writes_set_psr_mfl_mfh,
    "predicated_off_disabled_fp_does_not_fault":
        test_predicated_off_disabled_fp_does_not_fault,
    "cover_saves_interrupted_cfm_to_ifs":
        test_cover_saves_interrupted_cfm_to_ifs,
    "rfi_restores_interrupted_bsp_after_cover":
        test_rfi_restores_interrupted_bsp_after_cover,
    "cover_rfi_rebases_rotating_floating_registers":
        test_cover_rfi_rebases_rotating_floating_registers,
    "cover_rfi_rebases_rotating_general_registers":
        test_cover_rfi_rebases_rotating_general_registers,
    "br_call_ret_rebases_rotating_floating_registers":
        test_br_call_ret_rebases_rotating_floating_registers,
    "clrrrb_rebases_rotating_floating_registers":
        test_clrrrb_rebases_rotating_floating_registers,
    "nested_exception_keeps_handler_return_state": test_nested_exception_keeps_handler_return_state,
    "nested_exception_keeps_handler_interruption_state": test_nested_exception_keeps_handler_interruption_state,
    "rse_rfi_selects_matching_outer_exception_frame":
        test_rse_rfi_selects_matching_outer_exception_frame,
    "exception_illegal": test_exception_illegal,
    "exception_illegal_enters_general_vector":
        test_exception_illegal_enters_general_vector,
    "exception_reserved_template": test_exception_reserved_template,
    "exception_unaligned": test_exception_unaligned,
    "exception_unaligned_sets_ifa_isr": test_exception_unaligned_sets_ifa_isr,
    "exception_unaligned_slot1_uses_psr_ri":
        test_exception_unaligned_slot1_uses_psr_ri,
    "no_ic_data_access_enters_vector_with_ni":
        test_no_ic_data_access_enters_vector_with_ni,
    "firmware_unaligned_load_assist": test_firmware_unaligned_load_assist,
    "firmware_unaligned_store_assist": test_firmware_unaligned_store_assist,
    "firmware_unaligned_speculative_load_assist":
        test_firmware_unaligned_speculative_load_assist,
    "firmware_unaligned_virtual_load_assist":
        test_firmware_unaligned_virtual_load_assist,
    "speculative_unaligned_defers": test_speculative_unaligned_defers,
    "cmp_ge_or_decode": test_cmp_ge_or_decode,
    "cmp_ge_or_issue_raw_decode": test_cmp_ge_or_issue_raw_decode,
    "cmp_ge_and_decode": test_cmp_ge_and_decode,
    "cmp_ge_or_andcm_issue_raw_decode": test_cmp_ge_or_andcm_issue_raw_decode,
    "fselect_decode": test_fselect_decode,
    "fselect_natval_propagates": test_fselect_natval_propagates,
    "mux1_brcst_decode": test_mux1_brcst_decode,
    "scalar_shift_count_64": test_scalar_shift_count_64,
    "mov_ip_current_bundle": test_mov_ip_current_bundle,
    "brp_loop_imp_decode": test_brp_loop_imp_decode,
    "brp_sptk_decode": test_brp_sptk_decode,
    "predicate_register_roundtrip": test_predicate_register_roundtrip,
}

_duplicate_representation_names = (set(TEST_NAMES) &
                                   set(FP_REPRESENTATION_CASES))
if _duplicate_representation_names:
    raise RuntimeError(
        "duplicate generated IA-64 case names: " +
        ", ".join(sorted(_duplicate_representation_names)))
TEST_NAMES.update(FP_REPRESENTATION_CASES)
