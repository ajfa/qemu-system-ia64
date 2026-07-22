/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 CPU target skeleton.
 *
 * The target is still incomplete, but now has a runnable softmmu vCPU and a
 * semantic TCG translator for the current Phase 1 instruction subset.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/atomic.h"
#include "qemu/qemu-print.h"
#include "qemu/timer.h"
#include "cpu.h"
#include "decoder.h"
#include "fpreg.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "hw/core/qdev-properties.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/debug-assert.h"
#include "tcg/tcg-op.h"
#include "exec/translator.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "gdbstub/helpers.h"
#include "system/address-spaces.h"
#include "system/memory.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
    int mmu_idx;
    uint8_t start_slot;
    uint8_t goto_tb_slots;
    uint8_t current_ri;
    bool exit_after_bundle;
    bool current_ri_known;
    bool track_iipa;
    bool track_psr_suppression;
    bool be_data;
    bool full_alat;
    uint64_t nat_known_clear[2];
    bool instruction_group_start;
    bool next_instruction_group_start;
    TCGLabel *counted_self_label;
    TCGv_i64 counted_self_budget;
    uint64_t counted_self_ip;
    bool cloop_zero_st1_valid;
    bool cloop_zero_st1_release;
    uint8_t cloop_zero_st1_base;
    uint8_t cloop_zero_st1_slot;
} DisasContext;

static TCGv_i64 cpu_ip;
static TCGv_i64 cpu_gr[IA64_GR_COUNT];
static TCGv_i64 cpu_pr[IA64_PR_COUNT];
static TCGv_i64 cpu_br[IA64_BR_COUNT];
static TCGv_i64 cpu_psr;
static TCGv_i64 cpu_fr[IA64_FR_COUNT];
static TCGv_i64 cpu_fr_nat[2];
static TCGv_i64 cpu_fr_sig[2];
static TCGv_i64 cpu_fr_ext_valid[2];
static TCGv_i64 cpu_fr_int_origin[2];
static TCGv_i64 cpu_nat[2];
static TCGv_i64 cpu_rse_gr_dirty[2];

#define DISAS_EXIT DISAS_TARGET_0

#define IA64_TB_FLAG_DT       (1u << 0)
#define IA64_TB_FLAG_IT       (1u << 1)
#define IA64_TB_FLAG_RI_SHIFT 2
#define IA64_TB_FLAG_RI_MASK  (3u << IA64_TB_FLAG_RI_SHIFT)
#define IA64_TB_FLAG_PSR_SUPPRESS (1u << 4)
#define IA64_TB_FLAG_PSR_IC       (1u << 5)
#define IA64_TB_FLAG_BE           (1u << 6)
#define IA64_TB_FLAG_GROUP_START  (1u << 7)
#define IA64_TB_FLAG_PSR_IS       (1u << 8)
#define IA64_TB_FLAG_CPL_SHIFT    9
#define IA64_TB_FLAG_CPL_MASK     (3u << IA64_TB_FLAG_CPL_SHIFT)

#define IA64_COUNTED_SELF_BUDGET 4096
#define IA64_CLOOP_ZERO_ST1_MAX IA64_COUNTED_SELF_BUDGET

#define IA64_COVER_B_MASK     0x1e1f8000000ULL
#define IA64_COVER_B_VALUE    0x10000000ULL

const uint16_t ia64_ivt_vectors[IA64_EXCP_MAX] = {
    [IA64_EXCP_NONE]             = 0,
    [IA64_EXCP_BREAK]            = 0x2c00,
    [IA64_EXCP_ILLEGAL]          = 0x5400,
    [IA64_EXCP_RESERVED_TEMPLATE] = 0x5400,
    [IA64_EXCP_VHPT_FAULT]       = 0x0000,
    [IA64_EXCP_ITLB_FAULT]       = 0x0400,
    [IA64_EXCP_DTLB_FAULT]       = 0x0800,
    [IA64_EXCP_ALT_ITLB]         = 0x0c00,
    [IA64_EXCP_ALT_DTLB]         = 0x1000,
    [IA64_EXCP_DATA_NESTED_TLB]  = 0x1400,
    [IA64_EXCP_DATA_ACCESS]      = 0x5300,
    [IA64_EXCP_GENERAL]          = 0x5400,
    [IA64_EXCP_NAT_CONSUMPTION]  = 0x5600,
    [IA64_EXCP_EXTINT]           = 0x3000,
    [IA64_EXCP_UNALIGNED]        = 0x5a00,
    [IA64_EXCP_PAGE_NOT_PRESENT] = 0x5000,
    [IA64_EXCP_INST_ACCESS]      = 0x5200,
    [IA64_EXCP_DATA_DIRTY]       = 0x2000,
    [IA64_EXCP_INST_ACCESS_BIT]  = 0x2400,
    [IA64_EXCP_DATA_ACCESS_BIT]  = 0x2800,
    [IA64_EXCP_INST_KEY_MISS]    = 0x1800,
    [IA64_EXCP_DATA_KEY_MISS]    = 0x1c00,
    [IA64_EXCP_KEY_PERMISSION]   = 0x5100,
    [IA64_EXCP_UNIMPL_DATA_ADDR] = 0x5400,
    [IA64_EXCP_UNIMPL_INST_ADDR] = 0x5e00,
    [IA64_EXCP_PRIVILEGED_OP]    = 0x5400,
    [IA64_EXCP_PRIVILEGED_REG]   = 0x5400,
    [IA64_EXCP_RESERVED_REG_FIELD] = 0x5400,
    [IA64_EXCP_FP_FAULT]         = 0x5c00,
    [IA64_EXCP_FP_TRAP]          = 0x5d00,
    [IA64_EXCP_DISABLED_ISA_TRANSITION] = 0x5400,
    [IA64_EXCP_DISABLED_FP]      = 0x5500,
    [IA64_EXCP_UNSUPPORTED_DATA_REFERENCE] = 0x5b00,
    /*
     * The virtualization extensions post-date the reference SDM revision,
     * which leaves 0x6100 through 0x6800 reserved.  0x6100 is the first
     * reserved slot after the single-step trap and is where the Virtualization
     * fault vector was subsequently defined.
     */
    [IA64_EXCP_VIRTUALIZATION]   = 0x6100,
};

typedef enum Ia64SlotUnit {
    IA64_UNIT_RESERVED,
    IA64_UNIT_M,
    IA64_UNIT_I,
    IA64_UNIT_B,
    IA64_UNIT_F,
    IA64_UNIT_L,
    IA64_UNIT_X,
} Ia64SlotUnit;

typedef enum Ia64PredicateUpdate {
    IA64_PRED_UPDATE_NORMAL,
    IA64_PRED_UPDATE_AND,
    IA64_PRED_UPDATE_OR,
    IA64_PRED_UPDATE_OR_ANDCM,
} Ia64PredicateUpdate;

typedef enum Ia64Opcode {
    IA64_OP_ILLEGAL,
    IA64_OP_NOP,
    IA64_OP_BREAK,
    IA64_OP_ADDS,
    IA64_OP_ADDL,
    IA64_OP_SHLADD,
    IA64_OP_ADD,
    IA64_OP_ADD_ONE,
    IA64_OP_SUB,
    IA64_OP_SUB_ONE,
    IA64_OP_AND,
    IA64_OP_ANDCM,
    IA64_OP_OR,
    IA64_OP_XOR,
    IA64_OP_SUB_IMM,
    IA64_OP_AND_IMM,
    IA64_OP_ANDCM_IMM,
    IA64_OP_OR_IMM,
    IA64_OP_XOR_IMM,
    IA64_OP_CMP_EQ,
    IA64_OP_CMP_LT,
    IA64_OP_CMP_LE,
    IA64_OP_CMP_GT,
    IA64_OP_CMP_GE,
    IA64_OP_CMP_LTU,
    IA64_OP_CMP_LEU,
    IA64_OP_CMP_GTU,
    IA64_OP_CMP_GEU,
    IA64_OP_CMP_NE,
    IA64_OP_CMP_EQ_AND,
    IA64_OP_CMP_NE_AND,
    IA64_OP_CMP_GT_AND,
    IA64_OP_CMP_LE_AND,
    IA64_OP_CMP_GE_AND,
    IA64_OP_CMP_LT_AND,
    IA64_OP_CMP_EQ_OR,
    IA64_OP_CMP_NE_OR,
    IA64_OP_CMP_GT_OR,
    IA64_OP_CMP_LE_OR,
    IA64_OP_CMP_GE_OR,
    IA64_OP_CMP_LT_OR,
    IA64_OP_CMP_EQ_OR_ANDCM,
    IA64_OP_CMP_NE_OR_ANDCM,
    IA64_OP_CMP_GT_OR_ANDCM,
    IA64_OP_CMP_LE_OR_ANDCM,
    IA64_OP_CMP_GE_OR_ANDCM,
    IA64_OP_CMP_LT_OR_ANDCM,
    IA64_OP_CMP_EQ_IMM,
    IA64_OP_CMP_LT_IMM,
    IA64_OP_CMP_EQ_AND_IMM,
    IA64_OP_CMP_NE_AND_IMM,
    IA64_OP_CMP_EQ_OR_IMM,
    IA64_OP_CMP_NE_OR_IMM,
    IA64_OP_CMP_EQ_OR_ANDCM_IMM,
    IA64_OP_CMP_NE_OR_ANDCM_IMM,
    IA64_OP_CMP4_EQ_AND,
    IA64_OP_CMP4_NE_AND,
    IA64_OP_CMP4_EQ_OR,
    IA64_OP_CMP4_NE_OR,
    IA64_OP_CMP4_EQ_OR_ANDCM,
    IA64_OP_CMP4_NE_OR_ANDCM,
    IA64_OP_CMP4_GT_AND,
    IA64_OP_CMP4_LE_AND,
    IA64_OP_CMP4_GE_AND,
    IA64_OP_CMP4_LT_AND,
    IA64_OP_CMP4_GT_OR,
    IA64_OP_CMP4_LE_OR,
    IA64_OP_CMP4_GE_OR,
    IA64_OP_CMP4_LT_OR,
    IA64_OP_CMP4_GT_OR_ANDCM,
    IA64_OP_CMP4_LE_OR_ANDCM,
    IA64_OP_CMP4_GE_OR_ANDCM,
    IA64_OP_CMP4_LT_OR_ANDCM,
    IA64_OP_CMP4_EQ_OR_ANDCM_IMM,
    IA64_OP_CMP4_NE_OR_ANDCM_IMM,
    IA64_OP_CMP_LTU_IMM,
    IA64_OP_LD1,
    IA64_OP_LD2,
    IA64_OP_LD4,
    IA64_OP_LD8,
    IA64_OP_LD1S,
    IA64_OP_LD2S,
    IA64_OP_LD4S,
    IA64_OP_LD8S,
    IA64_OP_LD1A,
    IA64_OP_LD2A,
    IA64_OP_LD4A,
    IA64_OP_LD8A,
    IA64_OP_LD1SA,
    IA64_OP_LD2SA,
    IA64_OP_LD4SA,
    IA64_OP_LD8SA,
    IA64_OP_LD8FILL,
    IA64_OP_ST1,
    IA64_OP_ST2,
    IA64_OP_ST4,
    IA64_OP_ST8,
    IA64_OP_ST16,
    IA64_OP_ST1REL,
    IA64_OP_ST2REL,
    IA64_OP_ST4REL,
    IA64_OP_ST8REL,
    IA64_OP_ST8SPILL,
    IA64_OP_BR_COND,
    IA64_OP_BR_INDIRECT,
    IA64_OP_BR_CALL,
    IA64_OP_BR_CALL_INDIRECT,
    IA64_OP_BR_RET,
    IA64_OP_BR_IA,
    IA64_OP_BR_CLOOP,
    IA64_OP_SHL,
    IA64_OP_SHR,
    IA64_OP_SHRU,
    IA64_OP_SHL_IMM,
    IA64_OP_SHR_IMM,
    IA64_OP_SHRU_IMM,
    IA64_OP_SHRP_IMM,
    IA64_OP_DEPZ,
    IA64_OP_DEPZ_IMM,
    IA64_OP_DEP,
    IA64_OP_DEP_IMM,
    IA64_OP_EXTR,
    IA64_OP_EXTRU,
    IA64_OP_SXT1,
    IA64_OP_SXT2,
    IA64_OP_SXT4,
    IA64_OP_ZXT1,
    IA64_OP_ZXT2,
    IA64_OP_ZXT4,
    IA64_OP_PADD1,
    IA64_OP_PADD2,
    IA64_OP_PADD4,
    IA64_OP_PSUB1,
    IA64_OP_PSUB2,
    IA64_OP_PSUB4,
    IA64_OP_PSHLADD2,
    IA64_OP_PSHRADD2,
    IA64_OP_XCHG1,
    IA64_OP_XCHG2,
    IA64_OP_XCHG4,
    IA64_OP_XCHG8,
    IA64_OP_CMPXCHG1,
    IA64_OP_CMPXCHG2,
    IA64_OP_CMPXCHG4,
    IA64_OP_CMPXCHG8,
    IA64_OP_CMP8XCHG16,
    IA64_OP_FETCHADD4,
    IA64_OP_FETCHADD8,
    IA64_OP_MOVL,
    IA64_OP_MOV_BRGR,
    IA64_OP_MOV_GRBR,
    IA64_OP_MOV_PRGR,
    IA64_OP_MOV_GRPR,
    IA64_OP_MOV_PR_ROT_IMM,
    IA64_OP_MOV_ARGR,
    IA64_OP_MOV_GRAR,
    IA64_OP_MOV_IMMAR,
    IA64_OP_MOV_CRGR,
    IA64_OP_MOV_GRCR,
    IA64_OP_SSM,
    IA64_OP_RSM,
    IA64_OP_COVER,
    IA64_OP_ALLOC,
    IA64_OP_FLUSHRS,
    IA64_OP_LOADRS,
    IA64_OP_ITR_D,
    IA64_OP_ITR_I,
    IA64_OP_PTR_D,
    IA64_OP_PTR_I,
    IA64_OP_PTC_L,
    IA64_OP_PTC_G,
    IA64_OP_RFI,
    IA64_OP_LDFD,
    IA64_OP_LDFS,
    IA64_OP_LDF_FILL,
    IA64_OP_STFD,
    IA64_OP_STFS,
    IA64_OP_STF_SPILL,
    IA64_OP_FADD,
    IA64_OP_FSUB,
    IA64_OP_FMPY,
    IA64_OP_FMA,
    IA64_OP_XMA_L,
    IA64_OP_XMA_H,
    IA64_OP_XMA_HU,
    IA64_OP_XMPY_HU,
    IA64_OP_FCMP,
    IA64_OP_FMOV,
    IA64_OP_FCVT_XF,
    IA64_OP_FCVT_FX,
    IA64_OP_FCVT_FXU,
    IA64_OP_GETF_D,
    IA64_OP_GETF_S,
    IA64_OP_GETF_EXP,
    IA64_OP_SETF_D,
    IA64_OP_SETF_S,
    IA64_OP_SETF_EXP,
    IA64_OP_TPA,
    IA64_OP_SYNC_I,
    IA64_OP_CHK_S,
    IA64_OP_CHK_A,
    IA64_OP_CHK_A_CLR,
    IA64_OP_SRLZ,
    IA64_OP_SRLZ_D,
    IA64_OP_MF,
    IA64_OP_MF_A,
    IA64_OP_FWB,
    IA64_OP_PROBE_R,
    IA64_OP_PROBE_W,
    IA64_OP_PROBE_RW,
    IA64_OP_TAK,
    IA64_OP_THASH,
    IA64_OP_TTAG,
    IA64_OP_FC,
    IA64_OP_INVALA,
    IA64_OP_BR_WEXIT,
    IA64_OP_BR_WTOP,
    IA64_OP_BR_CEXIT,
    IA64_OP_BR_CTOP,
    IA64_OP_FCLASS,
    IA64_OP_FMERGE,
    IA64_OP_CMP4_EQ,
    IA64_OP_CMP4_LT,
    IA64_OP_CMP4_LE,
    IA64_OP_CMP4_GT,
    IA64_OP_CMP4_GE,
    IA64_OP_CMP4_LTU,
    IA64_OP_CMP4_LEU,
    IA64_OP_CMP4_GTU,
    IA64_OP_CMP4_GEU,
    IA64_OP_CMP4_EQ_IMM,
    IA64_OP_CMP4_LT_IMM,
    IA64_OP_CMP4_LTU_IMM,
    IA64_OP_CMP4_EQ_AND_IMM,
    IA64_OP_CMP4_NE_AND_IMM,
    IA64_OP_CMP4_EQ_OR_IMM,
    IA64_OP_CMP4_NE_OR_IMM,
    IA64_OP_TBIT_Z,
    IA64_OP_TBIT_NZ,
    IA64_OP_TBIT_Z_OR_ANDCM,
    IA64_OP_TBIT_NZ_OR_ANDCM,
    IA64_OP_TNAT_Z,
    IA64_OP_TNAT_NZ,
    IA64_OP_TNAT_NZ_AND,
    IA64_OP_TF_Z,
    IA64_OP_TF_NZ,
    IA64_OP_LD1C_CLR,
    IA64_OP_LD2C_CLR,
    IA64_OP_LD4C_CLR,
    IA64_OP_LD8C_CLR,
    IA64_OP_LD1C_NC,
    IA64_OP_LD2C_NC,
    IA64_OP_LD4C_NC,
    IA64_OP_LD8C_NC,
    IA64_OP_SHLADDP4,
    IA64_OP_MPY4,
    IA64_OP_MPYSHL4,
    IA64_OP_MPYSH,
    IA64_OP_MPYUH,
    IA64_OP_HINT_M,
    IA64_OP_LFETCH,
    IA64_OP_LFETCH_FAULT,
    IA64_OP_HINT_I,
    IA64_OP_HINT_B,
    IA64_OP_HINT_F,
    IA64_OP_HINT_X,
    IA64_OP_PTC_E,
    IA64_OP_CLRRRB,
    IA64_OP_CLRRRB_PR,
    IA64_OP_CLZ,
    IA64_OP_POPCNT,
    IA64_OP_MUX,
    IA64_OP_LDFP8,
    IA64_OP_LDFPD,
    IA64_OP_LDFPS,
    IA64_OP_FMERGE_S,
    IA64_OP_FMERGE_SE,
    IA64_OP_FMIN,
    IA64_OP_FMAX,
    IA64_OP_FAMIN,
    IA64_OP_FAMAX,
    IA64_OP_FRCPA,
    IA64_OP_FPRCPA,
    IA64_OP_FSETC,
    IA64_OP_FCLRF,
    IA64_OP_FCHKF,
    IA64_OP_GETF_SIG,
    IA64_OP_SETF_SIG,
    IA64_OP_ITC_D,
    IA64_OP_ITC_I,
    IA64_OP_PTC_GA,
    IA64_OP_MOV_PSRGR,
    IA64_OP_MOV_GRPSR,
    IA64_OP_MOV_RRGR,
    IA64_OP_MOV_GRRR,
    IA64_OP_BSW0,
    IA64_OP_BSW1,
    IA64_OP_BRL_COND,
    IA64_OP_BRL_CALL,
    IA64_OP_ADDP4,
    IA64_OP_ADDP4_IMM,
    IA64_OP_EPC,
    IA64_OP_INVALAT,
    IA64_OP_MOV_PKRGR,
    IA64_OP_MOV_PKRGR_INDEXED,
    IA64_OP_MOV_GRPKR,
    IA64_OP_MOV_GRPKR_INDEXED,
    IA64_OP_MOV_UMGR,
    IA64_OP_MOV_GRUM,
    IA64_OP_MOV_IBRGR,
    IA64_OP_MOV_GRIBR,
    IA64_OP_MOV_IBRGR_INDEXED,
    IA64_OP_MOV_GRIBR_INDEXED,
    IA64_OP_MOV_DBRGR,
    IA64_OP_MOV_GRDBR,
    IA64_OP_MOV_DBRGR_INDEXED,
    IA64_OP_MOV_GRDBR_INDEXED,
    IA64_OP_MOV_PMCGR,
    IA64_OP_MOV_GRPMC,
    IA64_OP_MOV_PMCGR_INDEXED,
    IA64_OP_MOV_GRPMC_INDEXED,
    IA64_OP_MOV_PMDGR,
    IA64_OP_MOV_GRPMD,
    IA64_OP_MOV_PMDGR_INDEXED,
    IA64_OP_MOV_GRPMD_INDEXED,
    IA64_OP_MOV_CPUID,
    IA64_OP_MOV_CPUID_INDEXED,
    IA64_OP_MOV_DAHRGR_INDEXED,
    IA64_OP_MOV_MSRGR,
    IA64_OP_MOV_GRMSR,
    IA64_OP_MOV_IP,
    IA64_OP_MOV_CURRENT_IP,
    IA64_OP_FMS,
    IA64_OP_FNMA,
    IA64_OP_FSELECT,
    IA64_OP_FNORM,
    IA64_OP_FPABS,
    IA64_OP_FPNEG,
    IA64_OP_FPNEGABS,
    IA64_OP_FPRSQRTA,
    IA64_OP_FRSQRTA,
    IA64_OP_FPACK,
    IA64_OP_FAND,
    IA64_OP_FANDCM,
    IA64_OP_FOR,
    IA64_OP_FXOR,
    IA64_OP_FSWAP,
    IA64_OP_FSWAP_NL,
    IA64_OP_FSWAP_NR,
    IA64_OP_FMIX_LR,
    IA64_OP_FMIX_R,
    IA64_OP_FMIX_L,
    IA64_OP_FSXT_R,
    IA64_OP_FSXT_L,
    IA64_OP_FPMERGE,
    IA64_OP_FPMERGE_S,
    IA64_OP_FPMERGE_SE,
    IA64_OP_FPMIN,
    IA64_OP_FPMAX,
    IA64_OP_FPAMIN,
    IA64_OP_FPAMAX,
    IA64_OP_FPCMP,
    IA64_OP_FPCVT,
    IA64_OP_FPMA,
    IA64_OP_FPMS,
    IA64_OP_FPNMA,
    IA64_OP_VMSW,
    IA64_OP_RUM,
    IA64_OP_SUM_UM,
    IA64_OP_BRP,
    IA64_OP_PAVG1,
    IA64_OP_PAVG2,
    IA64_OP_PAVGSUB1,
    IA64_OP_PAVGSUB2,
    IA64_OP_PCMP1_EQ,
    IA64_OP_PCMP1_GT,
    IA64_OP_PCMP2_EQ,
    IA64_OP_PCMP2_GT,
    IA64_OP_PCMP4_EQ,
    IA64_OP_PCMP4_GT,
    IA64_OP_PMAX1_U,
    IA64_OP_PMAX2,
    IA64_OP_PMIN1_U,
    IA64_OP_PMIN2,
    IA64_OP_PMPY2_L,
    IA64_OP_PMPY2_R,
    IA64_OP_PMPYSH2,
    IA64_OP_PMPYSH2_U,
    IA64_OP_PSHL2,
    IA64_OP_PSHL4,
    IA64_OP_PSHR2,
    IA64_OP_PSHR2_U,
    IA64_OP_PSHR4,
    IA64_OP_PSHR4_U,
    IA64_OP_PSAD1,
    IA64_OP_MUX1,
    IA64_OP_MUX2,
    IA64_OP_MIX1_L,
    IA64_OP_MIX1_R,
    IA64_OP_MIX2_L,
    IA64_OP_MIX2_R,
    IA64_OP_MIX4_L,
    IA64_OP_MIX4_R,
    IA64_OP_PACK2_SSS,
    IA64_OP_PACK2_USS,
    IA64_OP_PACK4_SSS,
    IA64_OP_UNPACK1_H,
    IA64_OP_UNPACK1_L,
    IA64_OP_UNPACK2_H,
    IA64_OP_UNPACK2_L,
    IA64_OP_UNPACK4_H,
    IA64_OP_UNPACK4_L,
    IA64_OP_SUM,
    IA64_OP_CZX1_L,
    IA64_OP_CZX1_R,
    IA64_OP_CZX2_L,
    IA64_OP_CZX2_R,
    IA64_OP_LD16,
    IA64_OP_LDF8,
    IA64_OP_LDFE,
    IA64_OP_STF8,
    IA64_OP_STFE,
} Ia64Opcode;

typedef struct Ia64Instruction {
    DisasContext *ctx;
    Ia64Opcode opcode;
    Ia64SlotUnit unit;
    uint64_t raw;
    uint64_t address;
    uint8_t slot;
    uint8_t qp;
    uint8_t r1;
    uint8_t r2;
    uint8_t r3;
    uint8_t p1;
    uint8_t p2;
    uint8_t b1;
    uint8_t b2;
    uint8_t sf;
    uint8_t fp_precision;
    int64_t imm;
    Ia64PredicateUpdate pred_update;
    bool hint_m_reg_increment;
    bool reg_base_update;
    bool imm_base_update;
    bool mem_acquire;
    bool mem_release;
    bool compare_unc;
    bool clear_p2_before_predicate;
    bool check_fp;
    bool fp_load_speculative;
    bool fp_load_advanced;
    bool fp_load_check;
    bool fp_load_check_clear;
    bool probe_fault;
    bool probe_imm;
    bool placement_illegal;
    bool reserved_field;
    bool valid;
} Ia64Instruction;

static bool ia64_cr_is_read_only(uint32_t cr_num);

typedef struct Ia64A3AluPattern {
    uint8_t x4;
    uint8_t x2b;
    Ia64Opcode opcode;
    bool immediate;
} Ia64A3AluPattern;

static const Ia64A3AluPattern ia64_a3_alu_patterns[] = {
    { 0x0, 0, IA64_OP_ADD, false },
    { 0x0, 1, IA64_OP_ADD_ONE, false },
    { 0x0, 3, IA64_OP_MUX, false },
    { 0x1, 0, IA64_OP_SUB_ONE, false },
    { 0x1, 1, IA64_OP_SUB, false },
    { 0x3, 0, IA64_OP_AND, false },
    { 0x3, 1, IA64_OP_ANDCM, false },
    { 0x3, 2, IA64_OP_OR, false },
    { 0x3, 3, IA64_OP_XOR, false },
    { 0x4, 0, IA64_OP_SHL, false },
    { 0x4, 1, IA64_OP_SHRU, false },
    { 0x5, 0, IA64_OP_SHR, false },
    { 0x6, 0, IA64_OP_DEPZ, false },
    { 0x6, 1, IA64_OP_DEP, false },
    { 0x7, 0, IA64_OP_EXTR, false },
    { 0x7, 1, IA64_OP_EXTRU, false },
    { 0x8, 0, IA64_OP_MPY4, false },
    { 0x8, 1, IA64_OP_MPYSH, false },
    { 0x8, 2, IA64_OP_MPYUH, false },
    { 0x9, 1, IA64_OP_SUB_IMM, true },
    { 0xa, 1, IA64_OP_POPCNT, false },
    { 0xb, 0, IA64_OP_AND_IMM, true },
    { 0xb, 1, IA64_OP_ANDCM_IMM, true },
    { 0xb, 2, IA64_OP_OR_IMM, true },
    { 0xb, 3, IA64_OP_XOR_IMM, true },
};

static uint64_t ia64_bits(uint64_t value, unsigned low, unsigned width)
{
    return (value >> low) & ((1ULL << width) - 1);
}

static uint64_t ia64_b_op(uint64_t value)
{
    return ia64_bits(value, 37, 4);
}

static int64_t ia64_sign_extend(uint64_t value, unsigned width)
{
    const uint64_t sign = 1ULL << (width - 1);
    const uint64_t mask = (1ULL << width) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

static uint64_t ia64_immu21(uint64_t raw)
{
    return ia64_bits(raw, 6, 20) | (ia64_bits(raw, 36, 1) << 20);
}

static int64_t ia64_imm14(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 6) << 7) |
                            (ia64_bits(raw, 36, 1) << 13), 14);
}

static int64_t ia64_imm8(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 36, 1) << 7), 8);
}

static uint64_t ia64_pr_mask(uint64_t raw)
{
    uint64_t imm17 = (ia64_bits(raw, 6, 7) << 1) |
                     (ia64_bits(raw, 24, 8) << 8) |
                     (ia64_bits(raw, 36, 1) << 16);

    return ia64_sign_extend(imm17, 17) & ~1ULL;
}

static uint64_t ia64_pr_rot_imm(uint64_t raw)
{
    uint64_t imm = ia64_bits(raw, 6, 7) |
                   (ia64_bits(raw, 13, 7) << 7) |
                   (ia64_bits(raw, 20, 4) << 14) |
                   (ia64_bits(raw, 24, 8) << 18) |
                   (ia64_bits(raw, 32, 1) << 26) |
                   (ia64_bits(raw, 36, 1) << 27);

    return imm << 16;
}

static uint64_t ia64_psr_mask(uint64_t raw)
{
    return ia64_bits(raw, 6, 7) |
           (ia64_bits(raw, 13, 7) << 7) |
           (ia64_bits(raw, 20, 7) << 14) |
           (ia64_bits(raw, 31, 2) << 21) |
           (ia64_bits(raw, 36, 1) << 23);
}

static uint64_t ia64_low_mask(uint64_t len)
{
    return len >= 64 ? UINT64_MAX : ((1ULL << len) - 1);
}

static uint64_t ia64_bitfield_effective_len(uint64_t pos, uint64_t len)
{
    pos &= 0x3f;
    return len > 64 - pos ? 64 - pos : len;
}

static uint64_t ia64_deposit_mask(uint64_t pos, uint64_t len)
{
    len = ia64_bitfield_effective_len(pos, len);
    return ia64_low_mask(len) << (pos & 0x3f);
}

static int64_t ia64_imm22(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 9) << 7) |
                            (ia64_bits(raw, 22, 5) << 16) |
                            (ia64_bits(raw, 36, 1) << 21), 22);
}

static int64_t ia64_branch_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static uint64_t ia64_mlx_x1_imm62(uint64_t l_slot, uint64_t x_slot)
{
    return ia64_immu21(x_slot) | (ia64_bits(l_slot, 0, 41) << 21);
}

static int64_t ia64_mlx_brl_disp(uint64_t l_slot, uint64_t x_slot)
{
    const uint64_t field = ia64_bits(x_slot, 13, 20) |
                           (ia64_bits(l_slot, 2, 39) << 20) |
                           (ia64_bits(x_slot, 36, 1) << 59);

    return ia64_sign_extend(field, 60) * 16;
}

static void ia64_fill_mlx_movl(Ia64Instruction *insn,
                               uint64_t l_slot, uint64_t x_slot)
{
    uint64_t i     = (x_slot >> 36) & 1;
    uint64_t imm9d = (x_slot >> 27) & 0x1ff;
    uint64_t imm5c = (x_slot >> 22) & 0x1f;
    uint64_t ic    = (x_slot >> 21) & 1;
    uint64_t imm7b = (x_slot >> 13) & 0x7f;
    uint64_t imm41 = l_slot & 0x1ffffffffffULL;
    uint64_t imm64 = (imm7b)
                   | (imm9d << 7)
                   | (imm5c << 16)
                   | (ic << 21)
                   | (imm41 << 22)
                   | (i << 63);

    insn->qp = x_slot & 0x3f;
    insn->r1 = (x_slot >> 6) & 0x7f;
    insn->imm = (int64_t)imm64;
}

static int64_t ia64_chk_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 6, 7) |
                           (ia64_bits(raw, 20, 13) << 7) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static int64_t ia64_chk_a_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static bool ia64_instruction_address_matches_physical_entry(CPUIA64State *env,
                                                            uint64_t address,
                                                            uint64_t entry_pa)
{
    const IA64TlbEntry *entry;
    uint64_t pa;
    uint8_t perm;
    uint32_t rid;

    if (!(env->psr & IA64_PSR_IT)) {
        return address == entry_pa;
    }

    if (ia64_firmware_identity_pa(env->cr_iva, address, env->psr,
                                  address, &pa) ||
        ia64_sal_boot_virtual_pa(env, address, &pa)) {
        return pa == entry_pa;
    }

    rid = ia64_region_rid(env, address);
    entry = ia64_tlb_find_cached(env, address, rid, true);
    if (entry) {
        ia64_tlb_entry_translate(entry, address, ia64_psr_cpl(env->psr),
                                 &pa, &perm);
    }
    if (entry && (perm & IA64_TLB_X)) {
        return pa == entry_pa;
    }

    if (ia64_sal_boot_identity_pa(env, address, &pa)) {
        return pa == entry_pa;
    }

    return false;
}

static bool ia64_is_pal_proc_break(CPUIA64State *env, uint64_t address)
{
    const uint64_t pal_proc_entry_pa = IA64_FW_IDENTITY_BASE + 0x60;

    if (ia64_instruction_address_matches_physical_entry(
            env, address, pal_proc_entry_pa)) {
        return true;
    }

    return env->pal_proc_copy_valid &&
           ia64_instruction_address_matches_physical_entry(
               env, address, env->pal_proc_copy_addr);
}

static bool ia64_is_firmware_debug_break(uint64_t address, uint64_t imm)
{
    if (imm == 0x100002) {
        return address >= IA64_FIRMWARE_IVT_BASE &&
               address < IA64_FIRMWARE_IVT_BASE + 0x8000;
    }
    if (imm == 0x100003 || imm == 0x100004) {
        return address >= IA64_FW_IDENTITY_BASE &&
               address < IA64_FW_IDENTITY_BASE + IA64_FW_IDENTITY_SIZE;
    }
    return false;
}

/*
 * Integer load/store x6 opcode extensions, SDM Vol 3 Table 4-29 (and the
 * matching +reg/+imm forms in Tables 4-30/4-31).  Values absent from that
 * table are reserved and must decode as an Illegal Operation fault; in
 * particular spill/fill exist only as 8-byte forms (ld8.fill x6=0x1b,
 * st8.spill x6=0x3b), so 0x18-0x1a and 0x38-0x3a fall through to the
 * default.  0x28-0x2b are the ld.c.clr.acq forms; their acquire semantics
 * come from ia64_memory_x6a_is_acquire_load() at the decode call sites.
 */
static Ia64Opcode ia64_memory_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1;
    case 0x01:
        return IA64_OP_LD2;
    case 0x02:
        return IA64_OP_LD4;
    case 0x03:
        return IA64_OP_LD8;
    case 0x04:
        return IA64_OP_LD1S;
    case 0x05:
        return IA64_OP_LD2S;
    case 0x06:
        return IA64_OP_LD4S;
    case 0x07:
        return IA64_OP_LD8S;
    case 0x08:
        return IA64_OP_LD1A;
    case 0x09:
        return IA64_OP_LD2A;
    case 0x0a:
        return IA64_OP_LD4A;
    case 0x0b:
        return IA64_OP_LD8A;
    case 0x0c:
        return IA64_OP_LD1SA;
    case 0x0d:
        return IA64_OP_LD2SA;
    case 0x0e:
        return IA64_OP_LD4SA;
    case 0x0f:
        return IA64_OP_LD8SA;
    case 0x10:
        return IA64_OP_LD1;
    case 0x11:
        return IA64_OP_LD2;
    case 0x12:
        return IA64_OP_LD4;
    case 0x13:
        return IA64_OP_LD8;
    case 0x14:
        return IA64_OP_LD1;
    case 0x15:
        return IA64_OP_LD2;
    case 0x16:
        return IA64_OP_LD4;
    case 0x17:
        return IA64_OP_LD8;
    case 0x1b:
        return IA64_OP_LD8FILL;
    case 0x20:
        return IA64_OP_LD1C_CLR;
    case 0x21:
        return IA64_OP_LD2C_CLR;
    case 0x22:
        return IA64_OP_LD4C_CLR;
    case 0x23:
        return IA64_OP_LD8C_CLR;
    case 0x24:
        return IA64_OP_LD1C_NC;
    case 0x25:
        return IA64_OP_LD2C_NC;
    case 0x26:
        return IA64_OP_LD4C_NC;
    case 0x27:
        return IA64_OP_LD8C_NC;
    case 0x28:
        return IA64_OP_LD1C_CLR;
    case 0x29:
        return IA64_OP_LD2C_CLR;
    case 0x2a:
        return IA64_OP_LD4C_CLR;
    case 0x2b:
        return IA64_OP_LD8C_CLR;
    case 0x30:
        return IA64_OP_ST1;
    case 0x31:
        return IA64_OP_ST2;
    case 0x32:
        return IA64_OP_ST4;
    case 0x33:
        return IA64_OP_ST8;
    case 0x34:
        return IA64_OP_ST1REL;
    case 0x35:
        return IA64_OP_ST2REL;
    case 0x36:
        return IA64_OP_ST4REL;
    case 0x37:
        return IA64_OP_ST8REL;
    case 0x3b:
        return IA64_OP_ST8SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_memory_x6a_is_acquire_load(uint64_t x6a)
{
    return (x6a >= 0x14 && x6a <= 0x17) ||
           (x6a >= 0x28 && x6a <= 0x2b);
}

static Ia64Opcode ia64_speculative_load_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1S;
    case 0x01:
        return IA64_OP_LD2S;
    case 0x02:
        return IA64_OP_LD4S;
    case 0x03:
        return IA64_OP_LD8S;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_fp_load_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f) || (x6a >= 0x20 && x6a <= 0x27)) {
        switch (x6a & 3) {
        case 0:
            return IA64_OP_LDFE;
        case 1:
            return IA64_OP_LDF8;
        case 2:
            return IA64_OP_LDFS;
        case 3:
            return IA64_OP_LDFD;
        }
    }

    switch (x6a) {
    case 0x1b:
        return IA64_OP_LDF_FILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static void ia64_fp_load_attrs_from_x6a(Ia64Instruction *insn, uint64_t x6a)
{
    switch (x6a >> 2) {
    case 1:
        insn->fp_load_speculative = true;
        break;
    case 2:
        insn->fp_load_advanced = true;
        break;
    case 3:
        insn->fp_load_speculative = true;
        insn->fp_load_advanced = true;
        break;
    case 8:
        insn->fp_load_check = true;
        insn->fp_load_check_clear = true;
        break;
    case 9:
        insn->fp_load_check = true;
        break;
    default:
        break;
    }
}

static Ia64Opcode ia64_fp_load_pair_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f || (x6a >= 0x20 && x6a <= 0x27)) &&
        (x6a & 3) != 0) {
        switch (x6a & 3) {
        case 1:
            return IA64_OP_LDFP8;
        case 2:
            return IA64_OP_LDFPS;
        case 3:
            return IA64_OP_LDFPD;
        }
    }

    return IA64_OP_ILLEGAL;
}

static Ia64Opcode ia64_fp_store_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x30:
        return IA64_OP_STFE;
    case 0x31:
        return IA64_OP_STF8;
    case 0x32:
        return IA64_OP_STFS;
    case 0x33:
        return IA64_OP_STFD;
    case 0x3b:
        return IA64_OP_STF_SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_check_load_opcode_from_x6a(uint64_t x6a, bool clr)
{
    switch (x6a) {
    case 0x00:
        return clr ? IA64_OP_LD1C_CLR : IA64_OP_LD1C_NC;
    case 0x01:
        return clr ? IA64_OP_LD2C_CLR : IA64_OP_LD2C_NC;
    case 0x02:
        return clr ? IA64_OP_LD4C_CLR : IA64_OP_LD4C_NC;
    case 0x03:
        return clr ? IA64_OP_LD8C_CLR : IA64_OP_LD8C_NC;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_fetchadd_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x12:
    case 0x16:
        return IA64_OP_FETCHADD4;
    case 0x13:
    case 0x17:
        return IA64_OP_FETCHADD8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_fetchadd_x6a_is_acquire(uint64_t x6a)
{
    return x6a == 0x12 || x6a == 0x13;
}

static bool ia64_fetchadd_x6a_is_release(uint64_t x6a)
{
    return x6a == 0x16 || x6a == 0x17;
}

static Ia64Opcode ia64_cmpxchg_acqrel_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_CMPXCHG1;
    case 1:
        return IA64_OP_CMPXCHG2;
    case 2:
        return IA64_OP_CMPXCHG4;
    case 3:
        return IA64_OP_CMPXCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_xchg_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_XCHG1;
    case 1:
        return IA64_OP_XCHG2;
    case 2:
        return IA64_OP_XCHG4;
    case 3:
        return IA64_OP_XCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_unpack_opcode_from_fields(uint64_t za, uint64_t zb,
                                                 uint64_t x2b)
{
    static const Ia64Opcode high[4] = {
        IA64_OP_UNPACK1_H, IA64_OP_UNPACK2_H, IA64_OP_UNPACK4_H,
        IA64_OP_ILLEGAL,
    };
    static const Ia64Opcode low[4] = {
        IA64_OP_UNPACK1_L, IA64_OP_UNPACK2_L, IA64_OP_UNPACK4_L,
        IA64_OP_ILLEGAL,
    };
    const unsigned size_code = (za << 1) | zb;

    if (x2b == 0) {
        return high[size_code];
    }
    if (x2b == 2) {
        return low[size_code];
    }
    return IA64_OP_ILLEGAL;
}

static int64_t ia64_fetchadd_imm(uint64_t inc3)
{
    static const int8_t values[8] = {
        16, 8, 4, 1, -16, -8, -4, -1,
    };

    return values[inc3 & 7];
}

static Ia64Opcode ia64_compare_opcode_from_cmp(uint64_t x2a, uint64_t ve)
{
    switch ((x2a << 1) | ve) {
    case 0:
        return IA64_OP_CMP_EQ;
    case 1:
        return IA64_OP_CMP_LT;
    case 2:
        return IA64_OP_CMP_LE;
    case 3:
        return IA64_OP_CMP_GT;
    case 4:
        return IA64_OP_CMP_GE;
    case 5:
        return IA64_OP_CMP_LTU;
    case 6:
        return IA64_OP_CMP_LEU;
    case 7:
        return IA64_OP_CMP_GTU;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static Ia64Opcode ia64_compare_zero_opcode(uint64_t major, bool cmp4,
                                           uint64_t ta, uint64_t c)
{
    static const Ia64Opcode zero_ops[3][2][4] = {
        {
            {
                IA64_OP_CMP_GT_AND,
                IA64_OP_CMP_LE_AND,
                IA64_OP_CMP_GE_AND,
                IA64_OP_CMP_LT_AND,
            },
            {
                IA64_OP_CMP4_GT_AND,
                IA64_OP_CMP4_LE_AND,
                IA64_OP_CMP4_GE_AND,
                IA64_OP_CMP4_LT_AND,
            },
        },
        {
            {
                IA64_OP_CMP_GT_OR,
                IA64_OP_CMP_LE_OR,
                IA64_OP_CMP_GE_OR,
                IA64_OP_CMP_LT_OR,
            },
            {
                IA64_OP_CMP4_GT_OR,
                IA64_OP_CMP4_LE_OR,
                IA64_OP_CMP4_GE_OR,
                IA64_OP_CMP4_LT_OR,
            },
        },
        {
            {
                IA64_OP_CMP_GT_OR_ANDCM,
                IA64_OP_CMP_LE_OR_ANDCM,
                IA64_OP_CMP_GE_OR_ANDCM,
                IA64_OP_CMP_LT_OR_ANDCM,
            },
            {
                IA64_OP_CMP4_GT_OR_ANDCM,
                IA64_OP_CMP4_LE_OR_ANDCM,
                IA64_OP_CMP4_GE_OR_ANDCM,
                IA64_OP_CMP4_LT_OR_ANDCM,
            },
        },
    };
    const unsigned relation = (ta << 1) | c;

    if (major < 0xc || major > 0xe) {
        return IA64_OP_ILLEGAL;
    }
    return zero_ops[major - 0xc][cmp4 ? 1 : 0][relation];
}

static Ia64Opcode ia64_f1_opcode_from_major(uint64_t major, uint64_t f2,
                                            uint64_t f4)
{
    switch (major) {
    case 8:
    case 9:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FADD;
        }
        return f2 == 0 ? IA64_OP_FMPY : IA64_OP_FMA;
    case 0xa:
    case 0xb:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FSUB;
        }
        return IA64_OP_FMS;
    case 0xc:
    case 0xd:
        return IA64_OP_FNMA;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static const Ia64A3AluPattern *ia64_lookup_a3_alu(uint64_t x4, uint64_t x2b)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ia64_a3_alu_patterns); ++i) {
        const Ia64A3AluPattern *pattern = &ia64_a3_alu_patterns[i];
        if (pattern->x4 == x4 && pattern->x2b == x2b) {
            return pattern;
        }
    }
    return NULL;
}

static MemOp ia64_memop_for_opcode(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD1S:
    case IA64_OP_LD1A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_ST1:
    case IA64_OP_ST1REL:
    case IA64_OP_XCHG1:
    case IA64_OP_CMPXCHG1:
        return MO_UB;
    case IA64_OP_LD2:
    case IA64_OP_LD2S:
    case IA64_OP_LD2A:
    case IA64_OP_LD2SA:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD2C_NC:
    case IA64_OP_ST2:
    case IA64_OP_ST2REL:
    case IA64_OP_XCHG2:
    case IA64_OP_CMPXCHG2:
        return MO_LEUW;
    case IA64_OP_LD4:
    case IA64_OP_LD4S:
    case IA64_OP_LD4A:
    case IA64_OP_LD4SA:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD4C_NC:
    case IA64_OP_ST4:
    case IA64_OP_ST4REL:
    case IA64_OP_XCHG4:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_FETCHADD4:
        return MO_LEUL;
    case IA64_OP_LD8:
    case IA64_OP_LD8S:
    case IA64_OP_LD8A:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD8C_NC:
    case IA64_OP_ST8:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
    case IA64_OP_XCHG8:
    case IA64_OP_CMPXCHG8:
    case IA64_OP_FETCHADD8:
        return MO_LEUQ;
    default:
        break;
    }
    g_assert_not_reached();
}

static MemOp ia64_memop_with_endian(MemOp memop, bool big_endian)
{
    if ((memop & MO_SIZE) == MO_8) {
        return memop & ~MO_BSWAP;
    }
    return (memop & ~MO_BSWAP) | (big_endian ? MO_BE : MO_LE);
}

static MemOp ia64_data_memop(DisasContext *ctx, MemOp memop)
{
    return ia64_memop_with_endian(memop, ctx->be_data);
}

static uint32_t ia64_memop_size(MemOp memop)
{
    return 1u << (memop & MO_SIZE);
}

static bool ia64_opcode_is_store(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST16:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_release_store(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_has_base_update(const Ia64Instruction *insn)
{
    return insn->reg_base_update || insn->imm_base_update;
}

static bool ia64_load_base_update_has_same_target(const Ia64Instruction *insn)
{
    return ia64_opcode_is_load(insn->opcode) &&
           ia64_insn_has_base_update(insn) &&
           insn->r1 == insn->r3;
}

static bool ia64_opcode_has_firmware_unaligned_load_assist(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_has_firmware_unaligned_store_assist(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_control_speculative_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_data_speculative_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_check_load_clear(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_check_load_no_clear(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_check_load(Ia64Opcode opcode)
{
    return ia64_opcode_is_check_load_clear(opcode) ||
           ia64_opcode_is_check_load_no_clear(opcode);
}

static bool ia64_opcode_is_fill_load(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD8FILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_is_m_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31) |
                          (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_m_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31);

    return (raw & mask) == 0;
}

static bool ia64_is_i_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27) | (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_i_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_b_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);
    const uint64_t value = 2ULL << 37;

    return (raw & mask) == value;
}

static bool ia64_is_b_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_f_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_f_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static Ia64Instruction ia64_base_insn(Ia64Opcode opcode, Ia64SlotUnit unit,
                                      uint64_t raw, uint64_t address,
                                      uint8_t slot)
{
    Ia64Instruction insn = {
        .opcode = opcode,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
        .qp = ia64_bits(raw, 0, 6),
        .sf = unit == IA64_UNIT_F ? ia64_bits(raw, 34, 2) : 0,
        .valid = true,
    };

    return insn;
}

static Ia64Instruction ia64_invalid_insn(Ia64SlotUnit unit, uint64_t raw,
                                         uint64_t address, uint8_t slot)
{
    Ia64Instruction insn = {
        .opcode = IA64_OP_ILLEGAL,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
    };

    return insn;
}

/*
 * MLX long forms are reported at slot 1.  The paired X slot carries the
 * opcode/predicate and low immediate bits, and must not execute separately.
 */
static void ia64_apply_mlx_long_fixup(uint8_t template_code,
                                      const uint64_t slots[3],
                                      int slot, Ia64Instruction *insn,
                                      bool *skip_x_slot)
{
    if ((template_code != 4 && template_code != 5) || slot != 1) {
        return;
    }

    uint64_t x_slot = slots[2];
    uint64_t l_slot = slots[1];

    if (ia64_is_i_break(x_slot)) {
        *insn = ia64_base_insn(IA64_OP_BREAK, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xc &&
               ia64_bits(x_slot, 6, 3) == 0) {
        *insn = ia64_base_insn(IA64_OP_BRL_COND, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xd) {
        *insn = ia64_base_insn(IA64_OP_BRL_CALL, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->b1 = ia64_bits(x_slot, 6, 3);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0 &&
               ia64_bits(x_slot, 27, 6) == 1) {
        Ia64Opcode opcode = ia64_bits(x_slot, 26, 1) ?
            IA64_OP_HINT_X : IA64_OP_NOP;
        *insn = ia64_base_insn(opcode, IA64_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL && ia64_b_op(x_slot) == 6) {
        ia64_fill_mlx_movl(insn, l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL) {
        *insn = ia64_invalid_insn(IA64_UNIT_L, l_slot, insn->address, slot);
    }
}

static Ia64Instruction ia64_decode_insn(Ia64SlotUnit unit, uint64_t raw,
                                        uint64_t address, uint8_t slot)
{
    raw &= IA64_SLOT_MASK;

    if (unit == IA64_UNIT_RESERVED) {
        return ia64_invalid_insn(unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_I &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 33, 3) == 7) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRBR, unit, raw, address, slot);

        /*
         * The btype/wh/ph/ih target-prediction fields are hints; the
         * architectural state update is still only BR[b1] = GR[r2].
         */
        insn.r2 = ia64_bits(raw, 6, 3);
        insn.r1 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M) {
        if (ia64_is_m_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_m_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 6) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ALLOC, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.imm = (ia64_bits(raw, 13, 7) << 0) |
                       (ia64_bits(raw, 20, 7) << 7) |
                       (ia64_bits(raw, 27, 4) << 14);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x21) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_UMGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x29) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRUM, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x25) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2d) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPSR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.imm = 1;
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x24) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2c) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRCR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRRR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_RRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x1e) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_TPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x1a ||
             ia64_bits(raw, 27, 6) == 0x1b ||
             ia64_bits(raw, 27, 6) == 0x1f)) {
            Ia64Opcode opcode;

            switch (ia64_bits(raw, 27, 6)) {
            case 0x1a:
                opcode = IA64_OP_THASH;
                break;
            case 0x1b:
                opcode = IA64_OP_TTAG;
                break;
            default:
                opcode = IA64_OP_TAK;
                break;
            }

            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x17 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CPUID_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x20) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_DAHRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x16 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_MSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x06) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRMSR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x11 ||
             ia64_bits(raw, 27, 6) == 0x12)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x12 ?
                               IA64_OP_MOV_IBRGR_INDEXED :
                               IA64_OP_MOV_DBRGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x01 ||
             ia64_bits(raw, 27, 6) == 0x02)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x02 ?
                               IA64_OP_MOV_GRIBR_INDEXED :
                               IA64_OP_MOV_GRDBR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x03) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPKR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x13) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PKRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x04 ||
             ia64_bits(raw, 27, 6) == 0x05)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x04 ?
                               IA64_OP_MOV_GRPMC_INDEXED :
                               IA64_OP_MOV_GRPMD_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x14 ||
             ia64_bits(raw, 27, 6) == 0x15)) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x14 ?
                               IA64_OP_MOV_PMCGR_INDEXED :
                               IA64_OP_MOV_PMDGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            return ia64_base_insn(IA64_OP_HINT_M, unit, raw, address, slot);
        }
    }

    if (unit == IA64_UNIT_I || unit == IA64_UNIT_X) {
        if (unit == IA64_UNIT_I &&
            ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_UNIT_I && ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 27, 2) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_UNIT_X && ia64_b_op(raw) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_X, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if (unit == IA64_UNIT_B) {
        if (ia64_is_b_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_b_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 && ia64_bits(raw, 12, 1) == 0 &&
            ia64_bits(raw, 27, 2) == 0 && ia64_bits(raw, 32, 1) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_B, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 33, 1);

        if (x2a == 2 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm14(raw);
            return insn;
        }

        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const unsigned size_code = ve | (ia64_bits(raw, 36, 1) << 1);
        if (x2a == 1 && (x4 == 0 || x4 == 1) &&
            ((size_code < 2 && x2b <= 3) ||
             (size_code == 2 && x2b == 0))) {
            Ia64Opcode opcode = IA64_OP_ILLEGAL;
            if (x4 == 0) {
                if (size_code == 0) {
                    opcode = IA64_OP_PADD1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PADD2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PADD4;
                }
            } else {
                if (size_code == 0) {
                    opcode = IA64_OP_PSUB1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PSUB2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PSUB4;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b;
                return insn;
            }
        }

        if (x2a == 1 && size_code == 1 && x4 == 4) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PSHLADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 && size_code == 1 && x4 == 6 && x2b <= 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PSHRADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 &&
            (x4 == 2 || x4 == 3) &&
            (x2b == 2 || (x4 == 2 && x2b == 3)) &&
            ia64_bits(raw, 36, 1) == 0) {
            Ia64Opcode opcode = IA64_OP_ILLEGAL;

            if (x4 == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVG1;
                } else {
                    opcode = IA64_OP_PAVG2;
                }
            } else if (x2b == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVGSUB1;
                } else {
                    opcode = IA64_OP_PAVGSUB2;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b == 3;
                return insn;
            }
        }

        if ((x4 == 4 || x4 == 6) && x2a == 0 && ve == 0) {
            const uint64_t count = x2b;
            Ia64Opcode shladd_op = (x4 == 6) ?
                IA64_OP_SHLADDP4 : IA64_OP_SHLADD;
            Ia64Instruction insn =
                ia64_base_insn(shladd_op, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = count + 1;
            return insn;
        }

        if (x2a == 0 && ve == 0) {
            const Ia64A3AluPattern *pattern = ia64_lookup_a3_alu(x4, x2b);

            if (pattern != NULL) {
                Ia64Instruction insn =
                    ia64_base_insn(pattern->opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                if (pattern->immediate) {
                    insn.imm = ia64_imm8(raw);
                } else {
                    insn.r2 = ia64_bits(raw, 13, 7);
                }
                return insn;
            }
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 9) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_ADDL, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 2);
        insn.imm = ia64_imm22(raw);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        (ia64_bits(raw, 33, 3) == 1 || ia64_bits(raw, 33, 3) == 3)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        insn.check_fp = ia64_bits(raw, 33, 3) == 3;
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 36, 1) == 0 &&
        (ia64_bits(raw, 34, 2) == 0 || ia64_bits(raw, 34, 2) == 1) &&
        (ia64_b_op(raw) == 0xc || ia64_b_op(raw) == 0xd ||
         ia64_b_op(raw) == 0xe)) {
        const bool cmp4 = ia64_bits(raw, 34, 2) == 1;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_b_op(raw)) {
        case 0xc:
            opcode = cmp4 ? IA64_OP_CMP4_LT : IA64_OP_CMP_LT;
            break;
        case 0xd:
            opcode = cmp4 ? IA64_OP_CMP4_LTU : IA64_OP_CMP_LTU;
            break;
        case 0xe:
            opcode = cmp4 ? IA64_OP_CMP4_EQ : IA64_OP_CMP_EQ;
            break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_b_op(raw) == 0xc) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP4_NE_AND : IA64_OP_CMP4_EQ_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        (ia64_b_op(raw) == 0xc || ia64_b_op(raw) == 0xd ||
         ia64_b_op(raw) == 0xe) &&
        ia64_bits(raw, 36, 1) == 1 &&
        (ia64_bits(raw, 34, 2) == 0 || ia64_bits(raw, 34, 2) == 1)) {
        Ia64Opcode opcode =
            ia64_compare_zero_opcode(ia64_b_op(raw),
                                     ia64_bits(raw, 34, 2) == 1,
                                     ia64_bits(raw, 33, 1),
                                     ia64_bits(raw, 12, 1));
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = 0;
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        (ia64_bits(raw, 34, 2) == 2 || ia64_bits(raw, 34, 2) == 3)) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const bool cmp4 = x2a == 3;
        const bool ne = ia64_bits(raw, 12, 1) != 0;
        Ia64Opcode opcode = cmp4 ?
            (ne ? IA64_OP_CMP4_NE_AND_IMM : IA64_OP_CMP4_EQ_AND_IMM) :
            (ne ? IA64_OP_CMP_NE_AND_IMM : IA64_OP_CMP_EQ_AND_IMM);
        Ia64Instruction insn = ia64_base_insn(opcode, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.imm = ia64_imm8(raw);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP_NE_AND : IA64_OP_CMP_EQ_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc &&
        ia64_bits(raw, 33, 1) == 1 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 12, 1) ?
                           IA64_OP_CMP_LT_AND : IA64_OP_CMP_GE_AND,
                           unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd && ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP_LTU, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP_LT, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        if (ia64_bits(raw, 33, 1) == 0 && (x2a == 2 || x2a == 3)) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_LT_IMM :
                                           IA64_OP_CMP4_LT_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 12, 1) == 1 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        if (x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LT, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = true;
            return insn;
        }
        if (x2a == 2 || x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_LT_IMM :
                                           IA64_OP_CMP4_LT_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = true;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe &&
        ia64_bits(raw, 36, 1) == 1) {
        const uint64_t x2 = ia64_bits(raw, 34, 2);
        const uint64_t ta = ia64_bits(raw, 33, 1);
        const uint64_t c = ia64_bits(raw, 12, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x2 == 0) {
            if (ta == 0 && c == 0) {
                opcode = IA64_OP_CMP_GT_OR_ANDCM;
            } else if (ta == 0 && c == 1) {
                opcode = IA64_OP_CMP_LE_OR_ANDCM;
            } else if (ta == 1 && c == 0) {
                opcode = IA64_OP_CMP_GE_OR_ANDCM;
            } else if (ta == 1 && c == 1) {
                opcode = IA64_OP_CMP_LT_OR_ANDCM;
            }
        } else if (x2 == 1) {
            if (ta == 0 && c == 0) {
                opcode = IA64_OP_CMP4_GT_OR_ANDCM;
            } else if (ta == 0 && c == 1) {
                opcode = IA64_OP_CMP4_LE_OR_ANDCM;
            } else if (ta == 1 && c == 0) {
                opcode = IA64_OP_CMP4_GE_OR_ANDCM;
            } else if (ta == 1 && c == 1) {
                opcode = IA64_OP_CMP4_LT_OR_ANDCM;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xc && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x4 == 0 && x2b == 0) {
            opcode = IA64_OP_PADD1;
        } else if (x4 == 0 && x2b == 1) {
            opcode = IA64_OP_PADD2;
        } else if (x4 == 0 && x2b == 2) {
            opcode = IA64_OP_PADD4;
        } else if (x4 == 1 && x2b == 0) {
            opcode = IA64_OP_PSUB1;
        } else if (x4 == 1 && x2b == 1) {
            opcode = IA64_OP_PSUB2;
        } else if (x4 == 1 && x2b == 2) {
            opcode = IA64_OP_PSUB4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8 &&
        ia64_bits(raw, 29, 4) == 9 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x2b == 0 || x2b == 1) {
            if (za == 0 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP1_EQ : IA64_OP_PCMP1_GT;
            } else if (za == 0 && zb == 1) {
                opcode = x2b == 0 ? IA64_OP_PCMP2_EQ : IA64_OP_PCMP2_GT;
            } else if (za == 1 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP4_EQ : IA64_OP_PCMP4_GT;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0) {
            opcode = IA64_OP_SHRU;
        } else if ((x6 & ~1ULL) == 4) {
            opcode = IA64_OP_SHR;
        } else if ((x6 & ~1ULL) == 8) {
            opcode = IA64_OP_SHL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            if (opcode == IA64_OP_SHL) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0x1a) {
            opcode = IA64_OP_MPY4;
        } else if ((x6 & ~1ULL) == 0x1e) {
            opcode = IA64_OP_MPYSHL4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        (ia64_bits(raw, 27, 6) & ~1ULL) == 0x08) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = -1;
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1 &&
        ia64_bits(raw, 28, 2) == 1 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        ia64_bits(raw, 25, 2) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = 31 - ia64_bits(raw, 20, 5);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7) {
        const uint64_t pshr_sig = raw & 0x1fff0000000ULL;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        bool fixed_count = false;

        switch (pshr_sig) {
        case 0xe220000000ULL:
            opcode = IA64_OP_PSHR2;
            break;
        case 0xe200000000ULL:
            opcode = IA64_OP_PSHR2_U;
            break;
        case 0xe630000000ULL:
            opcode = IA64_OP_PSHR2;
            fixed_count = true;
            break;
        case 0xe610000000ULL:
            opcode = IA64_OP_PSHR2_U;
            fixed_count = true;
            break;
        case 0xf020000000ULL:
            opcode = IA64_OP_PSHR4;
            break;
        case 0xf000000000ULL:
            opcode = IA64_OP_PSHR4_U;
            break;
        case 0xf430000000ULL:
            opcode = IA64_OP_PSHR4;
            fixed_count = true;
            break;
        case 0xf410000000ULL:
            opcode = IA64_OP_PSHR4_U;
            fixed_count = true;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (fixed_count) {
                insn.imm = ia64_bits(raw, 14, 5);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = -1;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 28, 2) == 2) {
        bool two_byte_form = ia64_bits(raw, 33, 1) != 0;
        Ia64Instruction insn =
            ia64_base_insn(two_byte_form ? IA64_OP_MUX2 : IA64_OP_MUX1,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = two_byte_form ? ia64_bits(raw, 20, 8) :
                                   ia64_bits(raw, 20, 4);
        if (!two_byte_form &&
            !(insn.imm == 0 || (insn.imm >= 8 && insn.imm <= 11))) {
            return ia64_invalid_insn(unit, raw, address, slot);
        }
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x12 &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_POPCNT, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x1a &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLZ, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 5) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x1e) {
            opcode = IA64_OP_PMPY2_L;
        } else if (x6 == 0x1a) {
            opcode = IA64_OP_PMPY2_R;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        uint64_t shift = 0;

        switch (x6) {
        case 0x06:
            opcode = IA64_OP_PMPYSH2;
            shift = 0;
            break;
        case 0x0e:
            opcode = IA64_OP_PMPYSH2;
            shift = 7;
            break;
        case 0x16:
            opcode = IA64_OP_PMPYSH2;
            shift = 15;
            break;
        case 0x1e:
            opcode = IA64_OP_PMPYSH2;
            shift = 16;
            break;
        case 0x02:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 0;
            break;
        case 0x0a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 7;
            break;
        case 0x12:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 15;
            break;
        case 0x1a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 16;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = shift;
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ((ia64_bits(raw, 27, 6) & ~1ULL) == 0x10 ||
         (ia64_bits(raw, 27, 6) & ~1ULL) == 0x14)) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const bool right = x6 == 0x10;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x3 == 4 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX1_R : IA64_OP_MIX1_L;
        } else if (x3 == 5 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX2_R : IA64_OP_MIX2_L;
        } else if (x3 == 4 && ia64_bits(raw, 36, 1) == 1) {
            opcode = right ? IA64_OP_MIX4_R : IA64_OP_MIX4_L;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 0) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (za == 0 && zb == 1 && x2b == 0) {
            opcode = IA64_OP_PACK2_USS;
        } else if (za == 0 && zb == 1 && x2b == 2) {
            opcode = IA64_OP_PACK2_SSS;
        } else if (za == 1 && zb == 0 && x2b == 2) {
            opcode = IA64_OP_PACK4_SSS;
        } else if (za == 0 && zb == 0 && x2b == 1) {
            opcode = IA64_OP_PMIN1_U;
        } else if (za == 0 && zb == 1 && x2b == 3) {
            opcode = IA64_OP_PMIN2;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);

        if (za == 0 && zb == 0 && x2b == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX1_U, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (za == 0 && zb == 1 && x2b == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_PSAD1, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        Ia64Opcode opcode =
            ia64_unpack_opcode_from_fields(ia64_bits(raw, 36, 1),
                                           ia64_bits(raw, 33, 1),
                                           ia64_bits(raw, 28, 2));

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 4) == 0) {
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x18: opcode = IA64_OP_CZX1_L; break;
        case 0x1c: opcode = IA64_OP_CZX1_R; break;
        case 0x19: opcode = IA64_OP_CZX2_L; break;
        case 0x1d: opcode = IA64_OP_CZX2_R; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 33, 1) == 0) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x4 == 0 && x2b == 0) {
            opcode = IA64_OP_SXT1;
        } else if (x4 == 0 && x2b == 1) {
            opcode = IA64_OP_SXT2;
        } else if (x4 == 0 && x2b == 2) {
            opcode = IA64_OP_SXT4;
        } else if (x4 == 1 && x2b == 0) {
            opcode = IA64_OP_ZXT1;
        } else if (x4 == 1 && x2b == 1) {
            opcode = IA64_OP_ZXT2;
        } else if (x4 == 1 && x2b == 2) {
            opcode = IA64_OP_ZXT4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* CMP-immediate: M/I-unit, b_op == 0xd, bits-34:33 != 0 */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xd &&
        !(ia64_bits(raw, 34, 2) == 0 && ia64_bits(raw, 33, 1) == 0)) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        const uint64_t x = ia64_bits(raw, 33, 1);
        const bool compare_unc = ia64_bits(raw, 12, 1) != 0;
        Ia64Opcode opcode = ia64_compare_opcode_from_cmp(x2a, ve);

        if (x == 1 && (x2a == 2 || x2a == 3)) {
            const bool cmp4 = x2a == 3;
            const bool ne = ia64_bits(raw, 12, 1) != 0;
            opcode = cmp4 ?
                (ne ? IA64_OP_CMP4_NE_OR_IMM : IA64_OP_CMP4_EQ_OR_IMM) :
                (ne ? IA64_OP_CMP_NE_OR_IMM : IA64_OP_CMP_EQ_OR_IMM);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ve == 1 && (x2a == 0 || x2a == 1)) {
            const uint64_t c = ia64_bits(raw, 12, 1);
            if (x2a == 0) {
                if (x == 0 && c == 0) {
                    opcode = IA64_OP_CMP_GT_OR;
                } else if (x == 0 && c == 1) {
                    opcode = IA64_OP_CMP_LE_OR;
                } else if (x == 1 && c == 0) {
                    opcode = IA64_OP_CMP_GE_OR;
                } else {
                    opcode = IA64_OP_CMP_LT_OR;
                }
            } else {
                if (x == 0 && c == 0) {
                    opcode = IA64_OP_CMP4_GT_OR;
                } else if (x == 0 && c == 1) {
                    opcode = IA64_OP_CMP4_LE_OR;
                } else if (x == 1 && c == 0) {
                    opcode = IA64_OP_CMP4_GE_OR;
                } else {
                    opcode = IA64_OP_CMP4_LT_OR;
                }
            }
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(compare_unc ? IA64_OP_CMP_NE_OR :
                                             IA64_OP_CMP_EQ_OR,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (x == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(compare_unc ? IA64_OP_CMP4_NE_OR :
                                             IA64_OP_CMP4_EQ_OR,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (opcode != IA64_OP_ILLEGAL && x == 0 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LTU, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (x == 0 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_LTU_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = compare_unc;
            return insn;
        }
        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_LTU_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.imm = ia64_imm8(raw);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.compare_unc = compare_unc;
            return insn;
        }
        if (opcode != IA64_OP_ILLEGAL && x == 0) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        const uint64_t x = ia64_bits(raw, 33, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x == 0 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 1 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 1 && ve == 1 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_GE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (x == 1 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 0 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (x == 0 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_EQ_IMM, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }

        if (x == 0) {
            opcode = ia64_compare_opcode_from_cmp(x2a, ve);
            if (opcode == IA64_OP_ILLEGAL && x2a == 3 && ve == 1) {
                opcode = IA64_OP_CMP_NE;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SHRP_IMM, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = ia64_bits(raw, 27, 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 20, 7) >= 64) {
        const uint64_t imm8 = ia64_bits(raw, 13, 7) |
                              (ia64_bits(raw, 36, 1) << 7);
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 127 - ia64_bits(raw, 20, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.imm = pos | (len << 6) | (imm8 << 13);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - ia64_bits(raw, 20, 7);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = pos | (len << 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 4) {
        const uint64_t len = (ia64_bits(raw, 27, 4) + 1) & 0x3f;
        const uint64_t cpos = ia64_bits(raw, 31, 2) |
                              (ia64_bits(raw, 33, 1) << 2) |
                              (ia64_bits(raw, 34, 2) << 3) |
                              (ia64_bits(raw, 36, 1) << 5);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEP, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = (63 - cpos) | (len << 6);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 3) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - (ia64_bits(raw, 13, 7) >> 1);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_DEP_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = pos | (len << 6) | (ia64_bits(raw, 36, 1) << 13);
        return insn;
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 1) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x3 == 2) {
            uint64_t pos_sign = ia64_bits(raw, 13, 7);
            Ia64Instruction insn = ia64_base_insn(
                (pos_sign & 1) ? IA64_OP_EXTR : IA64_OP_EXTRU,
                unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = (pos_sign >> 1) |
                       ((ia64_bits(raw, 27, 6) + 1) << 6);
            return insn;
        } else if (x3 == 3) {
            opcode = IA64_OP_SHL_IMM;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            if (opcode == IA64_OP_SHL_IMM) {
                insn.r3 = ia64_bits(raw, 13, 7);
                insn.imm = 63 - ia64_bits(raw, 20, 6);
            } else {
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = 63 - ia64_bits(raw, 27, 6);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PR_ROT_IMM, unit, raw, address, slot);
        insn.imm = ia64_pr_rot_imm(raw);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);

        if (x6 == 0x0a) {
            return ia64_base_insn(IA64_OP_LOADRS, unit, raw, address, slot);
        } else if (x6 == 0x0c) {
            return ia64_base_insn(IA64_OP_FLUSHRS, unit, raw, address, slot);
        } else if (x6 == 0x10) {
            return ia64_base_insn(IA64_OP_INVALA, unit, raw, address, slot);
        } else if (x6 == 0x12 || x6 == 0x13) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_INVALAT, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.check_fp = x6 == 0x13;
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x31) {
            opcode = IA64_OP_MOV_BRGR;  /* mov r=b (BR to GR) */
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x33) {
            opcode = IA64_OP_MOV_PRGR;  /* mov r=pr (PR to GR) */
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x30) {
            opcode = IA64_OP_MOV_CURRENT_IP;
        } else if (x3 == 3) {
            opcode = IA64_OP_MOV_GRPR;  /* mov pr=r (GR to PR) */
        } else if (x3 == 0 && x6 == 0x32) {
            opcode = IA64_OP_MOV_ARGR;  /* mov r=ar (AR to GR) */
        } else if (x3 == 0 && x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov ar=r (GR to AR) */
        } else if (x3 == 0 && x6 == 0x0a) {
            opcode = IA64_OP_MOV_IMMAR; /* mov ar=imm */
        } else if (unit == IA64_UNIT_M && x3 == 0 && x6 == 0x28) {
            opcode = IA64_OP_MOV_IMMAR; /* mov.m ar=imm */
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x10) {
            opcode = IA64_OP_ZXT1;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x11) {
            opcode = IA64_OP_ZXT2;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x12) {
            opcode = IA64_OP_ZXT4;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x14) {
            opcode = IA64_OP_SXT1;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x15) {
            opcode = IA64_OP_SXT2;
        } else if (unit == IA64_UNIT_I && x3 == 0 && x6 == 0x16) {
            opcode = IA64_OP_SXT4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SXT1 || opcode == IA64_OP_SXT2 ||
                opcode == IA64_OP_SXT4 || opcode == IA64_OP_ZXT1 ||
                opcode == IA64_OP_ZXT2 || opcode == IA64_OP_ZXT4) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_CURRENT_IP) {
                insn.r1 = ia64_bits(raw, 6, 7);
            } else if (opcode == IA64_OP_MOV_GRPR) {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.imm = ia64_pr_mask(raw);
            } else if (opcode == IA64_OP_MOV_GRAR) {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_IMMAR) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.imm = ia64_imm8(raw);
            } else if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                /*
                 * BR/PR-to-GR: TCG emitter reads insn->r1 as GR destination,
                 * insn->r2 as BR/PR source.
                 */
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 3);
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 1 && ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x22) {
            opcode = IA64_OP_MOV_ARGR;  /* mov.m r=ar */
        } else if (x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov.m ar=r */
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);

            if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 0xe && ia64_bits(raw, 12, 1) == 1) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 36, 1);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (ia64_bits(raw, 33, 1) == 0 && (x2a == 2 || x2a == 3)) {
            Ia64Instruction insn =
                ia64_base_insn(x2a == 2 ? IA64_OP_CMP_EQ_IMM :
                                           IA64_OP_CMP4_EQ_IMM,
                               unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            insn.compare_unc = true;
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 2) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_NE_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 0 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP_NE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 1 && ve == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_NE_OR_ANDCM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 1 && x2a == 3) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_CMP4_NE_OR_ANDCM_IMM, unit, raw,
                               address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm8(raw);
            return insn;
        }
        if (ia64_bits(raw, 33, 1) == 0) {
            switch ((x2a << 1) | ve) {
            case 0: opcode = IA64_OP_CMP4_EQ; break;
            case 1: opcode = IA64_OP_CMP4_LT; break;
            case 2: opcode = IA64_OP_CMP4_LE; break;
            case 3: opcode = IA64_OP_CMP4_GT; break;
            case 4: opcode = IA64_OP_CMP4_GE; break;
            case 5: opcode = IA64_OP_CMP4_LTU; break;
            case 6: opcode = IA64_OP_CMP4_LEU; break;
            case 7: opcode = IA64_OP_CMP4_GTU; break;
            case 8: opcode = IA64_OP_CMP4_GEU; break;
            }
        } else {
            switch ((x2a << 1) | ve) {
            case 0: opcode = IA64_OP_TBIT_Z;  break;
            case 1: opcode = IA64_OP_TBIT_NZ; break;
            case 2: opcode = IA64_OP_TNAT_Z;  break;
            case 3: opcode = IA64_OP_TNAT_NZ; break;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_I &&
        ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 0) {
        const bool bit13 = ia64_bits(raw, 13, 1);
        const bool bit33 = ia64_bits(raw, 33, 1);
        const bool bit36 = ia64_bits(raw, 36, 1);
        const bool nz_form = ia64_bits(raw, 12, 1);
        const bool is_tf = bit13 && ia64_bits(raw, 19, 1) == 1 &&
                           ia64_bits(raw, 20, 7) == 0;
        const bool is_tnat = bit13 && !is_tf;
        const bool is_tbit = !bit13;

        if (is_tbit || is_tnat || is_tf) {
            Ia64Instruction insn =
                ia64_base_insn(is_tf ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TF_NZ : IA64_OP_TF_Z) :
                               is_tnat ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TNAT_NZ : IA64_OP_TNAT_Z) :
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TBIT_NZ : IA64_OP_TBIT_Z),
                               unit, raw, address, slot);

            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (is_tbit) {
                insn.imm = ia64_bits(raw, 14, 6);
            } else if (is_tf) {
                insn.imm = 32 + ia64_bits(raw, 14, 5);
            }
            if (!bit33 && !bit36) {
                insn.compare_unc = nz_form;
            } else if (!bit33 && bit36) {
                insn.pred_update = IA64_PRED_UPDATE_AND;
            } else if (bit33 && !bit36) {
                insn.pred_update = IA64_PRED_UPDATE_OR;
            } else {
                insn.pred_update = IA64_PRED_UPDATE_OR_ANDCM;
            }
            return insn;
        }
    }

    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_bits(raw, 12, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_b_op(raw) == 0xc) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP4_LT, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_B &&
        (raw & IA64_COVER_B_MASK) == IA64_COVER_B_VALUE) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_COVER, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_UNIT_B && (raw & ~0x3fULL) == 0x20000000ULL) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_UNIT_B && (raw & ~0x3fULL) == 0x28000000ULL) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB_PR, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x28 ||
         ia64_bits(raw, 30, 6) == 0x2c)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_LD16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 30, 6) == 0x2c;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 6 &&
        (ia64_bits(raw, 27, 6) & ~0x26ULL) == 0x01) {
        uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_ST16, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_release = (x6 & 0x20) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 5) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            /* Cache hint bits do not affect the architectural load result. */
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
        if (ia64_opcode_is_store(opcode)) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x20 ||
         ia64_bits(raw, 30, 6) == 0x24)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_CMP8XCHG16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const Ia64Opcode opcode = ia64_cmpxchg_acqrel_opcode_from_size(size);
        Ia64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const Ia64Opcode opcode = ia64_xchg_opcode_from_size(size);
        Ia64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = true;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 2) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode =
            ia64_speculative_load_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 2) == 3) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const bool is_nc = ia64_bits(raw, 29, 1);
        const Ia64Opcode opcode =
            ia64_check_load_opcode_from_x6a(x6a, !is_nc);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.reg_base_update = true;
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const Ia64Opcode opcode = ia64_fetchadd_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_fetchadd_imm(ia64_bits(raw, 13, 3));
            insn.mem_acquire = ia64_fetchadd_x6a_is_acquire(x6a);
            insn.mem_release = ia64_fetchadd_x6a_is_release(x6a);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 2 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t xhint = ia64_bits(raw, 27, 2);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && xhint == 0) {
            opcode = IA64_OP_XCHG1;
        } else if (xm == 0 && xhint == 1) {
            opcode = IA64_OP_XCHG2;
        } else if (xm == 1 && xhint == 0) {
            opcode = IA64_OP_XCHG4;
        } else if (xm == 1 && xhint == 1) {
            opcode = IA64_OP_XCHG8;
        } else if (xm == 2 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG1;
        } else if (xm == 2 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG2;
        } else if (xm == 3 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG4;
        } else if (xm == 3 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 3 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x2 = ia64_bits(raw, 27, 1);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && x2 == 0) {
            opcode = IA64_OP_FETCHADD4;
        } else if (xm == 1 && x2 == 0) {
            opcode = IA64_OP_FETCHADD8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_F) {
        if (ia64_is_f_nop(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_f_break(raw)) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10 &&
            ia64_bits(raw, 13, 7) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_FPABS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x11) {
            const uint64_t f2 = ia64_bits(raw, 13, 7);
            const uint64_t f3 = ia64_bits(raw, 20, 7);

            if (f2 == 0 || f2 == f3) {
                Ia64Instruction insn =
                    ia64_base_insn(f2 == 0 ? IA64_OP_FPNEGABS :
                                             IA64_OP_FPNEG,
                                   unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = f3;
                return insn;
            }
        }
        if ((ia64_b_op(raw) == 0 || ia64_b_op(raw) == 1) &&
            ia64_bits(raw, 36, 1) == 1 &&
            ia64_bits(raw, 33, 1) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(ia64_b_op(raw) == 0 ? IA64_OP_FRSQRTA :
                                                     IA64_OP_FPRSQRTA,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 36, 1) == 0 &&
            ia64_bits(raw, 33, 1) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_FPRCPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 36, 1) == 0 &&
            ia64_bits(raw, 33, 1) == 0) {
            uint64_t form = ia64_bits(raw, 27, 6);
            Ia64Opcode opcode = IA64_OP_ILLEGAL;

            if (form == 0x10 || form == 0x11 || form == 0x12) {
                opcode = form == 0x10 ? IA64_OP_FPMERGE_S :
                         form == 0x11 ? IA64_OP_FPMERGE :
                                          IA64_OP_FPMERGE_SE;
            } else if (form >= 0x14 && form <= 0x17) {
                opcode = form == 0x14 ? IA64_OP_FPMIN :
                         form == 0x15 ? IA64_OP_FPMAX :
                         form == 0x16 ? IA64_OP_FPAMIN :
                                         IA64_OP_FPAMAX;
            } else if (form >= 0x18 && form <= 0x1b) {
                opcode = IA64_OP_FPCVT;
            } else if (form >= 0x30 && form <= 0x37) {
                opcode = IA64_OP_FPCMP;
            }

            if (opcode != IA64_OP_ILLEGAL) {
                Ia64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 34, 2);
                insn.imm = form & 7;
                return insn;
            }
        }
        if (ia64_b_op(raw) == 1) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_F, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        const uint64_t x = ia64_bits(raw, 36, 1);
        const uint64_t x6 = ia64_bits(raw, 30, 6);
        const uint64_t form = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (ia64_b_op(raw) == 4) {
            opcode = IA64_OP_FCMP;
        } else if (ia64_b_op(raw) == 8 && x == 1 &&
                   (x6 == 0x00 || x6 == 0x02 || x6 == 0x04 ||
                    x6 == 0x08 || x6 == 0x0a || x6 == 0x0c ||
                    x6 == 0x0e)) {
            if (x6 == 0x00) {
                opcode = IA64_OP_FMA;
            } else if (x6 == 0x02) {
                opcode = IA64_OP_FMPY;
            } else if (x6 == 0x04) {
                opcode = IA64_OP_FCMP;
            } else if (x6 == 0x08) {
                opcode = IA64_OP_FMIN;
            } else if (x6 == 0x0a) {
                opcode = IA64_OP_FMAX;
            } else if (x6 == 0x0c) {
                opcode = IA64_OP_FAMIN;
            } else if (x6 == 0x0e) {
                opcode = IA64_OP_FAMAX;
            }
        } else if (x == 0 && ia64_b_op(raw) >= 8 &&
                   ia64_b_op(raw) <= 0xd) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x8 ||
                    ia64_b_op(raw) == 0xa ||
                    ia64_b_op(raw) == 0xc)) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x9 ||
                    ia64_b_op(raw) == 0xb ||
                    ia64_b_op(raw) == 0xd)) {
            opcode = ia64_b_op(raw) == 0x9 ? IA64_OP_FPMA :
                     ia64_b_op(raw) == 0xb ? IA64_OP_FPMS :
                                             IA64_OP_FPNMA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x14 && form <= 0x17) {
            opcode = form == 0x14 ? IA64_OP_FMIN :
                     form == 0x15 ? IA64_OP_FMAX :
                     form == 0x16 ? IA64_OP_FAMIN :
                                    IA64_OP_FAMAX;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 0 && form == 0x1c) {
            opcode = IA64_OP_FCVT_XF;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 1) {
            opcode = IA64_OP_FRCPA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ia64_bits(raw, 34, 3) == 0 &&
                   ia64_bits(raw, 27, 6) == 0x28) {
            opcode = IA64_OP_FPACK;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x18 && form <= 0x1b) {
            opcode = (form & 1) ? IA64_OP_FCVT_FXU : IA64_OP_FCVT_FX;
        } else if (ia64_b_op(raw) == 0 && x == 0 && x6 == 0x02 &&
                   (ia64_bits(raw, 27, 6) == 0x10 ||
                    ia64_bits(raw, 27, 6) == 0x11 ||
                    ia64_bits(raw, 27, 6) == 0x12)) {
            opcode = form == 0x10 ? IA64_OP_FMERGE_S :
                     form == 0x11 ? IA64_OP_FMERGE :
                                      IA64_OP_FMERGE_SE;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   (ia64_bits(raw, 27, 6) == 0x04 ||
                    ia64_bits(raw, 27, 6) == 0x05 ||
                    ia64_bits(raw, 27, 6) == 0x08)) {
            opcode = form == 0x04 ? IA64_OP_FSETC :
                     form == 0x05 ? IA64_OP_FCLRF :
                                     IA64_OP_FCHKF;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ((form >= 0x2c && form <= 0x2f) ||
                    (form >= 0x34 && form <= 0x36) ||
                    (form >= 0x39 && form <= 0x3d))) {
            switch (ia64_bits(raw, 27, 6)) {
            case 0x2c:
                opcode = IA64_OP_FAND;
                break;
            case 0x2d:
                opcode = IA64_OP_FANDCM;
                break;
            case 0x2e:
                opcode = IA64_OP_FOR;
                break;
            case 0x2f:
                opcode = IA64_OP_FXOR;
                break;
            case 0x34:
                opcode = IA64_OP_FSWAP;
                break;
            case 0x35:
                opcode = IA64_OP_FSWAP_NL;
                break;
            case 0x36:
                opcode = IA64_OP_FSWAP_NR;
                break;
            case 0x39:
                opcode = IA64_OP_FMIX_LR;
                break;
            case 0x3a:
                opcode = IA64_OP_FMIX_R;
                break;
            case 0x3b:
                opcode = IA64_OP_FMIX_L;
                break;
            case 0x3c:
                opcode = IA64_OP_FSXT_R;
                break;
            case 0x3d:
                opcode = IA64_OP_FSXT_L;
                break;
            }
        } else if (ia64_b_op(raw) == 0 && x == 0) {
            opcode = IA64_OP_FMOV;
        } else if (ia64_b_op(raw) == 0xe && x == 0) {
            opcode = IA64_OP_FSELECT;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 0) {
            opcode = IA64_OP_XMA_L;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 3) {
            opcode = IA64_OP_XMA_H;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 2) {
            opcode = ia64_bits(raw, 13, 7) == 0 ?
                IA64_OP_XMPY_HU : IA64_OP_XMA_HU;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p1 = (opcode == IA64_OP_FMA ||
                       opcode == IA64_OP_FMS ||
                       opcode == IA64_OP_FNMA ||
                       opcode == IA64_OP_XMA_L ||
                       opcode == IA64_OP_XMA_H ||
                       opcode == IA64_OP_XMA_HU ||
                       opcode == IA64_OP_XMPY_HU) ?
                ia64_bits(raw, 27, 7) : ia64_bits(raw, 27, 6);
            if (opcode == IA64_OP_FCMP) {
                insn.p1 = ia64_bits(raw, 6, 6);
                insn.p2 = ia64_bits(raw, 27, 6);
                insn.imm = (ia64_bits(raw, 33, 1) << 1) |
                           ia64_bits(raw, 36, 1);
                insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
            } else if (opcode == IA64_OP_FSETC) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCLRF) {
                insn.p1 = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCHKF) {
                insn.p1 = ia64_bits(raw, 34, 2);
                uint64_t imm20b = ia64_bits(raw, 6, 20);
                uint64_t sign = ia64_bits(raw, 36, 1);
                insn.imm = ia64_sign_extend((sign << 20) | imm20b, 21) * 16;
            }
            if (opcode == IA64_OP_FMA ||
                opcode == IA64_OP_FMS ||
                opcode == IA64_OP_FNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FPMA ||
                       opcode == IA64_OP_FPMS ||
                       opcode == IA64_OP_FPNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSELECT) {
                insn.p1 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FMPY) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSUB) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else if (opcode == IA64_OP_FCVT_FX ||
                       opcode == IA64_OP_FCVT_FXU) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = form & 3;
            } else if (opcode == IA64_OP_FRCPA) {
                insn.p2 = insn.p1;
                insn.clear_p2_before_predicate = true;
            }
            if (ia64_b_op(raw) >= 8 && ia64_b_op(raw) <= 0xd) {
                insn.fp_precision = (ia64_b_op(raw) & 1) ? 2 :
                                    ia64_bits(raw, 36, 1) ? 1 : 0;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);
        bool is_store = opcode == IA64_OP_ILLEGAL;

        if (is_store) {
            opcode = ia64_fp_store_opcode_from_x6a(x6a);
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            if (is_store) {
                insn.r2 = ia64_bits(raw, 13, 7);
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                if (ia64_bits(raw, 36, 1) == 1) {
                    insn.r2 = ia64_bits(raw, 13, 7);
                    insn.reg_base_update = true;
                }
            }
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            Ia64Instruction insn =
                ia64_base_insn(x6a >= 0x2e ? IA64_OP_LFETCH_FAULT :
                                              IA64_OP_LFETCH,
                               unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.reg_base_update = true;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            uint64_t imm9 = (ia64_bits(raw, 36, 1) << 8) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            ia64_bits(raw, 13, 7);
            Ia64Instruction insn =
                ia64_base_insn(x6a >= 0x2e ? IA64_OP_LFETCH_FAULT :
                                              IA64_OP_LFETCH,
                               unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_store_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = ia64_fp_load_pair_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1) {
                insn.imm = opcode == IA64_OP_LDFPS ? 8 : 16;
                insn.imm_base_update = true;
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 7 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6a == 0x02) {
            opcode = IA64_OP_STFD;
        } else if (x6a == 0x03) {
            opcode = IA64_OP_STFS;
        } else if (x6a == 0x3b) {
            opcode = IA64_OP_STF_SPILL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) >= 4) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        Ia64Instruction insn =
            ia64_base_insn((x3 == 4 || x3 == 6) ?
                           IA64_OP_CHK_A : IA64_OP_CHK_A_CLR,
                           unit, raw, address, slot);

        insn.r2 = ia64_bits(raw, 6, 7);
        insn.imm = ia64_chk_a_disp(raw);
        insn.check_fp = x3 >= 6;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x18) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x19) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x31) {
            opcode = IA64_OP_PROBE_RW;
        } else if (x6 == 0x32) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x38) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x39) {
            opcode = IA64_OP_PROBE_W;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (x6 == 0x18 || x6 == 0x19) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_imm = true;
            } else if (x6 == 0x31 || x6 == 0x32 || x6 == 0x33) {
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_fault = true;
                insn.probe_imm = true;
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0 &&
        ia64_bits(raw, 27, 6) == 0x30) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_FC, unit, raw, address, slot);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 2) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 3) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 6) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 7) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B &&
        (ia64_b_op(raw) == 2 || ia64_b_op(raw) == 7)) {
        return ia64_base_insn(IA64_OP_BRP, unit, raw, address, slot);
    }

    if (unit == IA64_UNIT_F && ia64_b_op(raw) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_FCLASS, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = (ia64_bits(raw, 20, 7) << 2) |
                   ia64_bits(raw, 33, 2);
        insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
        return insn;
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        const uint64_t x4 = x6 & 0xf;
        Ia64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6 == 0x31) {
            opcode = IA64_OP_SRLZ;
        } else if (x6 == 0x30) {
            opcode = IA64_OP_SRLZ_D;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_SYNC_I;
        } else if (x6 == 0x20) {
            opcode = IA64_OP_FWB;
        } else if (x4 == 0x04) {
            opcode = IA64_OP_SUM_UM;
        } else if (x4 == 0x05) {
            opcode = IA64_OP_RUM;
        } else if (x4 == 0x06) {
            opcode = IA64_OP_SSM;
        } else if (x4 == 0x07) {
            opcode = IA64_OP_RSM;
        } else if (x6 == 0x22) {
            opcode = IA64_OP_MF;
        } else if (x6 == 0x23) {
            opcode = IA64_OP_MF_A;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SUM_UM || opcode == IA64_OP_RUM ||
                opcode == IA64_OP_SSM || opcode == IA64_OP_RSM) {
                insn.imm = ia64_psr_mask(raw);
            }
            return insn;
        }
    }

    if (unit == IA64_UNIT_L) {
        /*
         * movl r1 = imm64 (X2 format, MLX template).
         * In MLX, the L-slot carries imm41 (bits 62:22), and the X-slot
         * carries opcode(6), r1 and the remaining immediate fields.
         * r1/imm are completed during the MLX fixup pass.
         */
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_UNIT_X && ia64_b_op(raw) == 6) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 0) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_COND, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CLOOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x20) {
        const uint64_t btype = ia64_bits(raw, 6, 3);

        if (btype == 0 || (btype == 1 && ia64_bits(raw, 0, 6) == 0)) {
            Ia64Instruction insn =
                ia64_base_insn(btype == 0 ? IA64_OP_BR_INDIRECT :
                               IA64_OP_BR_IA,
                               unit, raw, address, slot);
            insn.b2 = ia64_bits(raw, 13, 3);
            return insn;
        }
    }

    /* Indirect call: br.call bRet=bTarget, B5. Completers are hints. */
    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL_INDIRECT, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);  /* target branch register */
        insn.b1 = ia64_bits(raw, 6, 3);   /* return branch register */
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 5) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL, unit, raw, address, slot);
        insn.b1 = ia64_bits(raw, 6, 3);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x21 && ia64_bits(raw, 6, 3) == 4) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_BR_RET, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);
        return insn;
    }

    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0) {
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x02: opcode = IA64_OP_COVER; break;
        case 0x04: opcode = IA64_OP_CLRRRB; break;
        case 0x05: opcode = IA64_OP_CLRRRB_PR; break;
        case 0x08: opcode = IA64_OP_RFI; break;
        case 0x0c: opcode = IA64_OP_BSW0; break;
        case 0x0d: opcode = IA64_OP_BSW1; break;
        case 0x10: opcode = IA64_OP_EPC; break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.qp = 0;
            return insn;
        }
    }

    if (unit == IA64_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        Ia64Opcode opcode = IA64_OP_ILLEGAL;

        switch (x6) {
        case 0x09: opcode = IA64_OP_PTC_L; break;
        case 0x0a: opcode = IA64_OP_PTC_G; break;
        case 0x0b: opcode = IA64_OP_PTC_GA; break;
        case 0x0c: opcode = IA64_OP_PTR_D; break;
        case 0x0d: opcode = IA64_OP_PTR_I; break;
        case 0x0e: opcode = IA64_OP_ITR_D; break;
        case 0x0f: opcode = IA64_OP_ITR_I; break;
        case 0x2e: opcode = IA64_OP_ITC_D; break;
        case 0x2f: opcode = IA64_OP_ITC_I; break;
        case 0x34: opcode = IA64_OP_PTC_E; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            Ia64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);

            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    /* VMSW.0 / VMSW.1: B-unit, opcode 0, x6 0x18/0x19. */
    if (unit == IA64_UNIT_B && ia64_b_op(raw) == 0 &&
        (ia64_bits(raw, 27, 6) == 0x18 ||
         ia64_bits(raw, 27, 6) == 0x19)) {
        Ia64Instruction insn =
            ia64_base_insn(IA64_OP_VMSW, unit, raw, address, slot);
        insn.imm = ia64_bits(raw, 27, 6) & 1;
        insn.qp = 0;
        return insn;
    }

    /* H. ADDP4 / ADDS-imm: M/I-unit, b_op == 8
     *
     * Register form (addp4 r1=r2,r3): x3=0, x4=2, x2b=0.
     * Immediate form (addp4/adds r1=imm,r3): bits 34:33 may carry
     * immediate value bits (up to 3), so we accept any x3 for the
     * I-unit path and decode it as an ADDP4/adds immediate.
     */
    if ((unit == IA64_UNIT_M || unit == IA64_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const uint64_t x3 = ia64_bits(raw, 33, 3);

        /* register form — a clean {0,2,0} */
        if (x3 == 0 && x4 == 2 && x2b == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        /*
         * A4 addp4 immediate uses x2a=3/ve=0; bits 36 and 32:27 are part
         * of the 14-bit signed immediate, not register-form extensions.
         */
        if (ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 33, 1) == 0) {
            Ia64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4_IMM, unit, raw, address, slot);
            insn.imm = ia64_imm14(raw);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    return ia64_invalid_insn(unit, raw, address, slot);
}

static TCGv_i64 ia64_gr_src(uint8_t reg)
{
    return reg == 0 ? tcg_constant_i64(0) : cpu_gr[reg];
}

static bool ia64_insn_must_start_group(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_ALLOC:
    case IA64_OP_FLUSHRS:
    case IA64_OP_LOADRS:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_must_end_group(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_BSW0:
    case IA64_OP_BSW1:
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
    case IA64_OP_COVER:
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
    case IA64_OP_PTC_G:
    case IA64_OP_PTC_GA:
    case IA64_OP_RFI:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_requires_slot2(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_BR_CEXIT:
    case IA64_OP_BR_CLOOP:
    case IA64_OP_BR_CTOP:
    case IA64_OP_BR_WEXIT:
    case IA64_OP_BR_WTOP:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_has_invalid_fp_pair(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        return insn->r1 <= 1 || insn->r2 <= 1 ||
               ((insn->r1 ^ insn->r2) & 1) == 0;
    default:
        return false;
    }
}

static bool ia64_insn_writes_gr_r1(const Ia64Instruction *insn)
{
    Ia64Opcode opcode = insn->opcode;

    if ((opcode >= IA64_OP_ADDS && opcode <= IA64_OP_XOR_IMM) ||
        (opcode >= IA64_OP_LD1 && opcode <= IA64_OP_LD8FILL) ||
        (opcode >= IA64_OP_SHL && opcode <= IA64_OP_ZXT4) ||
        (opcode >= IA64_OP_PADD1 && opcode <= IA64_OP_PSHRADD2) ||
        (opcode >= IA64_OP_XCHG1 && opcode <= IA64_OP_FETCHADD8) ||
        (opcode >= IA64_OP_LD1C_CLR && opcode <= IA64_OP_LD8C_NC) ||
        (opcode >= IA64_OP_PAVG1 && opcode <= IA64_OP_CZX2_R)) {
        return true;
    }

    switch (opcode) {
    case IA64_OP_LD16:
    case IA64_OP_MOVL:
    case IA64_OP_MOV_BRGR:
    case IA64_OP_MOV_PRGR:
    case IA64_OP_MOV_ARGR:
    case IA64_OP_MOV_CRGR:
    case IA64_OP_ALLOC:
    case IA64_OP_GETF_D:
    case IA64_OP_GETF_S:
    case IA64_OP_GETF_EXP:
    case IA64_OP_GETF_SIG:
    case IA64_OP_TPA:
    case IA64_OP_TAK:
    case IA64_OP_THASH:
    case IA64_OP_TTAG:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
    case IA64_OP_CLZ:
    case IA64_OP_POPCNT:
    case IA64_OP_MUX:
    case IA64_OP_ADDP4:
    case IA64_OP_ADDP4_IMM:
    case IA64_OP_MOV_PSRGR:
    case IA64_OP_MOV_RRGR:
    case IA64_OP_MOV_PKRGR:
    case IA64_OP_MOV_PKRGR_INDEXED:
    case IA64_OP_MOV_UMGR:
    case IA64_OP_MOV_IBRGR:
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_DBRGR:
    case IA64_OP_MOV_DBRGR_INDEXED:
    case IA64_OP_MOV_PMCGR:
    case IA64_OP_MOV_PMCGR_INDEXED:
    case IA64_OP_MOV_PMDGR:
    case IA64_OP_MOV_PMDGR_INDEXED:
    case IA64_OP_MOV_CPUID:
    case IA64_OP_MOV_CPUID_INDEXED:
    case IA64_OP_MOV_DAHRGR_INDEXED:
    case IA64_OP_MOV_MSRGR:
    case IA64_OP_MOV_IP:
    case IA64_OP_MOV_CURRENT_IP:
        return true;
    case IA64_OP_PROBE_R:
    case IA64_OP_PROBE_W:
    case IA64_OP_PROBE_RW:
        return !insn->probe_fault;
    default:
        return false;
    }
}

static bool ia64_nat_is_known_clear(const DisasContext *ctx, uint8_t reg)
{
    return reg == 0 ||
           (ctx->nat_known_clear[reg / 64] & (1ULL << (reg % 64)));
}

static void ia64_nat_set_known_clear(DisasContext *ctx, uint8_t reg,
                                     bool known_clear)
{
    uint64_t bit;

    if (reg == 0) {
        return;
    }
    bit = 1ULL << (reg % 64);
    if (known_clear) {
        ctx->nat_known_clear[reg / 64] |= bit;
    } else {
        ctx->nat_known_clear[reg / 64] &= ~bit;
    }
}

static bool ia64_nat_result_is_known_clear(const DisasContext *ctx,
                                           const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD16:
    case IA64_OP_MOVL:
    case IA64_OP_MOV_BRGR:
    case IA64_OP_MOV_PRGR:
    case IA64_OP_MOV_ARGR:
    case IA64_OP_MOV_CRGR:
    case IA64_OP_MOV_PSRGR:
    case IA64_OP_MOV_RRGR:
    case IA64_OP_MOV_PKRGR:
    case IA64_OP_MOV_PKRGR_INDEXED:
    case IA64_OP_MOV_UMGR:
    case IA64_OP_MOV_IBRGR:
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_DBRGR:
    case IA64_OP_MOV_DBRGR_INDEXED:
    case IA64_OP_MOV_PMCGR:
    case IA64_OP_MOV_PMCGR_INDEXED:
    case IA64_OP_MOV_PMDGR:
    case IA64_OP_MOV_PMDGR_INDEXED:
    case IA64_OP_MOV_CPUID:
    case IA64_OP_MOV_CPUID_INDEXED:
    case IA64_OP_MOV_DAHRGR_INDEXED:
    case IA64_OP_MOV_MSRGR:
    case IA64_OP_MOV_IP:
    case IA64_OP_MOV_CURRENT_IP:
    case IA64_OP_PROBE_R:
    case IA64_OP_PROBE_W:
    case IA64_OP_PROBE_RW:
        return true;
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        /* A full-ALAT hit preserves the old destination and its NaT. */
        return !ctx->full_alat;
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SHL_IMM:
    case IA64_OP_SHRU_IMM:
    case IA64_OP_SHR_IMM:
    case IA64_OP_EXTRU:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
        return ia64_nat_is_known_clear(ctx, insn->r3);
    case IA64_OP_DEPZ:
        return ia64_nat_is_known_clear(ctx, insn->r2);
    case IA64_OP_DEPZ_IMM:
        return true;
    case IA64_OP_SHLADD:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    case IA64_OP_SHR:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
    case IA64_OP_ADDP4:
        return ia64_nat_is_known_clear(ctx, insn->r2) &&
               ia64_nat_is_known_clear(ctx, insn->r3);
    case IA64_OP_ADDP4_IMM:
        return ia64_nat_is_known_clear(ctx, insn->r3);
    case IA64_OP_MUX:
        return ia64_nat_is_known_clear(ctx, insn->r1) &&
               ia64_nat_is_known_clear(ctx, insn->r2) &&
               ia64_nat_is_known_clear(ctx, insn->r3);
    default:
        return false;
    }
}

static void ia64_update_nat_known(DisasContext *ctx,
                                  const Ia64Instruction *insn)
{
    bool old_r1 = ia64_nat_is_known_clear(ctx, insn->r1);
    bool old_r2 = ia64_nat_is_known_clear(ctx, insn->r2);
    bool old_r3 = ia64_nat_is_known_clear(ctx, insn->r3);

    if (ia64_insn_writes_gr_r1(insn)) {
        bool result = ia64_nat_result_is_known_clear(ctx, insn);

        /* A predicated-off instruction preserves the old destination. */
        ia64_nat_set_known_clear(ctx, insn->r1,
                                 result && (insn->qp == 0 || old_r1));
    }

    if (insn->reg_base_update) {
        /* The executed update assigns base.NaT | increment.NaT. */
        ia64_nat_set_known_clear(ctx, insn->r3, old_r3 && old_r2);
    }
    /* An immediate base update preserves the base register's NaT bit. */
}

static bool ia64_insn_is_privileged(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_BSW0:
    case IA64_OP_BSW1:
    case IA64_OP_RFI:
    case IA64_OP_MOV_CRGR:
    case IA64_OP_MOV_GRCR:
    case IA64_OP_MOV_GRPSR:
    case IA64_OP_MOV_PSRGR:
    case IA64_OP_MOV_RRGR:
    case IA64_OP_MOV_GRRR:
    case IA64_OP_MOV_PKRGR:
    case IA64_OP_MOV_PKRGR_INDEXED:
    case IA64_OP_MOV_GRPKR:
    case IA64_OP_MOV_GRPKR_INDEXED:
    case IA64_OP_MOV_IBRGR:
    case IA64_OP_MOV_GRIBR:
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_GRIBR_INDEXED:
    case IA64_OP_MOV_DBRGR:
    case IA64_OP_MOV_GRDBR:
    case IA64_OP_MOV_DBRGR_INDEXED:
    case IA64_OP_MOV_GRDBR_INDEXED:
    case IA64_OP_MOV_PMCGR:
    case IA64_OP_MOV_GRPMC:
    case IA64_OP_MOV_PMCGR_INDEXED:
    case IA64_OP_MOV_GRPMC_INDEXED:
    case IA64_OP_MOV_GRPMD:
    case IA64_OP_MOV_GRPMD_INDEXED:
    case IA64_OP_MOV_DAHRGR_INDEXED:
    case IA64_OP_MOV_MSRGR:
    case IA64_OP_MOV_GRMSR:
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
    case IA64_OP_ITR_D:
    case IA64_OP_ITR_I:
    case IA64_OP_SSM:
    case IA64_OP_RSM:
    case IA64_OP_PTC_G:
    case IA64_OP_PTC_GA:
    case IA64_OP_PTC_L:
    case IA64_OP_PTR_D:
    case IA64_OP_PTR_I:
    case IA64_OP_PTC_E:
    case IA64_OP_TAK:
    case IA64_OP_TPA:
        return true;
    default:
        return false;
    }
}

static bool ia64_reserved_ar_for_unit(uint8_t ar, Ia64SlotUnit unit,
                                      bool write)
{
    if (unit == IA64_UNIT_I) {
        return ar <= 47 || (ar >= 67 && ar <= 111);
    }

    if ((ar >= 8 && ar <= 15) || ar == 20 ||
        (ar >= 22 && ar <= 23) || ar == 31 ||
        (ar >= 33 && ar <= 35) || (ar >= 37 && ar <= 39) ||
        (ar >= 41 && ar <= 43) || (ar >= 45 && ar <= 47) ||
        (ar >= 64 && ar <= 111)) {
        return true;
    }
    return write && ar == 17;
}

static bool ia64_insn_has_reserved_ar(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_MOV_ARGR:
        return ia64_reserved_ar_for_unit(insn->r2, insn->unit, false);
    case IA64_OP_MOV_GRAR:
    case IA64_OP_MOV_IMMAR:
        return ia64_reserved_ar_for_unit(insn->r2, insn->unit, true);
    default:
        return false;
    }
}

static bool ia64_reserved_cr(uint8_t cr)
{
    return (cr >= 3 && cr <= 7) || (cr >= 10 && cr <= 15) ||
           cr == 18 || (cr >= 26 && cr <= 63) ||
           (cr >= 75 && cr <= 79) || (cr >= 82);
}

static bool ia64_insn_has_illegal_register(const Ia64Instruction *insn)
{
    if (ia64_insn_has_reserved_ar(insn)) {
        return true;
    }
    switch (insn->opcode) {
    case IA64_OP_MOV_CRGR:
        return ia64_reserved_cr(insn->r2);
    case IA64_OP_MOV_GRCR:
        return ia64_reserved_cr(insn->r2) ||
               ia64_cr_is_read_only(insn->r2);
    default:
        return false;
    }
}

static bool ia64_insn_has_reserved_mask_field(const Ia64Instruction *insn)
{
    uint64_t allowed;

    switch (insn->opcode) {
    case IA64_OP_RUM:
    case IA64_OP_SUM_UM:
        return insn->imm & ~0x3eULL;
    case IA64_OP_RSM:
    case IA64_OP_SSM:
        allowed = 0x3eULL |
                  (0x7ULL << 13) |
                  (0x7ffULL << 17) |
                  (0x1fffULL << 32);
        return insn->imm & ~allowed;
    default:
        return false;
    }
}
static bool ia64_fr_is_writable(uint8_t reg)
{
    return reg > 1;
}

static TCGv_i32 ia64_fp_context(const Ia64Instruction *insn)
{
    return tcg_constant_i32(IA64_FP_CONTEXT(insn->sf, insn->fp_precision));
}

static void ia64_gen_fr_nat_clear(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_andi_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_fr_sig_clear(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_andi_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64],
                     ~(1ULL << (reg % 64)));
    tcg_gen_andi_i64(cpu_fr_int_origin[reg / 64],
                     cpu_fr_int_origin[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_fr_sig_set(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_ori_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64],
                    1ULL << (reg % 64));
    tcg_gen_ori_i64(cpu_fr_int_origin[reg / 64],
                    cpu_fr_int_origin[reg / 64],
                    1ULL << (reg % 64));
    tcg_gen_st_i64(cpu_fr[reg], tcg_env,
                   offsetof(CPUIA64State, fr_int_value[reg]));
}

static TCGv_i64 ia64_gen_fr_sig_read(uint8_t reg)
{
    TCGv_i64 bit = tcg_temp_new_i64();

    if (reg <= 1) {
        tcg_gen_movi_i64(bit, 1);
        return bit;
    }
    tcg_gen_shri_i64(bit, cpu_fr_sig[reg / 64], reg % 64);
    tcg_gen_andi_i64(bit, bit, 1);
    return bit;
}

static TCGv_i64 ia64_fr_significand_src(uint8_t reg)
{
    if (reg == 0) {
        return tcg_constant_i64(0);
    }
    if (reg == 1) {
        return tcg_constant_i64(1ULL << 63);
    }
    return cpu_fr[reg];
}

static void ia64_gen_fr_ext_clear(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_andi_i64(cpu_fr_ext_valid[reg / 64],
                     cpu_fr_ext_valid[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_fr_mark_written(uint8_t reg)
{
    if (reg > 1) {
        tcg_gen_ori_i64(cpu_psr, cpu_psr,
                        reg >= 32 ? IA64_PSR_MFH : IA64_PSR_MFL);
        if (reg >= 32) {
            tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                            offsetof(CPUIA64State, rotating_fr_live));
        }
    }
}

static void ia64_gen_fr_nat_set(uint8_t reg)
{
    if (reg <= 1) {
        return;
    }

    tcg_gen_ori_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                    1ULL << (reg % 64));
    ia64_gen_fr_sig_clear(reg);
    ia64_gen_fr_ext_clear(reg);
    ia64_gen_fr_mark_written(reg);
}

static TCGv_i64 ia64_gen_fr_nat_read(uint8_t reg)
{
    TCGv_i64 bit = tcg_temp_new_i64();

    if (reg <= 1) {
        tcg_gen_movi_i64(bit, 0);
        return bit;
    }

    tcg_gen_shri_i64(bit, cpu_fr_nat[reg / 64], reg % 64);
    tcg_gen_andi_i64(bit, bit, 1);
    return bit;
}

static void ia64_gen_fr_nat_assign(uint8_t reg, TCGv_i64 bit)
{
    TCGv_i64 shifted;

    if (reg <= 1) {
        return;
    }

    shifted = tcg_temp_new_i64();
    tcg_gen_andi_i64(shifted, bit, 1);
    tcg_gen_shli_i64(shifted, shifted, reg % 64);
    tcg_gen_andi_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
    tcg_gen_or_i64(cpu_fr_nat[reg / 64], cpu_fr_nat[reg / 64], shifted);
    tcg_gen_not_i64(shifted, shifted);
    tcg_gen_and_i64(cpu_fr_sig[reg / 64], cpu_fr_sig[reg / 64], shifted);
    tcg_gen_and_i64(cpu_fr_int_origin[reg / 64],
                    cpu_fr_int_origin[reg / 64], shifted);
    tcg_gen_and_i64(cpu_fr_ext_valid[reg / 64],
                    cpu_fr_ext_valid[reg / 64], shifted);
}

static void ia64_gen_fr_mov_sig(uint8_t reg, TCGv_i64 value);

static void ia64_gen_xma(const Ia64Instruction *insn, uint32_t mode)
{
    TCGv_i64 all_sig = tcg_temp_new_i64();
    TCGv_i64 test = tcg_temp_new_i64();
    TCGv_i64 low = tcg_temp_new_i64();
    TCGv_i64 high = tcg_temp_new_i64();
    TCGLabel *slow = gen_new_label();
    TCGLabel *done = gen_new_label();

    tcg_gen_and_i64(all_sig, ia64_gen_fr_sig_read(insn->r3),
                    ia64_gen_fr_sig_read(insn->p1));
    tcg_gen_or_i64(test, ia64_gen_fr_nat_read(insn->r3),
                   ia64_gen_fr_nat_read(insn->p1));
    if (mode != 3) {
        tcg_gen_and_i64(all_sig, all_sig,
                        ia64_gen_fr_sig_read(insn->r2));
        tcg_gen_or_i64(test, test, ia64_gen_fr_nat_read(insn->r2));
    }
    tcg_gen_xori_i64(all_sig, all_sig, 1);
    tcg_gen_or_i64(test, test, all_sig);
    tcg_gen_brcondi_i64(TCG_COND_NE, test, 0, slow);

    if (mode == 1) {
        tcg_gen_muls2_i64(low, high, ia64_fr_significand_src(insn->r3),
                          ia64_fr_significand_src(insn->p1));
    } else {
        tcg_gen_mulu2_i64(low, high, ia64_fr_significand_src(insn->r3),
                          ia64_fr_significand_src(insn->p1));
    }
    if (mode != 3) {
        tcg_gen_add2_i64(low, high, low, high,
                         ia64_fr_significand_src(insn->r2),
                         tcg_constant_i64(0));
    }
    ia64_gen_fr_mov_sig(insn->r1, mode == 0 ? low : high);
    tcg_gen_br(done);

    gen_set_label(slow);
    gen_helper_xma(tcg_env, tcg_constant_i32(insn->r1),
                   tcg_constant_i32(mode == 3 ? 0 : insn->r2),
                   tcg_constant_i32(insn->r3),
                   tcg_constant_i32(insn->p1), tcg_constant_i32(mode));
    gen_set_label(done);
}

static void ia64_gen_fr_mov(uint8_t reg, TCGv_i64 value)
{
    if (ia64_fr_is_writable(reg)) {
        tcg_gen_mov_i64(cpu_fr[reg], value);
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_clear(reg);
        ia64_gen_fr_ext_clear(reg);
        ia64_gen_fr_mark_written(reg);
    }
}

static void ia64_gen_fr_mov_sig(uint8_t reg, TCGv_i64 value)
{
    if (ia64_fr_is_writable(reg)) {
        tcg_gen_mov_i64(cpu_fr[reg], value);
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_set(reg);
        ia64_gen_fr_ext_clear(reg);
        ia64_gen_fr_mark_written(reg);
    }
}

static void ia64_gen_fr_ld(uint8_t reg, TCGv_i64 addr, int mmu_idx, MemOp memop)
{
    TCGv_i64 dst = ia64_fr_is_writable(reg) ? cpu_fr[reg] : tcg_temp_new_i64();

    tcg_gen_qemu_ld_i64(dst, addr, mmu_idx, memop);
    if (ia64_fr_is_writable(reg)) {
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_clear(reg);
        ia64_gen_fr_ext_clear(reg);
        ia64_gen_fr_mark_written(reg);
    }
}

static void ia64_gen_fr_ld_s(uint8_t reg, TCGv_i64 addr, int mmu_idx,
                             MemOp memop)
{
    TCGv_i64 value = tcg_temp_new_i64();

    tcg_gen_qemu_ld_i64(value, addr, mmu_idx, memop);
    gen_helper_setf_s(tcg_env, tcg_constant_i32(reg), value);
}

static void ia64_gen_fr_ld_sig(uint8_t reg, TCGv_i64 addr, int mmu_idx,
                               MemOp memop)
{
    TCGv_i64 dst = ia64_fr_is_writable(reg) ? cpu_fr[reg] : tcg_temp_new_i64();

    tcg_gen_qemu_ld_i64(dst, addr, mmu_idx, memop);
    if (ia64_fr_is_writable(reg)) {
        ia64_gen_fr_nat_clear(reg);
        ia64_gen_fr_sig_set(reg);
        ia64_gen_fr_ext_clear(reg);
        ia64_gen_fr_mark_written(reg);
    }
}

static void ia64_gen_raise_exception(uint32_t exception, uint64_t fault_ip,
                                     uint64_t fault_imm, uint32_t fault_slot);
static bool ia64_insn_is_empty_hint(const Ia64Instruction *insn);

static void ia64_gen_branch_if_alignment_fault(TCGv_i64 addr, uint32_t size,
                                               bool always_fault,
                                               TCGLabel *fault)
{
    TCGv_i64 tmp;
    TCGLabel *ok;

    if (size <= 1) {
        return;
    }

    ok = gen_new_label();
    tmp = tcg_temp_new_i64();
    tcg_gen_andi_i64(tmp, addr, size - 1);
    tcg_gen_brcondi_i64(TCG_COND_EQ, tmp, 0, ok);

    if (always_fault) {
        tcg_gen_br(fault);
    } else {
        tcg_gen_andi_i64(tmp, cpu_psr, IA64_PSR_AC);
        tcg_gen_brcondi_i64(TCG_COND_NE, tmp, 0, fault);

        tcg_gen_andi_i64(tmp, addr, 0xfff);
        tcg_gen_addi_i64(tmp, tmp, size - 1);
        tcg_gen_brcondi_i64(TCG_COND_GTU, tmp, 0xfff, fault);
    }

    gen_set_label(ok);
}

static void ia64_gen_check_alignment_access(const Ia64Instruction *insn,
                                            TCGv_i64 addr, uint32_t size,
                                            bool always_fault,
                                            uint64_t isr_access)
{
    TCGLabel *fault;
    TCGLabel *ok;

    if (size <= 1) {
        return;
    }

    fault = gen_new_label();
    ok = gen_new_label();
    ia64_gen_branch_if_alignment_fault(addr, size, always_fault, fault);
    tcg_gen_br(ok);

    gen_set_label(fault);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    gen_helper_raise_unaligned(tcg_env, addr, tcg_constant_i64(isr_access),
                               tcg_constant_i64(insn->address | insn->slot));
    gen_set_label(ok);
}

static void ia64_gen_check_alignment(const Ia64Instruction *insn,
                                     TCGv_i64 addr, uint32_t size,
                                     bool always_fault, bool is_write)
{
    ia64_gen_check_alignment_access(insn, addr, size, always_fault,
                                    is_write ? IA64_ISR_W : IA64_ISR_R);
}

static void ia64_gen_invalidate_alat_store(DisasContext *ctx, TCGv_i64 addr,
                                           uint32_t size)
{
    TCGLabel *done;
    TCGv_i32 active;

    if (!ctx->full_alat) {
        return;
    }

    done = gen_new_label();
    active = tcg_temp_new_i32();

    tcg_gen_ld_i32(active, tcg_env,
                   offsetof(CPUIA64State, alat_active_count));
    tcg_gen_brcondi_i32(TCG_COND_EQ, active, 0, done);
    gen_helper_invalidate_alat_store(tcg_env, addr, tcg_constant_i32(size));
    gen_set_label(done);
}

static TCGLabel *ia64_gen_predicate_skip(const Ia64Instruction *insn,
                                         TCGv_i64 qp_value)
{
    TCGLabel *skip;

    /*
     * For while-loop branches, PR[qp] is the kernel loop condition rather
     * than a predicate that nullifies the instruction.  A false condition
     * must still drain the software pipeline while AR.EC is nonzero.
     */
    if (insn->qp == 0 ||
        insn->opcode == IA64_OP_BR_WEXIT ||
        insn->opcode == IA64_OP_BR_WTOP) {
        return NULL;
    }

    skip = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, qp_value, 0, skip);
    return skip;
}

static void ia64_gen_predicate_end(TCGLabel *skip)
{
    if (skip != NULL) {
        gen_set_label(skip);
    }
}

static void ia64_gen_clear_unc_compare_targets(const Ia64Instruction *insn)
{
    if (insn->compare_unc) {
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
    }
}

static bool ia64_compare_has_equal_targets(const Ia64Instruction *insn)
{
    if (insn->p1 != insn->p2) {
        return false;
    }

    switch (insn->opcode) {
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_IMM:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM:
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM:
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND:
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ:
    case IA64_OP_FCMP:
    case IA64_OP_FCLASS:
        return true;
    default:
        return false;
    }
}

static void ia64_gen_predicate_test_write(const Ia64Instruction *insn,
                                          TCGv_i64 cond, TCGv_i64 not_cond)
{
    switch (insn->pred_update) {
    case IA64_PRED_UPDATE_AND: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_NE, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 1);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 1);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR_ANDCM: {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ, cond, 0, done);
        if (insn->p1 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p1], 1);
        }
        if (insn->p2 != 0) {
            tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
        }
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_NORMAL:
        if (insn->p1 != 0) {
            tcg_gen_mov_i64(cpu_pr[insn->p1], cond);
        }
        if (insn->p2 != 0) {
            tcg_gen_mov_i64(cpu_pr[insn->p2], not_cond);
        }
        break;
    }
}

static void ia64_gen_addp4_result(TCGv_i64 dst, TCGv_i64 src1, TCGv_i64 src3)
{
    TCGv_i64 low = tcg_temp_new_i64();
    TCGv_i64 high = tcg_temp_new_i64();

    tcg_gen_add_i64(low, src1, src3);
    tcg_gen_ext32u_i64(low, low);
    tcg_gen_shri_i64(high, src3, 30);
    tcg_gen_andi_i64(high, high, 3);
    tcg_gen_shli_i64(high, high, 61);
    tcg_gen_or_i64(dst, low, high);
}

static void ia64_gen_saturate_signed_i64(TCGv_i64 value, int bits)
{
    int64_t min_value = -(1LL << (bits - 1));
    int64_t max_value = (1LL << (bits - 1)) - 1;
    TCGLabel *ge_min = gen_new_label();
    TCGLabel *le_max = gen_new_label();

    tcg_gen_brcondi_i64(TCG_COND_GE, value, min_value, ge_min);
    tcg_gen_movi_i64(value, min_value);
    gen_set_label(ge_min);
    tcg_gen_brcondi_i64(TCG_COND_LE, value, max_value, le_max);
    tcg_gen_movi_i64(value, max_value);
    gen_set_label(le_max);
}

static void ia64_gen_clear_ri(void)
{
    tcg_gen_andi_i64(cpu_psr, cpu_psr, ~IA64_PSR_RI_MASK);
}

static void ia64_gen_set_ri(uint8_t slot)
{
    ia64_gen_clear_ri();
    if (slot != 0) {
        tcg_gen_ori_i64(cpu_psr, cpu_psr,
                        (uint64_t)slot << IA64_PSR_RI_SHIFT);
    }
}

static void ia64_gen_set_ri_tracked(DisasContext *ctx, uint8_t slot)
{
    if (ctx->current_ri_known && ctx->current_ri == slot) {
        return;
    }

    if (!ctx->current_ri_known || ctx->current_ri != 0) {
        ia64_gen_clear_ri();
    }
    if (slot != 0) {
        tcg_gen_ori_i64(cpu_psr, cpu_psr,
                        (uint64_t)slot << IA64_PSR_RI_SHIFT);
    }
    ctx->current_ri = slot;
    ctx->current_ri_known = true;
}

static void ia64_gen_force_ri_tracked(DisasContext *ctx, uint8_t slot)
{
    ia64_gen_set_ri(slot);
    ctx->current_ri = slot;
    ctx->current_ri_known = true;
}

/*
 * Keep the architecturally visible restart point at the next instruction
 * boundary after an instruction completes.  In particular, a vCPU kick can
 * make TCG leave a translated block between the end of one instruction and
 * the generated code for the next one.  Leaving PSR.ri at the slot that just
 * completed makes an asynchronous interruption replay that instruction; at
 * the end of a bundle it can also pair the following bundle address with a
 * stale slot number.
 *
 * An MLX L+X instruction occupies slots 1 and 2, so its successor is slot 0
 * of the next bundle rather than slot 2 of the current bundle.  SDM Vol. 2,
 * 5.5.3 likewise defines the successor of an MLX slot-1 instruction as the
 * next bundle at RI 0.
 */
static void ia64_gen_advance_restart_point(DisasContext *ctx,
                                           uint64_t bundle_ip,
                                           uint8_t slot,
                                           bool mlx_long)
{
    if (slot == 2 || (slot == 1 && mlx_long)) {
        ia64_gen_force_ri_tracked(ctx, 0);
        tcg_gen_movi_i64(cpu_ip, bundle_ip + 16);
    } else {
        ia64_gen_force_ri_tracked(ctx, slot + 1);
    }
}

static void ia64_gen_set_fault_slot(uint8_t slot)
{
    tcg_gen_st_i32(tcg_constant_i32(slot), tcg_env,
                   offsetof(CPUIA64State, fault_slot));
}

static void ia64_gen_save_fault_slot_from_ri(void)
{
    TCGv_i64 slot64 = tcg_temp_new_i64();
    TCGv_i32 slot32 = tcg_temp_new_i32();

    tcg_gen_extract_i64(slot64, cpu_psr, IA64_PSR_RI_SHIFT, 2);
    tcg_gen_extrl_i64_i32(slot32, slot64);
    tcg_gen_st_i32(slot32, tcg_env, offsetof(CPUIA64State, fault_slot));
}

static void ia64_gen_save_fault_slot_for_exit(DisasContext *ctx)
{
    if (ctx->current_ri_known) {
        ia64_gen_set_fault_slot(ctx->current_ri);
    } else {
        ia64_gen_save_fault_slot_from_ri();
    }
}

static void ia64_gen_note_successful_bundle(uint64_t bundle_ip,
                                            bool record_iipa,
                                            bool track_psr_suppression)
{
    if (record_iipa) {
        TCGv_i64 collecting = tcg_temp_new_i64();
        TCGLabel *l_done = gen_new_label();

        /*
         * Handler code with PSR.ic cleared must not advance the next IIPA
         * value.
         */
        tcg_gen_andi_i64(collecting, cpu_psr, IA64_PSR_IC);
        tcg_gen_brcondi_i64(TCG_COND_EQ, collecting, 0, l_done);
        tcg_gen_st_i64(tcg_constant_i64(ia64_ip_bundle_addr(bundle_ip)),
                       tcg_env,
                       offsetof(CPUIA64State, last_successful_bundle));
        gen_set_label(l_done);
    }

    if (track_psr_suppression) {
        TCGv_i64 suppression = tcg_temp_new_i64();
        TCGLabel *l_no_suppression = gen_new_label();

        tcg_gen_ld_i64(suppression, tcg_env,
                       offsetof(CPUIA64State, psr_suppression_before_insn));
        tcg_gen_brcondi_i64(TCG_COND_EQ, suppression, 0, l_no_suppression);
        gen_helper_clear_psr_fault_suppression(tcg_env);
        gen_set_label(l_no_suppression);
    }
}

static void ia64_gen_exit_to(DisasContext *ctx, uint64_t ip)
{
    ia64_gen_save_fault_slot_from_ri();
    ia64_gen_clear_ri();
    tcg_gen_movi_i64(cpu_ip, ip);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_gen_store_instruction_group_start(bool group_start)
{
    tcg_gen_st8_i32(tcg_constant_i32(group_start), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
}

static void ia64_gen_exit_to_completed(DisasContext *ctx, uint64_t ip,
                                       uint64_t completed_ip,
                                       bool record_iipa,
                                       bool track_psr_suppression)
{
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    ia64_gen_store_instruction_group_start(ctx->next_instruction_group_start);
    ia64_gen_exit_to(ctx, ip);
}

static void ia64_gen_lookup_tcg_completed(DisasContext *ctx, TCGv_i64 ip,
                                          uint64_t completed_ip,
                                          bool record_iipa,
                                          bool track_psr_suppression)
{
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    ia64_gen_store_instruction_group_start(true);
    ia64_gen_save_fault_slot_from_ri();
    ia64_gen_clear_ri();
    tcg_gen_mov_i64(cpu_ip, ip);
    tcg_gen_lookup_and_goto_ptr();
}

static void ia64_gen_lookup_current_completed(DisasContext *ctx,
                                             uint64_t completed_ip,
                                             bool record_iipa,
                                             bool track_psr_suppression)
{
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    ia64_gen_store_instruction_group_start(true);
    ia64_gen_save_fault_slot_from_ri();
    ia64_gen_clear_ri();
    tcg_gen_lookup_and_goto_ptr();
}

static void ia64_gen_exit_to_slot(DisasContext *ctx, uint64_t ip, uint8_t slot)
{
    if (slot >= 3) {
        ia64_gen_exit_to(ctx, ip + 16);
        return;
    }

    ia64_gen_set_fault_slot(slot);
    ia64_gen_set_ri(slot);
    tcg_gen_movi_i64(cpu_ip, ip);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_gen_exit_to_slot_completed(DisasContext *ctx, uint64_t ip,
                                            uint8_t slot,
                                            uint64_t completed_ip,
                                            bool record_iipa,
                                            bool track_psr_suppression)
{
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    ia64_gen_store_instruction_group_start(ctx->next_instruction_group_start);
    ia64_gen_exit_to_slot(ctx, ip, slot);
}

static void ia64_gen_goto_tb_group(DisasContext *ctx, uint64_t dest,
                                   bool group_start);

static void ia64_gen_goto_completed(DisasContext *ctx, uint64_t ip,
                                    uint64_t completed_ip,
                                    bool record_iipa,
                                    bool track_psr_suppression)
{
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    ia64_gen_goto_tb_group(ctx, ip, true);
}

static bool ia64_gen_completed_direct_branch(DisasContext *ctx,
                                             TCGLabel *skip,
                                             uint64_t target,
                                             uint64_t completed_ip,
                                             bool record_iipa,
                                             bool track_psr_suppression)
{
    ia64_gen_goto_completed(ctx, target, completed_ip, record_iipa,
                            track_psr_suppression);
    return skip == NULL;
}

static bool ia64_is_zero_st1_postinc(const Ia64Instruction *insn)
{
    return (insn->opcode == IA64_OP_ST1 ||
            insn->opcode == IA64_OP_ST1REL) &&
           insn->qp == 0 &&
           insn->r2 == 0 &&
           insn->r3 != 0 &&
           insn->imm == 1;
}

static bool ia64_analyze_self_counted_loop(uint8_t template_code,
                                           const IA64TemplateInfo *template_info,
                                           uint64_t *slots,
                                           uint64_t bundle_ip,
                                           uint8_t start_slot,
                                           DisasContext *ctx)
{
    bool skip_x_slot = false;
    bool zero_st1_exact = true;
    bool zero_st1_seen = false;
    uint8_t zero_st1_base = 0;
    uint8_t zero_st1_slot = 0;
    bool zero_st1_release = false;
    int self_loop_slot = -1;
    int slot;

    for (slot = start_slot; slot < 3; ++slot) {
        Ia64Instruction insn;

        if (skip_x_slot && slot == 2) {
            continue;
        }

        insn = ia64_decode_insn((Ia64SlotUnit)template_info->units[slot],
                                slots[slot], bundle_ip, slot);
        ia64_apply_mlx_long_fixup(template_code, slots, slot, &insn,
                                  &skip_x_slot);
        if (insn.valid &&
            ((insn.opcode == IA64_OP_BR_CLOOP &&
              insn.address + insn.imm == bundle_ip) ||
             (insn.opcode == IA64_OP_BR_CTOP &&
              insn.b2 == 0 &&
              insn.address + insn.imm == bundle_ip))) {
            self_loop_slot = slot;
            if (insn.opcode != IA64_OP_BR_CLOOP || insn.qp != 0) {
                zero_st1_exact = false;
            }
            continue;
        }
        if (insn.valid && ia64_is_zero_st1_postinc(&insn)) {
            if (zero_st1_seen) {
                zero_st1_exact = false;
            } else {
                zero_st1_seen = true;
                zero_st1_base = insn.r3;
                zero_st1_slot = slot;
                zero_st1_release = insn.mem_release;
            }
            continue;
        }
        if (!insn.valid || !ia64_insn_is_empty_hint(&insn)) {
            zero_st1_exact = false;
        }
    }

    if (self_loop_slot < 0) {
        return false;
    }

    if (zero_st1_exact && zero_st1_seen && zero_st1_slot < self_loop_slot) {
        ctx->cloop_zero_st1_valid = true;
        ctx->cloop_zero_st1_release = zero_st1_release;
        ctx->cloop_zero_st1_base = zero_st1_base;
        ctx->cloop_zero_st1_slot = zero_st1_slot;
    }
    return true;
}

static void ia64_prepare_self_counted_loop(DisasContext *ctx,
                                           uint8_t template_code,
                                           const IA64TemplateInfo *template_info,
                                           uint64_t *slots,
                                           uint64_t bundle_ip)
{
    ctx->counted_self_label = NULL;
    ctx->cloop_zero_st1_valid = false;

    if (ctx->start_slot != 0 ||
        ctx->base.plugin_enabled ||
        (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) ||
        !ia64_analyze_self_counted_loop(template_code, template_info, slots,
                                        bundle_ip, ctx->start_slot, ctx)) {
        return;
    }

    ctx->counted_self_label = gen_new_label();
    ctx->counted_self_budget = tcg_temp_new_i64();
    ctx->counted_self_ip = bundle_ip;
    tcg_gen_movi_i64(ctx->counted_self_budget, IA64_COUNTED_SELF_BUDGET);
    gen_set_label(ctx->counted_self_label);
}

static bool ia64_gen_self_counted_loop(DisasContext *ctx, uint64_t target,
                                       uint64_t completed_ip,
                                       bool record_iipa,
                                       bool track_psr_suppression)
{
    TCGLabel *exit_to_tb;

    if (ctx->counted_self_label == NULL ||
        target != ctx->counted_self_ip ||
        completed_ip != ctx->counted_self_ip) {
        return false;
    }

    exit_to_tb = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, ctx->counted_self_budget, 0, exit_to_tb);
    tcg_gen_subi_i64(ctx->counted_self_budget, ctx->counted_self_budget, 1);
    ia64_gen_note_successful_bundle(completed_ip, record_iipa,
                                    track_psr_suppression);
    /*
     * The taken branch restarts the target bundle at slot 0.  The internal
     * TCG back-edge bypasses the normal TB-entry RI initialization, so clear
     * the branch slot's RI before jumping back.  Otherwise a following
     * iteration can OR slot 1 onto stale slot 2 and expose reserved RI=3 to
     * a fault or interruption.
     */
    ia64_gen_force_ri_tracked(ctx, 0);
    tcg_gen_br(ctx->counted_self_label);

    gen_set_label(exit_to_tb);
    ia64_gen_goto_completed(ctx, target, completed_ip, record_iipa,
                            track_psr_suppression);
    return true;
}

static void ia64_gen_raise_exception(uint32_t exception, uint64_t fault_ip,
                                     uint64_t fault_imm, uint32_t fault_slot)
{
    tcg_gen_movi_i64(cpu_ip, fault_ip);
    gen_helper_raise_exception(tcg_env, tcg_constant_i32(exception),
                                tcg_constant_i64(fault_ip),
                                tcg_constant_i64(fault_imm),
                                tcg_constant_i32(fault_slot));
}

static bool ia64_cr_is_read_only(uint32_t cr_num)
{
    switch (cr_num) {
    case IA64_CR_SAPIC_IVR:
    case IA64_CR_SAPIC_IRR0:
    case IA64_CR_SAPIC_IRR1:
    case IA64_CR_SAPIC_IRR2:
    case IA64_CR_SAPIC_IRR3:
        return true;
    default:
        return false;
    }
}

static bool ia64_ar_access_reads_clock(uint32_t ar_num)
{
    return ar_num == 44;
}

static bool ia64_cr_write_reads_clock(uint32_t cr_num)
{
    return cr_num == 1 || cr_num == IA64_CR_ITV;
}

static bool ia64_clock_access_needs_io(const DisasContext *ctx)
{
    return tb_cflags(ctx->base.tb) & CF_USE_ICOUNT;
}

static void ia64_gen_note_stacked_gr_write(uint8_t reg)
{
    uint32_t bit;

    if (reg < IA64_STACKED_GR_BASE) {
        return;
    }
    bit = reg - IA64_STACKED_GR_BASE;
    tcg_gen_ori_i64(cpu_rse_gr_dirty[bit / 64],
                    cpu_rse_gr_dirty[bit / 64], 1ULL << (bit % 64));
}

static void ia64_gen_gr_nat_clear(uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    ia64_gen_note_stacked_gr_write(reg);
    tcg_gen_andi_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
}

static void ia64_gen_gr_nat_set(uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    ia64_gen_note_stacked_gr_write(reg);
    tcg_gen_ori_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                    1ULL << (reg % 64));
}

static void ia64_gen_gr_write_nat_clear(uint8_t reg, TCGv_i64 value)
{
    if (reg == 0) {
        return;
    }
    tcg_gen_mov_i64(cpu_gr[reg], value);
    ia64_gen_gr_nat_clear(reg);
}

typedef enum Ia64NatConsumptionKind {
    IA64_NAT_ACCESS,
    IA64_NAT_NON_ACCESS,
} Ia64NatConsumptionKind;

static void ia64_gen_gr_nat_assign(uint8_t reg, TCGv_i64 bit)
{
    TCGv_i64 shifted;

    if (reg == 0) {
        return;
    }

    ia64_gen_note_stacked_gr_write(reg);
    shifted = tcg_temp_new_i64();
    tcg_gen_andi_i64(shifted, bit, 1);
    tcg_gen_shli_i64(shifted, shifted, reg % 64);
    tcg_gen_andi_i64(cpu_nat[reg / 64], cpu_nat[reg / 64],
                     ~(1ULL << (reg % 64)));
    tcg_gen_or_i64(cpu_nat[reg / 64], cpu_nat[reg / 64], shifted);
}

static TCGv_i64 ia64_gen_gr_nat_read(uint8_t reg)
{
    TCGv_i64 bit = tcg_temp_new_i64();

    if (reg == 0) {
        tcg_gen_movi_i64(bit, 0);
        return bit;
    }

    tcg_gen_shri_i64(bit, cpu_nat[reg / 64], reg % 64);
    tcg_gen_andi_i64(bit, bit, 1);
    return bit;
}

static void ia64_gen_gr_nat_from_1(uint8_t dst, uint8_t src)
{
    if (dst == 0) {
        return;
    }

    ia64_gen_gr_nat_assign(dst, ia64_gen_gr_nat_read(src));
}

static TCGv_i64 ia64_gen_va_unimplemented(TCGv_i64 va)
{
    TCGv_i64 result = tcg_temp_new_i64();

    if (IA64_IMPL_VA_MSB >= 60) {
        tcg_gen_movi_i64(result, 0);
    } else {
        TCGv_i64 sign = tcg_temp_new_i64();
        TCGv_i64 expected = tcg_temp_new_i64();
        uint64_t count = 60 - IA64_IMPL_VA_MSB;
        uint64_t mask = (1ULL << count) - 1;

        tcg_gen_shri_i64(sign, va, IA64_IMPL_VA_MSB);
        tcg_gen_andi_i64(sign, sign, 1);
        tcg_gen_neg_i64(expected, sign);
        tcg_gen_andi_i64(expected, expected, mask);
        tcg_gen_shri_i64(result, va, IA64_IMPL_VA_MSB + 1);
        tcg_gen_andi_i64(result, result, mask);
        tcg_gen_xor_i64(result, result, expected);
        tcg_gen_setcondi_i64(TCG_COND_NE, result, result, 0);
    }

    return result;
}

static void ia64_gen_gr_nat_from_1_or_unimplemented_va(uint8_t dst,
                                                       uint8_t src)
{
    TCGv_i64 nat;
    TCGv_i64 unimplemented;

    if (dst == 0) {
        return;
    }

    nat = ia64_gen_gr_nat_read(src);
    unimplemented = ia64_gen_va_unimplemented(ia64_gr_src(src));
    tcg_gen_or_i64(nat, nat, unimplemented);
    ia64_gen_gr_nat_assign(dst, nat);
}

static void ia64_gen_fr_nat_from_gr(uint8_t dst, uint8_t src)
{
    if (dst <= 1) {
        return;
    }

    ia64_gen_fr_nat_assign(dst, ia64_gen_gr_nat_read(src));
}

static void ia64_gen_gr_nat_from_2(uint8_t dst, uint8_t src1, uint8_t src2)
{
    TCGv_i64 bit;
    TCGv_i64 src_bit;

    if (dst == 0) {
        return;
    }

    bit = ia64_gen_gr_nat_read(src1);
    src_bit = ia64_gen_gr_nat_read(src2);
    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_gr_nat_assign(dst, bit);
}

static void ia64_gen_gr_nat_from_3(uint8_t dst, uint8_t src1, uint8_t src2,
                                   uint8_t src3)
{
    TCGv_i64 bit;
    TCGv_i64 src_bit;

    if (dst == 0) {
        return;
    }

    bit = ia64_gen_gr_nat_read(src1);
    src_bit = ia64_gen_gr_nat_read(src2);
    tcg_gen_or_i64(bit, bit, src_bit);
    src_bit = ia64_gen_gr_nat_read(src3);
    tcg_gen_or_i64(bit, bit, src_bit);
    ia64_gen_gr_nat_assign(dst, bit);
}

static void ia64_gen_pshr(const Ia64Instruction *insn, int lane_bits,
                          bool unsigned_shift)
{
    const int lanes = 64 / lane_bits;
    const uint64_t lane_mask = (1ULL << lane_bits) - 1;
    TCGv_i64 result;
    TCGv_i64 count;
    TCGv_i64 clamped_count;

    if (insn->r1 == 0) {
        return;
    }

    result = tcg_temp_new_i64();
    count = tcg_temp_new_i64();
    clamped_count = tcg_temp_new_i64();

    if (insn->imm >= 0) {
        tcg_gen_movi_i64(count, insn->imm);
    } else {
        tcg_gen_mov_i64(count, ia64_gr_src(insn->r2));
    }
    tcg_gen_movcond_i64(TCG_COND_GTU, clamped_count, count,
                        tcg_constant_i64(lane_bits),
                        tcg_constant_i64(lane_bits), count);

    tcg_gen_movi_i64(result, 0);
    for (int i = 0; i < lanes; i++) {
        TCGv_i64 lane = tcg_temp_new_i64();

        tcg_gen_extract_i64(lane, ia64_gr_src(insn->r3),
                            i * lane_bits, lane_bits);
        if (!unsigned_shift) {
            if (lane_bits == 16) {
                tcg_gen_ext16s_i64(lane, lane);
            } else {
                tcg_gen_ext32s_i64(lane, lane);
            }
            tcg_gen_sar_i64(lane, lane, clamped_count);
        } else {
            tcg_gen_shr_i64(lane, lane, clamped_count);
        }
        tcg_gen_andi_i64(lane, lane, lane_mask);
        tcg_gen_shli_i64(lane, lane, i * lane_bits);
        tcg_gen_or_i64(result, result, lane);
    }

    tcg_gen_mov_i64(cpu_gr[insn->r1], result);
    if (insn->imm >= 0) {
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
    } else {
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
    }
}

static void ia64_gen_pshl(const Ia64Instruction *insn, int lane_bits)
{
    const int lanes = 64 / lane_bits;
    const uint64_t lane_mask = (1ULL << lane_bits) - 1;
    TCGv_i64 result;
    TCGv_i64 count;
    TCGv_i64 clamped_count;

    if (insn->r1 == 0) {
        return;
    }

    result = tcg_temp_new_i64();
    count = tcg_temp_new_i64();
    clamped_count = tcg_temp_new_i64();

    if (insn->imm >= 0) {
        tcg_gen_movi_i64(count, insn->imm);
    } else {
        tcg_gen_mov_i64(count, ia64_gr_src(insn->r3));
    }
    tcg_gen_movcond_i64(TCG_COND_GTU, clamped_count, count,
                        tcg_constant_i64(lane_bits),
                        tcg_constant_i64(lane_bits), count);

    tcg_gen_movi_i64(result, 0);
    for (int i = 0; i < lanes; i++) {
        TCGv_i64 lane = tcg_temp_new_i64();

        tcg_gen_extract_i64(lane, ia64_gr_src(insn->r2),
                            i * lane_bits, lane_bits);
        tcg_gen_shl_i64(lane, lane, clamped_count);
        tcg_gen_andi_i64(lane, lane, lane_mask);
        tcg_gen_shli_i64(lane, lane, i * lane_bits);
        tcg_gen_or_i64(result, result, lane);
    }

    tcg_gen_mov_i64(cpu_gr[insn->r1], result);
    if (insn->imm >= 0) {
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
    } else {
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
    }
}

static void ia64_gen_check_nat_consumption(const Ia64Instruction *insn,
                                           uint8_t reg, uint64_t isr_access,
                                           Ia64NatConsumptionKind kind)
{
    TCGv_i64 nat;
    TCGLabel *ok;

    if (reg == 0 ||
        (insn->ctx &&
         (insn->ctx->nat_known_clear[reg / 64] &
          (1ULL << (reg % 64))))) {
        return;
    }

    nat = ia64_gen_gr_nat_read(reg);
    ok = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, ok);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    if (kind == IA64_NAT_NON_ACCESS) {
        isr_access |= IA64_ISR_NA;
    }
    gen_helper_raise_nat_consumption(
        tcg_env, tcg_constant_i64(isr_access),
        tcg_constant_i64(insn->address | insn->slot));
    gen_set_label(ok);
}

static void ia64_gen_check_fr_nat_consumption(const Ia64Instruction *insn,
                                              uint8_t reg,
                                              uint64_t isr_access)
{
    TCGLabel *ok;

    if (reg <= 1) {
        return;
    }

    ok = gen_new_label();
    tcg_gen_brcondi_i64(TCG_COND_EQ, ia64_gen_fr_nat_read(reg), 0, ok);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    gen_helper_raise_nat_consumption(
        tcg_env, tcg_constant_i64(isr_access),
        tcg_constant_i64(insn->address | insn->slot));
    gen_set_label(ok);
}

static void ia64_gen_check_gr_in_frame(const Ia64Instruction *insn,
                                       uint8_t reg)
{
    if (reg == 0) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return;
    }

    if (reg >= IA64_STACKED_GR_BASE) {
        TCGv_i32 sof = tcg_temp_new_i32();
        TCGLabel *valid = gen_new_label();

        tcg_gen_ld8u_i32(sof, tcg_env, offsetof(CPUIA64State, cfm_sof));
        tcg_gen_brcondi_i32(TCG_COND_GTU, sof,
                            reg - IA64_STACKED_GR_BASE, valid);
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        gen_set_label(valid);
    }
}

static void ia64_gen_check_privileged(const Ia64Instruction *insn)
{
    TCGv_i64 cpl = tcg_temp_new_i64();
    TCGLabel *allowed = gen_new_label();
    uint64_t isr = 0x10;

    if (insn->opcode == IA64_OP_TAK) {
        isr |= IA64_ISR_NA | 3;
    } else if (insn->opcode == IA64_OP_TPA) {
        isr |= IA64_ISR_NA;
    }

    tcg_gen_andi_i64(cpl, cpu_psr, IA64_PSR_CPL_MASK);
    tcg_gen_brcondi_i64(TCG_COND_EQ, cpl, 0, allowed);
    tcg_gen_st_i64(tcg_constant_i64(isr), tcg_env,
                   offsetof(CPUIA64State, cr_isr));
    ia64_gen_raise_exception(IA64_EXCP_PRIVILEGED_OP, insn->address,
                              insn->raw, insn->slot);
    gen_set_label(allowed);
}

static void ia64_gen_check_register_index(const Ia64Instruction *insn,
                                          TCGv_i64 index, uint32_t count)
{
    TCGv_i64 low8 = tcg_temp_new_i64();
    TCGLabel *valid = gen_new_label();

    tcg_gen_andi_i64(low8, index, 0xff);
    tcg_gen_brcondi_i64(TCG_COND_LTU, low8, count, valid);
    tcg_gen_st_i64(tcg_constant_i64(0x30), tcg_env,
                   offsetof(CPUIA64State, cr_isr));
    ia64_gen_raise_exception(IA64_EXCP_RESERVED_REG_FIELD,
                              insn->address, insn->raw, insn->slot);
    gen_set_label(valid);
}

static void ia64_gen_check_reserved_bits(const Ia64Instruction *insn,
                                         TCGv_i64 value, uint64_t allowed)
{
    TCGv_i64 reserved = tcg_temp_new_i64();
    TCGLabel *valid = gen_new_label();

    tcg_gen_andi_i64(reserved, value, ~allowed);
    tcg_gen_brcondi_i64(TCG_COND_EQ, reserved, 0, valid);
    tcg_gen_st_i64(tcg_constant_i64(0x30), tcg_env,
                   offsetof(CPUIA64State, cr_isr));
    ia64_gen_raise_exception(IA64_EXCP_RESERVED_REG_FIELD,
                              insn->address, insn->raw, insn->slot);
    gen_set_label(valid);
}

static void ia64_gen_write_user_mask(TCGv_i64 value)
{
    TCGv_i64 new_psr = tcg_temp_new_i64();
    TCGv_i64 new_um = tcg_temp_new_i64();
    TCGv_i64 secure = tcg_temp_new_i64();
    TCGv_i64 old_up = tcg_temp_new_i64();
    TCGLabel *done = gen_new_label();

    tcg_gen_andi_i64(new_psr, cpu_psr, ~IA64_PSR_UM_WRITABLE_MASK);
    tcg_gen_andi_i64(new_um, value, IA64_PSR_UM_WRITABLE_MASK);
    tcg_gen_or_i64(new_psr, new_psr, new_um);

    /* PSR.sp makes the user performance-monitor bit read-only. */
    tcg_gen_andi_i64(secure, cpu_psr, IA64_PSR_SP);
    tcg_gen_brcondi_i64(TCG_COND_EQ, secure, 0, done);
    tcg_gen_andi_i64(new_psr, new_psr, ~IA64_PSR_UP);
    tcg_gen_andi_i64(old_up, cpu_psr, IA64_PSR_UP);
    tcg_gen_or_i64(new_psr, new_psr, old_up);
    gen_set_label(done);

    tcg_gen_mov_i64(cpu_psr, new_psr);
}

static void ia64_gen_validate_ar_access(const Ia64Instruction *insn,
                                        TCGv_i64 value, bool write)
{
    gen_helper_validate_ar_access(tcg_env, value,
                                  tcg_constant_i32(insn->r2),
                                  tcg_constant_i32(write),
                                  tcg_constant_i64(insn->address),
                                  tcg_constant_i64(insn->raw),
                                  tcg_constant_i32(insn->slot));
}

static bool ia64_ar_is_simple(uint32_t ar)
{
    switch (ar) {
    case 32: /* CCV */
    case 36: /* UNAT */
    case 40: /* FPSR */
    case 64: /* PFS */
    case 65: /* LC */
    case 66: /* EC */
        return true;
    default:
        return false;
    }
}

static void ia64_gen_read_simple_ar(TCGv_i64 value, uint32_t ar)
{
    tcg_gen_ld_i64(value, tcg_env,
                   offsetof(CPUIA64State, ar) + ar * sizeof(uint64_t));
}

static void ia64_gen_write_simple_ar(uint32_t ar, TCGv_i64 value)
{
    if (ar == 66) {
        TCGv_i64 masked = tcg_temp_new_i64();

        tcg_gen_andi_i64(masked, value, 0x3f);
        value = masked;
    }
    tcg_gen_st_i64(value, tcg_env,
                   offsetof(CPUIA64State, ar) + ar * sizeof(uint64_t));
}

static void ia64_gen_validate_cr_access(TCGv_i64 result,
                                        const Ia64Instruction *insn,
                                        TCGv_i64 value, bool write)
{
    gen_helper_validate_cr_access(result, tcg_env, value,
                                  tcg_constant_i32(insn->r2),
                                  tcg_constant_i32(write),
                                  tcg_constant_i64(insn->address),
                                  tcg_constant_i64(insn->raw),
                                  tcg_constant_i32(insn->slot));
}

static void ia64_gen_check_nat_register(const Ia64Instruction *insn,
                                        uint8_t reg)
{
    ia64_gen_check_nat_consumption(insn, reg, 0, IA64_NAT_ACCESS);
}

static void ia64_gen_check_nat_access(const Ia64Instruction *insn,
                                      uint8_t reg, bool is_write)
{
    ia64_gen_check_nat_consumption(insn, reg,
                                   is_write ? IA64_ISR_W : IA64_ISR_R,
                                   IA64_NAT_ACCESS);
}

/*
 * IA-64 acquire/release completers are one-way ordering constraints.
 * Full serialization is reserved for explicit fence instructions such as mf.
 */
#define IA64_TCG_MO_ACQUIRE \
    (TCG_BAR_LDAQ | TCG_MO_LD_LD | TCG_MO_LD_ST)
#define IA64_TCG_MO_RELEASE \
    (TCG_BAR_STRL | TCG_MO_LD_ST | TCG_MO_ST_ST)

static void ia64_gen_memory_acquire(const Ia64Instruction *insn)
{
    if (insn->mem_acquire) {
        tcg_gen_mb(IA64_TCG_MO_ACQUIRE);
    }
}

static void ia64_gen_memory_release(const Ia64Instruction *insn)
{
    if (insn->mem_release) {
        tcg_gen_mb(IA64_TCG_MO_RELEASE);
    }
}

static bool ia64_gen_zero_st1_cloop(DisasContext *ctx,
                                    const Ia64Instruction *insn,
                                    uint64_t target,
                                    TCGLabel *l_nobr,
                                    bool record_iipa,
                                    bool track_psr_suppression)
{
    TCGv_i64 taken;

    if (!ctx->cloop_zero_st1_valid ||
        target != ctx->counted_self_ip ||
        insn->address != ctx->counted_self_ip) {
        return false;
    }

    if (ctx->cloop_zero_st1_release) {
        tcg_gen_mb(IA64_TCG_MO_RELEASE);
    }

    /*
     * Faults from the helper's future loop-body stores must be reported as
     * the original store slot, not the branch slot that calls the helper.
     */
    ia64_gen_force_ri_tracked(ctx, ctx->cloop_zero_st1_slot);
    taken = tcg_temp_new_i64();
    gen_helper_cloop_zero_st1(taken, tcg_env,
                              tcg_constant_i32(ctx->cloop_zero_st1_base),
                              tcg_constant_i32(ctx->mmu_idx),
                              tcg_constant_i32(IA64_CLOOP_ZERO_ST1_MAX));
    ia64_gen_note_stacked_gr_write(ctx->cloop_zero_st1_base);
    ia64_gen_force_ri_tracked(ctx, insn->slot);

    tcg_gen_brcondi_i64(TCG_COND_EQ, taken, 0, l_nobr);
    ia64_gen_goto_completed(ctx, target, insn->address, record_iipa,
                            track_psr_suppression);
    return true;
}

static void ia64_gen_check_nat_non_access(const Ia64Instruction *insn,
                                          uint8_t reg, bool is_write)
{
    ia64_gen_check_nat_consumption(insn, reg,
                                   is_write ? IA64_ISR_W : IA64_ISR_R,
                                   IA64_NAT_NON_ACCESS);
}

static void ia64_gen_check_nat_semaphore(const Ia64Instruction *insn,
                                         uint8_t reg,
                                         Ia64NatConsumptionKind kind)
{
    ia64_gen_check_nat_consumption(insn, reg, IA64_ISR_R | IA64_ISR_W,
                                   kind);
}

static void ia64_gen_load_reg_base_update_inputs(
    const Ia64Instruction *insn,
    TCGv_i64 *increment,
    TCGv_i64 *base_nat,
    TCGv_i64 *increment_nat)
{
    if (!insn->reg_base_update) {
        return;
    }

    *increment = tcg_temp_new_i64();
    *base_nat = ia64_gen_gr_nat_read(insn->r3);
    *increment_nat = ia64_gen_gr_nat_read(insn->r2);
    tcg_gen_mov_i64(*increment, ia64_gr_src(insn->r2));
}

static void ia64_gen_load_reg_base_update(const Ia64Instruction *insn,
                                          TCGv_i64 addr,
                                          TCGv_i64 increment,
                                          TCGv_i64 base_nat,
                                          TCGv_i64 increment_nat)
{
    TCGv_i64 new_base = tcg_temp_new_i64();
    TCGv_i64 new_nat = tcg_temp_new_i64();

    tcg_gen_add_i64(new_base, addr, increment);
    tcg_gen_mov_i64(cpu_gr[insn->r3], new_base);
    tcg_gen_or_i64(new_nat, base_nat, increment_nat);
    ia64_gen_gr_nat_assign(insn->r3, new_nat);
}

static void ia64_gen_lfetch(const Ia64Instruction *insn)
{
    TCGv_i64 addr = tcg_temp_new_i64();
    TCGv_i64 increment = NULL;
    TCGv_i64 base_nat = NULL;
    TCGv_i64 increment_nat = NULL;

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
    ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                         &increment_nat);

    if (insn->opcode == IA64_OP_LFETCH_FAULT) {
        TCGLabel *done = gen_new_label();
        TCGv_i64 ed = tcg_temp_new_i64();

        tcg_gen_andi_i64(ed, cpu_psr, IA64_PSR_ED);
        tcg_gen_brcondi_i64(TCG_COND_NE, ed, 0, done);
        ia64_gen_check_nat_consumption(insn, insn->r3,
                                       IA64_ISR_R | 4,
                                       IA64_NAT_NON_ACCESS);
        tcg_gen_movi_i64(cpu_ip, ia64_ip_bundle_addr(insn->address));
        gen_helper_lfetch_fault(tcg_env, addr,
                                tcg_constant_i64(
                                    ia64_ip_bundle_addr(insn->address)),
                                tcg_constant_i32(insn->slot));
        gen_set_label(done);
    }

    if (insn->reg_base_update) {
        ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                      increment_nat);
    } else if (insn->imm_base_update && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        ia64_gen_note_stacked_gr_write(insn->r3);
    }
}

static void ia64_gen_ld_fill_nat(uint8_t reg, TCGv_i64 addr)
{
    TCGv_i64 unat = tcg_temp_new_i64();
    TCGv_i64 bitpos = tcg_temp_new_i64();
    TCGv_i64 natbit = tcg_temp_new_i64();

    ia64_gen_read_simple_ar(unat, 36);
    tcg_gen_shri_i64(bitpos, addr, 3);
    tcg_gen_andi_i64(bitpos, bitpos, 0x3f);
    tcg_gen_shr_i64(natbit, unat, bitpos);
    tcg_gen_andi_i64(natbit, natbit, 1);
    ia64_gen_gr_nat_assign(reg, natbit);
}

static void ia64_gen_check_branch(DisasContext *ctx, TCGv_i64 failed,
                                  uint64_t target,
                                  uint64_t completed_ip,
                                  bool record_iipa,
                                  bool track_psr_suppression)
{
    TCGLabel *l_done = gen_new_label();

    tcg_gen_brcondi_i64(TCG_COND_EQ, failed, 0, l_done);
    ia64_gen_goto_completed(ctx, target, completed_ip, record_iipa,
                            track_psr_suppression);
    gen_set_label(l_done);
}

static void ia64_gen_sync_ip_for_helper(const Ia64Instruction *insn)
{
    tcg_gen_movi_i64(cpu_ip, ia64_ip_bundle_addr(insn->address));
    ia64_gen_set_fault_slot(insn->slot);
}

static void ia64_gen_speculative_load(DisasContext *ctx,
                                      const Ia64Instruction *insn,
                                      bool advanced)
{
    MemOp mop = ia64_data_memop(ctx, ia64_memop_for_opcode(insn->opcode));
    TCGv_i64 addr;
    TCGv_i64 increment = NULL;
    TCGv_i64 base_nat = NULL;
    TCGv_i64 increment_nat = NULL;
    TCGv_i64 ok;
    TCGLabel *l_fail;
    TCGLabel *l_done;

    if (insn->r1 == 0) {
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        return;
    }

    addr = tcg_temp_new_i64();
    ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                         &increment_nat);
    ok = tcg_temp_new_i64();
    l_fail = gen_new_label();
    l_done = gen_new_label();

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
    if (insn->r3 != 0) {
        TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

        tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
    }
    ia64_gen_sync_ip_for_helper(insn);
    gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                 tcg_constant_i32(0),
                                 tcg_constant_i32(ia64_memop_size(mop)));
    tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

    tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr, ctx->mmu_idx, mop);
    ia64_gen_gr_nat_clear(insn->r1);
    if (advanced && ctx->full_alat) {
        gen_helper_set_alat(tcg_env, tcg_constant_i32(insn->r1), addr,
                            tcg_constant_i32(ia64_memop_size(mop)));
    }
    tcg_gen_br(l_done);

    gen_set_label(l_fail);
    if (advanced && ctx->full_alat) {
        gen_helper_invalidate_alat_reg(tcg_env, tcg_constant_i32(insn->r1));
    }
    tcg_gen_movi_i64(cpu_gr[insn->r1], 0);
    ia64_gen_gr_nat_set(insn->r1);

    gen_set_label(l_done);
    if (insn->reg_base_update && insn->r3 != 0) {
        ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                      increment_nat);
    } else if (insn->imm_base_update && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        ia64_gen_note_stacked_gr_write(insn->r3);
    }
}

static uint32_t ia64_fp_load_size(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LDFS:
        return 4;
    case IA64_OP_LDFD:
    case IA64_OP_LDF8:
        return 8;
    case IA64_OP_LDFE:
    case IA64_OP_LDF_FILL:
        return 16;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_value(DisasContext *ctx,
                                   const Ia64Instruction *insn,
                                   TCGv_i64 addr)
{
    switch (insn->opcode) {
    case IA64_OP_LDFS:
        ia64_gen_fr_ld_s(insn->r1, addr, ctx->mmu_idx,
                         ia64_data_memop(ctx, MO_LEUL));
        break;
    case IA64_OP_LDFD:
        ia64_gen_fr_ld(insn->r1, addr, ctx->mmu_idx,
                       ia64_data_memop(ctx, MO_LEUQ));
        break;
    case IA64_OP_LDF8:
        ia64_gen_fr_ld_sig(insn->r1, addr, ctx->mmu_idx,
                           ia64_data_memop(ctx, MO_LEUQ));
        break;
    case IA64_OP_LDF_FILL:
        gen_helper_ldf_fill(tcg_env, tcg_constant_i32(insn->r1), addr);
        break;
    case IA64_OP_LDFE:
        gen_helper_ldfe(tcg_env, tcg_constant_i32(insn->r1), addr);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_advanced_fail_value(const Ia64Instruction *insn)
{
    if (insn->opcode == IA64_OP_LDF8) {
        ia64_gen_fr_mov_sig(insn->r1, tcg_constant_i64(0));
    } else {
        ia64_gen_fr_mov(insn->r1, tcg_constant_i64(0));
    }
}

static void ia64_gen_fp_load_base_update(const Ia64Instruction *insn,
                                         TCGv_i64 addr,
                                         TCGv_i64 increment,
                                         TCGv_i64 base_nat,
                                         TCGv_i64 increment_nat)
{
    if (insn->reg_base_update && insn->r3 != 0) {
        ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                      increment_nat);
    } else if (insn->imm_base_update && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        ia64_gen_note_stacked_gr_write(insn->r3);
    }
}

static void ia64_gen_fp_load(DisasContext *ctx, const Ia64Instruction *insn)
{
    const uint32_t size = ia64_fp_load_size(insn->opcode);
    TCGv_i64 addr = tcg_temp_new_i64();
    TCGv_i64 increment = NULL;
    TCGv_i64 base_nat = NULL;
    TCGv_i64 increment_nat = NULL;

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
    ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                         &increment_nat);

    if (insn->fp_load_check && ctx->full_alat) {
        TCGv_i64 hit = tcg_temp_new_i64();
        TCGLabel *l_done = gen_new_label();

        ia64_gen_check_nat_non_access(insn, insn->r3, false);
        gen_helper_check_load_alat_fp_addr(hit, tcg_env,
                                           tcg_constant_i32(insn->r1),
                                           addr, tcg_constant_i32(size),
                                           tcg_constant_i32(
                                               insn->fp_load_check_clear));
        tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);

        ia64_gen_check_alignment(insn, addr, size, false, false);
        ia64_gen_fp_load_value(ctx, insn, addr);
        if (!insn->fp_load_check_clear) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }

        gen_set_label(l_done);
        ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                     increment_nat);
        return;
    }

    if (insn->fp_load_speculative) {
        TCGv_i64 ok = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        if (insn->r3 != 0) {
            TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

            tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
        }
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                     tcg_constant_i32(0),
                                     tcg_constant_i32(size));
        tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

        ia64_gen_fp_load_value(ctx, insn, addr);
        if (insn->fp_load_advanced && ctx->full_alat) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (insn->fp_load_advanced && ctx->full_alat) {
            gen_helper_invalidate_alat_fp_reg(tcg_env,
                                              tcg_constant_i32(insn->r1));
        }
        if (ia64_fr_is_writable(insn->r1)) {
            tcg_gen_movi_i64(cpu_fr[insn->r1], 0);
        }
        ia64_gen_fr_nat_set(insn->r1);

        gen_set_label(l_done);
        ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                     increment_nat);
        return;
    }

    ia64_gen_check_nat_non_access(insn, insn->r3, false);
    ia64_gen_check_alignment(insn, addr, size, false, false);
    if (insn->fp_load_advanced) {
        TCGv_i64 allowed = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        gen_helper_advanced_load_allowed(allowed, tcg_env, addr);
        tcg_gen_brcondi_i64(TCG_COND_EQ, allowed, 0, l_fail);
        ia64_gen_fp_load_value(ctx, insn, addr);
        if (ctx->full_alat) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (ctx->full_alat) {
            gen_helper_invalidate_alat_fp_reg(
                tcg_env, tcg_constant_i32(insn->r1));
        }
        ia64_gen_fp_load_advanced_fail_value(insn);

        gen_set_label(l_done);
        ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                     increment_nat);
        return;
    }
    ia64_gen_fp_load_value(ctx, insn, addr);
    ia64_gen_fp_load_base_update(insn, addr, increment, base_nat,
                                 increment_nat);
}

static uint32_t ia64_fp_load_pair_size(Ia64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LDFPS:
        return 8;
    case IA64_OP_LDFPD:
    case IA64_OP_LDFP8:
        return 16;
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_pair_value(DisasContext *ctx,
                                        const Ia64Instruction *insn,
                                        TCGv_i64 addr)
{
    TCGv_i64 first = tcg_temp_new_i64();
    TCGv_i64 second = tcg_temp_new_i64();

    switch (insn->opcode) {
    case IA64_OP_LDFPS: {
        TCGv_i64 pair = tcg_temp_new_i64();

        tcg_gen_qemu_ld_i64(pair, addr, ctx->mmu_idx,
                            ia64_data_memop(ctx, MO_UQ));
        if (ctx->be_data) {
            tcg_gen_shri_i64(first, pair, 32);
            tcg_gen_ext32u_i64(second, pair);
        } else {
            tcg_gen_ext32u_i64(first, pair);
            tcg_gen_shri_i64(second, pair, 32);
        }
        gen_helper_setf_s(tcg_env, tcg_constant_i32(insn->r1), first);
        gen_helper_setf_s(tcg_env, tcg_constant_i32(insn->r2), second);
        break;
    }
    case IA64_OP_LDFPD:
    case IA64_OP_LDFP8: {
        TCGv_i128 pair = tcg_temp_new_i128();

        tcg_gen_qemu_ld_i128(
            pair, addr, ctx->mmu_idx,
            ia64_data_memop(ctx, MO_UO));
        if (ctx->be_data) {
            tcg_gen_extr_i128_i64(second, first, pair);
        } else {
            tcg_gen_extr_i128_i64(first, second, pair);
        }
        if (insn->opcode == IA64_OP_LDFPD) {
            ia64_gen_fr_mov(insn->r1, first);
            ia64_gen_fr_mov(insn->r2, second);
        } else {
            ia64_gen_fr_mov_sig(insn->r1, first);
            ia64_gen_fr_mov_sig(insn->r2, second);
        }
        break;
    }
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_fp_load_pair_nat_set(const Ia64Instruction *insn)
{
    if (ia64_fr_is_writable(insn->r1)) {
        tcg_gen_movi_i64(cpu_fr[insn->r1], 0);
    }
    if (ia64_fr_is_writable(insn->r2)) {
        tcg_gen_movi_i64(cpu_fr[insn->r2], 0);
    }
    ia64_gen_fr_nat_set(insn->r1);
    ia64_gen_fr_nat_set(insn->r2);
}

static void ia64_gen_fp_load_pair_advanced_fail_value(
    const Ia64Instruction *insn)
{
    if (insn->opcode == IA64_OP_LDFP8) {
        ia64_gen_fr_mov_sig(insn->r1, tcg_constant_i64(0));
        ia64_gen_fr_mov_sig(insn->r2, tcg_constant_i64(0));
    } else {
        ia64_gen_fr_mov(insn->r1, tcg_constant_i64(0));
        ia64_gen_fr_mov(insn->r2, tcg_constant_i64(0));
    }
}

static void ia64_gen_fp_load_pair_base_update(const Ia64Instruction *insn,
                                              TCGv_i64 addr)
{
    if (insn->imm_base_update && insn->r3 != 0) {
        tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
        ia64_gen_note_stacked_gr_write(insn->r3);
    }
}

static void ia64_gen_fp_load_pair(DisasContext *ctx,
                                  const Ia64Instruction *insn)
{
    const uint32_t size = ia64_fp_load_pair_size(insn->opcode);
    TCGv_i64 addr = tcg_temp_new_i64();

    tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));

    if (insn->fp_load_check && ctx->full_alat) {
        TCGv_i64 hit = tcg_temp_new_i64();
        TCGLabel *l_done = gen_new_label();

        ia64_gen_check_nat_non_access(insn, insn->r3, false);
        gen_helper_check_load_alat_fp_addr(hit, tcg_env,
                                           tcg_constant_i32(insn->r1),
                                           addr, tcg_constant_i32(size),
                                           tcg_constant_i32(
                                               insn->fp_load_check_clear));
        tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);

        ia64_gen_check_alignment(insn, addr, size, false, false);
        ia64_gen_fp_load_pair_value(ctx, insn, addr);
        if (!insn->fp_load_check_clear) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }

        gen_set_label(l_done);
        ia64_gen_fp_load_pair_base_update(insn, addr);
        return;
    }

    if (insn->fp_load_speculative) {
        TCGv_i64 ok = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        if (insn->r3 != 0) {
            TCGv_i64 addr_nat = ia64_gen_gr_nat_read(insn->r3);

            tcg_gen_brcondi_i64(TCG_COND_NE, addr_nat, 0, l_fail);
        }
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_speculative_probe(ok, tcg_env, addr, tcg_constant_i32(0),
                                     tcg_constant_i32(0),
                                     tcg_constant_i32(size));
        tcg_gen_brcondi_i64(TCG_COND_EQ, ok, 0, l_fail);

        ia64_gen_fp_load_pair_value(ctx, insn, addr);
        if (insn->fp_load_advanced && ctx->full_alat) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (insn->fp_load_advanced && ctx->full_alat) {
            gen_helper_invalidate_alat_fp_reg(tcg_env,
                                              tcg_constant_i32(insn->r1));
        }
        ia64_gen_fp_load_pair_nat_set(insn);

        gen_set_label(l_done);
        ia64_gen_fp_load_pair_base_update(insn, addr);
        return;
    }

    ia64_gen_check_nat_non_access(insn, insn->r3, false);
    ia64_gen_check_alignment(insn, addr, size, false, false);
    if (insn->fp_load_advanced) {
        TCGv_i64 allowed = tcg_temp_new_i64();
        TCGLabel *l_fail = gen_new_label();
        TCGLabel *l_done = gen_new_label();

        gen_helper_advanced_load_allowed(allowed, tcg_env, addr);
        tcg_gen_brcondi_i64(TCG_COND_EQ, allowed, 0, l_fail);
        ia64_gen_fp_load_pair_value(ctx, insn, addr);
        if (ctx->full_alat) {
            gen_helper_set_alat_fp(tcg_env, tcg_constant_i32(insn->r1),
                                   addr, tcg_constant_i32(size));
        }
        tcg_gen_br(l_done);

        gen_set_label(l_fail);
        if (ctx->full_alat) {
            gen_helper_invalidate_alat_fp_reg(
                tcg_env, tcg_constant_i32(insn->r1));
        }
        ia64_gen_fp_load_pair_advanced_fail_value(insn);

        gen_set_label(l_done);
        ia64_gen_fp_load_pair_base_update(insn, addr);
        return;
    }
    ia64_gen_fp_load_pair_value(ctx, insn, addr);
    ia64_gen_fp_load_pair_base_update(insn, addr);
}

static void ia64_gen_native_integer_write(const Ia64Instruction *insn)
{
    TCGv_i64 tmp;
    TCGv_i64 tmp2;

    if (insn->r1 == 0) {
        return;
    }

    switch (insn->opcode) {
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
        tcg_gen_addi_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm);
        break;
    case IA64_OP_SHLADD:
        tmp = tcg_temp_new_i64();
        tcg_gen_shli_i64(tmp, ia64_gr_src(insn->r2), insn->imm);
        tcg_gen_add_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ADD:
        tcg_gen_add_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ADD_ONE:
        tmp = tcg_temp_new_i64();
        tcg_gen_add_i64(tmp, ia64_gr_src(insn->r2), ia64_gr_src(insn->r3));
        tcg_gen_addi_i64(cpu_gr[insn->r1], tmp, 1);
        break;
    case IA64_OP_SUB:
        tcg_gen_sub_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SUB_ONE:
        tmp = tcg_temp_new_i64();
        tcg_gen_sub_i64(tmp, ia64_gr_src(insn->r2), ia64_gr_src(insn->r3));
        tcg_gen_subi_i64(cpu_gr[insn->r1], tmp, 1);
        break;
    case IA64_OP_AND:
        tcg_gen_and_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ANDCM:
        tmp = tcg_temp_new_i64();
        tcg_gen_not_i64(tmp, ia64_gr_src(insn->r3));
        tcg_gen_and_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2), tmp);
        break;
    case IA64_OP_OR:
        tcg_gen_or_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                       ia64_gr_src(insn->r3));
        break;
    case IA64_OP_XOR:
        tcg_gen_xor_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                        ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHL:
        tmp = tcg_temp_new_i64();
        tcg_gen_andi_i64(tmp, ia64_gr_src(insn->r2), 0x3f);
        TCGv_i64 shifted_l = tcg_temp_new_i64();
        tcg_gen_shl_i64(shifted_l, ia64_gr_src(insn->r3), tmp);
        tcg_gen_movcond_i64(TCG_COND_GTU, cpu_gr[insn->r1],
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(0), shifted_l);
        break;
    case IA64_OP_SHRU:
        tmp = tcg_temp_new_i64();
        tcg_gen_andi_i64(tmp, ia64_gr_src(insn->r2), 0x3f);
        TCGv_i64 shifted_ru = tcg_temp_new_i64();
        tcg_gen_shr_i64(shifted_ru, ia64_gr_src(insn->r3), tmp);
        tcg_gen_movcond_i64(TCG_COND_GTU, cpu_gr[insn->r1],
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(0), shifted_ru);
        break;
    case IA64_OP_SHR:
        tmp = tcg_temp_new_i64();
        tcg_gen_movcond_i64(TCG_COND_GTU, tmp,
                            ia64_gr_src(insn->r2), tcg_constant_i64(63),
                            tcg_constant_i64(63), ia64_gr_src(insn->r2));
        tcg_gen_sar_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3), tmp);
        break;
    case IA64_OP_SHL_IMM:
        tcg_gen_shli_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_SHRU_IMM:
        tcg_gen_shri_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_SHR_IMM:
        tcg_gen_sari_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3),
                         insn->imm & 0x3f);
        break;
    case IA64_OP_DEPZ: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, ia64_deposit_mask(pos, len));
        tcg_gen_shli_i64(tmp2, ia64_gr_src(insn->r2), pos);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp2, tmp);
        break;
    }
    case IA64_OP_DEPZ_IMM: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;
        const int64_t src = (int8_t)((insn->imm >> 13) & 0xff);
        uint64_t mask_value = ia64_deposit_mask(pos, len);

        tcg_gen_movi_i64(cpu_gr[insn->r1],
                         (((uint64_t)src << pos) & mask_value));
        break;
    }
    case IA64_OP_EXTRU: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = ia64_bitfield_effective_len(pos,
                                                         insn->imm >> 6);

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, ia64_low_mask(len));
        tcg_gen_shri_i64(tmp2, ia64_gr_src(insn->r3), pos);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp2, tmp);
        break;
    }
    case IA64_OP_SXT1:
        tcg_gen_ext8s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SXT2:
        tcg_gen_ext16s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SXT4:
        tcg_gen_ext32s_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT1:
        tcg_gen_ext8u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT2:
        tcg_gen_ext16u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ZXT4:
        tcg_gen_ext32u_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHRP_IMM:
        if ((insn->imm & 0x3f) == 0) {
            tcg_gen_mov_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        } else {
            tmp = tcg_temp_new_i64();
            tmp2 = tcg_temp_new_i64();
            tcg_gen_shri_i64(tmp, ia64_gr_src(insn->r3), insn->imm & 0x3f);
            tcg_gen_shli_i64(tmp2, ia64_gr_src(insn->r2),
                             64 - (insn->imm & 0x3f));
            tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        }
        break;
    case IA64_OP_DEP: {
        TCGv_i64 mask = tcg_temp_new_i64();
        TCGv_i64 pos = tcg_temp_new_i64();
        TCGv_i64 len = tcg_temp_new_i64();
        TCGv_i64 base = tcg_temp_new_i64();
        TCGv_i64 shifted = tcg_temp_new_i64();
        tcg_gen_movi_i64(pos, insn->imm & 0x3f);
        tcg_gen_movi_i64(len, (insn->imm >> 6) & 0x3f);
        tcg_gen_movi_i64(mask, 1);
        tcg_gen_shl_i64(mask, mask, len);
        tcg_gen_subi_i64(mask, mask, 1);
        tcg_gen_shl_i64(mask, mask, pos);
        tcg_gen_not_i64(mask, mask);
        tcg_gen_and_i64(base, ia64_gr_src(insn->r3), mask);
        tcg_gen_not_i64(mask, mask);
        tcg_gen_shl_i64(shifted, ia64_gr_src(insn->r2), pos);
        tcg_gen_and_i64(shifted, shifted, mask);
        tcg_gen_or_i64(cpu_gr[insn->r1], base, shifted);
        break;
    }
    case IA64_OP_DEP_IMM: {
        const uint64_t pos = insn->imm & 0x3f;
        const uint64_t len = (insn->imm >> 6) & 0x7f;
        const uint64_t fill = (insn->imm >> 13) & 1;
        uint64_t mask_value = ia64_deposit_mask(pos, len);

        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp2, ~mask_value);
        tcg_gen_and_i64(tmp, ia64_gr_src(insn->r3), tmp2);
        if (fill) {
            tcg_gen_movi_i64(tmp2, mask_value);
            tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        } else {
            tcg_gen_mov_i64(cpu_gr[insn->r1], tmp);
        }
        break;
    }
    case IA64_OP_EXTR: {
        TCGv_i64 pos = tcg_temp_new_i64();
        TCGv_i64 len_tcg = tcg_temp_new_i64();
        TCGv_i64 val = tcg_temp_new_i64();
        TCGv_i64 sign_bit = tcg_temp_new_i64();
        const uint64_t pos_imm = insn->imm & 0x3f;
        const uint64_t len_imm =
            ia64_bitfield_effective_len(pos_imm, insn->imm >> 6);
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(pos, pos_imm);
        tcg_gen_movi_i64(len_tcg, len_imm);
        tcg_gen_shr_i64(val, ia64_gr_src(insn->r3), pos);
        tcg_gen_movi_i64(tmp, ia64_low_mask(len_imm));
        tcg_gen_and_i64(val, val, tmp);
        tcg_gen_subi_i64(len_tcg, len_tcg, 1);
        tcg_gen_movi_i64(sign_bit, 1);
        tcg_gen_shl_i64(sign_bit, sign_bit, len_tcg);
        tcg_gen_xor_i64(val, val, sign_bit);
        tcg_gen_sub_i64(cpu_gr[insn->r1], val, sign_bit);
        break;
    }
    case IA64_OP_SUB_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_sub_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_AND_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_ANDCM_IMM:
        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_not_i64(tmp2, ia64_gr_src(insn->r3));
        tcg_gen_and_i64(cpu_gr[insn->r1], tmp, tmp2);
        break;
    case IA64_OP_OR_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_or_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_XOR_IMM:
        tmp = tcg_temp_new_i64();
        tcg_gen_movi_i64(tmp, insn->imm);
        tcg_gen_xor_i64(cpu_gr[insn->r1], tmp, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_SHLADDP4:
        tmp = tcg_temp_new_i64();
        tcg_gen_shli_i64(tmp, ia64_gr_src(insn->r2), insn->imm);
        ia64_gen_addp4_result(cpu_gr[insn->r1], tmp,
                              ia64_gr_src(insn->r3));
        break;
    case IA64_OP_MPY4: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        tcg_gen_ext32u_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(cpu_gr[insn->r1], tmpr2, tmpr3);
        break;
    }
    case IA64_OP_MPYSHL4: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_shri_i64(tmpr2, ia64_gr_src(insn->r2), 32);
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_shli_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MPYSH: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_ext32s_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32s_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_sari_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MPYUH: {
        TCGv_i64 tmpr2 = tcg_temp_new_i64();
        TCGv_i64 tmpr3 = tcg_temp_new_i64();
        TCGv_i64 mul_res = tcg_temp_new_i64();
        tcg_gen_ext32u_i64(tmpr2, ia64_gr_src(insn->r2));
        tcg_gen_ext32u_i64(tmpr3, ia64_gr_src(insn->r3));
        tcg_gen_mul_i64(mul_res, tmpr2, tmpr3);
        tcg_gen_shri_i64(cpu_gr[insn->r1], mul_res, 32);
        break;
    }
    case IA64_OP_MUX: {
        TCGv_i64 r1_orig = tcg_temp_new_i64();
        tcg_gen_mov_i64(r1_orig, ia64_gr_src(insn->r1));
        tmp = tcg_temp_new_i64();
        tmp2 = tcg_temp_new_i64();
        tcg_gen_and_i64(tmp, ia64_gr_src(insn->r2), r1_orig);
        tcg_gen_not_i64(tmp2, ia64_gr_src(insn->r2));
        tcg_gen_and_i64(tmp2, tmp2, ia64_gr_src(insn->r3));
        tcg_gen_or_i64(cpu_gr[insn->r1], tmp, tmp2);
        break;
    }
    case IA64_OP_POPCNT:
        tcg_gen_ctpop_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3));
        break;
    case IA64_OP_CLZ:
        tcg_gen_clzi_i64(cpu_gr[insn->r1], ia64_gr_src(insn->r3), 64);
        break;
    case IA64_OP_ILLEGAL:
    case IA64_OP_NOP:
    case IA64_OP_BREAK:
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
    case IA64_OP_BR_COND:
    case IA64_OP_BR_INDIRECT:
    case IA64_OP_BR_IA:
    case IA64_OP_BR_CLOOP:
    case IA64_OP_BR_CALL:
    case IA64_OP_BR_CALL_INDIRECT:
    case IA64_OP_BR_RET:
    case IA64_OP_PADD1:
    case IA64_OP_PADD2:
    case IA64_OP_PADD4:
    case IA64_OP_PSUB1:
    case IA64_OP_PSUB2:
    case IA64_OP_PSUB4:
    case IA64_OP_XCHG1:
    case IA64_OP_XCHG2:
    case IA64_OP_XCHG4:
    case IA64_OP_XCHG8:
    case IA64_OP_CMPXCHG1:
    case IA64_OP_CMPXCHG2:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_CMPXCHG8:
    case IA64_OP_CMP8XCHG16:
    case IA64_OP_FETCHADD4:
    case IA64_OP_FETCHADD8:
    case IA64_OP_MOVL:
    case IA64_OP_MOV_BRGR:
    case IA64_OP_MOV_GRBR:
    case IA64_OP_MOV_PRGR:
    case IA64_OP_MOV_GRPR:
    case IA64_OP_MOV_PR_ROT_IMM:
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM:
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND:
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
    case IA64_OP_HINT_M:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
    case IA64_OP_PTC_E:
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
    case IA64_OP_FMERGE_S:
    case IA64_OP_FMERGE_SE:
    case IA64_OP_FMIN:
    case IA64_OP_FMAX:
    case IA64_OP_FAMIN:
    case IA64_OP_FAMAX:
    case IA64_OP_FRCPA:
    case IA64_OP_FPRCPA:
    case IA64_OP_GETF_SIG:
    case IA64_OP_GETF_EXP:
    case IA64_OP_SETF_SIG:
    case IA64_OP_SETF_EXP:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
        g_assert_not_reached();
    default:
        g_assert_not_reached();
    }
}

static void ia64_gen_native_integer_nat(const Ia64Instruction *insn)
{
    if (insn->r1 == 0) {
        return;
    }

    switch (insn->opcode) {
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SHL_IMM:
    case IA64_OP_SHRU_IMM:
    case IA64_OP_SHR_IMM:
    case IA64_OP_EXTRU:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        break;
    case IA64_OP_DEPZ:
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
        break;
    case IA64_OP_DEPZ_IMM:
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    case IA64_OP_SHLADD:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    case IA64_OP_SHR:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_MUX:
        ia64_gen_gr_nat_from_3(insn->r1, insn->r1, insn->r2, insn->r3);
        break;
    default:
        g_assert_not_reached();
    }
}

static uint32_t ia64_fp_reg_set(uint8_t reg)
{
    if (reg >= 32) {
        return 2;
    }
    if (reg >= 2) {
        return 1;
    }
    return 0;
}

static uint32_t ia64_insn_fp_read_sets(const Ia64Instruction *insn)
{
    uint32_t sets;

    switch (insn->opcode) {
    case IA64_OP_LDFD:
    case IA64_OP_LDFS:
    case IA64_OP_LDF_FILL:
    case IA64_OP_LDF8:
    case IA64_OP_LDFE:
    case IA64_OP_SETF_D:
    case IA64_OP_SETF_S:
    case IA64_OP_SETF_EXP:
    case IA64_OP_SETF_SIG:
        return 0;

    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        return 0;

    case IA64_OP_STFD:
    case IA64_OP_STFS:
    case IA64_OP_STF_SPILL:
    case IA64_OP_STF8:
    case IA64_OP_STFE:
    case IA64_OP_GETF_D:
    case IA64_OP_GETF_S:
    case IA64_OP_GETF_EXP:
    case IA64_OP_GETF_SIG:
    case IA64_OP_FCLASS:
        return ia64_fp_reg_set(insn->r2);

    case IA64_OP_CHK_S:
    case IA64_OP_CHK_A:
    case IA64_OP_CHK_A_CLR:
        return insn->check_fp ? ia64_fp_reg_set(insn->r2) : 0;

    case IA64_OP_FCMP:
        return ia64_fp_reg_set(insn->r2) |
               ia64_fp_reg_set(insn->r3);

    case IA64_OP_FPABS:
    case IA64_OP_FPNEG:
    case IA64_OP_FPNEGABS:
    case IA64_OP_FMOV:
    case IA64_OP_FCVT_XF:
    case IA64_OP_FCVT_FX:
    case IA64_OP_FCVT_FXU:
    case IA64_OP_FPCVT:
        return ia64_fp_reg_set(insn->r2);

    case IA64_OP_FPRSQRTA:
    case IA64_OP_FRSQRTA:
        return ia64_fp_reg_set(insn->r3);

    case IA64_OP_FMA:
    case IA64_OP_FMS:
    case IA64_OP_FNMA:
    case IA64_OP_FPMA:
    case IA64_OP_FPMS:
    case IA64_OP_FPNMA:
    case IA64_OP_FSELECT:
    case IA64_OP_XMA_L:
    case IA64_OP_XMA_H:
    case IA64_OP_XMA_HU:
    case IA64_OP_XMPY_HU:
        return ia64_fp_reg_set(insn->r2) |
               ia64_fp_reg_set(insn->r3) |
               ia64_fp_reg_set(insn->p1);

    case IA64_OP_FADD:
    case IA64_OP_FSUB:
    case IA64_OP_FMPY:
    case IA64_OP_FMIN:
    case IA64_OP_FMAX:
    case IA64_OP_FAMIN:
    case IA64_OP_FAMAX:
    case IA64_OP_FRCPA:
    case IA64_OP_FPRCPA:
    case IA64_OP_FNORM:
    case IA64_OP_FPACK:
    case IA64_OP_FAND:
    case IA64_OP_FANDCM:
    case IA64_OP_FOR:
    case IA64_OP_FXOR:
    case IA64_OP_FSWAP:
    case IA64_OP_FSWAP_NL:
    case IA64_OP_FSWAP_NR:
    case IA64_OP_FMIX_LR:
    case IA64_OP_FMIX_R:
    case IA64_OP_FMIX_L:
    case IA64_OP_FSXT_R:
    case IA64_OP_FSXT_L:
    case IA64_OP_FPMERGE:
    case IA64_OP_FPMERGE_S:
    case IA64_OP_FPMERGE_SE:
    case IA64_OP_FPMIN:
    case IA64_OP_FPMAX:
    case IA64_OP_FPAMIN:
    case IA64_OP_FPAMAX:
    case IA64_OP_FPCMP:
    case IA64_OP_FMERGE:
    case IA64_OP_FMERGE_S:
    case IA64_OP_FMERGE_SE:
        sets = ia64_fp_reg_set(insn->r2);
        sets |= ia64_fp_reg_set(insn->r3);
        return sets;

    default:
        return 0;
    }
}

static uint32_t ia64_insn_fp_write_sets(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_LDFD:
    case IA64_OP_LDFS:
    case IA64_OP_LDF_FILL:
    case IA64_OP_LDF8:
    case IA64_OP_LDFE:
    case IA64_OP_SETF_D:
    case IA64_OP_SETF_S:
    case IA64_OP_SETF_EXP:
    case IA64_OP_SETF_SIG:
    case IA64_OP_FADD:
    case IA64_OP_FSUB:
    case IA64_OP_FMPY:
    case IA64_OP_FMA:
    case IA64_OP_FMS:
    case IA64_OP_FNMA:
    case IA64_OP_XMA_L:
    case IA64_OP_XMA_H:
    case IA64_OP_XMA_HU:
    case IA64_OP_XMPY_HU:
    case IA64_OP_FMIN:
    case IA64_OP_FMAX:
    case IA64_OP_FAMIN:
    case IA64_OP_FAMAX:
    case IA64_OP_FRCPA:
    case IA64_OP_FPRCPA:
    case IA64_OP_FSELECT:
    case IA64_OP_FNORM:
    case IA64_OP_FPABS:
    case IA64_OP_FPNEG:
    case IA64_OP_FPNEGABS:
    case IA64_OP_FPRSQRTA:
    case IA64_OP_FRSQRTA:
    case IA64_OP_FPACK:
    case IA64_OP_FAND:
    case IA64_OP_FANDCM:
    case IA64_OP_FOR:
    case IA64_OP_FXOR:
    case IA64_OP_FSWAP:
    case IA64_OP_FSWAP_NL:
    case IA64_OP_FSWAP_NR:
    case IA64_OP_FMIX_LR:
    case IA64_OP_FMIX_R:
    case IA64_OP_FMIX_L:
    case IA64_OP_FSXT_R:
    case IA64_OP_FSXT_L:
    case IA64_OP_FPMERGE:
    case IA64_OP_FPMERGE_S:
    case IA64_OP_FPMERGE_SE:
    case IA64_OP_FPMIN:
    case IA64_OP_FPMAX:
    case IA64_OP_FPAMIN:
    case IA64_OP_FPAMAX:
    case IA64_OP_FPCMP:
    case IA64_OP_FPCVT:
    case IA64_OP_FPMA:
    case IA64_OP_FPMS:
    case IA64_OP_FPNMA:
    case IA64_OP_FMOV:
    case IA64_OP_FCVT_XF:
    case IA64_OP_FCVT_FX:
    case IA64_OP_FCVT_FXU:
    case IA64_OP_FMERGE:
    case IA64_OP_FMERGE_S:
    case IA64_OP_FMERGE_SE:
        return ia64_fp_reg_set(insn->r1);

    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        return ia64_fp_reg_set(insn->r1) |
               ia64_fp_reg_set(insn->r2);

    default:
        return 0;
    }
}

static uint64_t ia64_insn_disabled_fp_isr_flags(
    const Ia64Instruction *insn)
{
    /* ISR.R/W describe the instruction's memory access, not its FP operands. */
    switch (insn->opcode) {
    case IA64_OP_LDFD:
    case IA64_OP_LDFS:
    case IA64_OP_LDF_FILL:
    case IA64_OP_LDF8:
    case IA64_OP_LDFE:
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        return IA64_ISR_R |
               (insn->fp_load_speculative ? IA64_ISR_SP : 0);

    case IA64_OP_STFD:
    case IA64_OP_STFS:
    case IA64_OP_STF_SPILL:
    case IA64_OP_STF8:
    case IA64_OP_STFE:
        return IA64_ISR_W;

    default:
        return 0;
    }
}

static void ia64_gen_check_disabled_fp(const Ia64Instruction *insn)
{
    uint32_t reads = ia64_insn_fp_read_sets(insn);
    uint32_t writes = ia64_insn_fp_write_sets(insn);
    uint32_t sets = reads | writes;
    uint64_t disabled_mask;
    uint64_t isr_flags;
    TCGv_i64 disabled;
    TCGv_i64 isr;
    TCGLabel *done;

    if (sets == 0) {
        return;
    }

    /*
     * Check the live PSR: a mask instruction earlier in the same bundle can
     * change dfl/dfh after the TB was translated.
     */
    done = gen_new_label();
    disabled = tcg_temp_new_i64();
    isr = tcg_temp_new_i64();
    disabled_mask = ((sets & 1) ? IA64_PSR_DFL : 0) |
                    ((sets & 2) ? IA64_PSR_DFH : 0);
    isr_flags = ia64_insn_disabled_fp_isr_flags(insn);

    tcg_gen_andi_i64(disabled, cpu_psr, disabled_mask);
    tcg_gen_brcondi_i64(TCG_COND_EQ, disabled, 0, done);
    tcg_gen_shri_i64(isr, disabled, 18);
    if (isr_flags != 0) {
        tcg_gen_ori_i64(isr, isr, isr_flags);
    }
    tcg_gen_st_i64(isr, tcg_env, offsetof(CPUIA64State, cr_isr));
    ia64_gen_raise_exception(IA64_EXCP_DISABLED_FP, insn->address,
                             0, insn->slot);
    gen_set_label(done);
}

/* Instructions gated by the CPUID[4].ao 16-byte atomic capability bit. */
static bool ia64_insn_needs_16byte_atomics(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_LD16:
    case IA64_OP_ST16:
    case IA64_OP_CMP8XCHG16:
        return true;
    default:
        return false;
    }
}

static bool ia64_gen_insn(DisasContext *ctx, const Ia64Instruction *insn,
                          bool record_iipa)
{
    TCGLabel *skip;
    TCGv_i64 tmp;
    TCGv_i64 qp_value;
    const uint64_t next_ip = insn->address + 16;
    const bool track_psr_suppression = ctx->track_psr_suppression;

    if (!insn->valid) {
        static unsigned invalid_logs;

        if (qatomic_fetch_inc(&invalid_logs) < 128) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "ia64 invalid insn ip=0x%016" PRIx64
                          " slot=%u unit=%u raw=0x%010" PRIx64 "\n",
                          insn->address, insn->slot, insn->unit,
                          insn->raw);
        }
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }

    qp_value = insn->qp == 0 ? tcg_constant_i64(1) : cpu_pr[insn->qp];
    if ((insn->compare_unc ||
         (insn->clear_p2_before_predicate && insn->qp == insn->p2)) &&
        insn->qp != 0) {
        TCGv_i64 saved_qp = tcg_temp_new_i64();

        tcg_gen_mov_i64(saved_qp, qp_value);
        qp_value = saved_qp;
    }
    if (insn->compare_unc && ia64_compare_has_equal_targets(insn)) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }
    if (insn->opcode == IA64_OP_ALLOC && insn->qp != 0) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        return true;
    }
    ia64_gen_clear_unc_compare_targets(insn);
    if (insn->clear_p2_before_predicate && insn->p2 != 0) {
        tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
    }
    skip = ia64_gen_predicate_skip(insn, qp_value);
    if (insn->placement_illegal) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ia64 illegal placement ip=0x%016" PRIx64
                      " slot=%u opcode=%u raw=0x%010" PRIx64 "\n",
                      insn->address, insn->slot, insn->opcode, insn->raw);
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }
    if (insn->reserved_field) {
        tcg_gen_st_i64(tcg_constant_i64(0x30), tcg_env,
                       offsetof(CPUIA64State, cr_isr));
        ia64_gen_raise_exception(IA64_EXCP_RESERVED_REG_FIELD,
                                  insn->address, insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }
    if (ia64_insn_needs_16byte_atomics(insn) &&
        !(ia64_env_cpu_class(ctx->env)->cpuid_features & IA64_CPUID4_AO)) {
        /*
         * The encoding is reserved on a model that clears CPUID[4].ao, so
         * refuse it the same way an unimplemented opcode is refused.
         */
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }
    if (insn->opcode == IA64_OP_ALLOC) {
        uint32_t new_sof = insn->imm & 0x7f;

        if (insn->r1 == 0 ||
            (insn->r1 >= IA64_STACKED_GR_BASE &&
             insn->r1 - IA64_STACKED_GR_BASE >= new_sof)) {
            ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                      insn->raw, insn->slot);
            if (skip == NULL) {
                return true;
            }
            ia64_gen_predicate_end(skip);
            return false;
        }
    } else if (ia64_insn_writes_gr_r1(insn)) {
        ia64_gen_check_gr_in_frame(insn, insn->r1);
    }
    if (insn->reg_base_update || insn->imm_base_update) {
        ia64_gen_check_gr_in_frame(insn, insn->r3);
    }
    if (ia64_insn_is_privileged(insn)) {
        ia64_gen_check_privileged(insn);
    }
    if (ia64_load_base_update_has_same_target(insn)) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }
    if (ia64_compare_has_equal_targets(insn)) {
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        ia64_gen_predicate_end(skip);
        return false;
    }

    ia64_gen_check_disabled_fp(insn);

    switch (insn->opcode) {
    case IA64_OP_NOP:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
        break;
    case IA64_OP_HINT_M:
        if (insn->hint_m_reg_increment && insn->r3 != 0) {
            tcg_gen_add_i64(cpu_gr[insn->r3], cpu_gr[insn->r3],
                            cpu_gr[insn->r2]);
            ia64_gen_note_stacked_gr_write(insn->r3);
        } else if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    case IA64_OP_LFETCH:
    case IA64_OP_LFETCH_FAULT:
        ia64_gen_lfetch(insn);
        break;
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
        gen_helper_clrrrb_rse(
            tcg_env,
            tcg_constant_i32(insn->opcode == IA64_OP_CLRRRB_PR));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                       record_iipa,
                                       track_psr_suppression);
            return true;
        }
        break;
    case IA64_OP_VMSW:
        /*
         * Models without the virtualization extensions do not decode vmsw
         * at all: the encoding is reserved and raises an Illegal Operation
         * fault regardless of privilege.  Models with the extensions treat
         * vmsw as a privileged instruction, so PSR.cpl > 0 raises a
         * Privileged Operation fault first; at cpl 0 a Virtualization
         * fault is reported because this implementation provides no
         * virtual-machine environment.
         */
        if (ia64_env_cpu_class(ctx->env)->has_virtualization) {
            ia64_gen_check_privileged(insn);
            ia64_gen_raise_exception(IA64_EXCP_VIRTUALIZATION,
                                      insn->address, insn->raw, insn->slot);
        } else {
            ia64_gen_raise_exception(IA64_EXCP_ILLEGAL,
                                      insn->address, insn->raw, insn->slot);
        }
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_RUM:
    {
        TCGv_i64 value = tcg_temp_new_i64();

        tcg_gen_andi_i64(value, cpu_psr,
                         ~(insn->imm & IA64_PSR_UM_WRITABLE_MASK));
        ia64_gen_write_user_mask(value);
        ctx->exit_after_bundle = true;
        break;
    }
    case IA64_OP_SUM_UM:
    {
        TCGv_i64 value = tcg_temp_new_i64();

        tcg_gen_ori_i64(value, cpu_psr,
                        insn->imm & IA64_PSR_UM_WRITABLE_MASK);
        ia64_gen_write_user_mask(value);
        ctx->exit_after_bundle = true;
        break;
    }
    case IA64_OP_BRP:
        break;
    case IA64_OP_FSETC:
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_fsetc(tcg_env, tcg_constant_i32(insn->p1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FCLRF:
        gen_helper_fclrf(tcg_env, tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FCHKF: {
        TCGv_i64 taken = tcg_temp_new_i64();
        gen_helper_fchkf(taken, tcg_env, tcg_constant_i32(insn->p1));
        ia64_gen_check_branch(ctx, taken, insn->address + insn->imm,
                              insn->address, record_iipa,
                              track_psr_suppression);
        break;
    }
    case IA64_OP_BREAK:
        if (insn->p1 == 0 &&
            ia64_is_firmware_debug_break(insn->address, insn->imm)) {
            TCGv_i32 handled = tcg_temp_new_i32();
            TCGLabel *architected_break = gen_new_label();

            if (insn->imm == 0x100002) {
                gen_helper_firmware_debug_enter(
                    handled, tcg_env, tcg_constant_i64(insn->address));
            } else if (insn->imm == 0x100003) {
                gen_helper_firmware_debug_save(handled, tcg_env);
            } else {
                gen_helper_firmware_debug_restore(handled, tcg_env);
            }
            tcg_gen_brcondi_i32(TCG_COND_EQ, handled, 0,
                                architected_break);
            if (insn->imm == 0x100003) {
                ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                           record_iipa,
                                           track_psr_suppression);
            } else {
                tcg_gen_exit_tb(NULL, 0);
            }
            gen_set_label(architected_break);
            ia64_gen_raise_exception(IA64_EXCP_BREAK, insn->address,
                                      insn->imm, insn->slot);
            return true;
        } else if (insn->imm == 0x100001) {
            gen_helper_fpswa_dispatch(tcg_env);
        } else if ((insn->imm & 0x100000) &&
            ia64_is_pal_proc_break(ctx->env, insn->address)) {
            TCGv_i32 flags = tcg_temp_new_i32();
            TCGLabel *no_exit = gen_new_label();

            gen_helper_pal_dispatch(flags, tcg_env);
            tcg_gen_andi_i32(flags, flags,
                             IA64_PAL_DISPATCH_HALTED |
                             IA64_PAL_DISPATCH_EXIT_TB);
            tcg_gen_brcondi_i32(TCG_COND_EQ, flags, 0, no_exit);
            ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                       record_iipa,
                                       track_psr_suppression);
            gen_set_label(no_exit);
        } else {
            ia64_gen_raise_exception(IA64_EXCP_BREAK, insn->address,
                                      insn->imm, insn->slot);
            if (skip == NULL) {
                return true;
            }
        }
        break;
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SHLADD:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    case IA64_OP_SHR:
    case IA64_OP_SHL_IMM:
    case IA64_OP_SHRU_IMM:
    case IA64_OP_SHR_IMM:
    case IA64_OP_DEPZ:
    case IA64_OP_DEPZ_IMM:
    case IA64_OP_EXTRU:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_MPYSH:
    case IA64_OP_MPYUH:
    case IA64_OP_MUX:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
        ia64_gen_native_integer_write(insn);
        ia64_gen_native_integer_nat(insn);
        break;
    case IA64_OP_CMP_EQ:
    case IA64_OP_CMP_LT:
    case IA64_OP_CMP_LE:
    case IA64_OP_CMP_GT:
    case IA64_OP_CMP_GE:
    case IA64_OP_CMP_LTU:
    case IA64_OP_CMP_LEU:
    case IA64_OP_CMP_GTU:
    case IA64_OP_CMP_GEU:
    case IA64_OP_CMP_NE:
    case IA64_OP_CMP_EQ_AND:
    case IA64_OP_CMP_NE_AND:
    case IA64_OP_CMP_GT_AND:
    case IA64_OP_CMP_LE_AND:
    case IA64_OP_CMP_GE_AND:
    case IA64_OP_CMP_LT_AND:
    case IA64_OP_CMP_EQ_OR:
    case IA64_OP_CMP_NE_OR:
    case IA64_OP_CMP_GT_OR:
    case IA64_OP_CMP_LE_OR:
    case IA64_OP_CMP_GE_OR:
    case IA64_OP_CMP_LT_OR:
    case IA64_OP_CMP_EQ_OR_ANDCM:
    case IA64_OP_CMP_NE_OR_ANDCM:
    case IA64_OP_CMP_GT_OR_ANDCM:
    case IA64_OP_CMP_LE_OR_ANDCM:
    case IA64_OP_CMP_GE_OR_ANDCM:
    case IA64_OP_CMP_LT_OR_ANDCM:
    case IA64_OP_CMP_EQ_IMM:
    case IA64_OP_CMP_LT_IMM:
    case IA64_OP_CMP_EQ_AND_IMM:
    case IA64_OP_CMP_NE_AND_IMM:
    case IA64_OP_CMP_EQ_OR_IMM:
    case IA64_OP_CMP_NE_OR_IMM:
    case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP4_EQ_AND:
    case IA64_OP_CMP4_NE_AND:
    case IA64_OP_CMP4_EQ_OR:
    case IA64_OP_CMP4_NE_OR:
    case IA64_OP_CMP4_EQ_OR_ANDCM:
    case IA64_OP_CMP4_NE_OR_ANDCM:
    case IA64_OP_CMP4_GT_AND:
    case IA64_OP_CMP4_LE_AND:
    case IA64_OP_CMP4_GE_AND:
    case IA64_OP_CMP4_LT_AND:
    case IA64_OP_CMP4_GT_OR:
    case IA64_OP_CMP4_LE_OR:
    case IA64_OP_CMP4_GE_OR:
    case IA64_OP_CMP4_LT_OR:
    case IA64_OP_CMP4_GT_OR_ANDCM:
    case IA64_OP_CMP4_LE_OR_ANDCM:
    case IA64_OP_CMP4_GE_OR_ANDCM:
    case IA64_OP_CMP4_LT_OR_ANDCM:
    case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
    case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
    case IA64_OP_CMP_LTU_IMM:
    case IA64_OP_CMP4_EQ:
    case IA64_OP_CMP4_LT:
    case IA64_OP_CMP4_LE:
    case IA64_OP_CMP4_GT:
    case IA64_OP_CMP4_GE:
    case IA64_OP_CMP4_LTU:
    case IA64_OP_CMP4_LEU:
    case IA64_OP_CMP4_GTU:
    case IA64_OP_CMP4_GEU:
    case IA64_OP_CMP4_EQ_IMM:
    case IA64_OP_CMP4_LT_IMM:
    case IA64_OP_CMP4_LTU_IMM:
    case IA64_OP_CMP4_EQ_AND_IMM:
    case IA64_OP_CMP4_NE_AND_IMM:
    case IA64_OP_CMP4_EQ_OR_IMM:
    case IA64_OP_CMP4_NE_OR_IMM: {
        TCGCond cond;
        bool is_cmp4 = false;
        bool is_cmp_imm = false;
        bool is_signed_cmp4 = false;
        bool is_and = false;
        bool is_or = false;
        bool is_or_andcm = false;
        switch (insn->opcode) {
        case IA64_OP_CMP_EQ:
            cond = TCG_COND_EQ;
            break;
        case IA64_OP_CMP_LT:
            cond = TCG_COND_LT;
            break;
        case IA64_OP_CMP_LE:
            cond = TCG_COND_LE;
            break;
        case IA64_OP_CMP_GT:
            cond = TCG_COND_GT;
            break;
        case IA64_OP_CMP_GE:
            cond = TCG_COND_GE;
            break;
        case IA64_OP_CMP_LTU:
            cond = TCG_COND_LTU;
            break;
        case IA64_OP_CMP_LEU:
            cond = TCG_COND_LEU;
            break;
        case IA64_OP_CMP_GTU:
            cond = TCG_COND_GTU;
            break;
        case IA64_OP_CMP_GEU:
            cond = TCG_COND_GEU;
            break;
        case IA64_OP_CMP_NE:
            cond = TCG_COND_NE;
            break;
        case IA64_OP_CMP_EQ_AND:
            cond = TCG_COND_EQ;
            is_and = true;
            break;
        case IA64_OP_CMP_NE_AND:
            cond = TCG_COND_NE;
            is_and = true;
            break;
        case IA64_OP_CMP_GT_AND:
            cond = TCG_COND_GT;
            is_and = true;
            break;
        case IA64_OP_CMP_LE_AND:
            cond = TCG_COND_LE;
            is_and = true;
            break;
        case IA64_OP_CMP_GE_AND:
            cond = TCG_COND_GE;
            is_and = true;
            break;
        case IA64_OP_CMP_LT_AND:
            cond = TCG_COND_LT;
            is_and = true;
            break;
        case IA64_OP_CMP_EQ_OR:
            cond = TCG_COND_EQ;
            is_or = true;
            break;
        case IA64_OP_CMP_NE_OR:
            cond = TCG_COND_NE;
            is_or = true;
            break;
        case IA64_OP_CMP_GT_OR:
            cond = TCG_COND_GT;
            is_or = true;
            break;
        case IA64_OP_CMP_LE_OR:
            cond = TCG_COND_LE;
            is_or = true;
            break;
        case IA64_OP_CMP_GE_OR:
            cond = TCG_COND_GE;
            is_or = true;
            break;
        case IA64_OP_CMP_LT_OR:
            cond = TCG_COND_LT;
            is_or = true;
            break;
        case IA64_OP_CMP_EQ_OR_ANDCM:
            cond = TCG_COND_EQ;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_NE_OR_ANDCM:
            cond = TCG_COND_NE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_GT_OR_ANDCM:
            cond = TCG_COND_GT;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LE_OR_ANDCM:
            cond = TCG_COND_LE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_GE_OR_ANDCM:
            cond = TCG_COND_GE;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LT_OR_ANDCM:
            cond = TCG_COND_LT;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_EQ_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP_LT_IMM:
            cond = TCG_COND_LT;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP_EQ_AND_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP_NE_AND_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP_EQ_OR_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP_NE_OR_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP_EQ_OR_ANDCM_IMM:
            cond = TCG_COND_EQ;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_NE_OR_ANDCM_IMM:
            cond = TCG_COND_NE;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_EQ_AND:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_NE_AND:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_EQ_OR:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_NE_OR:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_EQ_OR_ANDCM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_NE_OR_ANDCM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_GT_AND:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_LE_AND:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_GE_AND:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_LT_AND:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_GT_OR:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_LE_OR:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_GE_OR:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_LT_OR:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_GT_OR_ANDCM:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_LE_OR_ANDCM:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_GE_OR_ANDCM:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_LT_OR_ANDCM:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_EQ_OR_ANDCM_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP4_NE_OR_ANDCM_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or_andcm = true;
            break;
        case IA64_OP_CMP_LTU_IMM:
            cond = TCG_COND_LTU;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_EQ:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_LT:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LE:
            cond = TCG_COND_LE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_GT:
            cond = TCG_COND_GT;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_GE:
            cond = TCG_COND_GE;
            is_cmp4 = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LTU:
            cond = TCG_COND_LTU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_LEU:
            cond = TCG_COND_LEU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_GTU:
            cond = TCG_COND_GTU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_GEU:
            cond = TCG_COND_GEU;
            is_cmp4 = true;
            break;
        case IA64_OP_CMP4_EQ_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_LT_IMM:
            cond = TCG_COND_LT;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_signed_cmp4 = true;
            break;
        case IA64_OP_CMP4_LTU_IMM:
            cond = TCG_COND_LTU;
            is_cmp4 = true;
            is_cmp_imm = true;
            break;
        case IA64_OP_CMP4_EQ_AND_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_NE_AND_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_and = true;
            break;
        case IA64_OP_CMP4_EQ_OR_IMM:
            cond = TCG_COND_EQ;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or = true;
            break;
        case IA64_OP_CMP4_NE_OR_IMM:
            cond = TCG_COND_NE;
            is_cmp4 = true;
            is_cmp_imm = true;
            is_or = true;
            break;
        default:
            cond = TCG_COND_EQ;
            break;
        }
        TCGv_i64 src2 = is_cmp_imm ? tcg_constant_i64(insn->imm)
                                   : ia64_gr_src(insn->r2);
        TCGv_i64 src3 = ia64_gr_src(insn->r3);
        TCGv_i64 src_nat = ia64_gen_gr_nat_read(insn->r3);
        TCGLabel *cmp_done = gen_new_label();

        if (!is_cmp_imm) {
            TCGv_i64 r2_nat = ia64_gen_gr_nat_read(insn->r2);
            tcg_gen_or_i64(src_nat, src_nat, r2_nat);
        }
        if (is_or || is_or_andcm) {
            tcg_gen_brcondi_i64(TCG_COND_NE, src_nat, 0, cmp_done);
        } else {
            TCGLabel *no_nat = gen_new_label();

            tcg_gen_brcondi_i64(TCG_COND_EQ, src_nat, 0, no_nat);
            if (insn->p1 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
            }
            if (insn->p2 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
            }
            tcg_gen_br(cmp_done);
            gen_set_label(no_nat);
        }
        if (is_cmp4) {
            TCGv_i64 tmp_a = tcg_temp_new_i64();
            TCGv_i64 tmp_b = tcg_temp_new_i64();
            if (is_signed_cmp4) {
                tcg_gen_ext32s_i64(tmp_a, src2);
                tcg_gen_ext32s_i64(tmp_b, src3);
            } else {
                tcg_gen_ext32u_i64(tmp_a, src2);
                tcg_gen_ext32u_i64(tmp_b, src3);
            }
            src2 = tmp_a;
            src3 = tmp_b;
        }
        tmp = tcg_temp_new_i64();
        tcg_gen_setcond_i64(cond, tmp, src2, src3);
        /* Parallel AND/OR compares apply the same result to both targets. */
        if (is_and) {
            if (insn->p1 != 0) {
                tcg_gen_and_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                tcg_gen_and_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], tmp);
            }
        } else if (is_or) {
            if (insn->p1 != 0) {
                tcg_gen_or_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                tcg_gen_or_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], tmp);
            }
        } else if (is_or_andcm) {
            if (insn->p1 != 0) {
                tcg_gen_or_i64(cpu_pr[insn->p1], cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                TCGv_i64 not_tmp = tcg_temp_new_i64();
                tcg_gen_xori_i64(not_tmp, tmp, 1);
                tcg_gen_and_i64(cpu_pr[insn->p2], cpu_pr[insn->p2], not_tmp);
            }
        } else {
            if (insn->p1 != 0) {
                tcg_gen_mov_i64(cpu_pr[insn->p1], tmp);
            }
            if (insn->p2 != 0) {
                tcg_gen_xori_i64(cpu_pr[insn->p2], tmp, 1);
            }
        }
        gen_set_label(cmp_done);
        break;
    }
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM: {
        const bool is_nz = insn->opcode == IA64_OP_TBIT_NZ ||
                           insn->opcode == IA64_OP_TBIT_NZ_OR_ANDCM;
        const bool old_or_andcm =
            insn->opcode == IA64_OP_TBIT_Z_OR_ANDCM ||
            insn->opcode == IA64_OP_TBIT_NZ_OR_ANDCM;
        TCGv_i64 bit = tcg_temp_new_i64();
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();
        TCGv_i64 src_nat = ia64_gen_gr_nat_read(insn->r3);
        TCGLabel *tbit_done = gen_new_label();
        Ia64Instruction pred_insn = *insn;

        if (old_or_andcm) {
            pred_insn.pred_update = IA64_PRED_UPDATE_OR_ANDCM;
        }
        if (pred_insn.pred_update == IA64_PRED_UPDATE_OR ||
            pred_insn.pred_update == IA64_PRED_UPDATE_OR_ANDCM) {
            tcg_gen_brcondi_i64(TCG_COND_NE, src_nat, 0, tbit_done);
        } else {
            TCGLabel *no_nat = gen_new_label();

            tcg_gen_brcondi_i64(TCG_COND_EQ, src_nat, 0, no_nat);
            if (insn->p1 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p1], 0);
            }
            if (insn->p2 != 0) {
                tcg_gen_movi_i64(cpu_pr[insn->p2], 0);
            }
            tcg_gen_br(tbit_done);
            gen_set_label(no_nat);
        }

        tcg_gen_mov_i64(bit, ia64_gr_src(insn->r3));
        tcg_gen_shri_i64(bit, bit, insn->imm & 0x3f);
        tcg_gen_andi_i64(bit, bit, 1);
        if (is_nz) {
            tcg_gen_mov_i64(cond, bit);
        } else {
            tcg_gen_xori_i64(cond, bit, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);
        ia64_gen_predicate_test_write(&pred_insn, cond, not_cond);
        gen_set_label(tbit_done);
        break;
    }
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND: {
        const bool is_nz = insn->opcode == IA64_OP_TNAT_NZ ||
                           insn->opcode == IA64_OP_TNAT_NZ_AND;
        TCGv_i64 natbit = ia64_gen_gr_nat_read(insn->r3);
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();
        Ia64Instruction pred_insn = *insn;

        if (is_nz) {
            tcg_gen_mov_i64(cond, natbit);
        } else {
            tcg_gen_xori_i64(cond, natbit, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);

        if (insn->opcode == IA64_OP_TNAT_NZ_AND) {
            pred_insn.pred_update = IA64_PRED_UPDATE_AND;
        }
        ia64_gen_predicate_test_write(&pred_insn, cond, not_cond);
        break;
    }
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ: {
        const bool is_nz = insn->opcode == IA64_OP_TF_NZ;
        TCGv_i64 features = tcg_temp_new_i64();
        TCGv_i64 cond = tcg_temp_new_i64();
        TCGv_i64 not_cond = tcg_temp_new_i64();

        gen_helper_read_cpuid(features, tcg_env, tcg_constant_i64(4));
        tcg_gen_shri_i64(features, features, insn->imm);
        tcg_gen_andi_i64(features, features, 1);
        if (is_nz) {
            tcg_gen_mov_i64(cond, features);
        } else {
            tcg_gen_xori_i64(cond, features, 1);
        }
        tcg_gen_xori_i64(not_cond, cond, 1);
        ia64_gen_predicate_test_write(insn, cond, not_cond);
        break;
    }
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_data_memop(
                    ctx, ia64_memop_for_opcode(insn->opcode));

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                     ctx->mmu_idx, mop);
                ia64_gen_gr_nat_clear(insn->r1);
                ia64_gen_memory_acquire(insn);
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm_base_update && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
                ia64_gen_note_stacked_gr_write(insn->r3);
            }
        }
        break;
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
        ia64_gen_speculative_load(ctx, insn, false);
        break;
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_data_memop(
                    ctx, ia64_memop_for_opcode(insn->opcode));

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                {
                    TCGv_i64 allowed = tcg_temp_new_i64();
                    TCGLabel *l_fail = gen_new_label();
                    TCGLabel *l_done = gen_new_label();

                    gen_helper_advanced_load_allowed(allowed, tcg_env, addr);
                    tcg_gen_brcondi_i64(TCG_COND_EQ, allowed, 0, l_fail);
                    tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                        ctx->mmu_idx, mop);
                    ia64_gen_gr_nat_clear(insn->r1);
                    if (ctx->full_alat) {
                        gen_helper_set_alat(
                            tcg_env, tcg_constant_i32(insn->r1), addr,
                            tcg_constant_i32(ia64_memop_size(mop)));
                    }
                    tcg_gen_br(l_done);

                    gen_set_label(l_fail);
                    if (ctx->full_alat) {
                        gen_helper_invalidate_alat_reg(
                            tcg_env, tcg_constant_i32(insn->r1));
                    }
                    tcg_gen_movi_i64(cpu_gr[insn->r1], 0);
                    ia64_gen_gr_nat_clear(insn->r1);

                    gen_set_label(l_done);
                }
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm_base_update && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
                ia64_gen_note_stacked_gr_write(insn->r3);
            }
        }
        break;
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
        ia64_gen_speculative_load(ctx, insn, true);
        break;
    case IA64_OP_LD8FILL:
        {
            TCGv_i64 addr = tcg_temp_new_i64();
            TCGv_i64 increment = NULL;
            TCGv_i64 base_nat = NULL;
            TCGv_i64 increment_nat = NULL;

            tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
            ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                                 &increment_nat);
            if (insn->r1 != 0) {
                MemOp mop = ia64_data_memop(
                    ctx, ia64_memop_for_opcode(insn->opcode));

                ia64_gen_check_nat_non_access(insn, insn->r3, false);
                ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                         false, false);
                tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr,
                                     ctx->mmu_idx, mop);
                ia64_gen_ld_fill_nat(insn->r1, addr);
                ia64_gen_memory_acquire(insn);
            }
            if (insn->reg_base_update && insn->r3 != 0) {
                ia64_gen_load_reg_base_update(insn, addr, increment,
                                              base_nat, increment_nat);
            } else if (insn->imm_base_update && insn->r3 != 0) {
                tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
                ia64_gen_note_stacked_gr_write(insn->r3);
            }
        }
        break;
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC: {
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 increment = NULL;
        TCGv_i64 base_nat = NULL;
        TCGv_i64 increment_nat = NULL;

        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        ia64_gen_load_reg_base_update_inputs(insn, &increment, &base_nat,
                                             &increment_nat);
        if (insn->r1 != 0) {
            MemOp mop = ia64_data_memop(
                ctx, ia64_memop_for_opcode(insn->opcode));
            const bool clear = insn->opcode >= IA64_OP_LD1C_CLR &&
                               insn->opcode <= IA64_OP_LD8C_CLR;
            ia64_gen_check_nat_non_access(insn, insn->r3, false);
            TCGLabel *l_done = NULL;

            if (ctx->full_alat) {
                TCGv_i64 hit = tcg_temp_new_i64();

                l_done = gen_new_label();
                gen_helper_check_load_alat_addr(
                    hit, tcg_env, tcg_constant_i32(insn->r1), addr,
                    tcg_constant_i32(ia64_memop_size(mop)),
                    tcg_constant_i32(clear));
                tcg_gen_brcondi_i64(TCG_COND_NE, hit, 0, l_done);
            }

            ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                     false, false);
            tcg_gen_qemu_ld_i64(cpu_gr[insn->r1], addr, ctx->mmu_idx, mop);
            ia64_gen_gr_nat_clear(insn->r1);
            ia64_gen_memory_acquire(insn);
            if (!clear && ctx->full_alat) {
                gen_helper_set_alat(tcg_env, tcg_constant_i32(insn->r1),
                                    addr,
                                    tcg_constant_i32(ia64_memop_size(mop)));
            }

            if (l_done) {
                gen_set_label(l_done);
            }
        }
        if (insn->reg_base_update && insn->r3 != 0) {
            ia64_gen_load_reg_base_update(insn, addr, increment, base_nat,
                                          increment_nat);
        } else if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_LD16:
        {
            TCGv_i128 pair = tcg_temp_new_i128();
            TCGv_i64 high = tcg_temp_new_i64();
            TCGv_i64 low = insn->r1 != 0 ? cpu_gr[insn->r1] :
                           tcg_temp_new_i64();

            ia64_gen_check_nat_non_access(insn, insn->r3, false);
            ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                     false);
            ia64_gen_sync_ip_for_helper(insn);
            gen_helper_check_montecito_16byte_access(
                tcg_env, ia64_gr_src(insn->r3), tcg_constant_i32(0));
            tcg_gen_qemu_ld_i128(
                pair, ia64_gr_src(insn->r3), ctx->mmu_idx,
                ia64_data_memop(ctx, MO_UO));
            if (ctx->be_data) {
                tcg_gen_extr_i128_i64(high, low, pair);
            } else {
                tcg_gen_extr_i128_i64(low, high, pair);
            }
            ia64_gen_memory_acquire(insn);
            if (insn->r1 != 0) {
                ia64_gen_gr_nat_clear(insn->r1);
            }
            gen_helper_write_ar(tcg_env, tcg_constant_i32(25), high);
        }
        break;
    case IA64_OP_ST16:
        {
            TCGv_i128 pair = tcg_temp_new_i128();
            TCGv_i64 high = tcg_temp_new_i64();

            ia64_gen_check_nat_non_access(insn, insn->r3, true);
            ia64_gen_check_nat_access(insn, insn->r2, true);
            ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                     true);
            ia64_gen_sync_ip_for_helper(insn);
            gen_helper_check_montecito_16byte_access(
                tcg_env, ia64_gr_src(insn->r3), tcg_constant_i32(1));
            ia64_gen_memory_release(insn);
            gen_helper_read_ar(high, tcg_env, tcg_constant_i32(25));
            if (ctx->be_data) {
                tcg_gen_concat_i64_i128(pair, high,
                                        ia64_gr_src(insn->r2));
            } else {
                tcg_gen_concat_i64_i128(pair, ia64_gr_src(insn->r2),
                                        high);
            }
            tcg_gen_qemu_st_i128(
                pair, ia64_gr_src(insn->r3), ctx->mmu_idx,
                ia64_data_memop(ctx, MO_UO));
            ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 16);
        }
        break;
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL: {
        MemOp mop = ia64_data_memop(ctx,
                                    ia64_memop_for_opcode(insn->opcode));
        bool spill = insn->opcode == IA64_OP_ST8SPILL;
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        if (!spill) {
            ia64_gen_check_nat_access(insn, insn->r2, true);
        }
        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        tcg_gen_mov_i64(value, ia64_gr_src(insn->r2));
        ia64_gen_check_alignment(insn, addr, ia64_memop_size(mop),
                                 false, true);
        ia64_gen_memory_release(insn);
        tcg_gen_qemu_st_i64(value, addr, ctx->mmu_idx, mop);
        ia64_gen_invalidate_alat_store(ctx, addr, ia64_memop_size(mop));
        if (spill) {
            gen_helper_st_spill_unat(tcg_env, tcg_constant_i32(insn->r2),
                                     addr);
        }
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], addr, insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_MOVL:
        if (insn->r1 != 0) {
            tcg_gen_movi_i64(cpu_gr[insn->r1], insn->imm);
            ia64_gen_gr_nat_clear(insn->r1);
        }
        break;
    case IA64_OP_ADDP4:
        if (insn->r1 != 0) {
            ia64_gen_addp4_result(cpu_gr[insn->r1], ia64_gr_src(insn->r2),
                                  ia64_gr_src(insn->r3));
            ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        }
        break;
    case IA64_OP_ADDP4_IMM:
        if (insn->r1 != 0) {
            TCGv_i64 imm = tcg_constant_i64(insn->imm);
            ia64_gen_addp4_result(cpu_gr[insn->r1], imm,
                                  ia64_gr_src(insn->r3));
            ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        }
        break;
    case IA64_OP_MOV_BRGR:
        ia64_gen_gr_write_nat_clear(insn->r1, cpu_br[insn->r2 & 7]);
        break;
    case IA64_OP_MOV_GRBR:
        ia64_gen_check_nat_register(insn, insn->r1);
        tcg_gen_mov_i64(cpu_br[insn->r2 & 7],
                        ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PRGR:
        if (insn->r1 != 0) {
            TCGv_i64 packed = tcg_temp_new_i64();

            gen_helper_read_pr(packed, tcg_env);
            ia64_gen_gr_write_nat_clear(insn->r1, packed);
        }
        break;
    case IA64_OP_MOV_GRPR:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_pr(tcg_env, ia64_gr_src(insn->r1),
                            tcg_constant_i64(insn->imm));
        break;
    case IA64_OP_MOV_PR_ROT_IMM:
        gen_helper_write_pr(tcg_env, tcg_constant_i64(insn->imm),
                            tcg_constant_i64(0xffffffffffff0000ULL));
        break;
    case IA64_OP_MOV_ARGR:
        if (insn->r1 != 0) {
            TCGv_i64 val = tcg_temp_new_i64();

            if (ia64_ar_is_simple(insn->r2)) {
                ia64_gen_read_simple_ar(val, insn->r2);
            } else {
                ia64_gen_validate_ar_access(insn, tcg_constant_i64(0),
                                            false);
                if (ia64_ar_access_reads_clock(insn->r2) &&
                    ia64_clock_access_needs_io(ctx)) {
                    translator_io_start(&ctx->base);
                }
                gen_helper_read_ar(val, tcg_env,
                                   tcg_constant_i32(insn->r2));
            }
            ia64_gen_gr_write_nat_clear(insn->r1, val);
        }
        break;
    case IA64_OP_MOV_GRAR:
        ia64_gen_check_nat_register(insn, insn->r1);
        if (ia64_ar_is_simple(insn->r2)) {
            if (insn->r2 == 40 || insn->r2 == 64) {
                ia64_gen_validate_ar_access(insn, ia64_gr_src(insn->r1),
                                            true);
            }
            ia64_gen_write_simple_ar(insn->r2, ia64_gr_src(insn->r1));
        } else {
            ia64_gen_validate_ar_access(insn, ia64_gr_src(insn->r1), true);
            if (ia64_ar_access_reads_clock(insn->r2)) {
                translator_io_start(&ctx->base);
                ctx->exit_after_bundle = true;
            }
            gen_helper_write_ar(tcg_env, tcg_constant_i32(insn->r2),
                                ia64_gr_src(insn->r1));
        }
        break;
    case IA64_OP_MOV_IMMAR:
        if (ia64_ar_is_simple(insn->r2)) {
            if (insn->r2 == 40 || insn->r2 == 64) {
                ia64_gen_validate_ar_access(
                    insn, tcg_constant_i64(insn->imm), true);
            }
            ia64_gen_write_simple_ar(insn->r2,
                                     tcg_constant_i64(insn->imm));
        } else {
            ia64_gen_validate_ar_access(
                insn, tcg_constant_i64(insn->imm), true);
            if (ia64_ar_access_reads_clock(insn->r2)) {
                translator_io_start(&ctx->base);
                ctx->exit_after_bundle = true;
            }
            gen_helper_write_ar(tcg_env, tcg_constant_i32(insn->r2),
                                tcg_constant_i64(insn->imm));
        }
        break;
    case IA64_OP_MOV_CRGR:
        if (insn->r1 != 0) {
            TCGv_i64 val = tcg_temp_new_i64();
            TCGv_i64 checked = tcg_temp_new_i64();

            ia64_gen_validate_cr_access(checked, insn,
                                        tcg_constant_i64(0), false);
            gen_helper_read_cr(val, tcg_env, tcg_constant_i32(insn->r2));
            ia64_gen_gr_write_nat_clear(insn->r1, val);
        }
        break;
    case IA64_OP_MOV_GRCR:
    {
        TCGv_i64 checked = tcg_temp_new_i64();

        if (ia64_cr_is_read_only(insn->r2)) {
            ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                      insn->raw, insn->slot);
            if (skip == NULL) {
                return true;
            }
            break;
        }
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_validate_cr_access(checked, insn,
                                    ia64_gr_src(insn->r1), true);
        if (ia64_cr_write_reads_clock(insn->r2)) {
            translator_io_start(&ctx->base);
        }
        gen_helper_write_cr(tcg_env, tcg_constant_i32(insn->r2),
                            checked);
        ctx->exit_after_bundle = true;
        break;
    }
    case IA64_OP_MOV_RRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r2);
        gen_helper_mov_rrgr_read(val, tcg_env, ia64_gr_src(insn->r2));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRRR:
    {
        TCGv_i64 checked = tcg_temp_new_i64();

        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_validate_rr_value(
            checked, tcg_env, ia64_gr_src(insn->r1),
            tcg_constant_i64(insn->address),
            tcg_constant_i64(insn->raw),
            tcg_constant_i32(insn->slot));
        gen_helper_mov_grrr_write(tcg_env, ia64_gr_src(insn->r2),
                                  checked);
        ctx->exit_after_bundle = true;
        break;
    }
    case IA64_OP_MOV_PKRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_pkrgr_read(val, tcg_env, tcg_constant_i32(insn->r2));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_PKRGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PKR_COUNT);
        gen_helper_mov_pkrgr_indexed_read(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPKR:
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_reserved_bits(insn, ia64_gr_src(insn->r1),
                                     IA64_PKR_MASK);
        gen_helper_mov_grpkr_write(tcg_env, tcg_constant_i32(insn->r2),
                                   ia64_gr_src(insn->r1));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_MOV_GRPKR_INDEXED:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PKR_COUNT);
        ia64_gen_check_reserved_bits(insn, ia64_gr_src(insn->r1),
                                     IA64_PKR_MASK);
        gen_helper_mov_grpkr_indexed_write(tcg_env, ia64_gr_src(insn->r3),
                                           ia64_gr_src(insn->r1));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_MOV_UMGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        tcg_gen_andi_i64(val, cpu_psr, IA64_PSR_UM_WRITABLE_MASK);
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRUM: {
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_reserved_bits(insn, ia64_gr_src(insn->r1),
                                     IA64_PSR_UM_WRITABLE_MASK);
        ia64_gen_write_user_mask(ia64_gr_src(insn->r1));
        ctx->exit_after_bundle = true;
        break;
    }
    case IA64_OP_MOV_IBRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_ibr(val, tcg_env, tcg_constant_i32(insn->r2 - 12));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRIBR:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_ibr(tcg_env, tcg_constant_i32(insn->r2 - 12),
                             ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_DBRGR_INDEXED: {
        TCGv_i64 index64 = tcg_temp_new_i64();
        TCGv_i32 index = tcg_temp_new_i32();
        TCGv_i64 val = tcg_temp_new_i64();

        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(
            insn, ia64_gr_src(insn->r3),
            insn->opcode == IA64_OP_MOV_IBRGR_INDEXED ?
            IA64_IBR_COUNT : IA64_DBR_COUNT);
        tcg_gen_mov_i64(index64, ia64_gr_src(insn->r3));
        tcg_gen_extrl_i64_i32(index, index64);
        if (insn->opcode == IA64_OP_MOV_IBRGR_INDEXED) {
            gen_helper_read_ibr(val, tcg_env, index);
        } else {
            gen_helper_read_dbr(val, tcg_env, index);
        }
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRIBR_INDEXED:
    case IA64_OP_MOV_GRDBR_INDEXED: {
        TCGv_i64 index64 = tcg_temp_new_i64();
        TCGv_i32 index = tcg_temp_new_i32();

        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_register_index(
            insn, ia64_gr_src(insn->r3),
            insn->opcode == IA64_OP_MOV_GRIBR_INDEXED ?
            IA64_IBR_COUNT : IA64_DBR_COUNT);
        tcg_gen_mov_i64(index64, ia64_gr_src(insn->r3));
        tcg_gen_extrl_i64_i32(index, index64);
        if (insn->opcode == IA64_OP_MOV_GRIBR_INDEXED) {
            gen_helper_write_ibr(tcg_env, index, ia64_gr_src(insn->r1));
        } else {
            gen_helper_write_dbr(tcg_env, index, ia64_gr_src(insn->r1));
        }
        break;
    }
    case IA64_OP_MOV_DBRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_dbr(val, tcg_env, tcg_constant_i32(insn->r2 - 8));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRDBR:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_dbr(tcg_env, tcg_constant_i32(insn->r2 - 8),
                             ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMCGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmc(val, tcg_env, tcg_constant_i32(insn->r2 - 32));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMC:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_pmc(tcg_env, tcg_constant_i32(insn->r2 - 32),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMCGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PMC_COUNT);
        gen_helper_read_pmc_indexed(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMC_INDEXED:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PMC_COUNT);
        gen_helper_write_pmc_indexed(tcg_env, ia64_gr_src(insn->r3),
                                     ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMDGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_pmd_checked(
            val, tcg_env, tcg_constant_i64(insn->r2 - 64),
            tcg_constant_i64(insn->address),
            tcg_constant_i64(insn->raw),
            tcg_constant_i32(insn->slot));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMD:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_pmd(tcg_env, tcg_constant_i32(insn->r2 - 64),
                            ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_PMDGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PMD_COUNT);
        gen_helper_read_pmd_checked(
            val, tcg_env, ia64_gr_src(insn->r3),
            tcg_constant_i64(insn->address),
            tcg_constant_i64(insn->raw),
            tcg_constant_i32(insn->slot));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPMD_INDEXED:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r1);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3),
                                      IA64_PMD_COUNT);
        gen_helper_write_pmd_indexed(tcg_env, ia64_gr_src(insn->r3),
                                     ia64_gr_src(insn->r1));
        break;
    case IA64_OP_MOV_CPUID: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_read_cr(val, tcg_env, tcg_constant_i32(13));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_CPUID_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3), 5);
        gen_helper_read_cpuid(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_DAHRGR_INDEXED: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(insn, ia64_gr_src(insn->r3), 8);
        gen_helper_read_dahr_indexed(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_MSRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        ia64_gen_check_nat_register(insn, insn->r3);
        gen_helper_read_msr(val, tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRMSR:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_write_msr(tcg_env, ia64_gr_src(insn->r3),
                             ia64_gr_src(insn->r1));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_MOV_IP:
    case IA64_OP_MOV_CURRENT_IP:
        if (insn->r1 != 0) {
            tcg_gen_movi_i64(cpu_gr[insn->r1], insn->address);
            ia64_gen_gr_nat_clear(insn->r1);
        }
        break;
    case IA64_OP_SSM:
        gen_helper_ssm(tcg_env, tcg_constant_i64(insn->imm));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_RSM:
        gen_helper_rsm(tcg_env, tcg_constant_i64(insn->imm));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_MOV_PSRGR: {
        TCGv_i64 val = tcg_temp_new_i64();
        gen_helper_mov_psrgr_read(val, tcg_env, tcg_constant_i32(0));
        ia64_gen_gr_write_nat_clear(insn->r1, val);
        break;
    }
    case IA64_OP_MOV_GRPSR:
        ia64_gen_check_nat_register(insn, insn->r1);
        gen_helper_mov_psr_write(tcg_env, ia64_gr_src(insn->r1),
                                 tcg_constant_i32(insn->imm != 0));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_BSW0:
        gen_helper_set_psr_bn(tcg_env, tcg_constant_i32(0));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                       record_iipa,
                                       track_psr_suppression);
            return true;
        }
        break;
    case IA64_OP_BSW1:
        gen_helper_set_psr_bn(tcg_env, tcg_constant_i32(1));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                       record_iipa,
                                       track_psr_suppression);
            return true;
        }
        break;
    case IA64_OP_ALLOC: {
        uint64_t packed = (uint64_t)insn->imm;
        uint32_t sof  = (packed >> 0) & 0x7f;
        uint32_t sol  = (packed >> 7) & 0x7f;
        uint32_t sor  = (packed >> 14) & 0x0f;
        if (sof > 96 || sol > sof || (sor << 3) > sof) {
            ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                      insn->raw, insn->slot);
            return true;
        }
        gen_helper_alloc_rse(tcg_env,
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(sof | (sol << 7) |
                                               (sor << 14)),
                              tcg_constant_i64(insn->address),
                              tcg_constant_i32(insn->slot));
        break;
    }
    case IA64_OP_COVER:
        gen_helper_cover_rse(tcg_env);
        break;
    case IA64_OP_FLUSHRS:
        gen_helper_flushrs_rse(tcg_env);
        break;
    case IA64_OP_LOADRS:
        gen_helper_loadrs_rse(tcg_env,
                              tcg_constant_i64(insn->address),
                              tcg_constant_i64(insn->raw),
                              tcg_constant_i32(insn->slot));
        break;
    case IA64_OP_ITR_D:
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(
            insn, ia64_gr_src(insn->r3),
            ia64_env_cpu_class(ctx->env)->dtr_count);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_itr_insert(tcg_env, ia64_gr_src(insn->r2),
                               ia64_gr_src(insn->r3),
                               tcg_constant_i32(1),
                               tcg_constant_i64(insn->raw),
                               tcg_constant_i32(insn->slot));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_ITR_I:
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_register_index(
            insn, ia64_gr_src(insn->r3),
            ia64_env_cpu_class(ctx->env)->itr_count);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_itr_insert(tcg_env, ia64_gr_src(insn->r2),
                               ia64_gr_src(insn->r3),
                               tcg_constant_i32(0),
                               tcg_constant_i64(insn->raw),
                               tcg_constant_i32(insn->slot));
        ia64_gen_exit_to_slot_completed(ctx, insn->address, insn->slot + 1,
                                        insn->address,
                                        record_iipa,
                                        track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_PTR_D:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptr_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(1));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_PTR_I:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptr_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(0));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_ITC_D:
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_itc_insert(tcg_env, ia64_gr_src(insn->r2),
                              tcg_constant_i32(1),
                              tcg_constant_i64(insn->raw),
                              tcg_constant_i32(insn->slot));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_ITC_I:
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_itc_insert(tcg_env, ia64_gr_src(insn->r2),
                              tcg_constant_i32(0),
                              tcg_constant_i64(insn->raw),
                              tcg_constant_i32(insn->slot));
        ia64_gen_exit_to_slot_completed(ctx, insn->address, insn->slot + 1,
                                        insn->address,
                                        record_iipa,
                                        track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_PTC_L:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(0));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_PTC_G:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(1));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_PTC_E:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              tcg_constant_i64(0),
                              tcg_constant_i32(2));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_PTC_GA:
        ia64_gen_check_nat_register(insn, insn->r3);
        ia64_gen_check_nat_register(insn, insn->r2);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_ptc_purge(tcg_env, ia64_gr_src(insn->r3),
                              ia64_gr_src(insn->r2),
                              tcg_constant_i32(3));
        ctx->exit_after_bundle = true;
        break;
    case IA64_OP_LDFD:
    case IA64_OP_LDFS:
    case IA64_OP_LDF_FILL:
    case IA64_OP_LDF8:
    case IA64_OP_LDFE:
        ia64_gen_fp_load(ctx, insn);
        break;
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        ia64_gen_fp_load_pair(ctx, insn);
        break;
    case IA64_OP_STFD: {
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_fr_nat_consumption(insn, insn->r2, IA64_ISR_W);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 8, false,
                                 true);
        gen_helper_getf(value, tcg_env, tcg_constant_i32(insn->r2),
                        tcg_constant_i32(0));
        tcg_gen_qemu_st_i64(value, ia64_gr_src(insn->r3), ctx->mmu_idx,
                            ia64_data_memop(ctx, MO_LEUQ));
        ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 8);
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_STFS: {
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_fr_nat_consumption(insn, insn->r2, IA64_ISR_W);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 4, false,
                                 true);
        gen_helper_getf(value, tcg_env, tcg_constant_i32(insn->r2),
                        tcg_constant_i32(1));
        tcg_gen_qemu_st_i64(value, ia64_gr_src(insn->r3), ctx->mmu_idx,
                            ia64_data_memop(ctx, MO_LEUL));
        ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 4);
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_STF_SPILL: {
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                 true);
        gen_helper_stf_spill(tcg_env, ia64_gr_src(insn->r3),
                             tcg_constant_i32(insn->r2));
        ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 16);
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_STF8: {
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_fr_nat_consumption(insn, insn->r2, IA64_ISR_W);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 8, false,
                                 true);
        gen_helper_getf(value, tcg_env, tcg_constant_i32(insn->r2),
                        tcg_constant_i32(2));
        tcg_gen_qemu_st_i64(value, ia64_gr_src(insn->r3), ctx->mmu_idx,
                            ia64_data_memop(ctx, MO_LEUQ));
        ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 8);
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    }
    case IA64_OP_STFE:
        ia64_gen_check_nat_non_access(insn, insn->r3, true);
        ia64_gen_check_fr_nat_consumption(insn, insn->r2, IA64_ISR_W);
        ia64_gen_check_alignment(insn, ia64_gr_src(insn->r3), 16, false,
                                 true);
        gen_helper_stfe(tcg_env, ia64_gr_src(insn->r3),
                        tcg_constant_i32(insn->r2));
        ia64_gen_invalidate_alat_store(ctx, ia64_gr_src(insn->r3), 10);
        if (insn->imm_base_update && insn->r3 != 0) {
            tcg_gen_addi_i64(cpu_gr[insn->r3], cpu_gr[insn->r3], insn->imm);
            ia64_gen_note_stacked_gr_write(insn->r3);
        }
        break;
    case IA64_OP_FADD:
        gen_helper_fadd(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FSUB:
        gen_helper_fsub(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FMPY:
        gen_helper_fmpy(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FMA:
        gen_helper_fma4(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1), ia64_fp_context(insn));
        break;
    case IA64_OP_XMA_L:
        ia64_gen_xma(insn, 0);
        break;
    case IA64_OP_XMA_H:
        ia64_gen_xma(insn, 1);
        break;
    case IA64_OP_XMA_HU:
        ia64_gen_xma(insn, 2);
        break;
    case IA64_OP_XMPY_HU:
        ia64_gen_xma(insn, 3);
        break;
    case IA64_OP_FMIN:
        gen_helper_fmin(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FMAX:
        gen_helper_fmax(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FAMIN:
        gen_helper_famin(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FAMAX:
        gen_helper_famax(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FRCPA:
        gen_helper_frcpa(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->p1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FPRCPA:
        gen_helper_fprcpa(tcg_env, tcg_constant_i32(insn->r1),
                          tcg_constant_i32(insn->p2),
                          tcg_constant_i32(insn->r2),
                          tcg_constant_i32(insn->r3),
                          ia64_fp_context(insn));
        break;
    case IA64_OP_FCMP:
        gen_helper_fcmp(tcg_env,
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(insn->p2),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->imm), ia64_fp_context(insn));
        break;
    case IA64_OP_FMS:
        gen_helper_fms(tcg_env, tcg_constant_i32(insn->r1),
                       tcg_constant_i32(insn->r2),
                       tcg_constant_i32(insn->r3),
                       tcg_constant_i32(insn->p1), ia64_fp_context(insn));
        break;
    case IA64_OP_FNMA:
        gen_helper_fnma4(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(insn->p1), ia64_fp_context(insn));
        break;
    case IA64_OP_FSELECT:
        gen_helper_fselect(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(insn->p1));
        break;
    case IA64_OP_FNORM:
        gen_helper_fnorm(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3), ia64_fp_context(insn));
        break;
    case IA64_OP_FPABS:
        gen_helper_fpabs(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPNEG:
        gen_helper_fpneg(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPNEGABS:
        gen_helper_fpnegabs(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FPRSQRTA:
        gen_helper_fprsqrta(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->p2),
                            tcg_constant_i32(insn->r3),
                            ia64_fp_context(insn));
        break;
    case IA64_OP_FRSQRTA:
        gen_helper_frsqrta(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->p2),
                           tcg_constant_i32(insn->r3),
                           ia64_fp_context(insn));
        break;
    case IA64_OP_FPACK:
        gen_helper_fpack(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FAND:
        gen_helper_flogical_and(tcg_env, tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FANDCM:
        gen_helper_flogical_andcm(tcg_env, tcg_constant_i32(insn->r1),
                                  tcg_constant_i32(insn->r2),
                                  tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FOR:
        gen_helper_flogical_or(tcg_env, tcg_constant_i32(insn->r1),
                               tcg_constant_i32(insn->r2),
                               tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FXOR:
        gen_helper_flogical_xor(tcg_env, tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FSWAP:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(0));
        break;
    case IA64_OP_FSWAP_NL:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(1));
        break;
    case IA64_OP_FSWAP_NR:
        gen_helper_fswap(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(2));
        break;
    case IA64_OP_FMIX_LR:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(0));
        break;
    case IA64_OP_FMIX_R:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(1));
        break;
    case IA64_OP_FMIX_L:
        gen_helper_fmix(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(2));
        break;
    case IA64_OP_FSXT_R:
        gen_helper_fsxt(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(0));
        break;
    case IA64_OP_FSXT_L:
        gen_helper_fsxt(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(1));
        break;
    case IA64_OP_FPMERGE:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(0));
        break;
    case IA64_OP_FPMERGE_S:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(1));
        break;
    case IA64_OP_FPMERGE_SE:
        gen_helper_fpmerge(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->r3),
                           tcg_constant_i32(2));
        break;
    case IA64_OP_FPMIN:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(0),
                            tcg_constant_i32(0),
                            ia64_fp_context(insn));
        break;
    case IA64_OP_FPMAX:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(1),
                            tcg_constant_i32(0),
                            ia64_fp_context(insn));
        break;
    case IA64_OP_FPAMIN:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(0),
                            tcg_constant_i32(1),
                            ia64_fp_context(insn));
        break;
    case IA64_OP_FPAMAX:
        gen_helper_fpminmax(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3),
                            tcg_constant_i32(1),
                            tcg_constant_i32(1),
                            ia64_fp_context(insn));
        break;
    case IA64_OP_FPCMP:
        gen_helper_fpcmp(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->r3),
                         tcg_constant_i32(insn->imm),
                         ia64_fp_context(insn));
        break;
    case IA64_OP_FPCVT:
        gen_helper_fpcvt(tcg_env, tcg_constant_i32(insn->r1),
                         tcg_constant_i32(insn->r2),
                         tcg_constant_i32(insn->imm & 1),
                         tcg_constant_i32((insn->imm >> 1) & 1),
                         ia64_fp_context(insn));
        break;
    case IA64_OP_FPMA:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(0),
                        ia64_fp_context(insn));
        break;
    case IA64_OP_FPMS:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(1),
                        ia64_fp_context(insn));
        break;
    case IA64_OP_FPNMA:
        gen_helper_fpma(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2),
                        tcg_constant_i32(insn->r3),
                        tcg_constant_i32(insn->p1),
                        tcg_constant_i32(2),
                        ia64_fp_context(insn));
        break;
    case IA64_OP_FMOV:
        gen_helper_fmov(tcg_env, tcg_constant_i32(insn->r1),
                        tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FCVT_XF:
        gen_helper_fcvt_xf(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2));
        break;
    case IA64_OP_FCVT_FX:
    case IA64_OP_FCVT_FXU:
        gen_helper_fcvt_fx(tcg_env, tcg_constant_i32(insn->r1),
                           tcg_constant_i32(insn->r2),
                           tcg_constant_i32(insn->opcode == IA64_OP_FCVT_FXU),
                           tcg_constant_i32((insn->imm >> 1) & 1),
                           ia64_fp_context(insn));
        break;
    case IA64_OP_GETF_D:
        if (insn->r1 != 0) {
            gen_helper_getf(cpu_gr[insn->r1], tcg_env,
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(0));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_S:
        if (insn->r1 != 0) {
            gen_helper_getf(cpu_gr[insn->r1], tcg_env,
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(1));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_SIG:
        if (insn->r1 != 0) {
            TCGLabel *slow = gen_new_label();
            TCGLabel *done = gen_new_label();

            tcg_gen_brcondi_i64(TCG_COND_EQ,
                                ia64_gen_fr_sig_read(insn->r2), 0, slow);
            tcg_gen_mov_i64(cpu_gr[insn->r1],
                            ia64_fr_significand_src(insn->r2));
            tcg_gen_br(done);
            gen_set_label(slow);
            gen_helper_getf(cpu_gr[insn->r1], tcg_env,
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(2));
            gen_set_label(done);
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    case IA64_OP_GETF_EXP: {
        if (insn->r1 != 0) {
            gen_helper_getf(cpu_gr[insn->r1], tcg_env,
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(3));
            ia64_gen_gr_nat_assign(insn->r1, ia64_gen_fr_nat_read(insn->r2));
        }
        break;
    }
    case IA64_OP_SETF_D:
        ia64_gen_fr_mov(insn->r1, ia64_gr_src(insn->r2));
        ia64_gen_fr_nat_from_gr(insn->r1, insn->r2);
        break;
    case IA64_OP_SETF_S: {
        gen_helper_setf_s(tcg_env, tcg_constant_i32(insn->r1),
                          ia64_gr_src(insn->r2));
        ia64_gen_fr_nat_from_gr(insn->r1, insn->r2);
        break;
    }
    case IA64_OP_SETF_EXP:
        gen_helper_setf_exp(tcg_env, tcg_constant_i32(insn->r1),
                            ia64_gr_src(insn->r2));
        ia64_gen_fr_nat_from_gr(insn->r1, insn->r2);
        break;
    case IA64_OP_SETF_SIG:
        ia64_gen_fr_mov_sig(insn->r1, ia64_gr_src(insn->r2));
        ia64_gen_fr_nat_from_gr(insn->r1, insn->r2);
        break;
    case IA64_OP_TPA: {
        TCGv_i64 val = tcg_temp_new_i64();

        ia64_gen_check_nat_consumption(insn, insn->r3, 0,
                                       IA64_NAT_NON_ACCESS);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_tpa(val, tcg_env, ia64_gr_src(insn->r3));
        if (insn->r1 != 0) {
            ia64_gen_gr_write_nat_clear(insn->r1, val);
        }
        break;
    }
    case IA64_OP_SYNC_I:
    case IA64_OP_FWB:
        break;
    case IA64_OP_CHK_S:
        if (!insn->check_fp) {
            TCGv_i64 failed = ia64_gen_gr_nat_read(insn->r2);

            ia64_gen_check_branch(ctx, failed, insn->address + insn->imm,
                                  insn->address, record_iipa,
                                  track_psr_suppression);
        } else {
            ia64_gen_check_branch(ctx, ia64_gen_fr_nat_read(insn->r2),
                                  insn->address + insn->imm, insn->address,
                                  record_iipa,
                                  track_psr_suppression);
        }
        break;
    case IA64_OP_CHK_A:
    case IA64_OP_CHK_A_CLR:
        if (!ctx->full_alat && insn->unit == IA64_UNIT_M) {
            ia64_gen_goto_completed(ctx, insn->address + insn->imm,
                                    insn->address, record_iipa,
                                    track_psr_suppression);
            if (skip == NULL) {
                return true;
            }
        } else if (!insn->check_fp && insn->unit == IA64_UNIT_M) {
            const bool clear = insn->opcode == IA64_OP_CHK_A_CLR;
            TCGv_i64 hit = tcg_temp_new_i64();
            TCGv_i64 failed = tcg_temp_new_i64();

            gen_helper_check_load_alat(hit, tcg_env,
                                       tcg_constant_i32(insn->r2),
                                       tcg_constant_i32(clear));
            tcg_gen_xori_i64(failed, hit, 1);
            ia64_gen_check_branch(ctx, failed, insn->address + insn->imm,
                                  insn->address, record_iipa,
                                  track_psr_suppression);
        } else if (insn->check_fp && insn->unit == IA64_UNIT_M) {
            const bool clear = insn->opcode == IA64_OP_CHK_A_CLR;
            TCGv_i64 hit = tcg_temp_new_i64();
            TCGv_i64 failed = tcg_temp_new_i64();

            gen_helper_check_load_alat_fp(hit, tcg_env,
                                          tcg_constant_i32(insn->r2),
                                          tcg_constant_i32(clear));
            tcg_gen_xori_i64(failed, hit, 1);
            ia64_gen_check_branch(ctx, failed, insn->address + insn->imm,
                                  insn->address, record_iipa,
                                  track_psr_suppression);
        }
        break;
    case IA64_OP_PROBE_R:
    case IA64_OP_PROBE_W:
    case IA64_OP_PROBE_RW: {
        /*
         * probe.rw exists only in the faulting form (M40), so the
         * read/write query never reaches the non-faulting helper below.
         */
        const bool write_probe = insn->opcode == IA64_OP_PROBE_W ||
                                 insn->opcode == IA64_OP_PROBE_RW;
        const bool rw_probe = insn->opcode == IA64_OP_PROBE_RW;
        TCGv_i64 access_level = insn->probe_imm ?
                                tcg_constant_i64(insn->imm & 3) :
                                ia64_gr_src(insn->r2);
        TCGv_i64 result = tcg_temp_new_i64();
        uint64_t isr_access =
            insn->opcode == IA64_OP_PROBE_R ? IA64_ISR_R :
            insn->opcode == IA64_OP_PROBE_W ? IA64_ISR_W :
                                              IA64_ISR_R | IA64_ISR_W;
        if (!insn->probe_imm) {
            ia64_gen_check_nat_consumption(insn, insn->r2,
                                           isr_access | 2,
                                           IA64_NAT_NON_ACCESS);
        }
        ia64_gen_check_nat_consumption(
            insn, insn->r3,
            isr_access | (insn->probe_fault ? 5 : 2),
            IA64_NAT_NON_ACCESS);
        if (insn->probe_fault) {
            ia64_gen_sync_ip_for_helper(insn);
            gen_helper_probe_fault(tcg_env, ia64_gr_src(insn->r3),
                                   tcg_constant_i32(write_probe),
                                   tcg_constant_i32(rw_probe),
                                   access_level);
            break;
        }
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_probe(result, tcg_env, ia64_gr_src(insn->r3),
                         tcg_constant_i32(write_probe), access_level);
        if (insn->r1 != 0) {
            ia64_gen_gr_write_nat_clear(insn->r1, result);
        }
        break;
    }
    case IA64_OP_TAK:
    case IA64_OP_THASH:
    case IA64_OP_TTAG: {
        TCGv_i64 result = tcg_temp_new_i64();

        if (insn->opcode == IA64_OP_TAK) {
            ia64_gen_check_nat_consumption(insn, insn->r3, 3,
                                           IA64_NAT_NON_ACCESS);
            gen_helper_tak(result, tcg_env, ia64_gr_src(insn->r3));
            if (insn->r1 != 0) {
                ia64_gen_gr_write_nat_clear(insn->r1, result);
            }
        } else if (insn->opcode == IA64_OP_THASH) {
            gen_helper_thash(result, tcg_env, ia64_gr_src(insn->r3));
            if (insn->r1 != 0) {
                tcg_gen_mov_i64(cpu_gr[insn->r1], result);
                ia64_gen_gr_nat_from_1_or_unimplemented_va(insn->r1,
                                                           insn->r3);
            }
        } else {
            gen_helper_ttag(result, tcg_env, ia64_gr_src(insn->r3));
            if (insn->r1 != 0) {
                tcg_gen_mov_i64(cpu_gr[insn->r1], result);
                ia64_gen_gr_nat_from_1_or_unimplemented_va(insn->r1,
                                                           insn->r3);
            }
        }
        break;
    }
    case IA64_OP_FC:
        ia64_gen_check_nat_consumption(insn, insn->r3, IA64_ISR_R | 1,
                                       IA64_NAT_NON_ACCESS);
        gen_helper_fc(tcg_env, ia64_gr_src(insn->r3));
        break;
    case IA64_OP_INVALA:
        if (ctx->full_alat) {
            gen_helper_invala(tcg_env);
        }
        break;
    case IA64_OP_INVALAT:
        if (!ctx->full_alat) {
            break;
        } else if (insn->check_fp) {
            gen_helper_invalidate_alat_fp_reg(tcg_env,
                                              tcg_constant_i32(insn->r1));
        } else {
            gen_helper_invalidate_alat_reg(tcg_env,
                                           tcg_constant_i32(insn->r1));
        }
        break;
    case IA64_OP_BR_WEXIT:
    case IA64_OP_BR_WTOP:
    case IA64_OP_BR_CEXIT:
    case IA64_OP_BR_CTOP: {
        TCGv_i64 tgt = tcg_temp_new_i64();
        TCGLabel *l_nobr = gen_new_label();
        uint64_t static_target = insn->address + insn->imm;
        bool target_is_static = insn->opcode == IA64_OP_BR_WEXIT ||
                                insn->opcode == IA64_OP_BR_WTOP ||
                                insn->b2 == 0;

        if (insn->opcode == IA64_OP_BR_WEXIT) {
            gen_helper_br_wexit(tgt, tcg_env,
                tcg_constant_i64(static_target),
                tcg_constant_i32(insn->qp));
        } else if (insn->opcode == IA64_OP_BR_WTOP) {
            gen_helper_br_wtop(tgt, tcg_env,
                tcg_constant_i64(static_target),
                tcg_constant_i32(insn->qp));
        } else if (insn->opcode == IA64_OP_BR_CEXIT) {
            gen_helper_br_cexit(tgt, tcg_env,
                tcg_constant_i64(static_target),
                tcg_constant_i32(insn->b2));
        } else {
            gen_helper_br_ctop(tgt, tcg_env,
                tcg_constant_i64(static_target),
                tcg_constant_i32(insn->b2));
        }
        tcg_gen_brcondi_i64(TCG_COND_EQ, tgt, 0, l_nobr);
        if (target_is_static) {
            if (insn->opcode == IA64_OP_BR_CTOP &&
                ia64_gen_self_counted_loop(ctx, static_target, insn->address,
                                           record_iipa,
                                           track_psr_suppression)) {
                gen_set_label(l_nobr);
                break;
            }
            ia64_gen_goto_completed(ctx, static_target, insn->address,
                                    record_iipa, track_psr_suppression);
        } else {
            ia64_gen_lookup_tcg_completed(ctx, tgt, insn->address,
                                          record_iipa, track_psr_suppression);
        }
        gen_set_label(l_nobr);
        break;
    }
    case IA64_OP_FCLASS:
        gen_helper_fclass(tcg_env, tcg_constant_i32(insn->p1),
                          tcg_constant_i32(insn->p2),
                          tcg_constant_i32(insn->r2),
                          tcg_constant_i32(insn->imm));
        break;
    case IA64_OP_FMERGE:
        gen_helper_fmerge_ns(tcg_env, tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMERGE_S:
        gen_helper_fmerge_s(tcg_env, tcg_constant_i32(insn->r1),
                            tcg_constant_i32(insn->r2),
                            tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_FMERGE_SE:
        gen_helper_fmerge_se(tcg_env, tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        break;
    case IA64_OP_SRLZ:
        gen_helper_tlb_serialize(tcg_env, tcg_constant_i32(1),
                                 tcg_constant_i32(1));
        ia64_gen_exit_to_slot_completed(ctx, insn->address, insn->slot + 1,
                                        insn->address,
                                        record_iipa,
                                        track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_SRLZ_D:
        gen_helper_tlb_serialize(tcg_env, tcg_constant_i32(1),
                                 tcg_constant_i32(0));
        ia64_gen_exit_to_slot_completed(ctx, insn->address, insn->slot + 1,
                                        insn->address,
                                        record_iipa,
                                        track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_MF:
    case IA64_OP_MF_A:
        tcg_gen_mb(TCG_MO_ALL);
        break;
    case IA64_OP_PADD1:
    case IA64_OP_PADD2:
    case IA64_OP_PADD4:
    case IA64_OP_PSUB1:
    case IA64_OP_PSUB2:
    case IA64_OP_PSUB4: {
        int lane_bits;
        int num_lanes;
        if (insn->opcode == IA64_OP_PADD1 || insn->opcode == IA64_OP_PSUB1) {
            lane_bits = 8;
            num_lanes = 8;
        } else if (insn->opcode == IA64_OP_PADD2 || insn->opcode == IA64_OP_PSUB2) {
            lane_bits = 16;
            num_lanes = 4;
        } else {
            lane_bits = 32;
            num_lanes = 2;
        }
        const uint64_t lane_mask = ((uint64_t)1 << lane_bits) - 1;
        bool is_sub = (insn->opcode == IA64_OP_PSUB1 ||
                       insn->opcode == IA64_OP_PSUB2 ||
                       insn->opcode == IA64_OP_PSUB4);
        const unsigned saturation = insn->imm & 3;
        TCGv_i64 result = tcg_temp_new_i64();
        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < num_lanes; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();
            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * lane_bits, lane_bits);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * lane_bits, lane_bits);
            if (saturation == 1) {
                if (lane_bits == 8) {
                    tcg_gen_ext8s_i64(lane_a, lane_a);
                    tcg_gen_ext8s_i64(lane_b, lane_b);
                } else if (lane_bits == 16) {
                    tcg_gen_ext16s_i64(lane_a, lane_a);
                    tcg_gen_ext16s_i64(lane_b, lane_b);
                }
            } else if (saturation == 3) {
                if (lane_bits == 8) {
                    tcg_gen_ext8s_i64(lane_b, lane_b);
                } else if (lane_bits == 16) {
                    tcg_gen_ext16s_i64(lane_b, lane_b);
                }
            }
            if (is_sub) {
                tcg_gen_sub_i64(lane_res, lane_a, lane_b);
            } else {
                tcg_gen_add_i64(lane_res, lane_a, lane_b);
            }
            if (saturation != 0 && lane_bits < 32) {
                int64_t min_value = 0;
                int64_t max_value = lane_mask;
                TCGLabel *ge_min = gen_new_label();
                TCGLabel *le_max = gen_new_label();

                if (saturation == 1) {
                    min_value = -(1LL << (lane_bits - 1));
                    max_value = (1LL << (lane_bits - 1)) - 1;
                }

                tcg_gen_brcondi_i64(TCG_COND_GE, lane_res, min_value,
                                    ge_min);
                tcg_gen_movi_i64(lane_res, min_value);
                gen_set_label(ge_min);
                tcg_gen_brcondi_i64(TCG_COND_LE, lane_res, max_value,
                                    le_max);
                tcg_gen_movi_i64(lane_res, max_value);
                gen_set_label(le_max);
            }
            tcg_gen_andi_i64(lane_res, lane_res, lane_mask);
            tcg_gen_shli_i64(lane_res, lane_res, i * lane_bits);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHLADD2: {
        TCGv_i64 result = tcg_temp_new_i64();

        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < 4; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();

            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * 16, 16);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * 16, 16);
            tcg_gen_ext16s_i64(lane_a, lane_a);
            tcg_gen_ext16s_i64(lane_b, lane_b);
            tcg_gen_shli_i64(lane_res, lane_a, insn->imm);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_add_i64(lane_res, lane_res, lane_b);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_andi_i64(lane_res, lane_res, 0xffff);
            tcg_gen_shli_i64(lane_res, lane_res, i * 16);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHRADD2: {
        TCGv_i64 result = tcg_temp_new_i64();

        tcg_gen_movi_i64(result, 0);
        for (int i = 0; i < 4; ++i) {
            TCGv_i64 lane_a = tcg_temp_new_i64();
            TCGv_i64 lane_b = tcg_temp_new_i64();
            TCGv_i64 lane_res = tcg_temp_new_i64();

            tcg_gen_extract_i64(lane_a, ia64_gr_src(insn->r2), i * 16, 16);
            tcg_gen_extract_i64(lane_b, ia64_gr_src(insn->r3), i * 16, 16);
            tcg_gen_ext16s_i64(lane_a, lane_a);
            tcg_gen_ext16s_i64(lane_b, lane_b);
            tcg_gen_sari_i64(lane_res, lane_a, insn->imm);
            tcg_gen_add_i64(lane_res, lane_res, lane_b);
            ia64_gen_saturate_signed_i64(lane_res, 16);
            tcg_gen_andi_i64(lane_res, lane_res, 0xffff);
            tcg_gen_shli_i64(lane_res, lane_res, i * 16);
            tcg_gen_or_i64(result, result, lane_res);
        }
        tcg_gen_mov_i64(cpu_gr[insn->r1], result);
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHR2:
        ia64_gen_pshr(insn, 16, false);
        break;
    case IA64_OP_PSHR2_U:
        ia64_gen_pshr(insn, 16, true);
        break;
    case IA64_OP_PSHR4:
        ia64_gen_pshr(insn, 32, false);
        break;
    case IA64_OP_PSHR4_U:
        ia64_gen_pshr(insn, 32, true);
        break;
    case IA64_OP_XCHG1:
    case IA64_OP_XCHG2:
    case IA64_OP_XCHG4:
    case IA64_OP_XCHG8: {
        MemOp memop = ia64_data_memop(ctx,
                                      ia64_memop_for_opcode(insn->opcode));
        uint32_t size = ia64_memop_size(memop);
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        tcg_gen_mov_i64(value, ia64_gr_src(insn->r2));
        ia64_gen_check_alignment_access(insn, addr, size, true,
                                        IA64_ISR_R | IA64_ISR_W);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_check_semaphore_access(tcg_env, addr);
        ia64_gen_memory_release(insn);
        tcg_gen_atomic_xchg_i64(cpu_gr[insn->r1], addr, value,
                                ctx->mmu_idx, memop);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        ia64_gen_invalidate_alat_store(ctx, addr, size);
        break;
    }
    case IA64_OP_CMPXCHG1:
    case IA64_OP_CMPXCHG2:
    case IA64_OP_CMPXCHG4:
    case IA64_OP_CMPXCHG8: {
        MemOp memop = ia64_data_memop(ctx,
                                      ia64_memop_for_opcode(insn->opcode));
        uint32_t size = ia64_memop_size(memop);
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 value = tcg_temp_new_i64();
        TCGv_i64 ccv = tcg_temp_new_i64();

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        tcg_gen_mov_i64(value, ia64_gr_src(insn->r2));
        ia64_gen_check_alignment_access(insn, addr, size, true,
                                        IA64_ISR_R | IA64_ISR_W);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_check_semaphore_access(tcg_env, addr);
        ia64_gen_read_simple_ar(ccv, 32);
        ia64_gen_memory_release(insn);
        gen_helper_cmpxchg(cpu_gr[insn->r1], tcg_env, addr, ccv, value,
                            tcg_constant_i32(size));
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    }
    case IA64_OP_CMP8XCHG16: {
        TCGv_i64 ccv = tcg_temp_new_i64();
        TCGv_i64 csd = tcg_temp_new_i64();

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        ia64_gen_check_alignment_access(insn, ia64_gr_src(insn->r3), 8, true,
                                        IA64_ISR_R | IA64_ISR_W);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_check_semaphore_access(tcg_env, ia64_gr_src(insn->r3));
        ia64_gen_read_simple_ar(ccv, 32);
        gen_helper_read_ar(csd, tcg_env, tcg_constant_i32(25));
        ia64_gen_memory_release(insn);
        gen_helper_cmp8xchg16(cpu_gr[insn->r1], tcg_env,
                              ia64_gr_src(insn->r3), ccv,
                              ia64_gr_src(insn->r2), csd);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        break;
    }
    case IA64_OP_FETCHADD4:
    case IA64_OP_FETCHADD8: {
        MemOp memop = ia64_data_memop(ctx,
                                      ia64_memop_for_opcode(insn->opcode));
        uint32_t size = ia64_memop_size(memop);
        TCGv_i64 addend = insn->imm ?
                           tcg_constant_i64(insn->imm) :
                           ia64_gr_src(insn->r2);
        TCGv_i64 addr = tcg_temp_new_i64();
        TCGv_i64 value = tcg_temp_new_i64();

        ia64_gen_check_nat_semaphore(insn, insn->r3, IA64_NAT_NON_ACCESS);
        if (!insn->imm) {
            ia64_gen_check_nat_semaphore(insn, insn->r2, IA64_NAT_ACCESS);
        }
        tcg_gen_mov_i64(addr, ia64_gr_src(insn->r3));
        tcg_gen_mov_i64(value, addend);
        ia64_gen_check_alignment_access(insn, addr, size, true,
                                        IA64_ISR_R | IA64_ISR_W);
        ia64_gen_sync_ip_for_helper(insn);
        gen_helper_check_semaphore_access(tcg_env, addr);
        ia64_gen_memory_release(insn);
        tcg_gen_atomic_fetch_add_i64(cpu_gr[insn->r1], addr, value,
                                     ctx->mmu_idx, memop);
        ia64_gen_memory_acquire(insn);
        ia64_gen_gr_nat_clear(insn->r1);
        ia64_gen_invalidate_alat_store(ctx, addr, size);
        break;
    }
    case IA64_OP_BR_COND:
    case IA64_OP_BRL_COND:
        if (ia64_gen_completed_direct_branch(ctx, skip,
                                             insn->address + insn->imm,
                                             insn->address, record_iipa,
                                             track_psr_suppression)) {
            return true;
        }
        break;
    case IA64_OP_BR_INDIRECT: {
        TCGv_i64 target = tcg_temp_new_i64();

        tcg_gen_andi_i64(target, cpu_br[insn->b2], IA64_IP_BUNDLE_MASK);
        ia64_gen_lookup_tcg_completed(ctx, target, insn->address, record_iipa,
                                      track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    }
    case IA64_OP_BR_CLOOP: {
        uint64_t target = insn->address + insn->imm;
        TCGv_i64 lc = tcg_temp_new_i64();
        TCGLabel *l_nobr = gen_new_label();

        tcg_gen_ld_i64(lc, tcg_env, offsetof(CPUIA64State, ar[65]));
        tcg_gen_brcondi_i64(TCG_COND_EQ, lc, 0, l_nobr);
        if (ia64_gen_zero_st1_cloop(ctx, insn, target, l_nobr, record_iipa,
                                    track_psr_suppression)) {
            gen_set_label(l_nobr);
            break;
        }
        tcg_gen_subi_i64(lc, lc, 1);
        tcg_gen_st_i64(lc, tcg_env, offsetof(CPUIA64State, ar[65]));
        if (ia64_gen_self_counted_loop(ctx, target, insn->address,
                                       record_iipa,
                                       track_psr_suppression)) {
            gen_set_label(l_nobr);
            break;
        }
        ia64_gen_goto_completed(ctx, target, insn->address, record_iipa,
                                track_psr_suppression);
        gen_set_label(l_nobr);
        break;
    }
    case IA64_OP_BR_IA:
        gen_helper_br_ia(tcg_env, tcg_constant_i32(insn->b2),
                         tcg_constant_i64(insn->address),
                         tcg_constant_i32(insn->slot));
        ia64_gen_lookup_current_completed(ctx, insn->address, record_iipa,
                                          track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_BR_CALL: {
        const uint64_t target = insn->address + insn->imm;

        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                tcg_constant_i64(target));
        if (ia64_gen_completed_direct_branch(ctx, skip, target, insn->address,
                                             record_iipa,
                                             track_psr_suppression)) {
            return true;
        }
        break;
    }
    case IA64_OP_BRL_CALL:
    {
        const uint64_t target = insn->address + insn->imm;

        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                tcg_constant_i64(target));
        if (ia64_gen_completed_direct_branch(ctx, skip, target, insn->address,
                                             record_iipa,
                                             track_psr_suppression)) {
            return true;
        }
        break;
    }
    case IA64_OP_BR_CALL_INDIRECT: {
        TCGv_i64 target = tcg_temp_new_i64();

        tcg_gen_mov_i64(target, cpu_br[insn->b2]);
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_call_rse(tcg_env,
                                tcg_constant_i32(insn->b1),
                                tcg_constant_i64(next_ip),
                                target);
        ia64_gen_lookup_current_completed(ctx, insn->address, record_iipa,
                                          track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    }
    case IA64_OP_BR_RET:
        tcg_gen_movi_i64(cpu_ip, insn->address);
        gen_helper_br_ret_rse(tcg_env, tcg_constant_i32(insn->b2));
        ia64_gen_lookup_current_completed(ctx, insn->address, record_iipa,
                                          track_psr_suppression);
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_RFI:
        gen_helper_rfi(tcg_env, tcg_constant_i64(insn->address),
                       tcg_constant_i32(insn->slot));
        tcg_gen_lookup_and_goto_ptr();
        if (skip == NULL) {
            return true;
        }
        break;
    case IA64_OP_EPC:
        gen_helper_epc(tcg_env, tcg_constant_i64(insn->address),
                       tcg_constant_i64(insn->raw),
                       tcg_constant_i32(insn->slot));
        if (skip == NULL) {
            ia64_gen_exit_to_completed(ctx, next_ip, insn->address,
                                       record_iipa,
                                       track_psr_suppression);
            return true;
        }
        break;
    case IA64_OP_PAVG1:
    case IA64_OP_PAVG2:
    case IA64_OP_PAVGSUB1:
    case IA64_OP_PAVGSUB2: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PAVG1) sel = insn->imm ? 4 : 0;
        else if (insn->opcode == IA64_OP_PAVG2) sel = insn->imm ? 5 : 1;
        else if (insn->opcode == IA64_OP_PAVGSUB1) sel = 2;
        else sel = 3;
        gen_helper_simd_pavg(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PCMP1_EQ:
    case IA64_OP_PCMP1_GT:
    case IA64_OP_PCMP2_EQ:
    case IA64_OP_PCMP2_GT:
    case IA64_OP_PCMP4_EQ:
    case IA64_OP_PCMP4_GT: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PCMP1_EQ) sel = 0;
        else if (insn->opcode == IA64_OP_PCMP1_GT) sel = 1;
        else if (insn->opcode == IA64_OP_PCMP2_EQ) sel = 2;
        else if (insn->opcode == IA64_OP_PCMP2_GT) sel = 3;
        else if (insn->opcode == IA64_OP_PCMP4_EQ) sel = 4;
        else sel = 5;
        gen_helper_simd_pcmp(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PMAX1_U:
    case IA64_OP_PMAX2:
    case IA64_OP_PMIN1_U:
    case IA64_OP_PMIN2: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PMAX1_U) sel = 0;
        else if (insn->opcode == IA64_OP_PMIN1_U) sel = 1;
        else if (insn->opcode == IA64_OP_PMAX2) sel = 2;
        else sel = 3;
        gen_helper_simd_pminmax(tcg_env, tcg_constant_i32(sel),
                                 tcg_constant_i32(insn->r1),
                                 tcg_constant_i32(insn->r2),
                                 tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PMPY2_L:
    case IA64_OP_PMPY2_R:
    case IA64_OP_PMPYSH2:
    case IA64_OP_PMPYSH2_U: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PMPY2_L) sel = 0;
        else if (insn->opcode == IA64_OP_PMPY2_R) sel = 1;
        else if (insn->opcode == IA64_OP_PMPYSH2) sel = 2;
        else sel = 3;
        gen_helper_simd_pmpy(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3),
                              tcg_constant_i32(insn->imm));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PSHL2:
        ia64_gen_pshl(insn, 16);
        break;
    case IA64_OP_PSHL4:
        ia64_gen_pshl(insn, 32);
        break;
    case IA64_OP_PSAD1:
        gen_helper_simd_psad1(tcg_env,
                               tcg_constant_i32(insn->r1),
                               tcg_constant_i32(insn->r2),
                               tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_MUX1:
    case IA64_OP_MUX2:
        gen_helper_simd_mux(tcg_env,
                             tcg_constant_i32(insn->opcode == IA64_OP_MUX1 ? 0 : 1),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->imm));
        ia64_gen_gr_nat_from_1(insn->r1, insn->r2);
        break;
    case IA64_OP_MIX1_L:
    case IA64_OP_MIX1_R:
    case IA64_OP_MIX2_L:
    case IA64_OP_MIX2_R:
    case IA64_OP_MIX4_L:
    case IA64_OP_MIX4_R: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_MIX1_L) sel = 0;
        else if (insn->opcode == IA64_OP_MIX1_R) sel = 1;
        else if (insn->opcode == IA64_OP_MIX2_L) sel = 2;
        else if (insn->opcode == IA64_OP_MIX2_R) sel = 3;
        else if (insn->opcode == IA64_OP_MIX4_L) sel = 4;
        else sel = 5;
        gen_helper_simd_mix(tcg_env, tcg_constant_i32(sel),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_PACK2_SSS:
    case IA64_OP_PACK2_USS:
    case IA64_OP_PACK4_SSS: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_PACK2_SSS) sel = 0;
        else if (insn->opcode == IA64_OP_PACK2_USS) sel = 1;
        else sel = 2;
        gen_helper_simd_pack(tcg_env, tcg_constant_i32(sel),
                              tcg_constant_i32(insn->r1),
                              tcg_constant_i32(insn->r2),
                              tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_UNPACK1_H:
    case IA64_OP_UNPACK1_L:
    case IA64_OP_UNPACK2_H:
    case IA64_OP_UNPACK2_L:
    case IA64_OP_UNPACK4_H:
    case IA64_OP_UNPACK4_L: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_UNPACK1_H) sel = 0;
        else if (insn->opcode == IA64_OP_UNPACK1_L) sel = 1;
        else if (insn->opcode == IA64_OP_UNPACK2_H) sel = 2;
        else if (insn->opcode == IA64_OP_UNPACK2_L) sel = 3;
        else if (insn->opcode == IA64_OP_UNPACK4_H) sel = 4;
        else sel = 5;
        gen_helper_simd_unpack(tcg_env, tcg_constant_i32(sel),
                                tcg_constant_i32(insn->r1),
                                tcg_constant_i32(insn->r2),
                                tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    }
    case IA64_OP_SUM:
        gen_helper_simd_sum(tcg_env,
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r2),
                             tcg_constant_i32(insn->r3));
        ia64_gen_gr_nat_from_2(insn->r1, insn->r2, insn->r3);
        break;
    case IA64_OP_CZX1_L:
    case IA64_OP_CZX1_R:
    case IA64_OP_CZX2_L:
    case IA64_OP_CZX2_R: {
        uint32_t sel;
        if (insn->opcode == IA64_OP_CZX1_L) sel = 0;
        else if (insn->opcode == IA64_OP_CZX1_R) sel = 1;
        else if (insn->opcode == IA64_OP_CZX2_L) sel = 2;
        else sel = 3;
        gen_helper_simd_czx(tcg_env, tcg_constant_i32(sel),
                             tcg_constant_i32(insn->r1),
                             tcg_constant_i32(insn->r3),
                             tcg_constant_i32(0));
        ia64_gen_gr_nat_from_1(insn->r1, insn->r3);
        break;
    }
    case IA64_OP_ILLEGAL:
        ia64_gen_raise_exception(IA64_EXCP_ILLEGAL, insn->address,
                                  insn->raw, insn->slot);
        if (skip == NULL) {
            return true;
        }
        break;
    }

    ia64_gen_predicate_end(skip);
    ia64_gen_note_successful_bundle(insn->address, record_iipa,
                                    track_psr_suppression);
    return false;
}

static void ia64_cpu_set_pc(CPUState *cs, vaddr value)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);

    cpu->env.ip = value;
}

static vaddr ia64_cpu_get_pc(CPUState *cs)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);

    return cpu->env.ip;
}

/* ---- Local SAPIC helpers ---- */

static int sapic_find_isr(CPUIA64State *env);

CPUState *ia64_cpu_by_sapic_id(uint8_t id, uint8_t eid)
{
    CPUState *cs;
    uint64_t lid = ia64_sapic_lid(id, eid);

    CPU_FOREACH(cs) {
        IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);

        if ((qatomic_read(&cpu->env.cr[IA64_CR_SAPIC_LID]) &
             (IA64_SAPIC_LID_ID_MASK | IA64_SAPIC_LID_EID_MASK)) == lid) {
            return cs;
        }
    }
    return NULL;
}

static bool sapic_vector_active(const uint64_t bitmap[4], int vector)
{
    return bitmap[vector / 64] & (1ULL << (vector % 64));
}

static int sapic_vector_priority(int vector)
{
    if (vector == 2) {
        return 257;
    }
    if (vector == 0) {
        return 256;
    }
    if (vector >= 16) {
        return vector;
    }
    return -1;
}

static int sapic_vector_priority_class(int vector)
{
    return vector >= 16 ? vector >> 4 : -1;
}

static bool sapic_vector_unmasked(CPUIA64State *env, int vector)
{
    uint64_t tpr = env->cr[IA64_CR_SAPIC_TPR];
    int isr = sapic_find_isr(env);
    int vector_priority = sapic_vector_priority(vector);
    int vector_class = sapic_vector_priority_class(vector);

    if (vector_priority <= sapic_vector_priority(isr)) {
        return false;
    }

    if (vector == 2) {
        return true;
    }
    if (vector == 0) {
        return !(tpr & IA64_TPR_MMI);
    }
    return !(tpr & IA64_TPR_MMI) &&
           ((uint64_t)vector_class > ((tpr & IA64_TPR_MIC_MASK) >> 4));
}

static int sapic_find_highest_normal(const uint64_t bitmap[4])
{
    int word;

    for (word = 3; word >= 0; word--) {
        uint64_t active = bitmap[word];

        if (word == 0) {
            active &= ~0xffffULL;
        }
        if (active) {
            return word * 64 + 63 - clz64(active);
        }
    }
    return IA64_SPURIOUS_VECTOR;
}

static int sapic_find_irr(CPUIA64State *env)
{
    int vector;

    if (sapic_vector_active(env->sapic_irr, 2) &&
        sapic_vector_unmasked(env, 2)) {
        return 2;
    }
    if (sapic_vector_active(env->sapic_irr, 0) &&
        sapic_vector_unmasked(env, 0)) {
        return 0;
    }
    vector = sapic_find_highest_normal(env->sapic_irr);
    if (vector != IA64_SPURIOUS_VECTOR &&
        sapic_vector_unmasked(env, vector)) {
        return vector;
    }
    return IA64_SPURIOUS_VECTOR;
}

static int sapic_find_isr(CPUIA64State *env)
{
    if (sapic_vector_active(env->sapic_isr, 2)) {
        return 2;
    }
    if (sapic_vector_active(env->sapic_isr, 0)) {
        return 0;
    }
    return sapic_find_highest_normal(env->sapic_isr);
}

void ia64_sapic_update_interrupt(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);

    if (sapic_find_irr(env) != IA64_SPURIOUS_VECTOR) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_HARD);
        qemu_cpu_kick(cs);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

bool ia64_sapic_has_pending(CPUIA64State *env)
{
    int vector = sapic_find_irr(env);
    return vector != IA64_SPURIOUS_VECTOR;
}

static int ia64_itv_vector(CPUIA64State *env)
{
    uint8_t vector = env->cr[IA64_CR_ITV] & 0xFF;

    return ia64_external_interrupt_vector_valid(vector) ? vector : -1;
}

static bool ia64_itv_masked(CPUIA64State *env)
{
    return env->cr[IA64_CR_ITV] & IA64_VECTOR_MASKED;
}

static bool ia64_itm_interrupt_active(CPUIA64State *env)
{
    int vector = ia64_itv_vector(env);

    return vector >= 0 && sapic_vector_active(env->sapic_isr, vector);
}

void ia64_itc_advance_pending_itm(CPUIA64State *env)
{
    ia64_itc_sync(env);

    /*
     * Once the timer interrupt is in service, the guest has not armed the next
     * ITM yet.  Expose at least the first tick after the matched deadline so a
     * handler cannot observe the equality as still pending.
     */
    if (!env->itm_armed &&
        env->itm_last_match_valid &&
        ia64_itm_interrupt_active(env) &&
        (int64_t)(env->ar_itc - (env->itm_last_match + 1)) < 0) {
        uint64_t ticks = env->itm_last_match + 1 - env->ar_itc;

        env->ar_itc += ticks;
        env->itc_delta += (int64_t)ticks * IA64_ITC_NS_PER_TICK;
    }
}

int ia64_sapic_accept(CPUIA64State *env)
{
    int vector = sapic_find_irr(env);
    if (vector != IA64_SPURIOUS_VECTOR) {
        int idx = vector / 64;
        int bit = vector % 64;
        env->sapic_irr[idx] &= ~(1ULL << bit);
        env->sapic_isr[idx] |= (1ULL << bit);
        ia64_sapic_update_interrupt(env);
    }
    return vector;
}

void ia64_sapic_eoi(CPUIA64State *env)
{
    int vector = sapic_find_isr(env);
    if (vector != IA64_SPURIOUS_VECTOR) {
        int idx = vector / 64;
        int bit = vector % 64;
        env->sapic_isr[idx] &= ~(1ULL << bit);
    }
    ia64_sapic_update_interrupt(env);
}

int ia64_sapic_get_ivr(CPUIA64State *env)
{
    return ia64_sapic_accept(env);
}

static void ia64_sapic_set_irq_work(CPUState *cs, run_on_cpu_data data)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    uint8_t vector = data.host_int;
    int idx = vector / 64;
    int bit = vector % 64;

    cpu->env.sapic_irr[idx] |= (1ULL << bit);
    ia64_sapic_update_interrupt(&cpu->env);
}

void ia64_sapic_set_irq(CPUState *cs, uint8_t vector)
{
    run_on_cpu_data data = RUN_ON_CPU_HOST_INT(vector);

    if (qemu_cpu_is_self(cs)) {
        ia64_sapic_set_irq_work(cs, data);
    } else {
        async_run_on_cpu(cs, ia64_sapic_set_irq_work, data);
    }
}

static void ia64_itm_raise(CPUIA64State *env, uint64_t itm_value)
{
    IA64CPU *cpu = container_of(env, IA64CPU, env);
    int vector = ia64_itv_vector(env);

    if (vector < 0) {
        return;
    }

    if (env->itm_last_match_valid && env->itm_last_match == itm_value) {
        ia64_sapic_update_interrupt(env);
        return;
    }

    env->itm_last_match = itm_value;
    env->itm_last_match_valid = true;
    ia64_sapic_set_irq(CPU(cpu), vector);
}

static bool ia64_itm_update_pending(CPUIA64State *env, uint64_t itc,
                                    uint64_t itm_value, bool was_armed)
{
    int64_t delta_ticks = (int64_t)(itm_value - itc);
    int vector = ia64_itv_vector(env);

    if (vector < 0) {
        return true;
    }

    if (ia64_itv_masked(env)) {
        return true;
    }

    if (delta_ticks > 0) {
        return false;
    }

    /*
     * The architecture raises an interval timer interrupt when ITC equals
     * ITM.  A freshly programmed value already behind the current ITC has
     * missed that equality and must not synthesize an interrupt.  If this
     * value was armed while it was still in the future, a late QEMU timer
     * callback still represents the equality that elapsed in virtual time.
     */
    if (delta_ticks == 0 || was_armed) {
        ia64_itm_raise(env, itm_value);
    }
    return true;
}

static void ia64_itm_timer_work(CPUState *cs, run_on_cpu_data data)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    uint64_t itm;
    bool was_armed;

    (void)data;
    if (!cpu->env.itm_armed) {
        return;
    }
    was_armed = cpu->env.itm_armed;
    cpu->env.itm_armed = false;
    itm = cpu->env.cr[1];

    ia64_itc_advance_pending_itm(&cpu->env);

    if (!ia64_itm_update_pending(&cpu->env, cpu->env.ar_itc, itm,
                                 was_armed)) {
        ia64_itm_update(&cpu->env, itm);
    }
}

static void ia64_itm_timer_cb(void *opaque)
{
    CPUState *cs = CPU(opaque);

    if (qemu_cpu_is_self(cs)) {
        ia64_itm_timer_work(cs, RUN_ON_CPU_NULL);
    } else {
        async_run_on_cpu(cs, ia64_itm_timer_work, RUN_ON_CPU_NULL);
    }
}

void ia64_itm_update(CPUIA64State *env, uint64_t itm_value)
{
    IA64CPU *cpu = container_of(env, IA64CPU, env);
    uint64_t itc;
    int64_t delta_ticks;
    int64_t delay_ns;
    int64_t deadline_ns;
    bool was_armed = env->itm_armed && env->itm_armed_value == itm_value;

    ia64_itc_advance_pending_itm(env);
    itc = env->ar_itc;
    delta_ticks = (int64_t)(itm_value - itc);

    timer_del(cpu->itm_timer);
    env->itm_armed = false;

    if (ia64_itm_update_pending(env, itc, itm_value, was_armed)) {
        ia64_itc_advance_pending_itm(env);
        return;
    }

    if (delta_ticks > INT64_MAX / IA64_ITC_NS_PER_TICK) {
        delay_ns = INT64_MAX;
    } else {
        delay_ns = delta_ticks * IA64_ITC_NS_PER_TICK;
    }
    env->itm_armed = true;
    env->itm_armed_value = itm_value;
    deadline_ns = delay_ns > INT64_MAX - env->itc_delta ?
                  INT64_MAX : env->itc_delta + delay_ns;
    timer_mod(cpu->itm_timer, deadline_ns);
}

void ia64_itc_sync(CPUIA64State *env)
{
    int64_t now = ia64_itc_clock_ns();
    int64_t elapsed = now - env->itc_delta;

    if (elapsed > 0) {
        uint64_t ticks = (uint64_t)(elapsed / IA64_ITC_NS_PER_TICK);

        if (ticks != 0) {
            env->ar_itc += ticks;
            env->itc_delta += (int64_t)ticks * IA64_ITC_NS_PER_TICK;
        }
    }
}

void ia64_itc_check_timer(CPUIA64State *env)
{
    bool was_armed;

    ia64_itc_advance_pending_itm(env);
    was_armed = env->itm_armed && env->itm_armed_value == env->cr_itm;

    if (was_armed && (int64_t)(env->cr_itm - env->ar_itc) <= 0) {
        env->itm_armed = false;
    }
    ia64_itm_update_pending(env, env->ar_itc, env->cr_itm, was_armed);
    ia64_itc_advance_pending_itm(env);
}

void ia64_itc_enter_halt(CPUIA64State *env)
{
    ia64_itc_advance_pending_itm(env);
    ia64_itm_update(env, env->cr_itm);
}

static bool ia64_cpu_has_work(CPUState *cs)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;
    bool nmi_pending = (env->sapic_irr[0] & (1ULL << 2)) != 0;
    bool interrupts_enabled = (env->psr & IA64_PSR_I) ||
                              (cs->halted && env->pal_halt_wake);

    /*
     * ia64_sapic_update_interrupt() maintains CPU_INTERRUPT_HARD whenever
     * IRR, ISR or TPR changes, and the ITM callback does the same when its
     * deadline expires.  Do not rescan IRR or reschedule the timer from this
     * exec-loop hot path.  PAL_HALT_LIGHT wakes only for an interrupt that
     * is actually deliverable; PSR.i does not mask NMI vector 2.
     */
    return cpu_test_interrupt(cs, CPU_INTERRUPT_HARD) &&
           (interrupts_enabled || nmi_pending);
}

static TCGTBCPUState ia64_get_tb_cpu_state(CPUState *cs)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    uint64_t psr = cpu->env.psr;
    uint32_t flags =
        ((psr >> 17) & IA64_TB_FLAG_DT) |
        ((psr >> 35) & IA64_TB_FLAG_IT) |
        ((psr >> (IA64_PSR_RI_SHIFT - IA64_TB_FLAG_RI_SHIFT)) &
         IA64_TB_FLAG_RI_MASK) |
        ((psr >> 8) & IA64_TB_FLAG_PSR_IC) |
        ((psr << 5) & IA64_TB_FLAG_BE) |
        ((uint32_t)cpu->env.instruction_group_start << 7) |
        ((psr >> 26) & IA64_TB_FLAG_PSR_IS) |
        ((psr >> (IA64_PSR_CPL_SHIFT - IA64_TB_FLAG_CPL_SHIFT)) &
         IA64_TB_FLAG_CPL_MASK);

    flags |= (psr & IA64_PSR_FAULT_SUPPRESS_MASK) != 0 ?
             IA64_TB_FLAG_PSR_SUPPRESS : 0;

    return (TCGTBCPUState) {
        .pc = cpu->env.ip,
        .flags = flags,
    };
}

void ia64_tlb_bump_generation(CPUIA64State *env, bool is_ifetch)
{
    IA64MicroTlbEntry *micro = is_ifetch ? env->tlb_inst_micro :
                                           env->tlb_data_micro;
    uint32_t *generation = is_ifetch ? &env->tlb_inst_generation :
                                       &env->tlb_data_generation;
    uint8_t *next = is_ifetch ? &env->tlb_inst_micro_next :
                                &env->tlb_data_micro_next;

    (*generation)++;
    if (*generation == 0) {
        *generation = 1;
        memset(micro, 0, sizeof(*micro) * IA64_MICRO_TLB_SIZE);
        *next = 0;
    }
}

const IA64TlbEntry *ia64_tlb_find_slow(CPUIA64State *env, uint64_t va,
                                       uint32_t rid, bool is_ifetch)
{
    IA64TlbEntry *tlb = is_ifetch ? env->tlb_inst : env->tlb_data;
    IA64MicroTlbEntry *micro = is_ifetch ? env->tlb_inst_micro :
                                           env->tlb_data_micro;
    uint8_t *next = is_ifetch ? &env->tlb_inst_micro_next :
                                &env->tlb_data_micro_next;
    uint16_t tlb_count = is_ifetch ? env->tlb_inst_count :
                                     env->tlb_data_count;
    uint32_t generation = is_ifetch ? env->tlb_inst_generation :
                                      env->tlb_data_generation;
    uint16_t i;

    for (i = 0; i < tlb_count; i++) {
        IA64TlbEntry *entry = &tlb[i];

        if (ia64_tlb_match(entry, va, rid)) {
            micro[*next] = (IA64MicroTlbEntry) {
                .va = entry->va,
                .page_mask = entry->page_mask,
                .rid = entry->rid,
                .generation = generation,
                .slot = i,
                .valid = true,
            };
            *next = (*next + 1) % IA64_MICRO_TLB_SIZE;
            return entry;
        }
    }
    return NULL;
}

static void ia64_cpu_synchronize_from_tb(CPUState *cs,
                                         const TranslationBlock *tb)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    uint64_t ri =
        (tb->flags & IA64_TB_FLAG_RI_MASK) >> IA64_TB_FLAG_RI_SHIFT;

    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu->env.ip = tb->pc;
    /*
     * Translation-time instruction fetch faults occur before generated TCG
     * can update PSR.ri.  Restore the slot encoded in the TB key along with
     * its bundle address; otherwise a stale slot from the preceding TB is
     * saved in IPSR and rfi can skip the faulting bundle's prologue.
     */
    cpu->env.psr = (cpu->env.psr & ~IA64_PSR_RI_MASK) |
                   (ri << IA64_PSR_RI_SHIFT);
}

static void ia64_restore_state_to_opc(CPUState *cs,
                                       const TranslationBlock *tb,
                                       const uint64_t *data)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);

    cpu->env.ip = data[0];
}

static int ia64_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);

    if (cpu->env.psr & (ifetch ? IA64_PSR_IT : IA64_PSR_DT)) {
        return MMU_IDX_VIRT_CPL(ia64_psr_cpl(cpu->env.psr));
    }
    return MMU_PHYS_IDX;
}

#ifndef CONFIG_USER_ONLY
static G_NORETURN void ia64_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                                    MMUAccessType access_type,
                                                    int mmu_idx,
                                                    uintptr_t retaddr)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;

    (void)mmu_idx;
    cpu_restore_state(cs, retaddr);
    env->fault_ip = env->ip;
    env->fault_imm = 0;
    env->cr_ifa = addr;
    env->cr_isr = access_type == MMU_DATA_STORE ? IA64_ISR_W : IA64_ISR_R;
    if (ia64_current_code_tlb_ed(env)) {
        env->cr_isr |= IA64_ISR_ED;
    }
    env->exception = IA64_EXCP_UNALIGNED;
    cs->exception_index = IA64_EXCP_UNALIGNED;
    cpu_loop_exit(cs);
}
#endif

static int ia64_tlb_perm_to_prot(uint8_t perm)
{
    int prot = 0;

    if (perm & IA64_TLB_R) {
        prot |= PAGE_READ;
    }
    if (perm & IA64_TLB_W) {
        prot |= PAGE_WRITE;
    }
    if (perm & IA64_TLB_X) {
        prot |= PAGE_EXEC;
    }
    return prot;
}

static int ia64_tlb_prot_for_pte_psr(uint64_t pte, uint8_t perm,
                                     bool is_ifetch, uint64_t psr)
{
    int prot = ia64_tlb_perm_to_prot(perm);

    /*
     * QEMU's software TLB may satisfy later accesses without re-entering
     * tlb_fill.  Do not cache write permission for a clean IA-64 PTE: a
     * later store must take Data Dirty so the OS can update the PTE or break
     * copy-on-write sharing.
     */
    if (!is_ifetch && !(psr & IA64_PSR_DA)) {
        if (!(pte & IA64_PTE_ACCESSED)) {
            prot &= ~(PAGE_READ | PAGE_WRITE);
        }
        if (!(pte & IA64_PTE_DIRTY)) {
            prot &= ~PAGE_WRITE;
        }
    } else if (is_ifetch && !(psr & IA64_PSR_IA) &&
               !(pte & IA64_PTE_ACCESSED)) {
        prot &= ~PAGE_EXEC;
    }

    return prot;
}

static int ia64_tlb_prot_for_pte(CPUIA64State *env, uint64_t pte,
                                 uint8_t perm, bool is_ifetch)
{
    return ia64_tlb_prot_for_pte_psr(pte, perm, is_ifetch, env->psr);
}

static void ia64_record_suppressed_tlb_fill(CPUIA64State *env, vaddr addr,
                                             int mmu_idx)
{
    uint64_t page = addr & TARGET_PAGE_MASK;
    uint16_t idxmap = 1u << mmu_idx;
    uint8_t i;

    for (i = 0; i < env->suppressed_tlb_count; i++) {
        if (env->suppressed_tlb_pages[i] == page) {
            env->suppressed_tlb_idxmaps[i] |= idxmap;
            return;
        }
    }

    if (env->suppressed_tlb_count == IA64_SUPPRESSED_TLB_MAX) {
        env->suppressed_tlb_overflow = true;
        return;
    }

    i = env->suppressed_tlb_count++;
    env->suppressed_tlb_pages[i] = page;
    env->suppressed_tlb_idxmaps[i] = idxmap;
}

static void ia64_record_suppressed_tlb_fill_if_needed(
    CPUIA64State *env, vaddr addr, int mmu_idx, uint64_t pte, uint8_t perm,
    bool is_ifetch, int prot)
{
    uint64_t unsuppressed_psr = env->psr & ~(IA64_PSR_DA | IA64_PSR_IA);
    int unsuppressed_prot;

    if (!(env->psr & (IA64_PSR_DA | IA64_PSR_IA))) {
        return;
    }

    unsuppressed_prot = ia64_tlb_prot_for_pte_psr(
        pte, perm, is_ifetch, unsuppressed_psr);
    if (prot != unsuppressed_prot) {
        ia64_record_suppressed_tlb_fill(env, addr, mmu_idx);
    }
}

void ia64_flush_suppressed_tlb(CPUIA64State *env)
{
    CPUState *cs = env_cpu(env);
    uint8_t i;

    if (env->suppressed_tlb_overflow) {
        tlb_flush(cs);
    } else {
        for (i = 0; i < env->suppressed_tlb_count; i++) {
            tlb_flush_page_by_mmuidx(cs, env->suppressed_tlb_pages[i],
                                     env->suppressed_tlb_idxmaps[i]);
        }
    }

    env->suppressed_tlb_count = 0;
    env->suppressed_tlb_overflow = false;
}

static void ia64_tlb_set_entry_page(CPUState *cs, vaddr addr, hwaddr pa,
                                    uint64_t page_size, int prot, int mmu_idx,
                                    IA64MemorySpeculation speculation,
                                    uint8_t memory_attribute)
{
    CPUTLBEntryFull full = {
        .phys_addr = pa & TARGET_PAGE_MASK,
        .attrs = MEMTXATTRS_UNSPECIFIED,
        .prot = prot,
        .lg_page_size = TARGET_PAGE_BITS,
    };

    (void)page_size;
    full.extra.ia64.speculation = speculation;
    full.extra.ia64.memory_attribute = memory_attribute;
    tlb_set_page_full(cs, mmu_idx, addr & TARGET_PAGE_MASK, &full);
}

static hwaddr ia64_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    const IA64TlbEntry *entry;
    uint64_t pa;
    uint8_t perm;
    uint32_t rid;

    if (!(cpu->env.psr & IA64_PSR_IT)) {
        return addr;
    }

    if (ia64_firmware_identity_pa(cpu->env.cr_iva, addr, cpu->env.psr,
                                  addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }

    if (ia64_sal_boot_virtual_pa(&cpu->env, addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }

    rid = ia64_region_rid(&cpu->env, addr);
    entry = ia64_tlb_find_cached(&cpu->env, addr, rid, true);
    if (entry) {
        ia64_tlb_entry_translate(entry, addr, ia64_psr_cpl(cpu->env.psr),
                                 &pa, &perm);
        return pa & TARGET_PAGE_MASK;
    }
    if (ia64_sal_boot_identity_pa(&cpu->env, addr, &pa)) {
        return pa & TARGET_PAGE_MASK;
    }
    return addr;
}

static bool ia64_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                              MMUAccessType access_type, int mmu_idx,
                              bool probe, uintptr_t retaddr)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    bool is_ifetch = (access_type == MMU_INST_FETCH);
    uint8_t needed = is_ifetch ? IA64_TLB_X :
                     (access_type == MMU_DATA_STORE ? IA64_TLB_W :
                      IA64_TLB_R);
    uint64_t pa;
    uint8_t perm;
    uint32_t rid;
    IA64Exception excp;
    bool is_rse = !is_ifetch && mmu_idx == MMU_IDX_RSE;
    uint8_t access_level;
    bool virt_translation_enabled;

    rid = ia64_region_rid(&cpu->env, addr);
    if (mmu_idx == MMU_PHYS_IDX) {
        if (!ia64_pa_is_implemented(addr)) {
            if (probe) {
                return false;
            }
            excp = is_ifetch ? IA64_EXCP_UNIMPL_INST_ADDR :
                   IA64_EXCP_UNIMPL_DATA_ADDR;
            if (is_ifetch) {
                cpu->env.ip = ia64_pa_canonicalize(addr);
            }
            goto raise_exception;
        }
        pa = ia64_physical_address(addr);
        ia64_tlb_set_entry_page(
            cs, addr, pa, TARGET_PAGE_SIZE,
            PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx,
            (addr & IA64_PHYS_UC_BIT) ? IA64_MEM_NON_SPECULATIVE :
                                       IA64_MEM_LIMITED_SPECULATION,
            (addr & IA64_PHYS_UC_BIT) ? 4 : 0);
        return true;
    }

    if (is_rse) {
        access_level = ia64_rsc_pl(cpu->env.ar_rsc);
    } else {
        g_assert(mmu_idx >= MMU_IDX_VIRT_CPL0 &&
                 mmu_idx <= MMU_IDX_VIRT_CPL3);
        access_level = mmu_idx - MMU_IDX_VIRT_CPL0;
    }

    /* A translated MMU index is itself the serialized translation state. */
    virt_translation_enabled = true;
    if (virt_translation_enabled && !ia64_va_is_implemented(addr)) {
        if (probe) {
            return false;
        }
        excp = is_ifetch ? IA64_EXCP_UNIMPL_INST_ADDR :
               IA64_EXCP_UNIMPL_DATA_ADDR;
        if (is_ifetch) {
            cpu->env.ip = ia64_va_canonicalize(addr);
        }
        goto raise_exception;
    }

    if (ia64_firmware_identity_pa(cpu->env.cr_iva,
                                  is_ifetch ? addr : cpu->env.ip,
                                  cpu->env.psr, addr, &pa)) {
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        ia64_tlb_set_entry_page(cs, addr, pa, TARGET_PAGE_SIZE, prot,
                                mmu_idx, IA64_MEM_SPECULATIVE, 0);
        return true;
    }

    if (ia64_sal_boot_virtual_pa(&cpu->env, addr, &pa)) {
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 firmware identity %c va=0x%016" PRIx64
                      " pa=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' :
                      (access_type == MMU_DATA_STORE ? 'w' : 'd'),
                      (uint64_t)addr, pa, cpu->env.psr);
        ia64_tlb_set_entry_page(cs, addr, pa, TARGET_PAGE_SIZE, prot,
                                mmu_idx, IA64_MEM_SPECULATIVE, 0);
        return true;
    }

    {
        const IA64TlbEntry *entry = ia64_tlb_find_cached(
            &cpu->env, addr, rid, is_ifetch);

        if (entry) {
            int prot;
            IA64Exception pte_excp;

            ia64_tlb_entry_translate(entry, addr, access_level, &pa, &perm);
            pte_excp = ia64_tlb_exception_for_access(
                &cpu->env, entry, perm, needed, is_ifetch,
                access_type == MMU_DATA_STORE, is_rse);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_prot_for_pte(&cpu->env, entry->pte, perm,
                                         is_ifetch);
            ia64_record_suppressed_tlb_fill_if_needed(
                &cpu->env, addr, mmu_idx, entry->pte, perm, is_ifetch, prot);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 tlb hit %c va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x\n",
                          is_ifetch ? 'i' : 'd', (uint64_t)addr, rid, pa,
                          perm);
            ia64_tlb_set_entry_page(
                cs, addr, pa, entry->ps, prot, mmu_idx,
                ia64_pte_memory_speculation(entry->pte),
                (entry->pte >> 2) & 7);
            return true;
        }
    }

    if (!is_ifetch) {
        const IA64TlbEntry *new_entry;
        uint64_t pte = 0;
        uint32_t key = 0;

        if (ia64_vhpt_walk_full(&cpu->env, addr, rid, false, is_rse,
                                access_level, &pa, &perm, &pte, &key,
                                &new_entry)) {
            int prot;
            IA64Exception pte_excp;
            uint64_t page_size = new_entry ? new_entry->ps : TARGET_PAGE_SIZE;

            pte_excp = new_entry ?
                ia64_tlb_exception_for_access(
                    &cpu->env, new_entry, perm, needed, false,
                    access_type == MMU_DATA_STORE, is_rse) :
                ia64_translation_exception_for_access(
                    &cpu->env, pte, key, perm, needed, false,
                    access_type == MMU_DATA_STORE, is_rse);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_prot_for_pte(&cpu->env,
                                         new_entry ? new_entry->pte : pte,
                                         perm, false);
            ia64_record_suppressed_tlb_fill_if_needed(
                &cpu->env, addr, mmu_idx,
                new_entry ? new_entry->pte : pte, perm, false, prot);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt hit d va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x iha=0x%016" PRIx64 "\n",
                          (uint64_t)addr, rid, pa, perm,
                          ia64_vhpt_hash_address(&cpu->env, addr));
            ia64_tlb_set_entry_page(
                cs, addr, pa, page_size, prot, mmu_idx,
                ia64_pte_memory_speculation(new_entry ? new_entry->pte :
                                                        pte),
                ((new_entry ? new_entry->pte : pte) >> 2) & 7);
            return true;
        }
    }

    if (is_ifetch) {
        const IA64TlbEntry *new_entry;
        uint64_t pte = 0;
        uint32_t key = 0;

        if (ia64_vhpt_walk_full(&cpu->env, addr, rid, true, false,
                                access_level, &pa, &perm, &pte, &key,
                                &new_entry)) {
            int prot;
            IA64Exception pte_excp;
            uint64_t page_size = new_entry ? new_entry->ps : TARGET_PAGE_SIZE;

            pte_excp = new_entry ?
                ia64_tlb_exception_for_access(
                    &cpu->env, new_entry, perm, needed, true, false, false) :
                ia64_translation_exception_for_access(
                    &cpu->env, pte, key, perm, needed, true, false, false);
            if (pte_excp != IA64_EXCP_NONE) {
                if (probe) {
                    return false;
                }
                excp = pte_excp;
                goto raise_exception;
            }
            prot = ia64_tlb_prot_for_pte(&cpu->env,
                                         new_entry ? new_entry->pte : pte,
                                         perm, true);
            ia64_record_suppressed_tlb_fill_if_needed(
                &cpu->env, addr, mmu_idx,
                new_entry ? new_entry->pte : pte, perm, true, prot);
            qemu_log_mask(CPU_LOG_MMU,
                          "ia64 vhpt hit i va=0x%016" PRIx64
                          " rid=0x%06" PRIx32 " pa=0x%016" PRIx64
                          " perm=0x%x iha=0x%016" PRIx64 "\n",
                          (uint64_t)addr, rid, pa, perm,
                          ia64_vhpt_hash_address(&cpu->env, addr));
            ia64_tlb_set_entry_page(
                cs, addr, pa, page_size, prot, mmu_idx,
                ia64_pte_memory_speculation(new_entry ? new_entry->pte :
                                                        pte),
                ((new_entry ? new_entry->pte : pte) >> 2) & 7);
            return true;
        }
    }
    if (ia64_sal_boot_identity_pa(&cpu->env, addr, &pa)) {
        int prot = is_ifetch ? PAGE_EXEC : (PAGE_READ | PAGE_WRITE);

        qemu_log_mask(CPU_LOG_MMU,
                      "ia64 sal boot identity %c va=0x%016" PRIx64
                      " pa=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                      is_ifetch ? 'i' :
                      (access_type == MMU_DATA_STORE ? 'w' : 'd'),
                      (uint64_t)addr, pa, cpu->env.psr);
        ia64_tlb_set_entry_page(cs, addr, pa, TARGET_PAGE_SIZE, prot,
                                mmu_idx, IA64_MEM_SPECULATIVE, 0);
        return true;
    }
    if (probe) {
        return false;
    }

    {
        uint64_t vhpt_entry_va;
        uint8_t vhpt_size;
        bool vhpt_long_format;
        bool vhpt_enabled = ia64_vhpt_walker_enabled(&cpu->env, addr,
                                                     is_ifetch, is_rse,
                                                     &vhpt_size,
                                                     &vhpt_long_format);

        if (!is_ifetch && ia64_data_nested_tlb_active(&cpu->env)) {
            excp = IA64_EXCP_DATA_NESTED_TLB;
        } else if (vhpt_enabled &&
                   ia64_vhpt_pte_not_present(&cpu->env, addr, is_ifetch,
                                             is_rse, &vhpt_entry_va)) {
            excp = IA64_EXCP_PAGE_NOT_PRESENT;
        } else if (!ia64_vhpt_entry_accessible(&cpu->env, addr, is_ifetch,
                                               is_rse, &vhpt_entry_va)) {
            excp = IA64_EXCP_VHPT_FAULT;
        } else if (vhpt_enabled) {
            excp = is_ifetch ? IA64_EXCP_ITLB_FAULT : IA64_EXCP_DTLB_FAULT;
        } else {
            excp = is_ifetch ? IA64_EXCP_ALT_ITLB : IA64_EXCP_ALT_DTLB;
        }
    }
raise_exception:
    if (is_ifetch && excp == IA64_EXCP_PAGE_NOT_PRESENT &&
        (cpu->env.psr & IA64_PSR_IC)) {
        /*
         * IIP receives IP on interruption entry, and for faults it must point
         * at the faulting instruction bundle when interruption collection is
         * enabled.  Instruction fetch page-not-present faults may be raised
         * while looking up the next TB, before env->ip has otherwise advanced
         * to the fetched bundle.
         */
        cpu->env.ip = ia64_ip_bundle_addr(addr);
    }
    /*
     * IPSR.ri must name the slot execution resumes at.  PSR.ri holds
     * the current slot for data references and, for instruction
     * fetches, the slot the fetch will resume at (0 after a branch;
     * the interrupted slot when refetching after an rfi).  Without
     * this, an instruction-fetch fault would reuse a stale fault_slot
     * and the handler's rfi would skip slots of the target bundle.
     */
    cpu->env.fault_slot =
        (cpu->env.psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT;
    if (cpu->env.psr & IA64_PSR_IC) {
        cpu->env.cr_ifa = addr;
        if (ia64_exception_initializes_iha(excp)) {
            cpu->env.cr_iha = ia64_vhpt_hash_address(&cpu->env, addr);
        }
        cpu->env.cr_itir = ia64_region_itir(
            &cpu->env, excp == IA64_EXCP_VHPT_FAULT ? cpu->env.cr_iha : addr);
    }
    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        if (excp == IA64_EXCP_UNIMPL_DATA_ADDR) {
            cpu->env.cr_isr = IA64_GENEX_UNIMPL_DATA_ADDR |
                              (access_type == MMU_DATA_STORE ?
                               IA64_ISR_W : IA64_ISR_R);
        } else if (excp == IA64_EXCP_UNIMPL_INST_ADDR) {
            cpu->env.cr_isr = IA64_GENEX_UNIMPL_INST_ADDR | IA64_ISR_X;
        } else {
            cpu->env.cr_isr = is_ifetch ? IA64_ISR_X :
                              (access_type == MMU_DATA_STORE ? IA64_ISR_W :
                               IA64_ISR_R);
            if (excp == IA64_EXCP_NAT_CONSUMPTION) {
                /*
                 * NaT Page Consumption reports ISR.code{5:4} = 2; the
                 * non-access code in ISR.code{3:0} is zero for an access.
                 */
                cpu->env.cr_isr |= IA64_ISR_CODE_NAT_PAGE;
            }
        }
        if (is_rse) {
            cpu->env.cr_isr |= IA64_ISR_RS;
            if (cpu->env.rse_dirty < 0 || cpu->env.rse_dirty_nat < 0) {
                /* Mandatory load for an incomplete frame (SDM 6.8). */
                cpu->env.cr_isr |= IA64_ISR_IR;
            }
        } else if (!is_ifetch && excp != IA64_EXCP_NAT_CONSUMPTION &&
                   ia64_current_code_tlb_ed(&cpu->env)) {
            /* NaT Page Consumption always reports ISR.ed as 0. */
            cpu->env.cr_isr |= IA64_ISR_ED;
        }
    }
    qemu_log_mask(CPU_LOG_MMU,
                  "ia64 tlb miss %c va=0x%016" PRIx64
                  " rid=0x%06" PRIx32 " ps=0x%016" PRIx64
                  " iha=0x%016" PRIx64 " pta=0x%016" PRIx64
                  " isr=0x%016" PRIx64 "\n",
                  is_ifetch ? 'i' :
                  (access_type == MMU_DATA_STORE ? 'w' : 'r'),
                  (uint64_t)addr, rid, cpu->env.cr_itir,
                  cpu->env.cr_iha, cpu->env.cr_pta, cpu->env.cr_isr);
    cs->exception_index = excp;
    cpu_loop_exit_restore(cs, retaddr);
}

static bool ia64_exception_writes_ifa(IA64Exception excp)
{
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_ACCESS:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_INST_KEY_MISS:
    case IA64_EXCP_DATA_KEY_MISS:
    case IA64_EXCP_KEY_PERMISSION:
    case IA64_EXCP_DATA_DIRTY:
    case IA64_EXCP_INST_ACCESS_BIT:
    case IA64_EXCP_DATA_ACCESS_BIT:
    case IA64_EXCP_NAT_CONSUMPTION:
    case IA64_EXCP_UNALIGNED:
    case IA64_EXCP_UNSUPPORTED_DATA_REFERENCE:
    case IA64_EXCP_PAGE_NOT_PRESENT:
    case IA64_EXCP_UNIMPL_DATA_ADDR:
        return true;
    default:
        return false;
    }
}

#define IA64_PSR_INTERRUPTION_PRESERVED_MASK \
    (IA64_PSR_UP | IA64_PSR_MFL | IA64_PSR_MFH | IA64_PSR_PK | \
     IA64_PSR_DT | IA64_PSR_RT | IA64_PSR_MC | IA64_PSR_IT)

static uint64_t ia64_interruption_psr(CPUIA64State *env)
{
    uint64_t psr = env->psr & IA64_PSR_INTERRUPTION_PRESERVED_MASK;

    if (env->cr_dcr & IA64_DCR_BE) {
        psr |= IA64_PSR_BE;
    }
    if (env->cr_dcr & IA64_DCR_PP) {
        psr |= IA64_PSR_PP;
    }

    return psr;
}

static void ia64_deliver_exception(CPUState *cs, IA64Exception excp,
                                   uint64_t fault_addr, uint8_t slot)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    uint64_t vector;
    uint64_t isr_status = 0;
    bool psr_ic_inflight;
    bool collect;

    if (excp >= IA64_EXCP_MAX || excp == IA64_EXCP_NONE) {
        return;
    }

    vector = ia64_ivt_vectors[excp];
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_NESTED_TLB:
    case IA64_EXCP_DATA_ACCESS:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_INST_KEY_MISS:
    case IA64_EXCP_DATA_KEY_MISS:
    case IA64_EXCP_KEY_PERMISSION:
    case IA64_EXCP_DATA_DIRTY:
    case IA64_EXCP_INST_ACCESS_BIT:
    case IA64_EXCP_DATA_ACCESS_BIT:
    case IA64_EXCP_NAT_CONSUMPTION:
    case IA64_EXCP_UNALIGNED:
    case IA64_EXCP_UNSUPPORTED_DATA_REFERENCE:
    case IA64_EXCP_PAGE_NOT_PRESENT:
    case IA64_EXCP_UNIMPL_DATA_ADDR:
    case IA64_EXCP_UNIMPL_INST_ADDR:
    case IA64_EXCP_PRIVILEGED_OP:
    case IA64_EXCP_PRIVILEGED_REG:
    case IA64_EXCP_RESERVED_REG_FIELD:
    case IA64_EXCP_FP_FAULT:
    case IA64_EXCP_FP_TRAP:
    case IA64_EXCP_DISABLED_ISA_TRANSITION:
    case IA64_EXCP_DISABLED_FP:
        isr_status = cpu->env.cr_isr;
        break;
    default:
        break;
    }
    qemu_log_mask(CPU_LOG_INT,
                  "ia64 exception excp=%u vector=0x%04x ip=0x%016" PRIx64
                  " fault=0x%016" PRIx64 " slot=%u psr=0x%016" PRIx64
                  " ifa=0x%016" PRIx64 " isr=0x%016" PRIx64 "\n",
                  excp, ia64_ivt_vectors[excp], cpu->env.ip, fault_addr,
                  slot, cpu->env.psr, cpu->env.cr_ifa, cpu->env.cr_isr);
    psr_ic_inflight = cpu->env.psr_ic_inflight;
    collect = cpu->env.psr & IA64_PSR_IC;

    /*
     * An interruption is an instruction serialization operation and also
     * performs data serialization (SDM Vol. 2, 3.1.4).  Complete any TLB
     * purges before the handler can make instruction or data references.
     */
    ia64_flush_suppressed_tlb(&cpu->env);
    cpu->env.psr_suppression_before_insn = 0;
    helper_tlb_serialize(&cpu->env, 1, 1);

    if (collect) {
        cpu->env.cr_ipsr = (cpu->env.psr & ~IA64_PSR_RI_MASK) |
                           (((uint64_t)slot & 3) << IA64_PSR_RI_SHIFT);
        cpu->env.cr_iip = ia64_ip_bundle_addr(cpu->env.ip);
        if (ia64_exception_writes_ifa(excp)) {
            cpu->env.cr_ifa = fault_addr;
        }
        cpu->env.cr_iipa = excp == IA64_EXCP_FP_TRAP ?
                           cpu->env.fault_imm :
                           cpu->env.last_successful_bundle;
        /*
         * A collected interruption records the interrupted IP/PSR and clears
         * IFS.v.  The interrupted frame remains current until the handler
         * executes cover, which then copies CFM into IFS.ifm.
         */
        cpu->env.cr_ifs = 0;

        if (excp == IA64_EXCP_BREAK) {
            cpu->env.cr_iim = cpu->env.fault_imm;
        }
    }

    if (excp != IA64_EXCP_DATA_NESTED_TLB) {
        cpu->env.cr_isr = isr_status;
        if (slot > 0) {
            cpu->env.cr_isr |= ((uint64_t)slot & 3) << IA64_ISR_EI_SHIFT;
        }
        if (!collect || psr_ic_inflight) {
            cpu->env.cr_isr |= IA64_ISR_NI;
        }
    }
    ia64_rse_delivery_check(&cpu->env, excp);
    ia64_firmware_debug_capture(&cpu->env, vector, collect);
    /*
     * Interruption delivery clears RSE.CFLE (SDM Vol.2 6.6): the
     * handler runs with the (possibly incomplete) interrupted frame,
     * which is completed by cover or by an rfi resuming the loads.
     */
    cpu->env.rse_cfle = false;
    ia64_set_psr(&cpu->env, ia64_interruption_psr(&cpu->env));
    cpu->env.psr_ic_inflight = false;

    cpu->env.ip = (cpu->env.cr_iva & ~0x7fffULL) | vector;
    cpu->env.instruction_group_start = true;
    if (excp == IA64_EXCP_EXTINT) {
        cs->halted = 0;
    }

    cpu->env.exception = 0;
    cpu->env.pending_extint = 0;
}

static bool ia64_debug_read_code(CPUState *cs, uint64_t addr, void *buf,
                                 size_t size)
{
    return cpu_memory_rw_debug(cs, addr, buf, size, false) == 0;
}

static bool ia64_firmware_data_access(CPUIA64State *env, uint64_t addr,
                                      void *buf, size_t size, bool is_write)
{
    uint64_t pa;

    if (!ia64_translate_data_access(env, addr, is_write, &pa)) {
        return false;
    }
    return address_space_rw(&address_space_memory, pa,
                            MEMTXATTRS_UNSPECIFIED, buf, size,
                            is_write) == MEMTX_OK;
}

static void ia64_resume_after_instruction(CPUIA64State *env, uint64_t ip,
                                          uint8_t slot)
{
    env->psr &= ~IA64_PSR_RI_MASK;
    if (slot >= 2) {
        env->ip = ip + 16;
    } else {
        env->ip = ip;
        env->psr |= (uint64_t)(slot + 1) << IA64_PSR_RI_SHIFT;
    }
}

static void ia64_gr_nat_clear_runtime(CPUIA64State *env, uint8_t reg)
{
    if (reg == 0) {
        return;
    }

    env->nat[reg / 64] &= ~(1ULL << (reg % 64));
    ia64_rse_mark_gr_dirty(env, reg);
}

static bool ia64_gr_nat_get_runtime(CPUIA64State *env, uint8_t reg)
{
    if (reg == 0) {
        return false;
    }

    return (env->nat[reg / 64] >> (reg % 64)) & 1;
}

static void ia64_gr_nat_set_runtime(CPUIA64State *env, uint8_t reg, bool nat)
{
    if (reg == 0) {
        return;
    }

    if (nat) {
        env->nat[reg / 64] |= 1ULL << (reg % 64);
    } else {
        env->nat[reg / 64] &= ~(1ULL << (reg % 64));
    }
    ia64_rse_mark_gr_dirty(env, reg);
}

static void ia64_unaligned_base_update(CPUIA64State *env,
                                       const Ia64Instruction *insn,
                                       uint64_t addr)
{
    if (insn->r3 == 0) {
        return;
    }

    if (insn->reg_base_update) {
        bool base_nat = ia64_gr_nat_get_runtime(env, insn->r3);
        bool inc_nat = ia64_gr_nat_get_runtime(env, insn->r2);

        env->gr[insn->r3] = addr + env->gr[insn->r2];
        ia64_gr_nat_set_runtime(env, insn->r3, base_nat || inc_nat);
    } else if (insn->imm_base_update) {
        env->gr[insn->r3] = addr + insn->imm;
    }
}

static void ia64_firmware_defer_speculative_load(CPUIA64State *env,
                                                 const Ia64Instruction *insn)
{
    if (insn->r1 != 0) {
        env->gr[insn->r1] = 0;
        ia64_gr_nat_set_runtime(env, insn->r1, true);
    }
    if (env->alat_full &&
        ia64_opcode_is_data_speculative_load(insn->opcode)) {
        helper_invalidate_alat_reg(env, insn->r1);
    }
}

static bool ia64_try_emulate_firmware_unaligned(CPUState *cs,
                                                uint64_t fault_addr,
                                                uint8_t fault_slot)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;
    uint8_t bundle[16];
    uint8_t data[16];
    uint64_t low, high;
    uint8_t template_code;
    const IA64TemplateInfo *template_info;
    Ia64Instruction insn;
    uint64_t slots[3];
    uint64_t addr;
    MemOp memop;
    uint32_t size;

    /*
     * Model the SAL/firmware IVT's unaligned assist only before the guest has
     * installed its own IVA.  Page-spanning and semaphore references remain
     * architectural faults.
     */
    if (env->cr_iva != IA64_FIRMWARE_IVT_BASE ||
        !(env->psr & IA64_PSR_IC) ||
        fault_slot > 2) {
        return false;
    }

    if (!ia64_debug_read_code(cs, env->fault_ip, bundle, sizeof(bundle))) {
        return false;
    }

    low = ldq_le_p(bundle);
    high = ldq_le_p(bundle + 8);
    template_code = ia64_bundle_template_code(low);
    template_info = ia64_template_info(template_code);
    if (!template_info->defined) {
        return false;
    }

    slots[0] = ia64_bundle_slot(low, high, 0);
    slots[1] = ia64_bundle_slot(low, high, 1);
    slots[2] = ia64_bundle_slot(low, high, 2);
    insn = ia64_decode_insn((Ia64SlotUnit)template_info->units[fault_slot],
                            slots[fault_slot], env->fault_ip, fault_slot);
    if (!insn.valid) {
        return false;
    }

    if (ia64_opcode_has_firmware_unaligned_load_assist(insn.opcode)) {
        bool check_load_clear = ia64_opcode_is_check_load_clear(insn.opcode);
        bool check_load_no_clear =
            ia64_opcode_is_check_load_no_clear(insn.opcode);

        memop = ia64_memop_with_endian(
            ia64_memop_for_opcode(insn.opcode),
            (env->psr & IA64_PSR_BE) != 0);
        size = ia64_memop_size(memop);
        addr = env->gr[insn.r3];
        if (addr != fault_addr || ((addr & 0xfff) + size - 1) > 0xfff) {
            return false;
        }

        if (ia64_opcode_is_control_speculative_load(insn.opcode) &&
            (env->cr_isr & IA64_ISR_SP) &&
            (env->cr_isr & IA64_ISR_ED)) {
            ia64_firmware_defer_speculative_load(env, &insn);
            ia64_unaligned_base_update(env, &insn, addr);
            ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
            env->exception = IA64_EXCP_NONE;
            return true;
        }

        /*
         * IA-64 SDM Vol. 2, 17.3.1 requires unaligned handlers to force
         * failed data-speculative loads; ALAT cannot track all misalignment
         * sizes for later store-conflict checks.
         */
        if (ia64_opcode_is_data_speculative_load(insn.opcode)) {
            helper_invalidate_alat_reg(env, insn.r1);
            ia64_unaligned_base_update(env, &insn, addr);
            ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
            env->exception = IA64_EXCP_NONE;
            return true;
        }

        if (env->alat_full && ia64_opcode_is_check_load(insn.opcode) &&
            helper_check_load_alat_addr(env, insn.r1, addr, size,
                                        check_load_clear)) {
            ia64_unaligned_base_update(env, &insn, addr);
            ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
            env->exception = IA64_EXCP_NONE;
            return true;
        }

        if (size > sizeof(data) ||
            !ia64_firmware_data_access(env, addr, data, size, false)) {
            return false;
        }
        if (insn.r1 != 0) {
            env->gr[insn.r1] = ldm_p(data, memop);
            if (ia64_opcode_is_fill_load(insn.opcode)) {
                uint64_t nat = (env->ar_unat >> ((addr >> 3) & 0x3f)) & 1;

                if (nat) {
                    ia64_gr_nat_set_runtime(env, insn.r1, true);
                } else {
                    ia64_gr_nat_clear_runtime(env, insn.r1);
                }
            } else {
                ia64_gr_nat_clear_runtime(env, insn.r1);
                if (check_load_no_clear && env->alat_full) {
                    helper_set_alat(env, insn.r1, addr, size);
                }
            }
        }
        ia64_unaligned_base_update(env, &insn, addr);
        ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
        env->exception = IA64_EXCP_NONE;
        return true;
    }

    if (ia64_opcode_has_firmware_unaligned_store_assist(insn.opcode)) {
        memop = ia64_memop_with_endian(
            ia64_memop_for_opcode(insn.opcode),
            (env->psr & IA64_PSR_BE) != 0);
        size = ia64_memop_size(memop);
        addr = env->gr[insn.r3];
        if (addr != fault_addr ||
            ((addr & 0xfff) + size - 1) > 0xfff ||
            size > sizeof(data)) {
            return false;
        }

        stm_p(data, memop, env->gr[insn.r2]);
        if (!ia64_firmware_data_access(env, addr, data, size, true)) {
            return false;
        }
        if (env->alat_full) {
            helper_invalidate_alat_store(env, addr, size);
        }
        if (insn.opcode == IA64_OP_ST8SPILL) {
            helper_st_spill_unat(env, insn.r2, addr);
        }
        ia64_unaligned_base_update(env, &insn, addr);
        ia64_resume_after_instruction(env, env->fault_ip, fault_slot);
        env->exception = IA64_EXCP_NONE;
        return true;
    }

    return false;
}

static bool ia64_exception_is_translation_fault(IA64Exception excp)
{
    switch (excp) {
    case IA64_EXCP_VHPT_FAULT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_DTLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_ALT_DTLB:
    case IA64_EXCP_DATA_NESTED_TLB:
        return true;
    default:
        return false;
    }
}

static bool ia64_exception_uses_psr_ri_slot(IA64Exception excp, uint64_t isr)
{
    switch (excp) {
    case IA64_EXCP_EXTINT:
    case IA64_EXCP_ITLB_FAULT:
    case IA64_EXCP_ALT_ITLB:
    case IA64_EXCP_INST_ACCESS:
    case IA64_EXCP_INST_ACCESS_BIT:
    case IA64_EXCP_UNIMPL_INST_ADDR:
        return true;
    case IA64_EXCP_PAGE_NOT_PRESENT:
        return isr & IA64_ISR_X;
    default:
        return false;
    }
}

static void ia64_cpu_do_interrupt(CPUState *cs)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    int excp = cs->exception_index;
    uint64_t fault_addr;
    uint8_t slot;

    if (excp == IA64_EXCP_NONE) {
        return;
    }
    cpu->env.fault_exception = excp;

    if (!(cpu->env.psr & IA64_PSR_IC) &&
        !ia64_exception_is_translation_fault(excp) &&
        cpu->env.cr_iva == 0 &&
        (excp == IA64_EXCP_BREAK ||
         excp == IA64_EXCP_ILLEGAL ||
         excp == IA64_EXCP_RESERVED_TEMPLATE ||
         excp == IA64_EXCP_PRIVILEGED_OP ||
         excp == IA64_EXCP_PRIVILEGED_REG ||
         excp == IA64_EXCP_RESERVED_REG_FIELD ||
         excp == IA64_EXCP_DISABLED_ISA_TRANSITION ||
         excp == IA64_EXCP_DISABLED_FP)) {
        /*
         * Bare loader tests have no IVT.  Keep decoder/sentinel faults at
         * the faulting bundle for inspection, and use break as a monitor stop.
         * Other faults may deliberately target a handler at IVA-relative
         * vectors, even when IVA is zero.
         */
        if (excp == IA64_EXCP_BREAK) {
            cs->halted = 1;
            cs->exception_index = IA64_EXCP_NONE;
        } else {
            cpu->env.ip = cpu->env.fault_ip;
        }
        return;
    }

    fault_addr = cpu->env.cr_ifa;
    switch (excp) {
    case IA64_EXCP_BREAK:
    case IA64_EXCP_ILLEGAL:
    case IA64_EXCP_RESERVED_TEMPLATE:
    case IA64_EXCP_PRIVILEGED_OP:
    case IA64_EXCP_PRIVILEGED_REG:
    case IA64_EXCP_RESERVED_REG_FIELD:
    case IA64_EXCP_FP_FAULT:
    case IA64_EXCP_FP_TRAP:
    case IA64_EXCP_DISABLED_ISA_TRANSITION:
    case IA64_EXCP_DISABLED_FP:
        fault_addr = cpu->env.fault_ip;
        break;
    case IA64_EXCP_UNIMPL_INST_ADDR:
        cpu->env.ip = cpu->env.psr & IA64_PSR_IT ?
                      ia64_va_canonicalize(cpu->env.ip) :
                      ia64_pa_canonicalize(cpu->env.ip);
        fault_addr = cpu->env.ip;
        break;
    case IA64_EXCP_EXTINT:
        break;
    default:
        break;
    }
    slot = cpu->env.fault_slot;
    if (ia64_exception_uses_psr_ri_slot(excp, cpu->env.cr_isr)) {
        slot = (cpu->env.psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT;
    }
    if (ia64_psr_cpl(cpu->env.psr) == 3 &&
        excp != IA64_EXCP_EXTINT) {
        uint64_t cfm =
            cpu->env.cfm_sof |
            ((uint64_t)cpu->env.cfm_sol << IA64_CFM_SOL_SHIFT) |
            ((uint64_t)cpu->env.cfm_sor << IA64_CFM_SOR_SHIFT) |
            ((uint64_t)cpu->env.cfm_rrb_gr << IA64_CFM_RRB_GR_SHIFT) |
            ((uint64_t)cpu->env.cfm_rrb_fr << IA64_CFM_RRB_FR_SHIFT) |
            ((uint64_t)cpu->env.cfm_rrb_pr << IA64_CFM_RRB_PR_SHIFT);

        /* RSE debug scaffolding: user-mode fault register dump (opt-in via
         * -d int only; de-escalated from LOG_GUEST_ERROR to avoid spam). */
        qemu_log_mask(CPU_LOG_INT,
                      "ia64 user exception excp=%d ip=%016" PRIx64
                      " fault=%016" PRIx64 " slot=%u psr=%016" PRIx64
                      " isr=%016" PRIx64 " bsp=%016" PRIx64
                      " bspstore=%016" PRIx64 " rsc=%016" PRIx64
                      " cfm=%016" PRIx64 " r1=%016" PRIx64
                      " r14=%016" PRIx64 " r15=%016" PRIx64
                      " r16=%016" PRIx64 " r32=%016" PRIx64
                      " r33=%016" PRIx64 "\n",
                      excp, cpu->env.ip, fault_addr, slot, cpu->env.psr,
                      cpu->env.cr_isr, cpu->env.ar_bsp,
                      cpu->env.ar_bspstore, cpu->env.ar_rsc, cfm,
                      cpu->env.gr[1], cpu->env.gr[14], cpu->env.gr[15],
                      cpu->env.gr[16], cpu->env.gr[32], cpu->env.gr[33]);

    }

    if (excp == IA64_EXCP_UNALIGNED &&
        ia64_try_emulate_firmware_unaligned(cs, fault_addr, slot)) {
        cs->exception_index = IA64_EXCP_NONE;
        return;
    }

    if (excp == IA64_EXCP_EXTINT) {
        if (sapic_find_irr(&cpu->env) != IA64_SPURIOUS_VECTOR) {
            ia64_deliver_exception(cs, excp, fault_addr, slot);
            cpu->env.pending_extint = 0;
        }
    } else {
        ia64_deliver_exception(cs, excp, fault_addr, slot);
    }
    cs->exception_index = IA64_EXCP_NONE;
}

static bool ia64_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    /*
     * While RSE.CFLE is set, instruction execution is stalled until
     * the mandatory RSE loads complete (SDM Vol.2 6.6).  This
     * implementation performs the whole load sequence without
     * accepting external interrupts (SDM Vol.2 6.7 permits, but does
     * not require, mandatory sequences to be interruptible), and it
     * extends the same deferral to any state in which the current
     * frame is still incomplete (SDM Vol.2 6.8): after a mandatory
     * load faults, the frame stays incomplete until the handler
     * executes cover or an rfi resumes the loads, and delivering an
     * asynchronous interrupt on top of a partially materialized frame
     * would let the nested handler spill registers that were never
     * loaded.
     */
    bool rse_frame_complete = !cpu->env.rse_cfle &&
        cpu->env.rse_dirty >= 0 && cpu->env.rse_dirty_nat >= 0;

    if ((interrupt_request & CPU_INTERRUPT_HARD) &&
        ((cpu->env.psr & IA64_PSR_I) ||
         (cpu->env.sapic_irr[0] & (1ULL << 2))) &&
        ia64_sapic_has_pending(&cpu->env) &&
        rse_frame_complete) {
        cs->exception_index = IA64_EXCP_EXTINT;
        ia64_cpu_do_interrupt(cs);
        return true;
    }
    return false;
}

static void ia64_cpu_reset_hold(Object *obj, ResetType type)
{
    IA64CPUClass *icc = IA64_CPU_GET_CLASS(obj);
    IA64CPU *cpu = IA64_CPU(obj);

    if (icc->parent_phases.hold) {
        icc->parent_phases.hold(obj, type);
    }

    if (cpu->itm_timer != NULL) {
        timer_del(cpu->itm_timer);
    }
    memset(&cpu->env, 0, sizeof(cpu->env));
    cpu->env.alat_full = cpu->alat_full;
    cpu->env.fr[1] = IA64_FR_ONE;
    cpu->env.pr[0] = 1;
    cpu->env.psr = 0;
    cpu->env.ar_rsc = 0;
    /* Empty frame: every stacked physical register is invalid. */
    cpu->env.rse_invalid = IA64_STACKED_GR_COUNT;
    cpu->env.ar_fpsr = IA64_FPSR_DEFAULT;
    cpu->env.cr_iva = 0;
    cpu->env.instruction_group_start = true;
    ia64_itc_write(&cpu->env, 0);
    set_float_2nan_prop_rule(float_2nan_prop_ab, &cpu->env.fp_status);
    set_float_3nan_prop_rule(float_3nan_prop_abc, &cpu->env.fp_status);
    set_float_infzeronan_rule(float_infzeronan_dnan_never, &cpu->env.fp_status);
    set_float_default_nan_pattern(0b01000000, &cpu->env.fp_status);
    cpu->env.cr[IA64_CR_SAPIC_LID] =
        ia64_sapic_lid(MAX(CPU(cpu)->cpu_index, 0), 0);
    cpu->env.cr[IA64_CR_SAPIC_TPR] = 0;
    cpu->env.cr[IA64_CR_ITV] = IA64_VECTOR_MASKED;
    cpu->env.pal_proc_copy_valid = false;
    cpu->env.pal_proc_copy_addr = 0;
    cpu->env.pal_interrupt_block_addr = IA64_LOCAL_SAPIC_PA;
    cpu->env.pal_io_block_addr = IA64_PAL_IO_BLOCK_PA;
}

static ObjectClass *ia64_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc = object_class_by_name(cpu_model);
    char *typename;

    if (oc != NULL && object_class_dynamic_cast(oc, TYPE_IA64_CPU) != NULL) {
        return oc;
    }

    typename = g_strdup_printf(IA64_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    return oc;
}

static void ia64_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    IA64CPU *cpu = IA64_CPU(dev);
    IA64CPUClass *icc = IA64_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    /* Resolve the ia32-exec property: NULL/"stop" => diagnostic stop. */
    if (cpu->ia32_exec == NULL || strcmp(cpu->ia32_exec, "stop") == 0) {
        cpu->ia32_exec_abort = false;
    } else if (strcmp(cpu->ia32_exec, "abort") == 0) {
        cpu->ia32_exec_abort = true;
    } else {
        error_setg(errp, "invalid ia32-exec '%s' (expected 'stop' or 'abort')",
                   cpu->ia32_exec);
        return;
    }

    cpu->itm_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ia64_itm_timer_cb, cpu);

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    icc->parent_realize(dev, errp);
}

static const Property ia64_cpu_properties[] = {
    DEFINE_PROP_STRING("ia32-exec", IA64CPU, ia32_exec),
};

static void ia64_dump_tlb(FILE *f, const char *name, const IA64TlbEntry *tlb,
                          uint16_t count)
{
    uint16_t i;

    for (i = 0; i < count; i++) {
        const IA64TlbEntry *entry = &tlb[i];

        if (!entry->valid) {
            continue;
        }
        qemu_fprintf(f, "%s[%u]%s va=0x%016" PRIx64
                     " pa=0x%016" PRIx64 " ps=0x%016" PRIx64
                     " rid=0x%06" PRIx32 " key=0x%06" PRIx32
                     " ar=%u pl=%u perm=0x%x pte=0x%016" PRIx64 "\n",
                     name, i, entry->is_tr ? " TR" : " TC",
                     entry->va, entry->pa, entry->ps, entry->rid,
                     entry->key, entry->ar, entry->pl, entry->perm,
                     entry->pte);
    }
}

static void ia64_dump_machine_state(CPUState *cs, FILE *f, int flags)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;
    uint64_t pr_mask = 1;
    unsigned i;

    for (i = 1; i < IA64_PR_COUNT; i++) {
        pr_mask |= (env->pr[i] != 0) ? 1ULL << i : 0;
    }

    qemu_fprintf(f, "IA64STATE META ip=%016" PRIx64
                 " psr=%016" PRIx64 " halted=%u\n",
                 env->ip, env->psr, cs->halted ? 1 : 0);
    qemu_fprintf(f, "IA64STATE EXCEPTION code=%016" PRIx64
                 " fault_code=%016" PRIx64
                 " fault_ip=%016" PRIx64 " fault_imm=%016" PRIx64 "\n",
                 (uint64_t)env->exception,
                 (uint64_t)env->fault_exception,
                 env->fault_ip, env->fault_imm);
    qemu_fprintf(f, "IA64STATE GRNAT lo=%016" PRIx64
                 " hi=%016" PRIx64 "\n", env->nat[0], env->nat[1]);

    for (i = 0; i < IA64_GR_COUNT; i++) {
        qemu_fprintf(f, "IA64STATE GR index=%03x value=%016" PRIx64
                     " nat=%u\n", i, i == 0 ? 0 : env->gr[i],
                     (unsigned)((env->nat[i / 64] >> (i % 64)) & 1));
    }
    for (i = 0; i < IA64_BR_COUNT; i++) {
        qemu_fprintf(f, "IA64STATE BR index=%03x value=%016" PRIx64 "\n",
                     i, env->br[i]);
    }

    qemu_fprintf(f, "IA64STATE PR value=%016" PRIx64 "\n", pr_mask);
    qemu_fprintf(f, "IA64STATE AR ccv=%016" PRIx64
                 " unat=%016" PRIx64 " fpsr=%016" PRIx64
                 " csd=%016" PRIx64 " ssd=%016" PRIx64
                 " rsc=%016" PRIx64 " rnat=%016" PRIx64
                 " pfs=%016" PRIx64 "\n",
                 env->ar_ccv, env->ar_unat, env->ar_fpsr,
                 env->ar_csd, env->ar_ssd, env->ar_rsc,
                 env->ar_rnat, env->ar_pfs);
    qemu_fprintf(f, "IA64STATE CFM sof=%016" PRIx64
                 " sol=%016" PRIx64 " sor=%016" PRIx64
                 " rrb_gr=%016" PRIx64 " rrb_fr=%016" PRIx64
                 " rrb_pr=%016" PRIx64 "\n",
                 (uint64_t)env->cfm_sof, (uint64_t)env->cfm_sol,
                 (uint64_t)env->cfm_sor, (uint64_t)env->cfm_rrb_gr,
                 (uint64_t)env->cfm_rrb_fr, (uint64_t)env->cfm_rrb_pr);

    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < IA64_FR_COUNT; i++) {
            uint64_t low;
            uint64_t high;

            ia64_fpreg_to_spill(env, i, &low, &high);
            qemu_fprintf(f, "IA64STATE FR index=%03x low=%016" PRIx64
                         " high=%016" PRIx64 " nat=%u\n",
                         i, low, high,
                         ia64_fpreg_is_nat(env, i) ? 1 : 0);
        }
    }
}

static void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    int i;

    qemu_fprintf(f, "IP: 0x%016" PRIx64 "  PSR: 0x%016" PRIx64
                 "  HALTED: %u\n",
                 cpu->env.ip, cpu->env.psr, cs->halted);
    qemu_fprintf(f, "exception: %" PRIu32 " fault_ip: 0x%016" PRIx64
                 " fault_imm: 0x%016" PRIx64 " fault_tmpl: 0x%016" PRIx64 "\n",
                 cpu->env.exception, cpu->env.fault_ip,
                 cpu->env.fault_imm, cpu->env.fault_tmpl);
    for (i = 0; i < IA64_GR_COUNT; i += 4) {
        qemu_fprintf(f,
                     "r%-3d 0x%016" PRIx64 " r%-3d 0x%016" PRIx64
                     " r%-3d 0x%016" PRIx64 " r%-3d 0x%016" PRIx64 "\n",
                     i, cpu->env.gr[i], i + 1, cpu->env.gr[i + 1],
                     i + 2, cpu->env.gr[i + 2], i + 3,
                     cpu->env.gr[i + 3]);
    }
    for (i = 0; i < 16; i += 4) {
        qemu_fprintf(f,
                     "p%d: %" PRIu64 " p%d: %" PRIu64
                     " p%d: %" PRIu64 " p%d: %" PRIu64 "\n",
                     i, cpu->env.pr[i], i + 1, cpu->env.pr[i + 1],
                     i + 2, cpu->env.pr[i + 2], i + 3,
                     cpu->env.pr[i + 3]);
    }
    qemu_fprintf(f, "b0: 0x%016" PRIx64 " b1: 0x%016" PRIx64
                 " b2: 0x%016" PRIx64 " b3: 0x%016" PRIx64 "\n",
                 cpu->env.br[0], cpu->env.br[1],
                 cpu->env.br[2], cpu->env.br[3]);
    qemu_fprintf(f, "b4: 0x%016" PRIx64 " b5: 0x%016" PRIx64
                 " b6: 0x%016" PRIx64 " b7: 0x%016" PRIx64 "\n",
                 cpu->env.br[4], cpu->env.br[5],
                 cpu->env.br[6], cpu->env.br[7]);
    qemu_fprintf(f, "AR.ITC: 0x%016" PRIx64 " AR.LC: 0x%016" PRIx64
                 " AR.EC: 0x%016" PRIx64 "\n",
                 ia64_itc_read(&cpu->env),
                 cpu->env.ar_lc, cpu->env.ar_ec);
    qemu_fprintf(f, "CR.DCR: 0x%016" PRIx64
                 " CR.ITM: 0x%016" PRIx64 " ITV: 0x%016" PRIx64
                 " TPR: 0x%016" PRIx64 " EOI: 0x%016" PRIx64 "\n",
                 cpu->env.cr_dcr, cpu->env.cr_itm, cpu->env.cr[IA64_CR_ITV],
                 cpu->env.cr[IA64_CR_SAPIC_TPR],
                 cpu->env.cr[IA64_CR_SAPIC_EOI]);
    qemu_fprintf(f, "SAPIC IRR: %016" PRIx64 " %016" PRIx64
                 " %016" PRIx64 " %016" PRIx64 "\n",
                 cpu->env.sapic_irr[0], cpu->env.sapic_irr[1],
                 cpu->env.sapic_irr[2], cpu->env.sapic_irr[3]);
    qemu_fprintf(f, "SAPIC ISR: %016" PRIx64 " %016" PRIx64
                 " %016" PRIx64 " %016" PRIx64 "\n",
                 cpu->env.sapic_isr[0], cpu->env.sapic_isr[1],
                 cpu->env.sapic_isr[2], cpu->env.sapic_isr[3]);
    qemu_fprintf(f, "IIP: 0x%016" PRIx64 " IFA: 0x%016" PRIx64
                 " IPSR: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iip, cpu->env.cr_ifa, cpu->env.cr_ipsr);
    qemu_fprintf(f, "ISR: 0x%016" PRIx64 " IFS: 0x%016" PRIx64
                 " IIM: 0x%016" PRIx64 "\n",
                 cpu->env.cr_isr, cpu->env.cr_ifs, cpu->env.cr_iim);
    qemu_fprintf(f, "IVA: 0x%016" PRIx64 " IIPA: 0x%016" PRIx64
                 " ITIR: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iva, cpu->env.cr_iipa, cpu->env.cr_itir);
    qemu_fprintf(f, "IHA: 0x%016" PRIx64 " PTA: 0x%016" PRIx64
                 " RR0: 0x%016" PRIx64 " RR5: 0x%016" PRIx64
                 " RR6: 0x%016" PRIx64 " RR7: 0x%016" PRIx64 "\n",
                 cpu->env.cr_iha, cpu->env.cr_pta, cpu->env.rr[0],
                 cpu->env.rr[5], cpu->env.rr[6], cpu->env.rr[7]);
    qemu_fprintf(f, "PKR0: 0x%016" PRIx64 " PKR1: 0x%016" PRIx64
                 " PKR2: 0x%016" PRIx64 " PKR3: 0x%016" PRIx64 "\n",
                 cpu->env.pkr[0], cpu->env.pkr[1],
                 cpu->env.pkr[2], cpu->env.pkr[3]);
    qemu_fprintf(f, "CFM: sof=%u sol=%u sor=%u rrb.gr=%u rrb.fr=%u"
                 " rrb.pr=%u AR.PFS=0x%016"
                 PRIx64 " BSP=0x%016" PRIx64 " BSPSTORE=0x%016" PRIx64 "\n",
                 cpu->env.cfm_sof, cpu->env.cfm_sol,
                 cpu->env.cfm_sor, cpu->env.cfm_rrb_gr,
                 cpu->env.cfm_rrb_fr, cpu->env.cfm_rrb_pr,
                 cpu->env.ar_pfs, cpu->env.ar_bsp, cpu->env.ar_bspstore);
    qemu_fprintf(f, "RSE: bol=%u dirty=%d/%d clean=%d/%d invalid=%d"
                 " RNAT=0x%016" PRIx64 " RSC=0x%016" PRIx64 "\n",
                 cpu->env.rse_bol, cpu->env.rse_dirty,
                 cpu->env.rse_dirty_nat, cpu->env.rse_clean,
                 cpu->env.rse_clean_nat, cpu->env.rse_invalid,
                 cpu->env.ar_rnat, cpu->env.ar_rsc);
    ia64_dump_tlb(f, "ITLB", cpu->env.tlb_inst, cpu->env.tlb_inst_count);
    ia64_dump_tlb(f, "DTLB", cpu->env.tlb_data, cpu->env.tlb_data_count);
    ia64_dump_machine_state(cs, f, flags);
}

/*
 * Keep this layout in sync with GDB's regformats/reg-ia64.dat.  IA-64 GDB
 * predates target-description XML and expects this 462-register raw layout.
 * In particular, floating-point registers occupy 128 bits on the wire even
 * though only 82 bits are architecturally significant.
 */
enum {
    IA64_GDB_GR0_REGNUM = 0,
    IA64_GDB_FR0_REGNUM = 128,
    IA64_GDB_PR0_REGNUM = 256,
    IA64_GDB_BR0_REGNUM = 320,
    IA64_GDB_VFP_REGNUM = 328,
    IA64_GDB_VRAP_REGNUM = 329,
    IA64_GDB_PR_REGNUM = 330,
    IA64_GDB_IP_REGNUM = 331,
    IA64_GDB_PSR_REGNUM = 332,
    IA64_GDB_CFM_REGNUM = 333,
    IA64_GDB_AR0_REGNUM = 334,
    IA64_GDB_NUM_CORE_REGS = 462,
};

static uint64_t ia64_gdb_read_pr(const CPUIA64State *env)
{
    uint64_t value = 1;

    for (unsigned logical = 1; logical < IA64_PR_COUNT; logical++) {
        unsigned physical = logical;

        if (logical >= 16) {
            physical = 16 + ((logical - 16 + env->cfm_rrb_pr) % 48);
        }
        value |= (uint64_t)(env->pr[logical] != 0) << physical;
    }
    return value;
}

static void ia64_gdb_write_pr(CPUIA64State *env, uint64_t value)
{
    for (unsigned logical = 1; logical < IA64_PR_COUNT; logical++) {
        unsigned physical = logical;

        if (logical >= 16) {
            physical = 16 + ((logical - 16 + env->cfm_rrb_pr) % 48);
        }
        env->pr[logical] = (value >> physical) & 1;
    }
    env->pr[0] = 1;
}

static uint64_t ia64_gdb_read_cfm(const CPUIA64State *env)
{
    return env->cfm_sof
        | ((uint64_t)env->cfm_sol << IA64_CFM_SOL_SHIFT)
        | ((uint64_t)env->cfm_sor << IA64_CFM_SOR_SHIFT)
        | ((uint64_t)env->cfm_rrb_gr << IA64_CFM_RRB_GR_SHIFT)
        | ((uint64_t)env->cfm_rrb_fr << IA64_CFM_RRB_FR_SHIFT)
        | ((uint64_t)env->cfm_rrb_pr << IA64_CFM_RRB_PR_SHIFT);
}

static void ia64_gdb_write_cfm(CPUIA64State *env, uint64_t value)
{
    unsigned sof = value & IA64_CFM_SOF_MASK;
    unsigned sol = (value & IA64_CFM_SOL_MASK) >> IA64_CFM_SOL_SHIFT;
    unsigned sor = (value & IA64_CFM_SOR_MASK) >> IA64_CFM_SOR_SHIFT;
    unsigned rrb_gr = (value & IA64_CFM_RRB_GR_MASK) >>
                      IA64_CFM_RRB_GR_SHIFT;
    unsigned rrb_fr = (value & IA64_CFM_RRB_FR_MASK) >>
                      IA64_CFM_RRB_FR_SHIFT;
    unsigned rrb_pr = (value & IA64_CFM_RRB_PR_MASK) >>
                      IA64_CFM_RRB_PR_SHIFT;
    uint64_t physical_pr;

    /*
     * Changing the frame shape or RRB.GR also changes the RSE partitions and
     * its logical stacked-register view.  There is no fault-reporting channel
     * in the GDB callback, so reject such writes instead of leaving an
     * internally inconsistent RSE.  RRB.FR and RRB.PR have complete rebasing
     * setters and can safely be changed independently.
     */
    if (sof != env->cfm_sof || sol != env->cfm_sol ||
        sor != env->cfm_sor || rrb_gr != env->cfm_rrb_gr ||
        rrb_fr >= 96 || rrb_pr >= 48) {
        return;
    }

    physical_pr = ia64_gdb_read_pr(env);
    ia64_set_cfm_rrb_fr(env, rrb_fr);
    env->cfm_rrb_pr = rrb_pr;
    /* env->pr[] is a logical view; preserve the raw physical PR file. */
    ia64_gdb_write_pr(env, physical_pr);
}

static int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *buf, int reg)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;
    uint64_t val = 0;

    if (reg >= IA64_GDB_GR0_REGNUM && reg < IA64_GDB_FR0_REGNUM) {
        val = reg == 0 ? 0 : env->gr[reg];
    } else if (reg < IA64_GDB_PR0_REGNUM) {
        uint64_t low, high;

        ia64_fpreg_to_spill(env, reg - IA64_GDB_FR0_REGNUM, &low, &high);
        return gdb_get_reg128(buf, high, low);
    } else if (reg < IA64_GDB_BR0_REGNUM) {
        val = (ia64_gdb_read_pr(env) >>
               (reg - IA64_GDB_PR0_REGNUM)) & 1;
    } else if (reg < IA64_GDB_VFP_REGNUM) {
        val = env->br[reg - IA64_GDB_BR0_REGNUM];
    } else if (reg == IA64_GDB_VFP_REGNUM ||
               reg == IA64_GDB_VRAP_REGNUM) {
        /* GDB computes these virtual registers itself. */
    } else if (reg == IA64_GDB_PR_REGNUM) {
        val = ia64_gdb_read_pr(env);
    } else if (reg == IA64_GDB_IP_REGNUM) {
        val = env->ip;
    } else if (reg == IA64_GDB_PSR_REGNUM) {
        val = env->psr;
    } else if (reg == IA64_GDB_CFM_REGNUM) {
        val = ia64_gdb_read_cfm(env);
    } else if (reg >= IA64_GDB_AR0_REGNUM &&
               reg < IA64_GDB_NUM_CORE_REGS) {
        val = helper_read_ar(env, reg - IA64_GDB_AR0_REGNUM);
    } else {
        return 0;
    }

    return gdb_get_reg64(buf, val);
}

static int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *buf, int reg)
{
    IA64CPU *cpu = ia64_cpu_from_cpu_state(cs);
    CPUIA64State *env = &cpu->env;
    uint64_t val = ldq_p(buf);

    if (reg >= IA64_GDB_GR0_REGNUM && reg < IA64_GDB_FR0_REGNUM) {
        if (reg != 0) {
            env->gr[reg] = val;
            ia64_rse_mark_gr_dirty(env, reg);
            helper_invalidate_alat_reg(env, reg);
        }
    } else if (reg < IA64_GDB_PR0_REGNUM) {
        unsigned freg = reg - IA64_GDB_FR0_REGNUM;

        ia64_fpreg_from_spill(env, freg, val, ldq_p(buf + 8));
        helper_invalidate_alat_fp_reg(env, freg);
        return 16;
    } else if (reg < IA64_GDB_BR0_REGNUM) {
        unsigned predicate = reg - IA64_GDB_PR0_REGNUM;
        uint64_t physical_pr = ia64_gdb_read_pr(env);

        if (predicate != 0) {
            if (val) {
                physical_pr |= 1ULL << predicate;
            } else {
                physical_pr &= ~(1ULL << predicate);
            }
        }
        ia64_gdb_write_pr(env, physical_pr);
    } else if (reg < IA64_GDB_VFP_REGNUM) {
        env->br[reg - IA64_GDB_BR0_REGNUM] = val;
    } else if (reg == IA64_GDB_VFP_REGNUM ||
               reg == IA64_GDB_VRAP_REGNUM) {
        /* Read-only virtual registers. */
    } else if (reg == IA64_GDB_PR_REGNUM) {
        ia64_gdb_write_pr(env, val);
    } else if (reg == IA64_GDB_IP_REGNUM) {
        env->ip = val;
    } else if (reg == IA64_GDB_PSR_REGNUM) {
        helper_mov_psr_write(env, val, 0);
    } else if (reg == IA64_GDB_CFM_REGNUM) {
        ia64_gdb_write_cfm(env, val);
    } else if (reg >= IA64_GDB_AR0_REGNUM &&
               reg < IA64_GDB_NUM_CORE_REGS) {
        unsigned ar = reg - IA64_GDB_AR0_REGNUM;

        if (ar != 17 && (ar != 18 || val != env->ar_bspstore)) {
            /*
             * AR.BSP is derived and read-only.  Reapplying the current
             * BSPSTORE would needlessly invalidate the RSE clean partition,
             * which makes a GDB g/G register echo non-idempotent.
             */
            helper_write_ar(env, ar, val);
        }
    } else {
        return 0;
    }

    return 8;
}

static const struct SysemuCPUOps ia64_sysemu_ops = {
    .has_work = ia64_cpu_has_work,
    .get_phys_page_debug = ia64_cpu_get_phys_page_debug,
};

static void ia64_cpu_tcg_init(void)
{
    static const char * const gr_names[IA64_GR_COUNT] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
        "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
        "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
        "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
        "r56", "r57", "r58", "r59", "r60", "r61", "r62", "r63",
        "r64", "r65", "r66", "r67", "r68", "r69", "r70", "r71",
        "r72", "r73", "r74", "r75", "r76", "r77", "r78", "r79",
        "r80", "r81", "r82", "r83", "r84", "r85", "r86", "r87",
        "r88", "r89", "r90", "r91", "r92", "r93", "r94", "r95",
        "r96", "r97", "r98", "r99", "r100", "r101", "r102", "r103",
        "r104", "r105", "r106", "r107", "r108", "r109", "r110",
        "r111", "r112", "r113", "r114", "r115", "r116", "r117",
        "r118", "r119", "r120", "r121", "r122", "r123", "r124",
        "r125", "r126", "r127",
    };
    static const char * const pr_names[IA64_PR_COUNT] = {
        "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7",
        "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",
        "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23",
        "p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31",
        "p32", "p33", "p34", "p35", "p36", "p37", "p38", "p39",
        "p40", "p41", "p42", "p43", "p44", "p45", "p46", "p47",
        "p48", "p49", "p50", "p51", "p52", "p53", "p54", "p55",
        "p56", "p57", "p58", "p59", "p60", "p61", "p62", "p63",
    };
    static const char * const br_names[IA64_BR_COUNT] = {
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    };
    int i;

    for (i = 0; i < IA64_GR_COUNT; ++i) {
        cpu_gr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, gr[i]),
                                           gr_names[i]);
    }
    for (i = 0; i < IA64_PR_COUNT; ++i) {
        cpu_pr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, pr[i]),
                                           pr_names[i]);
    }
    for (i = 0; i < IA64_BR_COUNT; ++i) {
        cpu_br[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, br[i]),
                                           br_names[i]);
    }
    cpu_ip = tcg_global_mem_new_i64(tcg_env, offsetof(CPUIA64State, ip), "ip");
    cpu_psr = tcg_global_mem_new_i64(tcg_env, offsetof(CPUIA64State, psr),
                                     "psr");
    for (i = 0; i < IA64_FR_COUNT; ++i) {
        cpu_fr[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, fr[i]),
                                           "fr");
    }
    for (i = 0; i < 2; ++i) {
        cpu_nat[i] = tcg_global_mem_new_i64(tcg_env,
                                           offsetof(CPUIA64State, nat[i]),
                                           "nat");
        cpu_fr_nat[i] = tcg_global_mem_new_i64(tcg_env,
                                               offsetof(CPUIA64State,
                                                        fr_nat[i]),
                                               "fr_nat");
        cpu_fr_sig[i] = tcg_global_mem_new_i64(tcg_env,
                                               offsetof(CPUIA64State,
                                                        fr_sig[i]),
                                               "fr_sig");
        cpu_fr_ext_valid[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUIA64State, fr_ext_valid[i]),
            "fr_ext_valid");
        cpu_fr_int_origin[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUIA64State, fr_int_origin[i]),
            "fr_int_origin");
        cpu_rse_gr_dirty[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUIA64State, rse_gr_dirty[i]),
            "rse_gr_dirty");
    }
}

static bool ia64_insn_may_set_fault_suppression(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_SSM:
        return insn->imm & IA64_PSR_FAULT_SUPPRESS_MASK;
    case IA64_OP_MOV_GRPSR:
        return insn->imm == 0;
    default:
        return false;
    }
}

static bool ia64_insn_may_set_psr_ic(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_SSM:
        return insn->imm & IA64_PSR_IC;
    case IA64_OP_MOV_GRPSR:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_may_modify_psr_ic(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_SSM:
    case IA64_OP_RSM:
    case IA64_OP_MOV_GRPSR:
        return true;
    default:
        return false;
    }
}

static bool ia64_insn_may_modify_psr_ri(const Ia64Instruction *insn)
{
    return insn->opcode == IA64_OP_MOV_GRPSR;
}

static bool ia64_insn_is_empty_hint(const Ia64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_NOP:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
    case IA64_OP_BRP:
        return true;
    default:
        return false;
    }
}

static void ia64_tr_init_disas_context(DisasContextBase *db, CPUState *cs)
{
    DisasContext *ctx = container_of(db, DisasContext, base);
    uint32_t flags = ctx->base.tb->flags;

    ctx->env = cpu_env(cs);
    ctx->mmu_idx = (flags & IA64_TB_FLAG_DT) ?
        MMU_IDX_VIRT_CPL((flags & IA64_TB_FLAG_CPL_MASK) >>
                         IA64_TB_FLAG_CPL_SHIFT) :
        MMU_PHYS_IDX;
    ctx->start_slot = (ctx->base.tb->flags & IA64_TB_FLAG_RI_MASK) >>
                      IA64_TB_FLAG_RI_SHIFT;
    if (ctx->start_slot > 2) {
        ctx->start_slot = 0;
    }
    ctx->current_ri = ctx->start_slot;
    ctx->current_ri_known = true;
    ctx->track_iipa = ctx->base.tb->flags & IA64_TB_FLAG_PSR_IC;
    ctx->track_psr_suppression =
        ctx->base.tb->flags & IA64_TB_FLAG_PSR_SUPPRESS;
    ctx->be_data = ctx->base.tb->flags & IA64_TB_FLAG_BE;
    ctx->full_alat = ctx->env->alat_full;
    ctx->nat_known_clear[0] = 1;
    ctx->nat_known_clear[1] = 0;
    ctx->instruction_group_start =
        ctx->base.tb->flags & IA64_TB_FLAG_GROUP_START;
    ctx->next_instruction_group_start =
        ctx->instruction_group_start;
}

static void ia64_tr_tb_start(DisasContextBase *db, CPUState *cs)
{
}

static void ia64_tr_insn_start(DisasContextBase *db, CPUState *cs)
{
    tcg_gen_insn_start(db->pc_next, 0, 0);
}

static void ia64_tr_translate_insn(DisasContextBase *db, CPUState *cs)
{
    DisasContext *ctx = container_of(db, DisasContext, base);
    const uint64_t bundle_ip = db->pc_next;
    uint64_t low;
    uint64_t high;
    uint8_t template_code;
    const IA64TemplateInfo *template_info;
    uint64_t slots[3];
    bool skip_x_slot;
    bool record_iipa;
    bool psr_ic_modified;
    int slot;

    if (ctx->base.tb->flags & IA64_TB_FLAG_PSR_IS) {
        db->pc_next = bundle_ip + 1;
        gen_helper_ia32_unsupported(tcg_env);
        db->is_jmp = DISAS_NORETURN;
        return;
    }

    low = translator_ldq_end(ctx->env, db, bundle_ip, MO_LE);
    high = translator_ldq_end(ctx->env, db, bundle_ip + 8, MO_LE);
    template_code = ia64_bundle_template_code(low);
    template_info = ia64_template_info(template_code);

    ctx->exit_after_bundle = false;
    db->pc_next = bundle_ip + 16;

    if (!template_info->defined) {
        ia64_gen_raise_exception(IA64_EXCP_RESERVED_TEMPLATE, bundle_ip,
                                  template_code, 0);
        db->is_jmp = DISAS_NORETURN;
        return;
    }

    slots[0] = ia64_bundle_slot(low, high, 0);
    slots[1] = ia64_bundle_slot(low, high, 1);
    slots[2] = ia64_bundle_slot(low, high, 2);
    ia64_prepare_self_counted_loop(ctx, template_code, template_info, slots,
                                   bundle_ip);

    skip_x_slot = false;
    record_iipa = true;
    psr_ic_modified = false;
    for (slot = ctx->start_slot; slot < 3; ++slot) {
        if (skip_x_slot && slot == 2) {
            continue;
        }

        Ia64Instruction insn = ia64_decode_insn(
            (Ia64SlotUnit)template_info->units[slot], slots[slot], bundle_ip,
            slot);
        bool stop_after;
        bool track_iipa_for_insn;

        ia64_apply_mlx_long_fixup(template_code, slots, slot, &insn,
                                  &skip_x_slot);
        insn.ctx = ctx;
        stop_after = template_info->stop_after[
            skip_x_slot && slot == 1 ? 2 : slot];
        insn.placement_illegal =
            (ia64_insn_must_start_group(&insn) &&
             !ctx->instruction_group_start) ||
            (ia64_insn_must_end_group(&insn) && !stop_after) ||
            (ia64_insn_requires_slot2(&insn) && slot != 2) ||
            ia64_insn_has_invalid_fp_pair(&insn) ||
            ia64_insn_has_illegal_register(&insn);
        insn.reserved_field = ia64_insn_has_reserved_mask_field(&insn);
        ctx->next_instruction_group_start = stop_after;
        if (ia64_insn_may_set_psr_ic(&insn)) {
            ctx->track_iipa = true;
        }
        if (ia64_insn_may_modify_psr_ic(&insn)) {
            psr_ic_modified = true;
        }
        track_iipa_for_insn = ctx->track_iipa;
        if (ia64_insn_is_empty_hint(&insn) &&
            !(record_iipa && track_iipa_for_insn) &&
            !ctx->track_psr_suppression) {
            ia64_gen_advance_restart_point(ctx, bundle_ip, slot,
                                           skip_x_slot);
            ctx->instruction_group_start =
                ctx->next_instruction_group_start;
            continue;
        }
        if (ctx->track_psr_suppression) {
            TCGv_i64 suppression = tcg_temp_new_i64();

            tcg_gen_andi_i64(suppression, cpu_psr,
                             IA64_PSR_FAULT_SUPPRESS_MASK);
            tcg_gen_st_i64(suppression, tcg_env,
                           offsetof(CPUIA64State,
                                    psr_suppression_before_insn));
        }
        ia64_gen_set_ri_tracked(ctx, slot);
        if (ia64_gen_insn(ctx, &insn, record_iipa && track_iipa_for_insn)) {
            db->is_jmp = DISAS_NORETURN;
            return;
        }
        ia64_gen_advance_restart_point(ctx, bundle_ip, slot, skip_x_slot);
        ia64_update_nat_known(ctx, &insn);
        ctx->instruction_group_start =
            ctx->next_instruction_group_start;
        if (ia64_insn_may_modify_psr_ri(&insn)) {
            ctx->current_ri_known = false;
        }
        if (track_iipa_for_insn && !psr_ic_modified) {
            record_iipa = false;
        }
        ctx->track_psr_suppression =
            ia64_insn_may_set_fault_suppression(&insn);
    }

    ctx->start_slot = 0;
    /* Preserve translator_io_start() requests for timer register accesses. */
    if (ctx->exit_after_bundle) {
        db->is_jmp = DISAS_EXIT;
    } else if (!translator_is_same_page(db, db->pc_next)) {
        /*
         * Bundles are 16-byte aligned and cannot straddle a 4 KiB target
         * page.  Do not fetch the next page until all bundles from this page
         * have executed; a translation fault there must not discard them.
         */
        db->is_jmp = DISAS_TOO_MANY;
    }
}

static void ia64_gen_goto_tb_group(DisasContext *ctx, uint64_t dest,
                                   bool group_start)
{
    uint8_t slot = ctx->goto_tb_slots;

    ia64_gen_store_instruction_group_start(group_start);
    ia64_gen_save_fault_slot_for_exit(ctx);
    ia64_gen_clear_ri();
    tcg_gen_movi_i64(cpu_ip, dest);
    if (slot < 2 && translator_use_goto_tb(&ctx->base, dest)) {
        ctx->goto_tb_slots = slot + 1;
        tcg_gen_goto_tb(slot);
        tcg_gen_exit_tb(ctx->base.tb, slot);
    } else {
        tcg_gen_lookup_and_goto_ptr();
    }
}

static void ia64_gen_goto_tb(DisasContext *ctx, uint64_t dest)
{
    ia64_gen_goto_tb_group(ctx, dest, ctx->instruction_group_start);
}

static void ia64_tr_tb_stop(DisasContextBase *db, CPUState *cs)
{
    DisasContext *ctx = container_of(db, DisasContext, base);

    switch (db->is_jmp) {
    case DISAS_EXIT:
    case DISAS_TOO_MANY:
        ia64_gen_goto_tb(ctx, db->pc_next);
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const char *ia64_unit_log_name(Ia64SlotUnit unit)
{
    switch (unit) {
    case IA64_UNIT_M:
        return "M";
    case IA64_UNIT_I:
        return "I";
    case IA64_UNIT_B:
        return "B";
    case IA64_UNIT_F:
        return "F";
    case IA64_UNIT_L:
        return "L";
    case IA64_UNIT_X:
        return "X";
    case IA64_UNIT_RESERVED:
    default:
        return "reserved";
    }
}

static bool ia64_tr_disas_log(const DisasContextBase *db, CPUState *cs,
                              FILE *logfile)
{
    const DisasContext *ctx = container_of(db, DisasContext, base);
    vaddr bundle_ip = db->pc_first;
    size_t size = translator_st_len(db);
    int start_slot = ctx->start_slot;

    fprintf(logfile, "QEMU-IA64-DECODE: pc=0x%016" PRIx64
            " size=%zu\n", (uint64_t)db->pc_first, size);

    while (size >= 16) {
        uint8_t bundle[16];
        uint64_t low;
        uint64_t high;
        uint8_t template_code;
        const IA64TemplateInfo *template_info;
        uint64_t slots[3];
        bool skip_x_slot = false;
        int slot;

        if (!translator_st(db, bundle, bundle_ip, sizeof(bundle))) {
            fprintf(logfile,
                    "QEMU-IA64-DECODE: read-failed pc=0x%016" PRIx64 "\n",
                    (uint64_t)bundle_ip);
            break;
        }

        low = ldq_le_p(bundle);
        high = ldq_le_p(bundle + 8);
        template_code = ia64_bundle_template_code(low);
        template_info = ia64_template_info(template_code);
        slots[0] = ia64_bundle_slot(low, high, 0);
        slots[1] = ia64_bundle_slot(low, high, 1);
        slots[2] = ia64_bundle_slot(low, high, 2);

        fprintf(logfile,
                "QEMU-IA64-DECODE: bundle=0x%016" PRIx64
                " template=0x%02x name=%s defined=%u\n",
                (uint64_t)bundle_ip, template_code, template_info->name,
                template_info->defined ? 1 : 0);

        if (template_info->defined) {
            for (slot = start_slot; slot < 3; ++slot) {
                Ia64SlotUnit unit;
                Ia64Instruction insn;

                if (skip_x_slot && slot == 2) {
                    continue;
                }

                unit = (Ia64SlotUnit)template_info->units[slot];
                insn = ia64_decode_insn(unit, slots[slot], bundle_ip, slot);
                ia64_apply_mlx_long_fixup(template_code, slots, slot, &insn,
                                          &skip_x_slot);
                fprintf(logfile,
                        "QEMU-IA64-DECODE: slot=%d unit=%s opcode=%u"
                        " valid=%u qp=%u raw=0x%010" PRIx64 "\n",
                        slot, ia64_unit_log_name(insn.unit),
                        (unsigned)insn.opcode, insn.valid ? 1 : 0,
                        insn.qp, insn.raw);
            }
        }

        bundle_ip += 16;
        size -= 16;
        start_slot = 0;
    }

    return false;
}

static void ia64_cpu_translate_code(CPUState *cs, TranslationBlock *tb,
                                    int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext ctx = {};
    static const TranslatorOps ia64_tr_ops = {
        .init_disas_context = ia64_tr_init_disas_context,
        .tb_start = ia64_tr_tb_start,
        .insn_start = ia64_tr_insn_start,
        .translate_insn = ia64_tr_translate_insn,
        .tb_stop = ia64_tr_tb_stop,
        .disas_log = ia64_tr_disas_log,
    };

    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}

static const TCGCPUOps ia64_tcg_ops = {
    .guest_default_memory_order = TCG_MO_ALL,
    .mttcg_supported = true,
    .initialize = ia64_cpu_tcg_init,
    .translate_code = ia64_cpu_translate_code,
    .get_tb_cpu_state = ia64_get_tb_cpu_state,
    .synchronize_from_tb = ia64_cpu_synchronize_from_tb,
    .restore_state_to_opc = ia64_restore_state_to_opc,
    .mmu_index = ia64_cpu_mmu_index,
    .tlb_fill = ia64_cpu_tlb_fill,
    .pointer_wrap = cpu_pointer_wrap_notreached,
#ifndef CONFIG_USER_ONLY
    .do_unaligned_access = ia64_cpu_do_unaligned_access,
#endif
    .cpu_exec_interrupt = ia64_cpu_exec_interrupt,
    .cpu_exec_halt = ia64_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
    .do_interrupt = ia64_cpu_do_interrupt,
};

/*
 * Per-model PAL profiles (see IA64PalProfile in cpu.h).  Madison/Montecito
 * carry the exact values helper_pal_dispatch used before profiles existed, so
 * their PAL responses stay bit-identical; only the merced profile differs.
 * All models report a 100 MHz PAL_FREQ_BASE and encode core/bus/ITC as ratios.
 */
static const IA64PalProfile ia64_pal_profile_madison = {
    .freq_base_hz = 100000000ULL,
    .proc_ratio_num = 16, .proc_ratio_den = 1,   /* 1.6 GHz */
    .bus_ratio_num = 4,   .bus_ratio_den = 1,     /* 400 MHz */
    .itc_ratio_num = 2,   .itc_ratio_den = 1,     /* 200 MHz */
    .has_post_merced_pal = true,
};

static const IA64PalProfile ia64_pal_profile_montecito = {
    .freq_base_hz = 100000000ULL,
    .proc_ratio_num = 16, .proc_ratio_den = 1,    /* 1.6 GHz */
    .bus_ratio_num = 16,  .bus_ratio_den = 3,      /* 533.33 MHz */
    .itc_ratio_num = 2,   .itc_ratio_den = 1,      /* 200 MHz */
    .has_post_merced_pal = true,
};

/*
 * Original Itanium (Merced), 800 MHz / 133 MHz bus SKU (249634-002 datasheet;
 * CPUID table 249720-009).  brl is not implemented (cpuid_features = 0) and the
 * post-Merced PAL procedures are absent (245318-001/-002 §11.8).  See
 * plans/merced-model-notes.md for full citations.
 */
static const IA64PalProfile ia64_pal_profile_merced = {
    .freq_base_hz = 100000000ULL,
    .proc_ratio_num = 8,  .proc_ratio_den = 1,     /* 800 MHz */
    .bus_ratio_num = 4,   .bus_ratio_den = 3,       /* 133.33 MHz */
    .itc_ratio_num = 2,   .itc_ratio_den = 1,       /* 200 MHz (ITC ratio not
                                                     * separately published) */
    .has_post_merced_pal = false,
};

static void ia64_cpu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    IA64CPUClass *icc = IA64_CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    device_class_set_parent_realize(dc, ia64_cpu_realize,
                                    &icc->parent_realize);
    device_class_set_props(dc, ia64_cpu_properties);
    resettable_class_set_parent_phases(rc, NULL, ia64_cpu_reset_hold, NULL,
                                       &icc->parent_phases);

    cc->class_by_name = ia64_cpu_class_by_name;
    cc->dump_state = ia64_cpu_dump_state;
    cc->set_pc = ia64_cpu_set_pc;
    cc->get_pc = ia64_cpu_get_pc;
    cc->sysemu_ops = &ia64_sysemu_ops;
    cc->gdb_read_register = ia64_cpu_gdb_read_register;
    cc->gdb_write_register = ia64_cpu_gdb_write_register;
    cc->gdb_num_core_regs = IA64_GDB_NUM_CORE_REGS;
    cc->tcg_ops = &ia64_tcg_ops;

    /* Keep direct instantiation of the base type backward compatible. */
    icc->cpuid_version = 0x000000001f010504ULL;
    icc->cpuid_features = IA64_CPUID4_LB;
    icc->itr_count = 64;
    icc->dtr_count = 64;
    icc->has_native_ia32 = true;
    icc->has_virtualization = false;
    icc->is_montecito = false;
    icc->pal = &ia64_pal_profile_madison;
}

typedef struct IA64CPUModelDef {
    uint64_t cpuid_version;
    uint64_t cpuid_features;
    uint8_t itr_count;
    uint8_t dtr_count;
    bool has_native_ia32;
    bool has_virtualization;
    bool is_montecito;
    const IA64PalProfile *pal;
} IA64CPUModelDef;

static void ia64_cpu_model_class_init(ObjectClass *oc, const void *data)
{
    IA64CPUClass *icc = IA64_CPU_CLASS(oc);
    const IA64CPUModelDef *model = data;

    icc->cpuid_version = model->cpuid_version;
    icc->cpuid_features = model->cpuid_features;
    icc->itr_count = model->itr_count;
    icc->dtr_count = model->dtr_count;
    icc->has_native_ia32 = model->has_native_ia32;
    icc->has_virtualization = model->has_virtualization;
    icc->is_montecito = model->is_montecito;
    icc->pal = model->pal;
}

/*
 * Translation-register file size is implementation-specific; the SDM only
 * guarantees eight of each bank.  Madison implements 64 ITRs and 64 DTRs,
 * and so does Tukwila.  No published figure for Montecito was found, so
 * take the value shared by the generations on either side of it.
 */
static const IA64CPUModelDef ia64_cpu_model_madison = {
    /* Family 0x1f, model 1, revision 5, CPUID[4] is the last register. */
    .cpuid_version = 0x000000001f010504ULL,
    /* No 16-byte atomics and no virtualization: both post-date Madison. */
    .cpuid_features = IA64_CPUID4_LB,
    .itr_count = 64,
    .dtr_count = 64,
    .has_native_ia32 = true,
    .has_virtualization = false,
    .pal = &ia64_pal_profile_madison,
};

static const IA64CPUModelDef ia64_cpu_model_montecito = {
    /* Family 0x20, model 0, C2 revision 7, CPUID[4] is the last register. */
    .cpuid_version = 0x0000000020000704ULL,
    .cpuid_features = IA64_CPUID4_LB | IA64_CPUID4_AO,
    .itr_count = 64,
    .dtr_count = 64,
    /*
     * Montecito implements the virtualization extensions, but this model
     * does not virtualize.  vmsw is decoded and reported as a Virtualization
     * fault so a guest sees the architected interruption instead of a
     * silently succeeding privilege-mode switch.
     */
    .has_virtualization = true,
    .is_montecito = true,
    .pal = &ia64_pal_profile_montecito,
};

/*
 * Original Itanium ("Merced"), 800 MHz / 4 MB L3, C2 stepping.  Family 0x07,
 * model 0, revision 8, CPUID[4] is the last register (249720-009 spec update).
 * cpuid_features = 0: brl is not implemented (CPUID[4].lb = 0, 245319-002 brl
 * page), which is what Windows' KF_BRL check expects on Merced.  Asymmetric TR
 * file: 8 ITR / 48 DTR (248701-002 §2.5.6).  No 16-byte atomics, no
 * virtualization.  See plans/merced-model-notes.md.
 */
static const IA64CPUModelDef ia64_cpu_model_merced = {
    .cpuid_version = 0x0000000007000804ULL,
    .cpuid_features = 0,
    .itr_count = 8,
    .dtr_count = 48,
    .has_native_ia32 = true,
    .has_virtualization = false,
    .is_montecito = false,
    .pal = &ia64_pal_profile_merced,
};

static const TypeInfo ia64_cpu_type_info[] = {
    {
        .name = TYPE_IA64_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(IA64CPU),
        .instance_align = __alignof__(IA64CPU),
        .class_size = sizeof(IA64CPUClass),
        .class_init = ia64_cpu_class_init,
    },
    {
        .name = IA64_CPU_TYPE_NAME("itanium2"),
        .parent = TYPE_IA64_CPU,
        .class_init = ia64_cpu_model_class_init,
        .class_data = &ia64_cpu_model_madison,
    },
    {
        .name = IA64_CPU_TYPE_NAME("madison"),
        .parent = TYPE_IA64_CPU,
        .class_init = ia64_cpu_model_class_init,
        .class_data = &ia64_cpu_model_madison,
    },
    {
        .name = IA64_CPU_TYPE_NAME("montecito"),
        .parent = TYPE_IA64_CPU,
        .class_init = ia64_cpu_model_class_init,
        .class_data = &ia64_cpu_model_montecito,
    },
    {
        .name = IA64_CPU_TYPE_NAME("merced"),
        .parent = TYPE_IA64_CPU,
        .class_init = ia64_cpu_model_class_init,
        .class_data = &ia64_cpu_model_merced,
    },
    {
        /* "itanium" is an alias for the original Itanium (Merced). */
        .name = IA64_CPU_TYPE_NAME("itanium"),
        .parent = TYPE_IA64_CPU,
        .class_init = ia64_cpu_model_class_init,
        .class_data = &ia64_cpu_model_merced,
    },
};

DEFINE_TYPES(ia64_cpu_type_info)
