#ifndef IA64_CPU_H
#define IA64_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "fpu/softfloat.h"
#include "qemu/timer.h"

#ifdef CONFIG_USER_ONLY
#error "IA-64 target currently supports system mode only"
#endif

#define CPU_RESOLVING_TYPE TYPE_IA64_CPU

#undef NB_MMU_MODES
#define MMU_PHYS_IDX       0
#define MMU_IDX_VIRT_CPL0  1
#define MMU_IDX_VIRT_CPL1  2
#define MMU_IDX_VIRT_CPL2  3
#define MMU_IDX_VIRT_CPL3  4
#define MMU_IDX_RSE        5
#define NB_MMU_MODES       6

#define MMU_IDX_VIRT_CPL(cpl) (MMU_IDX_VIRT_CPL0 + (cpl))
#define MMU_IDX_VIRT_MASK \
    (((1u << 4) - 1) << MMU_IDX_VIRT_CPL0)
#define MMU_IDX_TRANSLATED_MASK \
    (MMU_IDX_VIRT_MASK | (1u << MMU_IDX_RSE))

#define IA64_GR_COUNT    128
#define IA64_STACKED_GR_BASE   32
#define IA64_STACKED_GR_COUNT  (IA64_GR_COUNT - IA64_STACKED_GR_BASE)
#define IA64_PR_COUNT    64
#define IA64_BR_COUNT    8
#define IA64_AR_COUNT    128
#define IA64_CR_COUNT    128
#define IA64_DBR_COUNT   16
#define IA64_FR_COUNT    128
#define IA64_IBR_COUNT   16
#define IA64_PMC_COUNT   64
#define IA64_PMD_COUNT   64
#define IA64_PKR_COUNT   16
#define IA64_RR_COUNT    8
#define IA64_MSR_COUNT   1024
/* Maximum translation-register count implemented by a supported CPU model. */
#define IA64_TR_MAX      64
#define IA64_TLB_MAX     128

/*
 * CPUID register 4 general features/capability bits.  A model advertises
 * only what it implements, and the translator refuses the corresponding
 * instructions on models that do not.
 */
#define IA64_CPUID4_LB   (1ULL << 0)  /* brl, long branch */
#define IA64_CPUID4_SD   (1ULL << 1)  /* spontaneous deferral */
#define IA64_CPUID4_AO   (1ULL << 2)  /* ld16/st16/cmp8xchg16 atomics */

#define IA64_MICRO_TLB_SIZE 4
#define IA64_SUPPRESSED_TLB_MAX 4

#define IA64_REGION_BITS 3
#define IA64_IMPL_PA_BITS 50
/*
 * This CPU model exposes 64-bit virtual addressing: VA{60:0} plus the
 * three region bits VA{63:61}.
 */
#define IA64_IMPL_VA_MSB 60
#define IA64_IMPL_VA_BITS (IA64_IMPL_VA_MSB + 1 + IA64_REGION_BITS)
#define IA64_PAL_IMPL_VA_MSB IA64_IMPL_VA_MSB
#define IA64_IMPL_RID_BITS 24
#define IA64_IMPL_KEY_BITS 24

#define IA64_PAL_DISPATCH_HALTED  (1U << 0)
#define IA64_PAL_DISPATCH_EXIT_TB (1U << 1)

#define IA64_FR_ONE      0x3ff0000000000000ULL
/* Architected FP status expected by IA-64 firmware and OS hand-off. */
#define IA64_FPSR_DEFAULT 0x0009804c0270033fULL

#define IA64_FP_CONTEXT_SF_MASK       0x3u
#define IA64_FP_CONTEXT_PREC_SHIFT    2
#define IA64_FP_CONTEXT(sf, precision) \
    (((sf) & IA64_FP_CONTEXT_SF_MASK) | \
     ((precision) << IA64_FP_CONTEXT_PREC_SHIFT))

/* ---- PSR bit definitions ---- */
#define IA64_PSR_BE      (1ULL << 1)
#define IA64_PSR_UP      (1ULL << 2)
#define IA64_PSR_AC      (1ULL << 3)
#define IA64_PSR_MFL     (1ULL << 4)
#define IA64_PSR_MFH     (1ULL << 5)
#define IA64_PSR_IC      (1ULL << 13)
#define IA64_PSR_I       (1ULL << 14)
#define IA64_PSR_PK      (1ULL << 15)
#define IA64_PSR_UM_MASK 0x3fULL
#define IA64_PSR_UM_WRITABLE_MASK 0x3eULL
#define IA64_PSR_DT      (1ULL << 17)
#define IA64_PSR_DFL     (1ULL << 18)
#define IA64_PSR_DFH     (1ULL << 19)
#define IA64_PSR_SP      (1ULL << 20)
#define IA64_PSR_PP      (1ULL << 21)
#define IA64_PSR_DI      (1ULL << 22)
#define IA64_PSR_SI      (1ULL << 23)
#define IA64_PSR_DB      (1ULL << 24)
#define IA64_PSR_TB      (1ULL << 26)
#define IA64_PSR_RT      (1ULL << 27)
#define IA64_PSR_IS      (1ULL << 34)
#define IA64_PSR_MC      (1ULL << 35)
#define IA64_PSR_IT      (1ULL << 36)
#define IA64_PSR_ID      (1ULL << 37)
#define IA64_PSR_CPL_MASK (3ULL << 32)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_BN      (1ULL << 44)
#define IA64_PSR_VM      (1ULL << 46)
#define IA64_PSR_ED      (1ULL << 43)
#define IA64_PSR_DA      (1ULL << 38)
#define IA64_PSR_DD      (1ULL << 39)
#define IA64_PSR_SS      (1ULL << 40)
#define IA64_PSR_IA      (1ULL << 45)
#define IA64_PSR_RI_MASK (3ULL << 41)
#define IA64_PSR_RI_SHIFT  41
#define IA64_PSR_FAULT_SUPPRESS_MASK \
    (IA64_PSR_DA | IA64_PSR_DD | IA64_PSR_ED | IA64_PSR_IA)

#define IA64_REGION_SHIFT 61
#define IA64_REGION_MASK  ((1ULL << IA64_REGION_BITS) - 1)
#define IA64_BUNDLE_SIZE  16ULL
#define IA64_IP_BUNDLE_MASK (~(IA64_BUNDLE_SIZE - 1))
#define IA64_REGION7_PHYS_MASK ((1ULL << IA64_REGION_SHIFT) - 1)
#define IA64_PHYS_UC_BIT (1ULL << 63)
#define IA64_FW_IDENTITY_BASE 0x00100000ULL
#define IA64_FW_IDENTITY_SIZE 0x00100000ULL
/*
 * Fixed physical addresses of the SAL runtime stub trio (entry.S,
 * .text.sal_runtime, pinned by firmware.lds).  The machine recognises the
 * bridge breaks by entry address so they work for both a physical and a
 * virtual fetch.  Windows Server 2003's HAL only derives a virtual SAL entry
 * from the EfiRuntimeServicesCode descriptor containing the SST SalProc
 * address, so the stubs live in runtime-services code, not the PAL page.
 */
#define IA64_FW_SAL_RUNTIME_ENTRY_PA  (IA64_FW_IDENTITY_BASE + 0x2000)
#define IA64_FW_SAL_RUNTIME_RETURN_PA (IA64_FW_IDENTITY_BASE + 0x2020)
#define IA64_FW_SAL_DISPATCH_BLOCK_PA (IA64_FW_IDENTITY_BASE + 0x2040)
#define IA64_FIRMWARE_IVT_BASE 0x10000ULL
#define IA64_FW_BOOT_IDENTITY_LIMIT 0x0000010000000000ULL
/*
 * IA-64 OS loaders alias physical memory through region 7 with a fixed
 * 0x8000_0000 virtual base (region-7 VA = PA + 0x8000_0000).  The loader's
 * own region-7 TRs map e.g. 0xe000_0000_8100_0000 -> PA 0x0100_0000, and its
 * free-memory descriptors near the top of RAM carry addresses such as
 * 0xe000_0000_bf7f_ffe0 for PA 0x3f7f_ffe0.  SAL's boot-time TLB-miss handler
 * fills otherwise-unmapped region-7 pages with the same bias.
 */
#define IA64_FW_REGION7_DIRECTMAP_BASE 0x0000000080000000ULL
#define IA64_LOCAL_SAPIC_PA   0x00000000fee00000ULL
#define IA64_LOCAL_SAPIC_SIZE 0x00200000ULL
#define IA64_PAL_IO_BLOCK_PA  0x000080000c000000ULL

#define IA64_SAPIC_LID_ID_SHIFT   24
#define IA64_SAPIC_LID_EID_SHIFT  16
#define IA64_SAPIC_LID_ID_MASK    (0xffULL << IA64_SAPIC_LID_ID_SHIFT)
#define IA64_SAPIC_LID_EID_MASK   (0xffULL << IA64_SAPIC_LID_EID_SHIFT)

static inline uint64_t ia64_sapic_lid(uint8_t id, uint8_t eid)
{
    return ((uint64_t)id << IA64_SAPIC_LID_ID_SHIFT) |
           ((uint64_t)eid << IA64_SAPIC_LID_EID_SHIFT);
}

#define IA64_RR_RID_MASK   (0xffffffULL << 8)
#define IA64_RR_RID_SHIFT  8
#define IA64_RR_VE         (1ULL << 0)

static inline uint32_t ia64_rr_rid(uint64_t rr)
{
    return (rr & IA64_RR_RID_MASK) >> IA64_RR_RID_SHIFT;
}

static inline bool ia64_firmware_owns_iva(uint64_t iva)
{
    return iva == 0 || iva == IA64_FIRMWARE_IVT_BASE;
}

static inline bool ia64_firmware_identity_pa(uint64_t iva, uint64_t ip,
                                             uint64_t psr, uint64_t va,
                                             uint64_t *pa)
{
    bool firmware_context =
        (psr & IA64_PSR_CPL_MASK) == 0 &&
        (ia64_firmware_owns_iva(iva) ||
         (ip >= IA64_FW_IDENTITY_BASE &&
          ip < IA64_FW_IDENTITY_BASE + IA64_FW_IDENTITY_SIZE));

    if (firmware_context &&
        va >= IA64_FW_IDENTITY_BASE &&
        va < IA64_FW_IDENTITY_BASE + IA64_FW_IDENTITY_SIZE) {
        *pa = va;
        return true;
    }

    return false;
}

static inline uint64_t ia64_physical_address(uint64_t addr)
{
    return addr & ~IA64_PHYS_UC_BIT;
}

static inline bool ia64_pa_is_implemented(uint64_t addr)
{
    uint64_t implemented_mask = (1ULL << IA64_IMPL_PA_BITS) - 1;

    return (addr & ~(IA64_PHYS_UC_BIT | implemented_mask)) == 0;
}

static inline uint64_t ia64_pa_canonicalize(uint64_t addr)
{
    uint64_t implemented_mask = (1ULL << IA64_IMPL_PA_BITS) - 1;

    return addr & (IA64_PHYS_UC_BIT | implemented_mask);
}

static inline uint64_t ia64_ip_bundle_addr(uint64_t ip)
{
    return ip & IA64_IP_BUNDLE_MASK;
}

static inline bool ia64_va_is_implemented(uint64_t va)
{
    if (IA64_IMPL_VA_MSB >= 60) {
        return true;
    }

    {
        uint64_t count = 60 - IA64_IMPL_VA_MSB;
        uint64_t mask = (1ULL << count) - 1;
        uint64_t unimplemented = (va >> (IA64_IMPL_VA_MSB + 1)) & mask;
        uint64_t expected = (va & (1ULL << IA64_IMPL_VA_MSB)) ? mask : 0;

        return unimplemented == expected;
    }
}

static inline uint64_t ia64_va_canonicalize(uint64_t va)
{
    uint64_t region = va & (IA64_REGION_MASK << IA64_REGION_SHIFT);
    uint64_t implemented_mask = (1ULL << (IA64_IMPL_VA_MSB + 1)) - 1;
    uint64_t payload = va & implemented_mask;

    if (IA64_IMPL_VA_MSB < 60 &&
        (payload & (1ULL << IA64_IMPL_VA_MSB))) {
        payload |= ((1ULL << (60 - IA64_IMPL_VA_MSB)) - 1) <<
                   (IA64_IMPL_VA_MSB + 1);
    }

    return region | payload;
}

static inline uint8_t ia64_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

#define IA64_RI_0        (0ULL << 41)
#define IA64_RI_1        (1ULL << 41)
#define IA64_RI_2        (2ULL << 41)

/* ---- RSC bit definitions ---- */
#define IA64_RSC_MODE    0x3ULL
#define IA64_RSC_PL      0xcULL
#define IA64_RSC_PL_SHIFT 2
#define IA64_RSC_BE      0x10ULL
#define IA64_RSC_LOADRS_SHIFT 16
#define IA64_RSC_LOADRS_MASK  0x3fffULL

static inline uint8_t ia64_rsc_pl(uint64_t rsc)
{
    return (rsc & IA64_RSC_PL) >> IA64_RSC_PL_SHIFT;
}

/* ---- CFM mask definitions ---- */
#define IA64_CFM_SOF_MASK     0x7f
#define IA64_CFM_SOL_MASK     (0x7f << 7)
#define IA64_CFM_SOL_SHIFT    7
#define IA64_CFM_SOR_MASK     (0x0f << 14)
#define IA64_CFM_SOR_SHIFT    14
#define IA64_CFM_RRB_GR_MASK  (0x7f << 18)
#define IA64_CFM_RRB_GR_SHIFT 18
#define IA64_CFM_RRB_FR_MASK  (0x7fULL << 25)
#define IA64_CFM_RRB_FR_SHIFT 25
#define IA64_CFM_RRB_PR_MASK  (0x3fULL << 32)
#define IA64_CFM_RRB_PR_SHIFT 32
#define IA64_IFS_V            (1ULL << 63)
#define IA64_IFS_IFM_MASK     (IA64_CFM_SOF_MASK | IA64_CFM_SOL_MASK | \
                               IA64_CFM_SOR_MASK | IA64_CFM_RRB_GR_MASK | \
                               IA64_CFM_RRB_FR_MASK | IA64_CFM_RRB_PR_MASK)

/* ---- PFS field definitions ---- */
#define IA64_PFS_PFM_MASK     ((1ULL << 38) - 1)
#define IA64_PFS_PEC_SHIFT    52
#define IA64_PFS_PEC_MASK     (0x3fULL << IA64_PFS_PEC_SHIFT)
#define IA64_PFS_PPL_SHIFT    62
#define IA64_PFS_PPL_MASK     (0x3ULL << IA64_PFS_PPL_SHIFT)

/* ---- ISR fields ---- */
#define IA64_ISR_CODE_MASK   0xffff
#define IA64_ISR_VECTOR_MASK (0xffUL << 16)
#define IA64_ISR_VECTOR_SHIFT 16
#define IA64_ISR_X           (1ULL << 32)
#define IA64_ISR_W           (1ULL << 33)
#define IA64_ISR_R           (1ULL << 34)
#define IA64_ISR_NA          (1ULL << 35)
#define IA64_ISR_SP          (1ULL << 36)
#define IA64_ISR_RS          (1ULL << 37)
#define IA64_ISR_IR          (1ULL << 38)
#define IA64_ISR_NI          (1ULL << 39)
#define IA64_ISR_EI_MASK     (3ULL << 41)
#define IA64_ISR_EI_SHIFT    41
#define IA64_ISR_ED          (1ULL << 43)
#define IA64_ISR_CODE_REG_NAT  0x10
/* NaT Consumption ISR.code{5:4} = 2 for a NaTPage reference. */
#define IA64_ISR_CODE_NAT_PAGE 0x20
/* Concurrent trap conditions reported in ISR.code (SDM Vol. 2, Table 8-3). */
#define IA64_ISR_CODE_TB       (1ULL << 2)
#define IA64_ISR_CODE_SS       (1ULL << 3)
#define IA64_ISR_CODE_UI       (1ULL << 4)

/* ---- ITIR fields ---- */
#define IA64_ITIR_PS_MASK    0x3f
#define IA64_ITIR_PS_SHIFT   2
#define IA64_ITIR_KEY_MASK   (0xffffffULL << 8)
#define IA64_ITIR_KEY_SHIFT  8
#define IA64_INSERTABLE_PAGE_SIZE_MASK \
    ((1ULL << 12) | (1ULL << 13) | (1ULL << 14) | (1ULL << 16) | \
     (1ULL << 18) | (1ULL << 20) | (1ULL << 22) | (1ULL << 24) | \
     (1ULL << 26) | (1ULL << 28) | (1ULL << 30) | (1ULL << 32))
#define IA64_PURGEABLE_PAGE_SIZE_MASK IA64_INSERTABLE_PAGE_SIZE_MASK

/* ---- General exception codes ---- */
#define IA64_GENEX_UNIMPL_DATA_ADDR 43
#define IA64_GENEX_UNIMPL_INST_ADDR 69

/* ---- Protection Key Register fields ---- */
#define IA64_PKR_VALID       (1ULL << 0)
#define IA64_PKR_WD          (1ULL << 1)
#define IA64_PKR_RD          (1ULL << 2)
#define IA64_PKR_XD          (1ULL << 3)
#define IA64_PKR_KEY_SHIFT   8
#define IA64_PKR_KEY_MASK \
    (((1ULL << IA64_IMPL_KEY_BITS) - 1) << IA64_PKR_KEY_SHIFT)
#define IA64_PKR_MASK        (IA64_PKR_VALID | IA64_PKR_WD | IA64_PKR_RD | \
                              IA64_PKR_XD | IA64_PKR_KEY_MASK)

/* ---- PTE fields ---- */
#define IA64_PTE_PRESENT  (1ULL << 0)
#define IA64_PTE_ACCESSED (1ULL << 5)
#define IA64_PTE_DIRTY    (1ULL << 6)
#define IA64_PTE_ED       (1ULL << 52)
#define IA64_PTE_MA_SHIFT 2
#define IA64_PTE_MA_MASK  (7ULL << IA64_PTE_MA_SHIFT)
#define IA64_PTE_MA_WB      0
#define IA64_PTE_MA_UC      4
#define IA64_PTE_MA_UCE     5
#define IA64_PTE_MA_WC      6
#define IA64_PTE_MA_NATPAGE 7

static inline uint8_t ia64_pte_ma(uint64_t pte)
{
    return (pte & IA64_PTE_MA_MASK) >> IA64_PTE_MA_SHIFT;
}

/* ---- PTA fields ---- */
#define IA64_PTA_VE          (1ULL << 0)
#define IA64_PTA_SIZE_MASK   (0x3fULL << 2)
#define IA64_PTA_SIZE_SHIFT  2
#define IA64_PTA_VF          (1ULL << 8)
#define IA64_PTA_BASE_MASK   (~0x7fffULL)
#define IA64_PTA_BASE_SHIFT  15

/* ---- DCR fields ---- */
#define IA64_DCR_PP          (1ULL << 0)
#define IA64_DCR_BE          (1ULL << 1)
#define IA64_DCR_LC          (1ULL << 2)
#define IA64_DCR_DM          (1ULL << 8)
#define IA64_DCR_DP          (1ULL << 9)
#define IA64_DCR_DK          (1ULL << 10)
#define IA64_DCR_DX          (1ULL << 11)
#define IA64_DCR_DR          (1ULL << 12)
#define IA64_DCR_DA          (1ULL << 13)
#define IA64_DCR_DD          (1ULL << 14)

/*
 * Architecturally and software-convention-defined register indices.
 * See IA-64 SDM volume 2, section 11.8.2.5, and the FPSWA interface.
 */
typedef enum IA64GeneralRegisterIndex {
    IA64_GR_ZERO = 0,
    IA64_GR_GLOBAL_POINTER = 1,
    /*
     * Scratch t0/t1.  NT's DebugPrint/DebugPrompt breaks pass their
     * output buffer address and length here (WSRV03 rtl/ia64).
     */
    IA64_GR_NT_DEBUG_BUFFER = 2,
    IA64_GR_NT_DEBUG_LENGTH = 3,
    IA64_GR_RETURN0 = 8,
    IA64_GR_RETURN1 = 9,
    IA64_GR_RETURN2 = 10,
    IA64_GR_RETURN3 = 11,
    IA64_GR_STACK_POINTER = 12,
    IA64_GR_THREAD_POINTER = 13,
} IA64GeneralRegisterIndex;

typedef enum IA64PredicateRegisterIndex {
    IA64_PR_TRUE = 0,
    IA64_PR_ROTATING_BASE = 16,
    IA64_PR_ROTATING_NEXT = 17,
    IA64_PR_LAST = 63,
} IA64PredicateRegisterIndex;

typedef enum IA64BranchRegisterIndex {
    IA64_BR_RETURN_LINK = 0,
} IA64BranchRegisterIndex;

typedef enum IA64FloatingRegisterIndex {
    IA64_FR_ZERO_INDEX = 0,
    IA64_FR_ONE_INDEX = 1,
} IA64FloatingRegisterIndex;

typedef enum IA64RegionRegisterIndex {
    IA64_RR_REGION0 = 0,
    IA64_RR_REGION1 = 1,
    IA64_RR_REGION2 = 2,
    IA64_RR_REGION3 = 3,
    IA64_RR_REGION4 = 4,
    IA64_RR_REGION5 = 5,
    IA64_RR_REGION6 = 6,
    IA64_RR_REGION7 = 7,
} IA64RegionRegisterIndex;

typedef enum IA64ProtectionKeyRegisterIndex {
    IA64_PKR_0 = 0,
    IA64_PKR_1 = 1,
    IA64_PKR_2 = 2,
    IA64_PKR_3 = 3,
} IA64ProtectionKeyRegisterIndex;

typedef enum IA64PalGeneralRegisterIndex {
    IA64_PAL_GR_STATUS = IA64_GR_RETURN0,
    IA64_PAL_GR_RESULT1 = IA64_GR_RETURN1,
    IA64_PAL_GR_RESULT2 = IA64_GR_RETURN2,
    IA64_PAL_GR_RESULT3 = IA64_GR_RETURN3,
    IA64_PAL_GR_INDEX = 28,
    IA64_PAL_GR_ARG1 = 29,
    IA64_PAL_GR_ARG2 = 30,
    IA64_PAL_GR_ARG3 = 31,
} IA64PalGeneralRegisterIndex;

typedef enum IA64FirmwareDebugRegisterIndex {
    IA64_FW_DEBUG_GR_HANDLER = 16,
    IA64_FW_DEBUG_GR_EXCEPTION = 16,
    IA64_FW_DEBUG_GR_CONTEXT = 17,
    IA64_FW_DEBUG_GR_CPU = 18,
} IA64FirmwareDebugRegisterIndex;

typedef enum IA64FpswaGeneralRegisterIndex {
    IA64_FPSWA_GR_TRAP_TYPE = 32,
    IA64_FPSWA_GR_BUNDLE = 33,
    IA64_FPSWA_GR_IPSR_PTR = 34,
    IA64_FPSWA_GR_FPSR_PTR = 35,
    IA64_FPSWA_GR_ISR_PTR = 36,
    IA64_FPSWA_GR_PREDS_PTR = 37,
    IA64_FPSWA_GR_IFS_PTR = 38,
    IA64_FPSWA_GR_STATE = 39,
} IA64FpswaGeneralRegisterIndex;

typedef enum IA64ControlRegisterIndex {
    IA64_CR_DCR = 0,
    IA64_CR_ITM = 1,
    IA64_CR_IVA = 2,
    IA64_CR_PTA = 8,
    IA64_CR_IPSR = 16,
    IA64_CR_ISR = 17,
    IA64_CR_IIP = 19,
    IA64_CR_IFA = 20,
    IA64_CR_ITIR = 21,
    IA64_CR_IIPA = 22,
    IA64_CR_IFS = 23,
    IA64_CR_IIM = 24,
    IA64_CR_IHA = 25,
    IA64_CR_SAPIC_LID = 64,
    IA64_CR_SAPIC_IVR = 65,
    IA64_CR_SAPIC_TPR = 66,
    IA64_CR_SAPIC_EOI = 67,
    IA64_CR_SAPIC_IRR0 = 68,
    IA64_CR_SAPIC_IRR1 = 69,
    IA64_CR_SAPIC_IRR2 = 70,
    IA64_CR_SAPIC_IRR3 = 71,
    IA64_CR_ITV = 72,
    IA64_CR_PMV = 73,
    IA64_CR_CMCV = 74,
    IA64_CR_LRR0 = 80,
    IA64_CR_LRR1 = 81,
} IA64ControlRegisterIndex;

typedef enum IA64ApplicationRegisterIndex {
    IA64_AR_KR0 = 0,
    IA64_AR_KR7 = 7,
    IA64_AR_RSC = 16,
    IA64_AR_BSP = 17,
    IA64_AR_BSPSTORE = 18,
    IA64_AR_RNAT = 19,
    IA64_AR_FCR = 21,
    IA64_AR_EFLAG = 24,
    IA64_AR_CSD = 25,
    IA64_AR_SSD = 26,
    IA64_AR_CFLG = 27,
    IA64_AR_FSR = 28,
    IA64_AR_FIR = 29,
    IA64_AR_FDR = 30,
    IA64_AR_CCV = 32,
    IA64_AR_UNAT = 36,
    IA64_AR_FPSR = 40,
    IA64_AR_ITC = 44,
    IA64_AR_PFS = 64,
    IA64_AR_LC = 65,
    IA64_AR_EC = 66,
} IA64ApplicationRegisterIndex;

#define IA64_SPURIOUS_VECTOR      0x0F
#define IA64_VECTOR_MASKED        (1ULL << 16)
#define IA64_TPR_MIC_MASK         0x00000000000000f0ULL
#define IA64_TPR_MMI              (1ULL << 16)
#define IA64_TPR_WRITABLE_MASK    (IA64_TPR_MIC_MASK | IA64_TPR_MMI)

/* ---- TLB permissions ---- */
#define IA64_TLB_R           1
#define IA64_TLB_W           2
#define IA64_TLB_X           4
#define IA64_TLB_ALL         7

static inline uint8_t ia64_tlb_effective_perm(uint8_t ar, uint8_t pl,
                                              uint8_t access_level)
{
    if (access_level > 3 || pl > 3) {
        return 0;
    }

    switch (ar & 7) {
    case 0:
        return access_level <= pl ? IA64_TLB_R : 0;
    case 1:
        return access_level <= pl ? (IA64_TLB_R | IA64_TLB_X) : 0;
    case 2:
        return access_level <= pl ? (IA64_TLB_R | IA64_TLB_W) : 0;
    case 3:
        return access_level <= pl ? IA64_TLB_ALL : 0;
    case 4:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? (IA64_TLB_R | IA64_TLB_W) : IA64_TLB_R;
    case 5:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? IA64_TLB_ALL : (IA64_TLB_R | IA64_TLB_X);
    case 6:
        if (access_level > pl) {
            return 0;
        }
        return access_level < pl ? IA64_TLB_ALL : (IA64_TLB_R | IA64_TLB_W);
    case 7:
        return access_level == 0 ? (IA64_TLB_R | IA64_TLB_X) : IA64_TLB_X;
    default:
        return 0;
    }
}

/* ---- ALAT (Advanced Load Address Table) ---- */
#define IA64_ALAT_ENTRIES    32

typedef struct IA64AlatEntry {
    uint64_t phys_addr;
    uint8_t  size;
    uint8_t  reg;
    bool     fp;
    bool     valid;
} IA64AlatEntry;

/* ---- Exception type enum (internal IDs, not IVT vectors) ---- */
typedef enum IA64Exception {
    IA64_EXCP_NONE = 0,
    IA64_EXCP_BREAK = 1,
    IA64_EXCP_ILLEGAL = 2,
    IA64_EXCP_RESERVED_TEMPLATE = 3,
    IA64_EXCP_VHPT_FAULT = 4,
    IA64_EXCP_ITLB_FAULT = 5,
    IA64_EXCP_DTLB_FAULT = 6,
    IA64_EXCP_ALT_ITLB = 7,
    IA64_EXCP_ALT_DTLB = 8,
    IA64_EXCP_DATA_NESTED_TLB = 9,
    IA64_EXCP_DATA_ACCESS = 10,
    IA64_EXCP_GENERAL = 11,
    IA64_EXCP_NAT_CONSUMPTION = 12,
    IA64_EXCP_EXTINT = 13,
    IA64_EXCP_UNALIGNED = 14,
    IA64_EXCP_PAGE_NOT_PRESENT = 15,
    IA64_EXCP_INST_ACCESS = 16,
    IA64_EXCP_DATA_DIRTY = 17,
    IA64_EXCP_INST_ACCESS_BIT = 18,
    IA64_EXCP_DATA_ACCESS_BIT = 19,
    IA64_EXCP_INST_KEY_MISS = 20,
    IA64_EXCP_DATA_KEY_MISS = 21,
    IA64_EXCP_KEY_PERMISSION = 22,
    IA64_EXCP_UNIMPL_DATA_ADDR = 23,
    IA64_EXCP_UNIMPL_INST_ADDR = 24,
    IA64_EXCP_PRIVILEGED_OP = 25,
    IA64_EXCP_PRIVILEGED_REG = 26,
    IA64_EXCP_RESERVED_REG_FIELD = 27,
    IA64_EXCP_FP_FAULT = 28,
    IA64_EXCP_FP_TRAP = 29,
    IA64_EXCP_DISABLED_ISA_TRANSITION = 30,
    IA64_EXCP_DISABLED_FP = 31,
    IA64_EXCP_UNSUPPORTED_DATA_REFERENCE = 32,
    IA64_EXCP_VIRTUALIZATION = 33,
    IA64_EXCP_IA32_EXCEPTION = 34,
    IA64_EXCP_IA32_INTERCEPT = 35,
    IA64_EXCP_IA32_INTERRUPT = 36,
    IA64_EXCP_TAKEN_BRANCH = 37,
    IA64_EXCP_SINGLE_STEP = 38,
    IA64_EXCP_MAX,
} IA64Exception;

/* ---- IVT vector mapping table ---- */
extern const uint16_t ia64_ivt_vectors[IA64_EXCP_MAX];

static inline IA64Exception
ia64_pte_exception_for_access(uint64_t pte, uint8_t perm, uint8_t needed,
                              bool is_ifetch, bool is_write, uint64_t psr)
{
    if (!(pte & IA64_PTE_PRESENT)) {
        return IA64_EXCP_PAGE_NOT_PRESENT;
    }

    if ((perm & needed) != needed) {
        return is_ifetch ? IA64_EXCP_INST_ACCESS : IA64_EXCP_DATA_ACCESS;
    }

    /*
     * The Data Dirty Bit fault outranks the Data Access Bit fault, so a
     * store to a page with both bits clear reports the dirty-bit vector.
     * That is what lets an operating system resolve both bits from the one
     * handler (Linux's dirty_bit vector sets _PAGE_D|_PAGE_A) instead of
     * taking a second fault.
     */
    if (is_ifetch) {
        if (!(pte & IA64_PTE_ACCESSED) && !(psr & IA64_PSR_IA)) {
            return IA64_EXCP_INST_ACCESS_BIT;
        }
    } else {
        if (is_write && !(pte & IA64_PTE_DIRTY) &&
            !(psr & IA64_PSR_DA)) {
            return IA64_EXCP_DATA_DIRTY;
        }
        if (!(pte & IA64_PTE_ACCESSED) && !(psr & IA64_PSR_DA)) {
            return IA64_EXCP_DATA_ACCESS_BIT;
        }
    }

    return IA64_EXCP_NONE;
}

/* ---- TLB entry ---- */
typedef struct IA64TlbEntry {
    uint64_t va;
    uint64_t pa;
    uint64_t ps;
    uint64_t page_mask;
    uint64_t pte;
    uint8_t  perm;
    uint8_t  ar;
    uint8_t  pl;
    uint8_t  valid;
    uint8_t  is_tr;
    uint8_t  pending_purge;
    uint32_t rid;
    uint32_t key;
    uint16_t slot;
} IA64TlbEntry;

typedef struct IA64MicroTlbEntry {
    uint64_t va;
    uint64_t page_mask;
    uint32_t rid;
    uint32_t generation;
    uint16_t slot;
    bool valid;
} IA64MicroTlbEntry;

/*
 * The EFI 1.10 native debug-support ABI uses a fixed 1192-byte IA-64
 * context record.  Firmware places one record per vCPU immediately after
 * the architected IVT.  The emulator retains only the RSE bookkeeping that
 * is needed while a registered callback runs; architected state is carried
 * in the guest-visible context record itself.
 */
#define IA64_FW_DEBUG_CONTEXT_BASE    0x0000000000018000ULL
#define IA64_FW_DEBUG_CONTEXT_STRIDE  0x800ULL
#define IA64_FW_DEBUG_CONTEXT_SIZE    1192U
#define IA64_FW_DEBUG_MAX_CPUS        4U
#define IA64_FW_DEBUG_STACK_BASE      0x0000000000020000ULL
#define IA64_FW_DEBUG_STACK_SIZE      0x8000ULL

typedef struct IA64FirmwareDebugRseState {
    uint64_t pgr[IA64_STACKED_GR_COUNT];
    uint64_t pgr_nat[2];
    uint64_t gr_dirty[2];
    uint64_t bsp;
    uint64_t bspstore;
    uint64_t rnat;
    uint32_t bol;
    int32_t dirty;
    int32_t dirty_nat;
    int32_t clean;
    int32_t clean_nat;
    int32_t invalid;
    uint32_t rnat_first;
    uint8_t cfm_sof;
    uint8_t cfm_sol;
    uint8_t cfm_sor;
    uint8_t cfm_rrb_gr;
    uint8_t cfm_rrb_fr;
    uint8_t cfm_rrb_pr;
    bool cfle;
} IA64FirmwareDebugRseState;

typedef enum IA64MemorySpeculation {
    IA64_MEM_NON_SPECULATIVE,
    IA64_MEM_LIMITED_SPECULATION,
    IA64_MEM_SPECULATIVE,
} IA64MemorySpeculation;

static inline IA64MemorySpeculation
ia64_pte_memory_speculation(uint64_t pte)
{
    switch ((pte >> 2) & 7) {
    case 0: /* WB */
    case 6: /* WC */
    case 7: /* NaTPage */
        return IA64_MEM_SPECULATIVE;
    case 4: /* UC */
    case 5: /* UCE */
    default:
        return IA64_MEM_NON_SPECULATIVE;
    }
}

static inline bool ia64_tlb_entry_present(const IA64TlbEntry *entry)
{
    return entry->pte & IA64_PTE_PRESENT;
}

static inline void ia64_tlb_entry_translate(const IA64TlbEntry *entry,
                                            uint64_t va,
                                            uint8_t access_level,
                                            uint64_t *pa, uint8_t *perm)
{
    uint64_t page_offset = va & (entry->ps - 1);

    *pa = (entry->pa & ~(entry->ps - 1)) | page_offset;
    *perm = ia64_tlb_entry_present(entry) ?
            ia64_tlb_effective_perm(entry->ar, entry->pl, access_level) : 0;
}

#include "internals.h"
#include "ia32/compat.h"

/* ---- CPU architectural state ---- */
typedef struct CPUArchState {
    /*
     * Keep the private IA-32 backing state at offset zero.  The x86 TCG
     * translator addresses CPUX86State fields relative to tcg_env; placing
     * this view first lets those offsets be reused without a second CPU
     * object or a fork of the x86 decoder.
     */
    CPUX86State ia32;

    /* General / Predicate / Branch registers */
    uint64_t gr[IA64_GR_COUNT];
    uint64_t pr[IA64_PR_COUNT];
    uint64_t br[IA64_BR_COUNT];
    uint64_t ip;
    uint64_t last_successful_bundle;
    uint64_t psr;

    /* NaT bits for GRs (2x64 bits, little-endian bit numbering) */
    uint64_t nat[2];

    /* Inactive bank for GR16-GR31 selected by PSR.bn/bsw. */
    uint64_t banked_gr[16];
    uint16_t banked_nat;

    IA64ExceptionState exception_state;

    /* Control Registers */
    uint64_t cr[IA64_CR_COUNT];
#define cr_dcr    cr[IA64_CR_DCR]
#define cr_itm    cr[IA64_CR_ITM]
#define cr_iva    cr[IA64_CR_IVA]
#define cr_pta    cr[IA64_CR_PTA]
#define cr_ipsr   cr[IA64_CR_IPSR]
#define cr_isr    cr[IA64_CR_ISR]
#define cr_iip    cr[IA64_CR_IIP]
#define cr_ifa    cr[IA64_CR_IFA]
#define cr_itir   cr[IA64_CR_ITIR]
#define cr_iipa   cr[IA64_CR_IIPA]
#define cr_ifs    cr[IA64_CR_IFS]
#define cr_iim    cr[IA64_CR_IIM]
#define cr_iha    cr[IA64_CR_IHA]

    /* Model-specific registers */
    uint64_t msr[IA64_MSR_COUNT];
    uint64_t pmc[IA64_PMC_COUNT];
    uint64_t pmd[IA64_PMD_COUNT];
    uint64_t pkr[IA64_PKR_COUNT];

    /* Debug and instruction break registers */
    uint64_t dbr[IA64_DBR_COUNT];
    uint64_t ibr[IA64_IBR_COUNT];
    uint64_t dahr[8];
    uint8_t ia32_data_breakpoints;

    /* Rollback state for precise IA-32 Streaming SIMD exceptions. */
    bool ia32_sse_instruction_active;
    uint16_t ia32_sse_old_flags;
    target_ulong ia32_sse_old_cc_dst;
    target_ulong ia32_sse_old_cc_src;
    target_ulong ia32_sse_old_cc_src2;
    uint32_t ia32_sse_old_cc_op;
    FPReg ia32_sse_old_fpregs[8];
    uint64_t ia32_sse_old_xmm[8][2];

    /* Region Registers */
    uint64_t rr[IA64_RR_COUNT];

    /* Application Registers */
    uint64_t ar[IA64_AR_COUNT];
#define ar_kr0    ar[IA64_AR_KR0]
#define ar_kr7    ar[IA64_AR_KR7]
#define ar_rsc    ar[IA64_AR_RSC]
#define ar_bsp    ar[IA64_AR_BSP]
#define ar_bspstore ar[IA64_AR_BSPSTORE]
#define ar_rnat   ar[IA64_AR_RNAT]
#define ar_fcr    ar[IA64_AR_FCR]
#define ar_eflag  ar[IA64_AR_EFLAG]
#define ar_csd    ar[IA64_AR_CSD]
#define ar_ssd    ar[IA64_AR_SSD]
#define ar_cflg   ar[IA64_AR_CFLG]
#define ar_fsr    ar[IA64_AR_FSR]
#define ar_fir    ar[IA64_AR_FIR]
#define ar_fdr    ar[IA64_AR_FDR]
#define ar_ccv    ar[IA64_AR_CCV]
#define ar_unat   ar[IA64_AR_UNAT]
#define ar_fpsr   ar[IA64_AR_FPSR]
#define ar_itc    ar[IA64_AR_ITC]
#define ar_pfs    ar[IA64_AR_PFS]
#define ar_lc     ar[IA64_AR_LC]
#define ar_ec     ar[IA64_AR_EC]
    /* Current Frame Marker (derived from pfs bits) */
    uint8_t cfm_sof;
    uint8_t cfm_sol;
    uint8_t cfm_sor;
    uint8_t cfm_rrb_gr;
    uint8_t cfm_rrb_fr;
    uint8_t cfm_rrb_pr;

    IA64MMUState mmu;
    IA64SalBridgeState sal_bridge;
    IA64InterruptState interrupt;
    IA64PalState pal;

    /*
     * Register Stack Engine state (SDM Vol.2 ch.6).  The register
     * stack backing store in guest memory is the authoritative home of
     * stacked register values; the emulator keeps the architecture's
     * physical stacked register file and its four partitions
     * explicitly.  rse_pgr[]/rse_pgr_nat[] form the circular physical
     * file and rse_bol is RSE.BOF, the physical index of the current
     * frame's GR32.  env->gr[32..127] only cache the virtual
     * (renamed/rotated) view of the current frame and are
     * re-synchronized with the physical file whenever the frame
     * mapping changes.
     *
     * Partition counters follow SDM Vol.2 6.3 (all counts in
     * registers; the intervening NaT collection words of a partition
     * are counted separately by the *_nat fields):
     *   cfm_sof + rse_dirty + rse_clean + rse_invalid == 96
     *   AR.BSPSTORE == AR.BSP - 8*(rse_dirty + rse_dirty_nat)
     * rse_dirty/rse_dirty_nat go negative while the current frame is
     * incomplete (mandatory RSE loads pending after br.ret/rfi,
     * SDM Vol.2 6.8).  rse_cfle is RSE.CFLE (SDM Vol.2 table 6-1): it
     * is set while a br.ret/rfi mandatory load sequence is in
     * progress and cleared by interruption delivery or by completing
     * the sequence.
     */
    IA64RSEState rse;

    bool instruction_group_start;  /* next instruction starts a new group */

    IA64AlatState alat_state;

    /* Performance counter */
    uint64_t bundles_retired;

    IA64FPState fp;

} CPUIA64State;

void ia64_tlb_bump_generation(CPUIA64State *env, bool is_ifetch);
const IA64TlbEntry *ia64_tlb_find_slow(CPUIA64State *env, uint64_t va,
                                       uint32_t rid, bool is_ifetch);

static inline void ia64_rse_mark_gr_dirty(CPUIA64State *env, uint32_t reg)
{
    if (reg >= IA64_STACKED_GR_BASE && reg < IA64_GR_COUNT) {
        uint32_t bit = reg - IA64_STACKED_GR_BASE;

        env->rse.rse_gr_dirty[bit / 64] |= 1ULL << (bit % 64);
    }
}

void ia64_set_cfm_rrb_fr(CPUIA64State *env, uint32_t new_rrb);
void ia64_flush_suppressed_tlb(CPUIA64State *env);
void ia64_firmware_debug_capture(CPUIA64State *env, uint16_t vector,
                                 bool collected);

static inline bool ia64_key_check_enabled(const CPUIA64State *env,
                                          bool is_ifetch, bool is_rse)
{
    uint64_t translation_bit;

    if (!(env->psr & IA64_PSR_PK)) {
        return false;
    }

    translation_bit = is_ifetch ? IA64_PSR_IT :
                      (is_rse ? IA64_PSR_RT : IA64_PSR_DT);
    return env->psr & translation_bit;
}

/*
 * Raw protection-key lookup, gated only by the caller.  Used directly by
 * probe, whose key checks depend on PSR.pk alone: the probe query is a
 * virtual DTLB lookup even while PSR.dt is 0.
 */
static inline IA64Exception
ia64_key_exception_for_key(const CPUIA64State *env, uint32_t key,
                           uint8_t needed, bool is_ifetch)
{
    const uint64_t pkr_key = (uint64_t)key << IA64_PKR_KEY_SHIFT;
    uint64_t disable_bits = 0;
    bool matched = false;

    for (uint32_t i = 0; i < IA64_PKR_COUNT; i++) {
        uint64_t pkr = env->pkr[i];

        if ((pkr & IA64_PKR_VALID) &&
            (pkr & IA64_PKR_KEY_MASK) == pkr_key) {
            matched = true;
            disable_bits = pkr;
            break;
        }
    }

    if (!matched) {
        return is_ifetch ? IA64_EXCP_INST_KEY_MISS :
                           IA64_EXCP_DATA_KEY_MISS;
    }

    if (((needed & IA64_TLB_R) && (disable_bits & IA64_PKR_RD)) ||
        ((needed & IA64_TLB_W) && (disable_bits & IA64_PKR_WD)) ||
        ((needed & IA64_TLB_X) && (disable_bits & IA64_PKR_XD))) {
        return IA64_EXCP_KEY_PERMISSION;
    }

    return IA64_EXCP_NONE;
}

static inline IA64Exception
ia64_key_exception_for_access(const CPUIA64State *env, uint32_t key,
                              uint8_t needed, bool is_ifetch, bool is_rse)
{
    if (!ia64_key_check_enabled(env, is_ifetch, is_rse)) {
        return IA64_EXCP_NONE;
    }

    return ia64_key_exception_for_key(env, key, needed, is_ifetch);
}

static inline IA64Exception
ia64_translation_exception_for_access(const CPUIA64State *env, uint64_t pte,
                                      uint32_t key, uint8_t perm,
                                      uint8_t needed, bool is_ifetch,
                                      bool is_write, bool is_rse)
{
    IA64Exception excp;

    /*
     * Once a translation is found the remaining faults are checked in the
     * architected order: Page Not Present, NaT Page Consumption, Key Miss,
     * Key Permission, Access Rights, Dirty Bit, Access Bit.
     */
    if (!(pte & IA64_PTE_PRESENT)) {
        return IA64_EXCP_PAGE_NOT_PRESENT;
    }

    /*
     * A NaTPage translation prevents every non-speculative reference:
     * instruction fetches, loads, stores and semaphores all raise NaT Page
     * Consumption.  Control-speculative loads instead defer the fault, which
     * the speculative probe helper decides before the access is attempted.
     */
    if (ia64_pte_ma(pte) == IA64_PTE_MA_NATPAGE) {
        return IA64_EXCP_NAT_CONSUMPTION;
    }

    excp = ia64_key_exception_for_access(env, key, needed, is_ifetch, is_rse);
    if (excp != IA64_EXCP_NONE) {
        return excp;
    }

    return ia64_pte_exception_for_access(pte, perm, needed, is_ifetch,
                                         is_write, env->psr);
}

static inline IA64Exception
ia64_tlb_exception_for_access(const CPUIA64State *env,
                              const IA64TlbEntry *entry, uint8_t perm,
                              uint8_t needed, bool is_ifetch,
                              bool is_write, bool is_rse)
{
    return ia64_translation_exception_for_access(env, entry->pte, entry->key,
                                                perm, needed, is_ifetch,
                                                is_write, is_rse);
}

static inline uint8_t ia64_rr_index(uint64_t va)
{
    return (va >> IA64_REGION_SHIFT) & IA64_REGION_MASK;
}

static inline uint64_t ia64_va_vpn_mask(uint64_t ps)
{
    return IA64_REGION7_PHYS_MASK & ~(ps - 1);
}

static inline uint64_t ia64_va_page_base(uint64_t va, uint64_t ps)
{
    return va & ia64_va_vpn_mask(ps);
}

static inline bool ia64_tlb_match(const IA64TlbEntry *entry, uint64_t va,
                                  uint32_t rid)
{
    if (!entry->valid || entry->ps == 0 || entry->rid != rid) {
        return false;
    }

    return ((va ^ entry->va) & entry->page_mask) == 0;
}

static inline QEMU_ALWAYS_INLINE const IA64TlbEntry *
ia64_tlb_find_cached(CPUIA64State *env, uint64_t va, uint32_t rid,
                     bool is_ifetch)
{
    IA64TlbEntry *tlb = is_ifetch ? env->mmu.tlb_inst : env->mmu.tlb_data;
    IA64MicroTlbEntry *micro = is_ifetch ? env->mmu.tlb_inst_micro :
                                           env->mmu.tlb_data_micro;
    uint8_t next = is_ifetch ? env->mmu.tlb_inst_micro_next :
                               env->mmu.tlb_data_micro_next;
    uint32_t generation = is_ifetch ? env->mmu.tlb_inst_generation :
                                      env->mmu.tlb_data_generation;
    uint16_t i;

    for (i = 0; i < IA64_MICRO_TLB_SIZE; i++) {
        uint16_t slot = (next - 1 - i) & (IA64_MICRO_TLB_SIZE - 1);
        IA64MicroTlbEntry *cached = &micro[slot];

        if (!cached->valid || cached->generation != generation ||
            cached->rid != rid ||
            ((va ^ cached->va) & cached->page_mask) != 0) {
            continue;
        }
        return &tlb[cached->slot];
    }

    return ia64_tlb_find_slow(env, va, rid, is_ifetch);
}

static inline bool ia64_tlb_entry_covers_va_any_rid(const IA64TlbEntry *entry,
                                                    uint64_t va)
{
    if (!entry->valid || entry->ps == 0) {
        return false;
    }
    if (ia64_rr_index(entry->va) != ia64_rr_index(va)) {
        return false;
    }
    return ((entry->va ^ va) & entry->page_mask) == 0;
}

static inline bool ia64_tlb_has_explicit_va_mapping(const IA64TlbEntry *tlb,
                                                    uint16_t tlb_count,
                                                    uint64_t va)
{
    uint16_t i;

    for (i = 0; i < tlb_count; i++) {
        if (ia64_tlb_entry_covers_va_any_rid(&tlb[i], va)) {
            return true;
        }
    }
    return false;
}

static inline bool ia64_page_shift_insertable(uint8_t page_shift)
{
    return (IA64_INSERTABLE_PAGE_SIZE_MASK >> page_shift) & 1;
}

static inline uint32_t ia64_region_rid(const CPUIA64State *env, uint64_t va)
{
    return ia64_rr_rid(env->rr[ia64_rr_index(va)]);
}

static inline bool ia64_current_code_tlb_ed(CPUIA64State *env)
{
    const IA64TlbEntry *entry;
    uint32_t rid;

    if (!(env->psr & IA64_PSR_IT)) {
        return false;
    }

    rid = ia64_region_rid(env, env->ip);
    entry = ia64_tlb_find_cached(env, env->ip, rid, true);
    return entry && (entry->pte & IA64_PTE_ED);
}

static inline uint64_t ia64_region_itir(const CPUIA64State *env, uint64_t va)
{
    uint64_t rr = env->rr[ia64_rr_index(va)];

    return (rr & (IA64_ITIR_PS_MASK << IA64_ITIR_PS_SHIFT)) |
           (((rr & IA64_RR_RID_MASK) >> IA64_RR_RID_SHIFT) <<
            IA64_ITIR_KEY_SHIFT);
}

static inline bool ia64_sal_boot_environment_active(const CPUIA64State *env)
{
    return env->cr_iva == IA64_FIRMWARE_IVT_BASE &&
           (env->psr & IA64_PSR_IC) != 0;
}

static inline bool ia64_data_nested_tlb_active(const CPUIA64State *env)
{
    return !(env->psr & IA64_PSR_IC) && !env->exception_state.psr_ic_inflight;
}

static inline bool ia64_sal_boot_virtual_pa(const CPUIA64State *env,
                                            uint64_t va, uint64_t *pa)
{
    /*
     * Before ExitBootServices(), IA-64 OS loaders execute under the SAL
     * environment and may run in virtual mode while SAL still owns IVA and
     * translation faults.  Model SAL's boot-time identity mappings when the
     * firmware IVT is still active.
     */
    if (!ia64_sal_boot_environment_active(env)) {
        return false;
    }

    if (ia64_rr_index(va) == 0 && va < IA64_FW_BOOT_IDENTITY_LIMIT) {
        *pa = va;
        return true;
    }

    return false;
}

static inline bool ia64_sal_boot_identity_pa_type(const CPUIA64State *env,
                                                  uint64_t va, uint64_t *pa,
                                                  bool is_inst)
{
    uint64_t phys;

    /*
     * An explicit TR/TC for the same virtual range always wins: a RID
     * mismatch there must remain an architectural TLB miss rather than
     * silently falling back to a different identity physical address.  (This
     * is only reached after the cached TLB/TR lookup has already missed.)
     *
     * ITRs and DTRs are independent translation resources (SDM Vol.2 4.1.1):
     * a data reference must only defer to data TRs and an instruction fetch
     * only to instruction TRs.  The XP-era loader installs a 4th ITR for its
     * [64-80MB] decompression range but no matching DTR; a *data* read there
     * (e.g. KdInitSystem walking a loader debug block) must therefore still
     * reach the region-7 direct map below rather than deferring to that ITR
     * and taking a VHPT fault into the not-yet-installed self-map (0x2B).
     */
    if (is_inst) {
        if (ia64_tlb_has_explicit_va_mapping(
                env->mmu.tlb_inst, env->mmu.tlb_inst_count, va)) {
            return false;
        }
    } else {
        if (ia64_tlb_has_explicit_va_mapping(
                env->mmu.tlb_data, env->mmu.tlb_data_count, va)) {
            return false;
        }
    }

    phys = va & IA64_REGION7_PHYS_MASK;

    /*
     * Persistent region-7 physical alias (the "KSEG" direct map): the IA-64
     * OS loaders and the early kernel reach loader-built structures near the
     * top of RAM through region-7 VA = PA + IA64_FW_REGION7_DIRECTMAP_BASE
     * before the kernel's self-mapped page tables are active (e.g.
     * KdInitSystem walks a loader debug-block list this way).  Model it as a
     * last-resort translation that survives the loader -> kernel handoff,
     * bounded to backed RAM (region7_directmap_limit = base + guest RAM size)
     * so that paged system space and the recursive page-table self-map window
     * -- both above the alias -- still take ordinary TLB-miss faults.
     */
    if (ia64_rr_index(va) == 7 &&
        phys >= IA64_FW_REGION7_DIRECTMAP_BASE &&
        phys < env->mmu.region7_directmap_limit) {
        *pa = phys - IA64_FW_REGION7_DIRECTMAP_BASE;
        return true;
    }

    /*
     * The remaining identity behaviour models SAL's boot-time TLB miss handler
     * and only applies while SAL still owns the IVT (until ExitBootServices()
     * completes).  It is a miss fallback only.
     */
    if (!ia64_sal_boot_environment_active(env)) {
        return false;
    }

    if (phys >= IA64_FW_BOOT_IDENTITY_LIMIT) {
        return false;
    }

    if (phys >= IA64_FW_REGION7_DIRECTMAP_BASE) {
        phys -= IA64_FW_REGION7_DIRECTMAP_BASE;
    }

    *pa = phys;
    return true;
}

/* Data-reference default: defers only to data TRs. */
static inline bool ia64_sal_boot_identity_pa(const CPUIA64State *env,
                                             uint64_t va, uint64_t *pa)
{
    return ia64_sal_boot_identity_pa_type(env, va, pa, false);
}

static inline bool ia64_vhpt_config_valid(const CPUIA64State *env,
                                          uint8_t *size,
                                          bool *long_format)
{
    uint64_t pta = env->cr_pta;

    /*
     * PTA.ve gates only the hardware VHPT walker.  Software-visible thash and
     * IHA still use the configured PTA base, size, and format.
     */
    *size = (pta & IA64_PTA_SIZE_MASK) >> IA64_PTA_SIZE_SHIFT;
    *long_format = pta & IA64_PTA_VF;
    if (*size < 15 || *size > (*long_format ? 61 : 52)) {
        return false;
    }
    return true;
}

static inline bool ia64_vhpt_walker_enabled(const CPUIA64State *env,
                                            uint64_t va, bool is_ifetch,
                                            bool is_rse,
                                            uint8_t *size,
                                            bool *long_format)
{
    if (!(env->cr_pta & IA64_PTA_VE)) {
        return false;
    }
    if (!ia64_vhpt_config_valid(env, size, long_format)) {
        return false;
    }
    if (!(env->rr[ia64_rr_index(va)] & IA64_RR_VE)) {
        return false;
    }
    if (!(env->psr & IA64_PSR_DT) ||
        (is_rse && !(env->psr & IA64_PSR_RT))) {
        return false;
    }
    if (is_ifetch &&
        (env->psr & (IA64_PSR_IT | IA64_PSR_IC)) !=
        (IA64_PSR_IT | IA64_PSR_IC)) {
        return false;
    }
    return true;
}

static inline bool ia64_exception_initializes_iha(int excp)
{
    return excp != IA64_EXCP_ALT_ITLB &&
           excp != IA64_EXCP_ALT_DTLB &&
           excp != IA64_EXCP_DATA_NESTED_TLB &&
           excp != IA64_EXCP_INST_KEY_MISS &&
           excp != IA64_EXCP_DATA_KEY_MISS &&
           excp != IA64_EXCP_KEY_PERMISSION;
}

bool ia64_vhpt_walk(CPUIA64State *env, uint64_t va, uint32_t rid,
                    bool is_ifetch, bool is_rse, uint8_t access_level,
                    uint64_t *pa, uint8_t *perm);
bool ia64_vhpt_walk_full(CPUIA64State *env, uint64_t va, uint32_t rid,
                         bool is_ifetch, bool is_rse, uint8_t access_level,
                         uint64_t *pa, uint8_t *perm, uint64_t *pte,
                         uint32_t *key,
                         const IA64TlbEntry **installed_entry);
bool ia64_vhpt_pte_not_present(CPUIA64State *env, uint64_t va,
                               bool is_ifetch, bool is_rse,
                               uint64_t *entry_va);
bool ia64_vhpt_entry_accessible(CPUIA64State *env, uint64_t va,
                                bool is_ifetch, bool is_rse,
                                uint64_t *entry_va);
uint64_t ia64_vhpt_hash_address(CPUIA64State *env, uint64_t va);
bool ia64_translate_data_access(CPUIA64State *env, uint64_t va,
                                bool is_write, uint64_t *pa);

void ia64_set_psr(CPUIA64State *env, uint64_t value);
void ia64_set_psr_bn(CPUIA64State *env, bool bank1);
void ia64_rse_delivery_check(CPUIA64State *env, int excp);

CPUState *ia64_cpu_by_sapic_id(uint8_t id, uint8_t eid);
void ia64_sapic_set_irq(CPUState *cs, uint8_t vector);
void ia64_sapic_update_interrupt(CPUIA64State *env);
bool ia64_sapic_has_pending(CPUIA64State *env);
int  ia64_sapic_accept(CPUIA64State *env);
void ia64_sapic_eoi(CPUIA64State *env);
int  ia64_sapic_get_ivr(CPUIA64State *env);
void ia64_itm_update(CPUIA64State *env, uint64_t itm_value);
void ia64_itc_sync(CPUIA64State *env);
void ia64_itc_advance_pending_itm(CPUIA64State *env);
void ia64_itc_check_timer(CPUIA64State *env);
void ia64_itc_enter_halt(CPUIA64State *env);

#define IA64_ITC_NS_PER_TICK 5

static inline bool ia64_external_interrupt_vector_valid(uint8_t vector)
{
    return vector == 0 || vector == 2 || vector >= 16;
}

static inline int64_t ia64_itc_clock_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static inline uint64_t ia64_itc_read(CPUIA64State *env)
{
    ia64_itc_advance_pending_itm(env);
    return env->ar_itc;
}

static inline void ia64_itc_write(CPUIA64State *env, uint64_t value)
{
    env->ar_itc = value;
    env->interrupt.itc_delta = ia64_itc_clock_ns();
    env->interrupt.itm_last_match_valid = false;
}

typedef struct IA64BootInfo {
    uint64_t firmware_base;
    uint64_t firmware_entry;
    uint64_t global_pointer;
    uint64_t iva;
    uint64_t bsp;
    uint64_t stack_pointer;
    uint64_t rsc;
    bool powered_off;
} IA64BootInfo;

struct ArchCPU {
    CPUState parent_obj;
    CPUIA64State env;
    QEMUTimer *itm_timer;
    IA64BootInfo boot_info;
    IA64FirmwareDebugState firmware_debug;
    bool boot_info_valid;
    bool boot_info_pending;
    bool alat_full;
    uint32_t socket_id;
    uint32_t core_id;
    uint32_t thread_id;
    uint32_t cores_per_socket;
    uint32_t threads_per_core;
    uint32_t package_base;
    uint32_t package_cpus;
};

void ia64_cpu_set_boot_info(IA64CPU *cpu, const IA64BootInfo *info);
void ia64_cpu_reset_to_boot_info(IA64CPU *cpu);

/*
 * Model-dependent PAL response data.  Rather than sprinkling is_montecito /
 * is_merced conditionals through the PAL dispatcher, each CPU model points at
 * one profile carrying the values that differ between generations.  Values that
 * are still identical across every supported model (PAL_VERSION words, cache
 * geometry, PA/VA widths) stay shared in arch/pal.c and are not duplicated
 * here; add them to the profile when a model needs to differ.
 */
typedef struct IA64PalProfile {
    /* PAL_FREQ_BASE base clock in Hz. */
    uint64_t freq_base_hz;
    /* PAL_FREQ_RATIOS: each ratio is reported as (num << 32) | den. */
    uint32_t proc_ratio_num, proc_ratio_den;   /* processor / base */
    uint32_t bus_ratio_num, bus_ratio_den;      /* system bus / base */
    uint32_t itc_ratio_num, itc_ratio_den;      /* interval timer / base */
    /*
     * PAL procedures that post-date the original Itanium (Merced).  When false,
     * these indices return PAL_STATUS_NOT_IMPLEMENTED so the merced model
     * reports the Merced-era PAL surface (245318-001/-002 §11.8).
     */
    bool has_post_merced_pal;
} IA64PalProfile;

struct IA64CPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;

    /* Guest-visible processor-model data. */
    uint64_t cpuid_version;
    uint64_t cpuid_features;
    /*
     * Translation-register file sizes.  These are asymmetric on the original
     * Itanium (8 ITR / 48 DTR, 248701-002 §2.5.6); Madison/Montecito use 64 of
     * each in this model.  Bounds-checked separately for itr.i vs itr.d.
     */
    uint8_t itr_count;
    uint8_t dtr_count;
    bool has_native_ia32;
    bool has_virtualization;
    bool is_montecito;
    const IA64PalProfile *pal;
};

static inline IA64CPU *ia64_cpu_from_cpu_state(CPUState *cs)
{
    return container_of(cs, IA64CPU, parent_obj);
}

static inline IA64FirmwareDebugState *
ia64_firmware_debug_state(CPUIA64State *env)
{
    return &ia64_cpu_from_cpu_state(env_cpu(env))->firmware_debug;
}

static inline const IA64FirmwareDebugState *
ia64_firmware_debug_state_const(const CPUIA64State *env)
{
    return &ia64_cpu_from_cpu_state(env_cpu((CPUIA64State *)env))
            ->firmware_debug;
}

static inline IA64CPUClass *ia64_env_cpu_class(CPUIA64State *env)
{
    return IA64_CPU_GET_CLASS(ia64_cpu_from_cpu_state(env_cpu(env)));
}

#endif
