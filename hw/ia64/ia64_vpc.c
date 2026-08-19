/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * IA-64 virtual PC platform.
 *
 * Provides RAM, a bootstrap CPU, a memory-mapped serial console,
 * firmware ROM loading via -bios, a PCI host bridge, SCSI and AHCI storage
 * controllers, an Ethernet controller, OHCI/UHCI USB,
 * local SAPIC/I/O SAPIC wiring,
 * and ACPI fixed power-management registers.
 */

#include "qemu/osdep.h"

#include CONFIG_DEVICES

#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/char/serial-mm.h"
#include "hw/display/bochs-vbe.h"
#include "hw/display/edid.h"
#include "hw/display/vga_regs.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ahci-pci.h"
#include "hw/ide/ide-dev.h"
#include "hw/ide/pci.h"
#include "hw/input/i8042.h"
#include "hw/acpi/acpi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "net/net.h"
#include "hw/isa/isa.h"
#include "hw/usb/hcd-uhci.h"
#include "hw/usb/usb.h"
#include "hw/ia64/ia64_loader.h"
#include "hw/ia64/ia64_pci.h"
#include "hw/ia64/ia64_iosapic.h"
#include "hw/ia64/ia64_agp.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"
#include "system/rtc.h"
#include "system/runstate.h"
#include "system/system.h"
#include "system/reset.h"
#include "system/watchdog.h"
#include "target/ia64/cpu-qom.h"
#include "target/ia64/cpu.h"

#define IA64_FW_BASE    0x0000000000100000ULL
/*
 * Firmware image loaded when no -bios is given.  It is installed beside the
 * binary (share/), so an unpacked package runs without naming it every time.
 */
#define IA64_VPC_DEFAULT_FIRMWARE "ia64-firmware.bin"
/*
 * Low (sub-aperture) DRAM runs contiguously from 0 up to the PCI/MMIO
 * aperture, exactly as the real 460GX keeps a single MMIO gap at the top of
 * the 32-bit space; RAM displaced by that gap is remapped above 4 GiB.  There
 * is no DRAM island between the aperture and the chipset/SAPIC region.
 */
#define IA64_LOW_RAM_LIMIT IA64_PCI_MMIO_BASE
#define IA64_FIRMWARE_ADDRESS_SPACE_BASE 0x00000000ff000000ULL
#define IA64_FIRMWARE_ADDRESS_SPACE_SIZE (16 * MiB)
#define IA64_RTC_BASE 0x00000000ffef0000ULL
#define IA64_RTC_SIZE (8 * KiB)
#define IA64_WATCHDOG_BASE 0x00000000ffee0000ULL
#define IA64_WATCHDOG_SIZE (4 * KiB)
#define IA64_WATCHDOG_TIMEOUT 0x00
#define IA64_WATCHDOG_CODE    0x08
#define IA64_NVRAM_BASE 0x00000000fff00000ULL
#define IA64_NVRAM_SIZE (64 * KiB)
#define IA64_NVRAM_COMMIT_OFFSET (IA64_NVRAM_SIZE - 8)
#define IA64_NVRAM_COMMIT_MAGIC 0x54494d4d4f43564eULL /* "NVCOMMIT" */
#define IA64_HIGH_RAM_AFTER_FIRMWARE_BASE \
    (IA64_FIRMWARE_ADDRESS_SPACE_BASE + IA64_FIRMWARE_ADDRESS_SPACE_SIZE)
#define IA64_IVT_BASE   0x10000ULL
#define IA64_IVT_SIZE   0x8000ULL
#define IA64_AHCI_IDP_IO_BASE   0x0000c100U
#define IA64_UHCI_IO_BASE       0x0000c120U
/* LSI BAR0 is 0x100 bytes and therefore requires 0x100-byte alignment. */
#define IA64_LSI_IO_BASE        0x0000c200U
#define IA64_VGA_IO_BASE        0x0000c300U
#define IA64_E1000_IO_BASE      0x0000c400U
#define IA64_OHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00010000ULL)
#define IA64_AHCI_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00020000ULL)
#define IA64_LSI_MMIO_PCI_BASE  (IA64_PCI_MMIO_BASE + 0x00030000ULL)
#define IA64_LSI_RAM_PCI_BASE   (IA64_PCI_MMIO_BASE + 0x00032000ULL)
#define IA64_E1000_MMIO_PCI_BASE (IA64_PCI_MMIO_BASE + 0x00040000ULL)
#define IA64_E1000_MMIO_SIZE    0x00020000ULL
#define IA64_E1000_IO_SIZE      0x00000040U
/*
 * Per-adapter slice of the NIC memory / I/O windows.  Sized to hold the
 * largest BAR set of any supported model: the Intel PRO/100 needs a 1 MiB
 * flash BAR on top of its CSR/I/O BARs, so reserve 2 MiB of memory (and a
 * generous I/O slice) per adapter.  MAX_NICS slices stay well inside the
 * PCI0 _CRS windows the firmware advertises.
 */
#define IA64_NIC_MMIO_STRIDE    0x00200000ULL
#define IA64_NIC_IO_STRIDE      0x00000100U
#define IA64_VGA_FB_PCI_BASE    (IA64_PCI_MMIO_BASE + 0x02000000ULL)
#define IA64_VGA_MMIO_PCI_BASE  (IA64_PCI_MMIO_BASE + 0x07000000ULL)
#define IA64_VGA_ROM_PCI_BASE   (IA64_PCI_MMIO_BASE + 0x08000000ULL)
#define IA64_VGA_LEGACY_BASE   0x000a0000U
#define IA64_VGA_LEGACY_SIZE   0x00020000U
#ifdef CONFIG_IA64_VPC_GRAPHICS
#define IA64_INT10_ROM_BASE     0x000c0000U
/*
 * At least 2 KB: the XP inbox Rage 128 miniport validates the option ROM's
 * size byte and rejects images smaller than 4 x 512 bytes
 * (.GetVgaEnabledRomImage compares size_byte << 9 against 2048 and logs
 * event 0xC1010002 UniqueId 26 on failure).
 */
#define IA64_INT10_ROM_SIZE     0x00000800U
/*
 * PCIR sits above the ATI data blocks.  A real Rage 128 Pro BIOS keeps it
 * at 16Ch, well clear of both the ATI ROM signature at 30h and the legacy
 * ATI BIOS pointer at 48h (verified against three retail Rage 128 Pro
 * dumps).  At 20h its 18h-byte data structure would straddle 30h.
 */
#define IA64_INT10_ROM_PCIR_OFFSET    0x00e0U
#define IA64_INT10_ROM_ATI_SIG_OFFSET 0x0030U
#define IA64_INT10_ROM_ATI_HEADER_OFFSET 0x0080U
#define IA64_INT10_ROM_ATI_PLL_OFFSET 0x00c0U
#define IA64_INT10_ROM_HANDLER_OFFSET 0x0100U
#define IA64_INT10_ROM_OEM_OFFSET     0x0180U
#define IA64_INT10_ROM_VENDOR_OFFSET  0x0190U
#define IA64_INT10_ROM_PRODUCT_OFFSET 0x01a0U
#define IA64_INT10_ROM_REVISION_OFFSET 0x01c0U
#define IA64_INT10_ROM_MODES_OFFSET   0x01d0U
#define IA64_INT10_VECTOR_ADDR  (0x10U * 4U)
#define IA64_INT10_IO_BASE      0x000001e0U
#define IA64_INT10_IO_SIZE      0x00000010U
#define IA64_INT10_TRIGGER      0x4941U
#define IA64_VBE2_SIGNATURE     0x32454256U
#define IA64_VBE_IO_INDEX       0x01ceU
#define IA64_VBE_IO_DATA        0x01d0U
#define IA64_VGA_PLANAR_MEMORY_SIZE (256 * KiB)
#define IA64_BDA_VIDEO_MODE      0x00000449U
#define IA64_BDA_VIDEO_COLUMNS   0x0000044aU
#define IA64_BDA_VIDEO_PAGE_SIZE 0x0000044cU
#define IA64_BDA_VIDEO_PAGE_START 0x0000044eU
#define IA64_BDA_CURSOR_POSITIONS 0x00000450U
#define IA64_BDA_CURSOR_TYPE     0x00000460U
#define IA64_BDA_VIDEO_PAGE      0x00000462U
#define IA64_BDA_CRTC_ADDRESS    0x00000463U
#define IA64_BDA_VIDEO_ROWS      0x00000484U
#define IA64_BDA_CHARACTER_HEIGHT 0x00000485U
#define IA64_BDA_VIDEO_CONTROL   0x00000487U
#define IA64_BDA_VIDEO_SWITCHES  0x00000488U
#define IA64_ATI_VENDOR_ID        0x1002U
#define IA64_ATI_RAGE128_PF_ID    0x5046U
#define IA64_ATI_PLL_XCLK         12000U
#define IA64_ATI_PLL_REFERENCE_FREQ 2950U
#define IA64_ATI_PLL_REFERENCE_DIV  65U
#define IA64_ATI_PLL_MIN_FREQ     12500U
#define IA64_ATI_PLL_MAX_FREQ     40000U
#endif
/*
 * IOSAPIC at the 460GX/i2000 SDV address (SAPIC/IOAPIC message block just
 * below the local SAPIC at 0xFEE00000), inside the fixed chipset region above
 * the PCI aperture.  Keeping it here -- rather than the old 2 GiB parking spot
 * -- leaves low DRAM contiguous all the way to the aperture.
 */
#define IA64_IOSAPIC_BASE       0x00000000fec00000ULL
#define IA64_IOSAPIC_SIZE       0x0000000000002000ULL
#define IA64_ACPI_PM_IO_BASE    0x00002000U
#define IA64_ACPI_PM_IO_SIZE    0x00000010U
#define IA64_LEGACY_COM1_IO_BASE 0x000003f8U
#define IA64_LEGACY_COM1_IO_SIZE 0x00000008U
#define IA64_ACPI_PM_RESET_OFFSET 0x0000000cU
#define IA64_ACPI_PM_RESET_VALUE  0x01U
#define IA64_ACPI_SCI_IRQ       9
#define IA64_PIB_IPI_LIMIT          0x00100000ULL
#define IA64_PIB_INTA_OFFSET        0x001e0000ULL
#define IA64_PIB_XTP_OFFSET         0x001e0008ULL
/* Graphics (Rage 128) lands here: slots 0-4 are reserved/built-in, VGA next. */
#define IA64_VPC_VGA_SLOT           5
#define IA64_VPC_NIC_SLOT           6

#define IA64_SAPIC_DELIVERY_INT     0
#define IA64_SAPIC_DELIVERY_NMI     4
#define IA64_SAPIC_DELIVERY_EXTINT  7

#ifdef CONFIG_IA64_VPC_GRAPHICS
enum {
    IA64_INT10_REG_AX,
    IA64_INT10_REG_BX,
    IA64_INT10_REG_CX,
    IA64_INT10_REG_DX,
    IA64_INT10_REG_DI,
    IA64_INT10_REG_ES,
    IA64_INT10_REG_EXEC,
    IA64_INT10_REG_DATA,
};

typedef struct IA64Int10Registers {
    uint16_t ax;
    uint16_t bx;
    uint16_t cx;
    uint16_t dx;
    uint16_t di;
    uint16_t es;
} IA64Int10Registers;

typedef struct IA64VbeMode {
    uint16_t number;
    uint16_t width;
    uint16_t height;
    uint8_t bpp;
} IA64VbeMode;

typedef struct IA64VgaLegacyMode {
    uint8_t number;
    uint8_t columns;
    uint8_t rows;
    uint8_t character_height;
    uint16_t page_size;
    uint8_t misc;
    const uint8_t *sequencer;
    const uint8_t *crtc;
    const uint8_t *attribute;
    const uint8_t *graphics;
} IA64VgaLegacyMode;

static const IA64VbeMode ia64_vbe_modes[] = {
    { 0x111,  640,  480, 16 },
    { 0x112,  640,  480, 24 },
    { 0x114,  800,  600, 16 },
    { 0x115,  800,  600, 24 },
    { 0x117, 1024,  768, 16 },
    { 0x118, 1024,  768, 24 },
    { 0x11a, 1280, 1024, 16 },
    { 0x11b, 1280, 1024, 24 },
    { 0x141,  640,  400, 32 },
    { 0x142,  640,  480, 32 },
    { 0x143,  800,  600, 32 },
    { 0x144, 1024,  768, 32 },
    { 0x145, 1280, 1024, 32 },
};

/* Standard VGA BIOS mode 12h: 640x480, 16-color planar graphics. */
static const uint8_t ia64_vga_mode_12_sequencer[] = {
    0x01, 0x0f, 0x00, 0x06,
};

static const uint8_t ia64_vga_mode_12_crtc[] = {
    0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0x0b, 0x3e,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xea, 0x8c, 0xdf, 0x28, 0x00, 0xe7, 0x04, 0xe3,
    0xff,
};

static const uint8_t ia64_vga_mode_12_attribute[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x01, 0x00, 0x0f, 0x00, 0x00,
};

static const uint8_t ia64_vga_mode_12_graphics[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f,
    0xff,
};

static const IA64VgaLegacyMode ia64_vga_legacy_modes[] = {
    {
        .number = 0x12,
        .columns = 80,
        .rows = 30,
        .character_height = 16,
        .page_size = 0xa000,
        .misc = 0xe3,
        .sequencer = ia64_vga_mode_12_sequencer,
        .crtc = ia64_vga_mode_12_crtc,
        .attribute = ia64_vga_mode_12_attribute,
        .graphics = ia64_vga_mode_12_graphics,
    },
};

static const char ia64_vbe_oem[] = "QEMU IA64 VBE";
static const char ia64_vbe_vendor[] = "QEMU";
static const char ia64_vbe_product[] = "IA64 VGA VBE bridge";
static const char ia64_vbe_revision[] = "1.0";

/*
 * The real-mode INT 10h entry marshals the registers through the private
 * I/O window above.  Keeping the executable stub small is intentional: the
 * VBE implementation remains normal, testable C code, and the stub also
 * works when the guest uses a software x86 BIOS emulator instead of native
 * IA-32 execution.  The bytes below are 16-bit code equivalent to:
 *
 *     push bp                 ; save registers not returned by VBE
 *     mov  bp, sp
 *     push ax
 *     push dx
 *     mov  dx, 1e0h
 *     out  dx, ax
 *     add  dx, 2
 *     mov  ax, bx
 *     out  dx, ax
 *     add  dx, 2
 *     mov  ax, cx
 *     out  dx, ax
 *     add  dx, 2
 *     mov  ax, [bp-4]
 *     out  dx, ax
 *     add  dx, 2
 *     mov  ax, di
 *     out  dx, ax
 *     add  dx, 2
 *     mov  ax, es
 *     out  dx, ax
 *     add  dx, 2
 *     cmp  word [bp-2], 4f00h
 *     jne  execute
 *     add  dx, 2
 *     mov  ax, es:[di]
 *     out  dx, ax
 *     mov  ax, es:[di+2]
 *     out  dx, ax             ; pass the VBE2 input signature
 *     sub  dx, 2
 * execute:
 *     mov  ax, 4941h
 *     out  dx, ax             ; execute the request at 1ech
 *     in   ax, dx
 *     mov  cx, ax
 *     jcxz response_done
 *     push di                 ; deliver the response to the RESULT es:di.  For
 *     mov  dx, 1e8h           ; VBE that is the request es:di (unchanged); the
 *     in   ax, dx             ; ATI BIOS query sets it to the caller's dx:bx
 *     mov  di, ax             ; buffer instead.
 *     mov  dx, 1eah
 *     in   ax, dx
 *     mov  es, ax
 *     mov  dx, 1eeh
 *     cld
 * response_loop:
 *     in   ax, dx
 *     stosw
 *     loop response_loop
 *     pop  di
 * response_done:
 *     mov  dx, 1e0h
 *     in   ax, dx
 *     mov  [bp-2], ax
 *     add  dx, 2
 *     in   ax, dx
 *     mov  bx, ax
 *     add  dx, 2
 *     in   ax, dx
 *     mov  cx, ax
 *     add  dx, 2
 *     in   ax, dx
 *     mov  dx, ax
 *     mov  ax, [bp-2]
 *     mov  sp, bp
 *     pop  bp
 *     iret
 */
static const uint8_t ia64_int10_handler[] = {
    0x55, 0x89, 0xe5, 0x50, 0x52, 0xba, 0xe0, 0x01,
    0xef, 0x83, 0xc2, 0x02, 0x89, 0xd8, 0xef, 0x83,
    0xc2, 0x02, 0x89, 0xc8, 0xef, 0x83, 0xc2, 0x02,
    0x8b, 0x46, 0xfc, 0xef, 0x83, 0xc2, 0x02, 0x89,
    0xf8, 0xef, 0x83, 0xc2, 0x02, 0x8c, 0xc0, 0xef,
    0x83, 0xc2, 0x02, 0x81, 0x7e, 0xfe, 0x00, 0x4f,
    0x75, 0x0f, 0x83, 0xc2, 0x02, 0x26, 0x8b, 0x05,
    0xef, 0x26, 0x8b, 0x45, 0x02, 0xef, 0x83, 0xea,
    0x02, 0xb8, 0x41, 0x49, 0xef, 0xed, 0x89, 0xc1,
    0xe3, 0x16, 0x57, 0xba, 0xe8, 0x01, 0xed, 0x89,
    0xc7, 0xba, 0xea, 0x01, 0xed, 0x8e, 0xc0, 0xba,
    0xee, 0x01, 0xfc, 0xed, 0xab, 0xe2, 0xfc, 0x5f,
    0xba, 0xe0, 0x01, 0xed, 0x89, 0x46, 0xfe, 0x83,
    0xc2, 0x02, 0xed, 0x89, 0xc3, 0x83, 0xc2, 0x02,
    0xed, 0x89, 0xc1, 0x83, 0xc2, 0x02, 0xed, 0x89,
    0xc2, 0x8b, 0x46, 0xfe, 0x89, 0xec, 0x5d, 0xcf,
};

/* Option-ROM initialization entry: install C000:0100 as vector 10h. */
static const uint8_t ia64_int10_rom_init[] = {
    0x50, 0x1e, 0x31, 0xc0, 0x8e, 0xd8, 0xc7, 0x06,
    0x40, 0x00, 0x00, 0x01, 0xc7, 0x06, 0x42, 0x00,
    0x00, 0xc0, 0x1f, 0x58, 0xcb,
};
#endif

#define TYPE_IA64_VPC_MACHINE MACHINE_TYPE_NAME("ia64-vpc")
OBJECT_DECLARE_SIMPLE_TYPE(IA64VpcMachineState, IA64_VPC_MACHINE)

struct IA64VpcMachineState {
    MachineState parent_obj;

    bool i8042_enabled;
    bool ahci_enabled;
    bool ide_enabled;
    bool firmware_ide_dma;
    bool agp_enabled;
    uint64_t firmware_console;
    char *nvram_path;
    char *vga_model;
    bool alat_full;

    PCIDevice *agp_dev;
    PCIDevice *ahci_dev;
    PCIDevice *ide_dev;
    PCIDevice *ohci_dev;
    PCIDevice *uhci_dev;
    PCIDevice *lsi_dev;
    PCIDevice *vga_dev;
    PCIDevice *nic_devs[MAX_NICS];
    unsigned int nic_count;

    MemoryRegion *ram_aliases[4];
    unsigned int ram_alias_count;
    MemoryRegion *vga_fb_alias;
    MemoryRegion *vga_mmio_alias;
    MemoryRegion *vga_legacy_alias;
    MemoryRegion *lsapic_mmio;
    MemoryRegion firmware_space;
    MemoryRegion rtc_mmio;
    MemoryRegion watchdog_mmio;
    MemoryRegion nvram_mmio;
    MemoryRegion acpi_pm;
    MemoryRegion acpi_reset;
    MemoryRegion debug_uart_legacy_io;
    SerialMM *debug_uart;
#ifdef CONFIG_IA64_VPC_GRAPHICS
    MemoryRegion int10_pci_io;
    IA64Int10Registers int10_request;
    IA64Int10Registers int10_result;
    uint32_t int10_input_signature;
    uint8_t int10_response[512];
    uint16_t int10_response_length;
    uint16_t int10_response_offset;
    uint8_t int10_input_signature_words;
    uint8_t int10_dpms_state;
    uint8_t int10_legacy_mode;
    uint8_t int10_legacy_columns;
#endif

    Object *pci_fixup_reset;
    QEMUTimer *watchdog_timer;
    uint64_t watchdog_timeout;
    uint64_t watchdog_code;
    uint8_t nvram_data[IA64_NVRAM_SIZE];
    size_t firmware_size;
    char *nvram_resolved_path;
    bool nvram_write_warning;
    ACPIREGS acpi_regs;
    qemu_irq acpi_sci_irq;
    qemu_irq isa_irqs[ISA_NUM_IRQS];
    Notifier powerdown_notifier;
    Notifier done_notifier;
    bool vmstate_registered;
};

#ifdef CONFIG_IA64_VPC_GRAPHICS
static const IA64VbeMode *ia64_vbe_find_mode(uint16_t number)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(ia64_vbe_modes); i++) {
        if (ia64_vbe_modes[i].number == number) {
            return &ia64_vbe_modes[i];
        }
    }
    return NULL;
}

static const IA64VgaLegacyMode *ia64_vga_find_legacy_mode(uint8_t number)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(ia64_vga_legacy_modes); i++) {
        if (ia64_vga_legacy_modes[i].number == number) {
            return &ia64_vga_legacy_modes[i];
        }
    }
    return NULL;
}

static void ia64_vbe_write(uint16_t index, uint16_t value)
{
    address_space_stw_le(&address_space_memory,
                         IA64_PCI_IO_BASE + IA64_VBE_IO_INDEX,
                         index, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory,
                         IA64_PCI_IO_BASE + IA64_VBE_IO_DATA,
                         value, MEMTXATTRS_UNSPECIFIED, NULL);
}

static uint16_t ia64_vbe_read(uint16_t index)
{
    address_space_stw_le(&address_space_memory,
                         IA64_PCI_IO_BASE + IA64_VBE_IO_INDEX,
                         index, MEMTXATTRS_UNSPECIFIED, NULL);
    return address_space_lduw_le(&address_space_memory,
                                 IA64_PCI_IO_BASE + IA64_VBE_IO_DATA,
                                 MEMTXATTRS_UNSPECIFIED, NULL);
}

static uint32_t ia64_vbe_memory_size(void)
{
    return (uint32_t)ia64_vbe_read(VBE_DISPI_INDEX_VIDEO_MEMORY_64K) *
           (64 * KiB);
}

static void ia64_vga_writeb(uint16_t port, uint8_t value)
{
    address_space_stb(&address_space_memory, IA64_PCI_IO_BASE + port,
                      value, MEMTXATTRS_UNSPECIFIED, NULL);
}

static uint8_t ia64_vga_readb(uint16_t port)
{
    return address_space_ldub(&address_space_memory,
                              IA64_PCI_IO_BASE + port,
                              MEMTXATTRS_UNSPECIFIED, NULL);
}

static void ia64_vga_indexed_write(uint16_t index_port,
                                   uint16_t data_port,
                                   uint8_t index, uint8_t value)
{
    ia64_vga_writeb(index_port, index);
    ia64_vga_writeb(data_port, value);
}

static void ia64_int10_update_legacy_bda(const IA64VgaLegacyMode *mode,
                                         bool no_clear)
{
    address_space_stb(&address_space_memory, IA64_BDA_VIDEO_MODE,
                      mode->number, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory, IA64_BDA_VIDEO_COLUMNS,
                         mode->columns, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory, IA64_BDA_VIDEO_PAGE_SIZE,
                         mode->page_size, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory, IA64_BDA_VIDEO_PAGE_START,
                         0, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_set(&address_space_memory, IA64_BDA_CURSOR_POSITIONS,
                      0, 16, MEMTXATTRS_UNSPECIFIED);
    address_space_stw_le(&address_space_memory, IA64_BDA_CURSOR_TYPE,
                         0, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stb(&address_space_memory, IA64_BDA_VIDEO_PAGE,
                      0, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory, IA64_BDA_CRTC_ADDRESS,
                         VGA_CRT_IC, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stb(&address_space_memory, IA64_BDA_VIDEO_ROWS,
                      mode->rows - 1, MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stw_le(&address_space_memory, IA64_BDA_CHARACTER_HEIGHT,
                         mode->character_height,
                         MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stb(&address_space_memory, IA64_BDA_VIDEO_CONTROL,
                      0x60 | (no_clear ? 0x80 : 0),
                      MEMTXATTRS_UNSPECIFIED, NULL);
    address_space_stb(&address_space_memory, IA64_BDA_VIDEO_SWITCHES,
                      0xf9, MEMTXATTRS_UNSPECIFIED, NULL);
}

static void ia64_vga_load_ega_palette(void)
{
    unsigned int color;

    ia64_vga_writeb(VGA_PEL_MSK, 0xff);
    ia64_vga_writeb(VGA_PEL_IW, 0);
    for (color = 0; color < 64; color++) {
        uint8_t red = (color & 0x04 ? 0x2a : 0) |
                      (color & 0x20 ? 0x15 : 0);
        uint8_t green = (color & 0x02 ? 0x2a : 0) |
                        (color & 0x10 ? 0x15 : 0);
        uint8_t blue = (color & 0x01 ? 0x2a : 0) |
                       (color & 0x08 ? 0x15 : 0);

        ia64_vga_writeb(VGA_PEL_D, red);
        ia64_vga_writeb(VGA_PEL_D, green);
        ia64_vga_writeb(VGA_PEL_D, blue);
    }
}

static void ia64_int10_program_legacy_mode(IA64VpcMachineState *s,
                                            const IA64VgaLegacyMode *mode,
                                            bool no_clear)
{
    size_t i;

    /*
     * A legacy VGA caller uses the planar A0000h aperture.  Disable the
     * synthetic VBE layout before programming standard VGA registers so a
     * previous packed-pixel framebuffer cannot reinterpret those writes.
     */
    ia64_vbe_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    ia64_vga_indexed_write(VGA_SEQ_I, VGA_SEQ_D, VGA_SEQ_RESET, 0x01);
    for (i = 0; i < VGA_SEQ_C - 1; i++) {
        ia64_vga_indexed_write(VGA_SEQ_I, VGA_SEQ_D, i + 1,
                               mode->sequencer[i]);
    }
    ia64_vga_writeb(VGA_MIS_W, mode->misc);
    ia64_vga_indexed_write(VGA_GFX_I, VGA_GFX_D, VGA_GFX_MISC,
                           mode->graphics[VGA_GFX_MISC]);
    ia64_vga_indexed_write(VGA_SEQ_I, VGA_SEQ_D, VGA_SEQ_RESET, 0x03);
    for (i = 0; i < VGA_GFX_C; i++) {
        ia64_vga_indexed_write(VGA_GFX_I, VGA_GFX_D, i,
                               mode->graphics[i]);
    }

    ia64_vga_indexed_write(VGA_CRT_IC, VGA_CRT_DC,
                           VGA_CRTC_V_SYNC_END, 0);
    for (i = 0; i < VGA_CRT_C; i++) {
        ia64_vga_indexed_write(VGA_CRT_IC, VGA_CRT_DC, i,
                               mode->crtc[i]);
    }
    for (i = 0; i < VGA_ATT_C; i++) {
        (void)ia64_vga_readb(VGA_IS1_RC);
        ia64_vga_writeb(VGA_ATT_W, i);
        ia64_vga_writeb(VGA_ATT_W, mode->attribute[i]);
    }
    ia64_vga_load_ega_palette();

    if (!no_clear) {
        address_space_set(&address_space_memory, IA64_VGA_FB_PCI_BASE,
                          0, IA64_VGA_PLANAR_MEMORY_SIZE,
                          MEMTXATTRS_UNSPECIFIED);
    }
    (void)ia64_vga_readb(VGA_IS1_RC);
    ia64_vga_writeb(VGA_ATT_W, VGA_AR_ENABLE_DISPLAY);

    s->int10_legacy_mode = mode->number;
    s->int10_legacy_columns = mode->columns;
    ia64_int10_update_legacy_bda(mode, no_clear);
}

static bool ia64_int10_set_legacy_mode(IA64VpcMachineState *s,
                                       uint8_t request)
{
    uint8_t number = request & 0x7f;
    bool no_clear = request & 0x80;
    const IA64VgaLegacyMode *mode;

    if (number == 3) {
        ia64_vbe_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
        s->int10_legacy_mode = number;
        s->int10_legacy_columns = 80;
        return true;
    }

    mode = ia64_vga_find_legacy_mode(number);
    if (mode == NULL) {
        return false;
    }
    ia64_int10_program_legacy_mode(s, mode, no_clear);
    return true;
}

static uint32_t ia64_int10_rom_pointer(uint16_t offset)
{
    return ((IA64_INT10_ROM_BASE >> 4) << 16) | offset;
}

static void ia64_int10_response_clear(IA64VpcMachineState *s)
{
    memset(s->int10_response, 0, sizeof(s->int10_response));
    s->int10_response_length = 0;
    s->int10_response_offset = 0;
}

static void ia64_int10_response_size(IA64VpcMachineState *s, size_t size)
{
    g_assert(size <= sizeof(s->int10_response));
    g_assert((size & 1) == 0);
    memset(s->int10_response, 0, size);
    s->int10_response_length = size;
    s->int10_response_offset = 0;
}

static void ia64_int10_vbe_success(IA64VpcMachineState *s)
{
    s->int10_result.ax = 0x004f;
}

static void ia64_int10_vbe_failure(IA64VpcMachineState *s)
{
    s->int10_result.ax = 0x014f;
}

static void ia64_int10_vbe_unsupported(IA64VpcMachineState *s)
{
    s->int10_result.ax = 0x024f;
}

static void ia64_int10_controller_info(IA64VpcMachineState *s)
{
    size_t response_size;
    uint8_t *info;

    response_size = s->int10_input_signature == IA64_VBE2_SIGNATURE ?
                    512 : 256;
    ia64_int10_response_size(s, response_size);
    info = s->int10_response;
    memcpy(info, "VESA", 4);
    stw_le_p(info + 4, 0x0300);
    stl_le_p(info + 6,
             ia64_int10_rom_pointer(IA64_INT10_ROM_OEM_OFFSET));
    stl_le_p(info + 10, 0);
    stl_le_p(info + 14,
             ia64_int10_rom_pointer(IA64_INT10_ROM_MODES_OFFSET));
    stw_le_p(info + 18,
             ia64_vbe_read(VBE_DISPI_INDEX_VIDEO_MEMORY_64K));
    stw_le_p(info + 20, 0x0100);
    stl_le_p(info + 22,
             ia64_int10_rom_pointer(IA64_INT10_ROM_VENDOR_OFFSET));
    stl_le_p(info + 26,
             ia64_int10_rom_pointer(IA64_INT10_ROM_PRODUCT_OFFSET));
    stl_le_p(info + 30,
             ia64_int10_rom_pointer(IA64_INT10_ROM_REVISION_OFFSET));
    ia64_int10_vbe_success(s);
}

static void ia64_int10_mode_info(IA64VpcMachineState *s)
{
    const IA64VbeMode *mode =
        ia64_vbe_find_mode(s->int10_request.cx & 0x01ff);
    uint32_t pitch;
    uint32_t image_size;
    uint32_t memory_size;
    uint32_t pages;
    uint8_t red_size;
    uint8_t green_size;
    uint8_t alpha_size;
    uint8_t alpha_pos;
    uint8_t *info;

    if (mode == NULL) {
        ia64_int10_vbe_failure(s);
        return;
    }

    ia64_int10_response_size(s, 256);
    info = s->int10_response;
    pitch = mode->width * DIV_ROUND_UP(mode->bpp, 8);
    image_size = pitch * mode->height;
    memory_size = ia64_vbe_memory_size();
    if (image_size > memory_size) {
        ia64_int10_response_clear(s);
        ia64_int10_vbe_failure(s);
        return;
    }
    pages = memory_size /
            ((image_size + 64 * KiB - 1) & ~((64 * KiB) - 1));
    pages = CLAMP(pages, 1, 256) - 1;

    stw_le_p(info + 0, 0x00bb);
    info[2] = 0x07;
    info[3] = 0;
    stw_le_p(info + 4, 64);
    stw_le_p(info + 6, 64);
    stw_le_p(info + 8, 0xa000);
    stw_le_p(info + 10, 0);
    stl_le_p(info + 12, 0);
    stw_le_p(info + 16, pitch);
    stw_le_p(info + 18, mode->width);
    stw_le_p(info + 20, mode->height);
    info[22] = 8;
    info[23] = 16;
    info[24] = 1;
    info[25] = mode->bpp;
    info[26] = 1;
    info[27] = 6; /* Direct-color memory model. */
    info[28] = 64;
    info[29] = pages;
    info[30] = 1;

    red_size = mode->bpp == 16 ? 5 : 8;
    green_size = mode->bpp == 16 ? 6 : 8;
    alpha_size = mode->bpp == 32 ? 8 : 0;
    alpha_pos = mode->bpp == 32 ? 24 : 0;
    info[31] = red_size;
    info[32] = mode->bpp == 16 ? 11 : 16;
    info[33] = green_size;
    info[34] = mode->bpp == 16 ? 5 : 8;
    info[35] = mode->bpp == 16 ? 5 : 8;
    info[36] = 0;
    info[37] = alpha_size;
    info[38] = alpha_pos;
    info[39] = mode->bpp == 32 ? 2 : 0;
    stl_le_p(info + 40, IA64_VGA_FB_PCI_BASE);
    stw_le_p(info + 50, pitch);
    info[52] = pages;
    info[53] = pages;
    memcpy(info + 54, info + 31, 8);
    ia64_int10_vbe_success(s);
}

static const IA64VbeMode *ia64_int10_current_mode(IA64VpcMachineState *s,
                                                   uint16_t *number)
{
    const IA64VbeMode *mode = NULL;
    uint16_t enable = ia64_vbe_read(VBE_DISPI_INDEX_ENABLE);
    uint16_t width;
    uint16_t height;
    uint16_t bpp;
    size_t i;

    (void)s;
    if (!(enable & VBE_DISPI_ENABLED)) {
        *number = 3;
        return NULL;
    }
    width = ia64_vbe_read(VBE_DISPI_INDEX_XRES);
    height = ia64_vbe_read(VBE_DISPI_INDEX_YRES);
    bpp = ia64_vbe_read(VBE_DISPI_INDEX_BPP);
    for (i = 0; i < G_N_ELEMENTS(ia64_vbe_modes); i++) {
        if (ia64_vbe_modes[i].width == width &&
            ia64_vbe_modes[i].height == height &&
            ia64_vbe_modes[i].bpp == bpp) {
            mode = &ia64_vbe_modes[i];
            break;
        }
    }
    *number = mode ? mode->number : 3;
    if (mode && (enable & VBE_DISPI_LFB_ENABLED)) {
        *number |= 0x4000;
    }
    return mode;
}

static void ia64_int10_set_mode(IA64VpcMachineState *s)
{
    const IA64VbeMode *mode =
        ia64_vbe_find_mode(s->int10_request.bx & 0x01ff);
    uint32_t image_size;
    uint16_t enable;

    if (mode == NULL) {
        ia64_int10_vbe_failure(s);
        return;
    }
    image_size = mode->width * mode->height *
                 DIV_ROUND_UP(mode->bpp, 8);
    if (image_size > ia64_vbe_memory_size()) {
        ia64_int10_vbe_failure(s);
        return;
    }

    ia64_vbe_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    ia64_vbe_write(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);
    ia64_vbe_write(VBE_DISPI_INDEX_BPP, mode->bpp);
    ia64_vbe_write(VBE_DISPI_INDEX_XRES, mode->width);
    ia64_vbe_write(VBE_DISPI_INDEX_YRES, mode->height);
    ia64_vbe_write(VBE_DISPI_INDEX_BANK, 0);
    ia64_vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, mode->width);
    ia64_vbe_write(VBE_DISPI_INDEX_X_OFFSET, 0);
    ia64_vbe_write(VBE_DISPI_INDEX_Y_OFFSET, 0);
    enable = VBE_DISPI_ENABLED;
    if (s->int10_request.bx & 0x4000) {
        enable |= VBE_DISPI_LFB_ENABLED;
    }
    if (s->int10_request.bx & 0x8000) {
        enable |= VBE_DISPI_NOCLEARMEM;
    }
    ia64_vbe_write(VBE_DISPI_INDEX_ENABLE, enable);

    /*
     * Enabling the Bochs VBE registers programs the packed-pixel layout but
     * leaves the VGA attribute controller's Palette-Address-Source bit clear,
     * exactly as it is after reset.  QEMU's VGA core treats a clear PAS bit as
     * "screen disabled" and forces GMODE_BLANK in vga_update_display(), so the
     * guest would render its desktop into VRAM yet the console would stay
     * black.  A real VGABIOS finishes every mode-set by writing 0x20 to the
     * attribute-controller write port to re-enable video output; the legacy
     * text/planar path above already does this.  Do the same for VBE modes so
     * the linear framebuffer is actually scanned out.
     *
     * The attribute controller shares an address/data flip-flop that a read of
     * Input Status 1 resets to the index state.  That register is only decoded
     * at its colour alias (0x3DA) when the Misc Output register selects colour
     * I/O addressing, so force that bit first; otherwise the reset (and hence
     * the enable) would silently depend on whatever mode ran before.
     */
    ia64_vga_writeb(VGA_MIS_W, ia64_vga_readb(VGA_MIS_R) | 0x01);
    (void)ia64_vga_readb(VGA_IS1_RC);
    ia64_vga_writeb(VGA_ATT_W, VGA_AR_ENABLE_DISPLAY);

    if (getenv("IA64_INT10_TRACE")) {
        fprintf(stderr, "int10: set_mode bx=%04x -> %dx%dx%d img=%u vbemem=%u "
                "enable=%04x readback=%04x\n", s->int10_request.bx,
                mode->width, mode->height, mode->bpp, image_size,
                (unsigned)ia64_vbe_memory_size(), enable,
                ia64_vbe_read(VBE_DISPI_INDEX_ENABLE));
    }
    ia64_int10_vbe_success(s);
}

static void ia64_int10_window_control(IA64VpcMachineState *s)
{
    uint8_t subfunction = s->int10_request.bx >> 8;
    uint8_t window = s->int10_request.bx;

    if (window != 0 || subfunction > 1) {
        ia64_int10_vbe_failure(s);
        return;
    }
    if (subfunction == 0) {
        ia64_vbe_write(VBE_DISPI_INDEX_BANK, s->int10_request.dx);
    } else {
        s->int10_result.dx = ia64_vbe_read(VBE_DISPI_INDEX_BANK);
    }
    ia64_int10_vbe_success(s);
}

static void ia64_int10_scanline(IA64VpcMachineState *s)
{
    uint16_t number;
    const IA64VbeMode *mode = ia64_int10_current_mode(s, &number);
    uint8_t subfunction = s->int10_request.bx;
    uint32_t bytes_per_pixel;
    uint32_t width;
    uint32_t pitch;

    if (mode == NULL || subfunction > 2) {
        ia64_int10_vbe_failure(s);
        return;
    }

    bytes_per_pixel = DIV_ROUND_UP(mode->bpp, 8);
    if (subfunction == 0) {
        ia64_vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH,
                       s->int10_request.cx);
    } else if (subfunction == 2) {
        width = DIV_ROUND_UP(s->int10_request.cx, bytes_per_pixel);
        if (width == 0 || width > UINT16_MAX) {
            ia64_int10_vbe_failure(s);
            return;
        }
        ia64_vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, width);
    }

    width = ia64_vbe_read(VBE_DISPI_INDEX_VIRT_WIDTH);
    pitch = width * bytes_per_pixel;
    if (pitch == 0) {
        ia64_int10_vbe_failure(s);
        return;
    }
    s->int10_result.bx = pitch;
    s->int10_result.cx = width;
    s->int10_result.dx = MIN(ia64_vbe_memory_size() / pitch, UINT16_MAX);
    ia64_int10_vbe_success(s);
}

static void ia64_int10_display_start(IA64VpcMachineState *s)
{
    uint16_t number;
    const IA64VbeMode *mode = ia64_int10_current_mode(s, &number);
    uint8_t subfunction = s->int10_request.bx;

    if (mode == NULL) {
        ia64_int10_vbe_failure(s);
        return;
    }
    switch (subfunction) {
    case 0x00:
    case 0x80:
        ia64_vbe_write(VBE_DISPI_INDEX_X_OFFSET, s->int10_request.cx);
        ia64_vbe_write(VBE_DISPI_INDEX_Y_OFFSET, s->int10_request.dx);
        break;
    case 0x01:
        s->int10_result.cx = ia64_vbe_read(VBE_DISPI_INDEX_X_OFFSET);
        s->int10_result.dx = ia64_vbe_read(VBE_DISPI_INDEX_Y_OFFSET);
        break;
    default:
        ia64_int10_vbe_failure(s);
        return;
    }
    ia64_int10_vbe_success(s);
}

static void ia64_int10_dpms(IA64VpcMachineState *s)
{
    uint8_t subfunction = s->int10_request.bx;

    switch (subfunction) {
    case 0:
        s->int10_result.bx = 0x0f30;
        break;
    case 1:
        s->int10_dpms_state = (s->int10_request.bx >> 8) & 0x0f;
        break;
    case 2:
        s->int10_result.bx = (uint16_t)s->int10_dpms_state << 8 | 2;
        break;
    default:
        ia64_int10_vbe_failure(s);
        return;
    }
    ia64_int10_vbe_success(s);
}

static void ia64_int10_ddc(IA64VpcMachineState *s)
{
    qemu_edid_info edid_info = {
        .vendor = "RHT",
        .name = "QEMU IA64",
        .prefx = 1280,
        .prefy = 1024,
        .maxx = 1280,
        .maxy = 1024,
        .refresh_rate = 60000,
    };
    uint8_t subfunction = s->int10_request.bx;

    switch (subfunction) {
    case 0:
        s->int10_result.bx = 0x0103;
        break;
    case 1:
        if (s->int10_request.dx != 0) {
            ia64_int10_vbe_failure(s);
            return;
        }
        ia64_int10_response_size(s, 128);
        qemu_edid_generate(s->int10_response, 128, &edid_info);
        break;
    default:
        ia64_int10_vbe_failure(s);
        return;
    }
    ia64_int10_vbe_success(s);
}

/*
 * ATI Accelerator-BIOS INT 10h functions (BIOS prefix 0xA000, "VGA enabled").
 * The native Mach64 miniport calls these to obtain the card's configuration;
 * the function number is the low byte of AX.  The synthesised VBE handler does
 * not otherwise answer them, so without this the driver reports "Unable to
 * obtain configuration information for graphics card" and never brings up a
 * mode.  Contract from the ATI Mach64 SDK (M64BIOS.C long_query) and the
 * query_structure layout (Mach64 driver source amach1.h / SDK MAIN.H):
 *   0x08 BIOS_GET_QUERY_SIZE -> CX = header size in bytes, AH = 0.
 *   0x09 BIOS_QUERY          -> write the query_structure header to the buffer
 *                               at DX:BX (segment:offset), AH = 0.
 */
static void ia64_int10_ati_bios(IA64VpcMachineState *s)
{
    unsigned fn = s->int10_request.ax & 0xff;
    uint8_t *q;

    switch (fn) {
    case 0x08:  /* BIOS_GET_QUERY_SIZE */
        s->int10_result.cx = 0x20;              /* 32-byte header */
        s->int10_result.ax &= 0x00ff;           /* AH = 0: success */
        break;
    case 0x09:  /* BIOS_QUERY: deliver the header to DX:BX via the stub copy */
        ia64_int10_response_size(s, 0x20);
        q = s->int10_response;
        stw_le_p(q + 0x00, 0x20);               /* q_sizeof_struct */
        q[0x02] = 0x02;                         /* q_structure_rev */
        q[0x03] = 0x00;                         /* q_number_modes (header only) */
        stw_le_p(q + 0x04, 0x0000);             /* q_mode_offset */
        q[0x06] = 0x00;                         /* q_sizeof_mode */
        q[0x07] = 0x01;                         /* q_VGA_type: enabled */
        stw_le_p(q + 0x08, 0x4752);             /* q_asic_id (Rage XL) */
        q[0x0a] = 0x00;                         /* q_VGA_boundary */
        /*
         * q_memory_size is an INDEX into the miniport's video-RAM-size table,
         * NOT a byte/quarter-meg count.  The XP Rage XL miniport (atimpae.sys
         * .BiosQueryAdapter) rejects the whole query with
         * "Unable to obtain configuration information" (0xC1010003, event
         * DumpData UniqueId 0x106) when this index is >= 16, then falls back to
         * VgaSave.  Its table (ex_ulaVideoRamSize) maps 0->512K, 1->1M, 2->2M,
         * 3->4M, 4->6M, 5->8M, ... so 8 MiB of VRAM is index 5.
         */
        q[0x0b] = 0x05;                         /* q_memory_size: index 5 = 8MiB */
        q[0x0c] = 0x00;                         /* q_DAC_type: 0 = internal (CT) DAC */
        q[0x0d] = 0x0a;                         /* q_memory_type: SDRAM */
        q[0x0e] = 0x07;                         /* q_bus_type: BUS_PCI */
        q[0x0f] = 0x00;                         /* q_monitor_cntl */
        stw_le_p(q + 0x10, IA64_VGA_FB_PCI_BASE >> 20); /* q_aperture_addr (MiB) */
        q[0x12] = 0x02;                         /* q_aperture_cfg: 8MiB linear */
        q[0x13] = 0x2f;                         /* colour depths 565/555/RGB/BGR/RGBA */
        s->int10_result.es = s->int10_request.dx;
        s->int10_result.di = s->int10_request.bx;
        s->int10_result.ax &= 0x00ff;           /* AH = 0: success */
        break;
    default:
        /* Acknowledge other ATI functions (e.g. 0x14) as success no-ops. */
        s->int10_result.ax &= 0x00ff;
        break;
    }
}

static void ia64_int10_execute(IA64VpcMachineState *s)
{
    uint16_t current_mode;

    s->int10_result = s->int10_request;
    ia64_int10_response_clear(s);

    if (getenv("IA64_INT10_TRACE")) {
        bool handled = (s->int10_request.ax & 0xff00) == 0x4f00 ||
                       (s->int10_request.ax >> 8) == 0x00 ||
                       (s->int10_request.ax >> 8) == 0x0f ||
                       (s->int10_request.ax >> 8) == 0x1a;
        fprintf(stderr, "int10: ax=%04x bx=%04x cx=%04x dx=%04x di=%04x "
                "es=%04x%s\n", s->int10_request.ax, s->int10_request.bx,
                s->int10_request.cx, s->int10_request.dx, s->int10_request.di,
                s->int10_request.es, handled ? "" : "  [UNHANDLED]");
    }

    if ((s->int10_request.ax & 0xff00) == 0xa000) {
        ia64_int10_ati_bios(s);
        return;
    }

    if ((s->int10_request.ax & 0xff00) == 0x4f00) {
        switch (s->int10_request.ax & 0xff) {
        case 0x00:
            ia64_int10_controller_info(s);
            return;
        case 0x01:
            ia64_int10_mode_info(s);
            return;
        case 0x02:
            ia64_int10_set_mode(s);
            return;
        case 0x03:
            ia64_int10_current_mode(s, &current_mode);
            s->int10_result.bx = current_mode;
            ia64_int10_vbe_success(s);
            return;
        case 0x05:
            ia64_int10_window_control(s);
            return;
        case 0x06:
            ia64_int10_scanline(s);
            return;
        case 0x07:
            ia64_int10_display_start(s);
            return;
        case 0x10:
            ia64_int10_dpms(s);
            return;
        case 0x15:
            ia64_int10_ddc(s);
            return;
        default:
            ia64_int10_vbe_unsupported(s);
            return;
        }
    }

    switch (s->int10_request.ax >> 8) {
    case 0x00:
        ia64_int10_set_legacy_mode(s, s->int10_request.ax);
        break;
    case 0x0f:
        if (ia64_vbe_read(VBE_DISPI_INDEX_ENABLE) & VBE_DISPI_ENABLED) {
            s->int10_result.ax = 80 << 8 | 3;
        } else {
            s->int10_result.ax = (uint16_t)s->int10_legacy_columns << 8 |
                                 s->int10_legacy_mode;
        }
        s->int10_result.bx &= 0x00ff;
        break;
    case 0x1a:
        if ((s->int10_request.ax & 0xff) == 0) {
            s->int10_result.ax = 0x001a;
            s->int10_result.bx = 0x0008;
        }
        break;
    default:
        break;
    }
}

static uint64_t ia64_int10_io_read(void *opaque, hwaddr addr, unsigned size)
{
    IA64VpcMachineState *s = opaque;
    unsigned reg = addr >> 1;

    if (size != 2 || (addr & 1)) {
        return 0xffff;
    }
    switch (reg) {
    case IA64_INT10_REG_AX:
        return s->int10_result.ax;
    case IA64_INT10_REG_BX:
        return s->int10_result.bx;
    case IA64_INT10_REG_CX:
        return s->int10_result.cx;
    case IA64_INT10_REG_DX:
        return s->int10_result.dx;
    case IA64_INT10_REG_DI:
        return s->int10_result.di;
    case IA64_INT10_REG_ES:
        return s->int10_result.es;
    case IA64_INT10_REG_EXEC:
        return s->int10_response_length / 2;
    case IA64_INT10_REG_DATA:
        if (s->int10_response_offset < s->int10_response_length) {
            uint16_t value = lduw_le_p(s->int10_response +
                                      s->int10_response_offset);

            s->int10_response_offset += 2;
            return value;
        }
        return 0;
    default:
        return 0xffff;
    }
}

static void ia64_int10_io_write(void *opaque, hwaddr addr, uint64_t value,
                                unsigned size)
{
    IA64VpcMachineState *s = opaque;
    unsigned reg = addr >> 1;

    if (size != 2 || (addr & 1)) {
        return;
    }
    switch (reg) {
    case IA64_INT10_REG_AX:
        s->int10_request.ax = value;
        s->int10_input_signature = 0;
        s->int10_input_signature_words = 0;
        break;
    case IA64_INT10_REG_BX:
        s->int10_request.bx = value;
        break;
    case IA64_INT10_REG_CX:
        s->int10_request.cx = value;
        break;
    case IA64_INT10_REG_DX:
        s->int10_request.dx = value;
        break;
    case IA64_INT10_REG_DI:
        s->int10_request.di = value;
        break;
    case IA64_INT10_REG_ES:
        s->int10_request.es = value;
        break;
    case IA64_INT10_REG_EXEC:
        if ((uint16_t)value == IA64_INT10_TRIGGER) {
            ia64_int10_execute(s);
        }
        break;
    case IA64_INT10_REG_DATA:
        if (s->int10_input_signature_words < 2) {
            s->int10_input_signature |=
                (uint32_t)(uint16_t)value <<
                (s->int10_input_signature_words * 16);
            s->int10_input_signature_words++;
        }
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ia64_int10_io_ops = {
    .read = ia64_int10_io_read,
    .write = ia64_int10_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 2,
        .max_access_size = 2,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 2,
        .max_access_size = 2,
        .unaligned = false,
    },
};

static void ia64_int10_install_ati_bios_info(uint8_t *rom,
                                             uint16_t vendor,
                                             uint16_t device)
{
    if (vendor != IA64_ATI_VENDOR_ID) {
        return;
    }

    /*
     * ATI's drivers locate and validate the video BIOS by the ROM signature
     * " 761295520" at 30h before following the pointer chain at 48h.  All
     * three retail Rage 128 Pro dumps carry it there.  Windows Whistler
     * build 2462's miniport (ati2mpaa.sys, "RAGE128/128PRO Miniport Driver
     * VersionR128.121") embeds the string and bugchecks 0x1E dereferencing
     * the NULL table pointer it is left with when the signature is absent.
     *
     * The Server 2003 (build 3790) inbox *mach64* miniport (ati2mpad.sys)
     * needs it too: its GetVgaEnabledRomImage scans offsets 30h..80h of the
     * C0000h shadow for "761295520" (Get_BIOS_Seg, WSRV03 drivers/video/ms/
     * ati/mini/services.c:1472) and, when absent, returns a NULL RomImage
     * that RageProEnable->InitializeBiosInfoStructure dereferences unchecked
     * at base+78h -> STOP 0x8E in videoprt!VideoPortReadRegisterBufferUchar.
     * So the signature is published for every ATI adapter, not just Rage128.
     */
    memcpy(rom + IA64_INT10_ROM_ATI_SIG_OFFSET, " 761295520", 10);

    if (device != IA64_ATI_RAGE128_PF_ID) {
        /*
         * mach64 (DEV_4752 Rage XL): ati2mpad reads its adapter configuration
         * through the a009 INT 10h query (ia64_int10_ati_bios), not the legacy
         * 48h Rage128 PLL pointer chain, so only the signature is required
         * here.  Do not publish the Rage128-format header/PLL block below.
         */
        return;
    }

    /*
     * Native Rage128 drivers follow the legacy ATI BIOS pointer chain at
     * 48h to obtain PLL limits.  A generic VBE ROM which only has a valid
     * 55AAh header is otherwise mistaken for an ATI BIOS, and the driver
     * interprets executable bytes as clock values.  Publish the small,
     * device-specific data block expected by those drivers while keeping
     * all video services in the generic INT 10h implementation.
     *
     * Values use the units defined by the Rage128 BIOS interface: clocks
     * are in 10 kHz units.  They match the range supported by QEMU's
     * Rage128-compatible display model and its existing VGA BIOS.
     */
    stw_le_p(rom + 0x48, IA64_INT10_ROM_ATI_HEADER_OFFSET);
    stw_le_p(rom + IA64_INT10_ROM_ATI_HEADER_OFFSET + 0x30,
             IA64_INT10_ROM_ATI_PLL_OFFSET);
    stw_le_p(rom + IA64_INT10_ROM_ATI_PLL_OFFSET + 0x08,
             IA64_ATI_PLL_XCLK);
    stw_le_p(rom + IA64_INT10_ROM_ATI_PLL_OFFSET + 0x0e,
             IA64_ATI_PLL_REFERENCE_FREQ);
    stw_le_p(rom + IA64_INT10_ROM_ATI_PLL_OFFSET + 0x10,
             IA64_ATI_PLL_REFERENCE_DIV);
    stl_le_p(rom + IA64_INT10_ROM_ATI_PLL_OFFSET + 0x12,
             IA64_ATI_PLL_MIN_FREQ);
    stl_le_p(rom + IA64_INT10_ROM_ATI_PLL_OFFSET + 0x16,
             IA64_ATI_PLL_MAX_FREQ);
}

static void ia64_vpc_install_int10(IA64VpcMachineState *s)
{
    uint8_t rom[IA64_INT10_ROM_SIZE] = { 0 };
    uint8_t vector[4];
    uint8_t checksum = 0;
    uint16_t vendor = pci_get_word(s->vga_dev->config + PCI_VENDOR_ID);
    uint16_t device = pci_get_word(s->vga_dev->config + PCI_DEVICE_ID);
    size_t i;

    g_assert(IA64_INT10_ROM_ATI_SIG_OFFSET + 10 <= 0x48);
    g_assert(IA64_INT10_ROM_ATI_PLL_OFFSET + 0x20 <=
             IA64_INT10_ROM_PCIR_OFFSET);
    g_assert(IA64_INT10_ROM_PCIR_OFFSET + 0x18 <=
             IA64_INT10_ROM_HANDLER_OFFSET);
    g_assert(IA64_INT10_ROM_HANDLER_OFFSET +
             sizeof(ia64_int10_handler) <= IA64_INT10_ROM_OEM_OFFSET);
    g_assert(IA64_INT10_ROM_OEM_OFFSET + sizeof(ia64_vbe_oem) <=
             IA64_INT10_ROM_VENDOR_OFFSET);
    g_assert(IA64_INT10_ROM_VENDOR_OFFSET + sizeof(ia64_vbe_vendor) <=
             IA64_INT10_ROM_PRODUCT_OFFSET);
    g_assert(IA64_INT10_ROM_PRODUCT_OFFSET + sizeof(ia64_vbe_product) <=
             IA64_INT10_ROM_REVISION_OFFSET);
    g_assert(IA64_INT10_ROM_REVISION_OFFSET + sizeof(ia64_vbe_revision) <=
             IA64_INT10_ROM_MODES_OFFSET);
    g_assert(IA64_INT10_ROM_MODES_OFFSET +
             (G_N_ELEMENTS(ia64_vbe_modes) + 1) * 2 < sizeof(rom));
    rom[0] = 0x55;
    rom[1] = 0xaa;
    rom[2] = IA64_INT10_ROM_SIZE / 512;
    memcpy(rom + 3, ia64_int10_rom_init, sizeof(ia64_int10_rom_init));

    /*
     * Keep PCIR away from the legacy ATI BIOS pointer at 48h.  Both fields
     * are consumed by real drivers and ROM validators.
     */
    stw_le_p(rom + 0x18, IA64_INT10_ROM_PCIR_OFFSET);
    memcpy(rom + IA64_INT10_ROM_PCIR_OFFSET, "PCIR", 4);
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x04, vendor);
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x06, device);
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x08, 0);
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x0a, 0x18);
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x0c] = 0;
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x0d] = 0;
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x0e] = 0;
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x0f] =
        PCI_CLASS_DISPLAY_VGA >> 8;
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x10,
             IA64_INT10_ROM_SIZE / 512);
    stw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 0x12, 0x0100);
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x14] = 0;
    rom[IA64_INT10_ROM_PCIR_OFFSET + 0x15] = 0x80;
    memcpy(rom + 0x60, "QEMU IA64 VBE INT10", 20);
    ia64_int10_install_ati_bios_info(rom, vendor, device);
    memcpy(rom + IA64_INT10_ROM_HANDLER_OFFSET, ia64_int10_handler,
           sizeof(ia64_int10_handler));
    memcpy(rom + IA64_INT10_ROM_OEM_OFFSET,
           ia64_vbe_oem, sizeof(ia64_vbe_oem));
    memcpy(rom + IA64_INT10_ROM_VENDOR_OFFSET,
           ia64_vbe_vendor, sizeof(ia64_vbe_vendor));
    memcpy(rom + IA64_INT10_ROM_PRODUCT_OFFSET,
           ia64_vbe_product, sizeof(ia64_vbe_product));
    memcpy(rom + IA64_INT10_ROM_REVISION_OFFSET,
           ia64_vbe_revision, sizeof(ia64_vbe_revision));
    for (i = 0; i < G_N_ELEMENTS(ia64_vbe_modes); i++) {
        stw_le_p(rom + IA64_INT10_ROM_MODES_OFFSET + i * 2,
                 ia64_vbe_modes[i].number);
    }
    stw_le_p(rom + IA64_INT10_ROM_MODES_OFFSET +
             G_N_ELEMENTS(ia64_vbe_modes) * 2, 0xffff);

    for (i = 0; i < sizeof(rom) - 1; i++) {
        checksum += rom[i];
    }
    rom[sizeof(rom) - 1] = -checksum;
    cpu_physical_memory_write(IA64_INT10_ROM_BASE, rom, sizeof(rom));

    /*
     * Keep the interrupt entry inside its option ROM.  In addition to being
     * the conventional PC BIOS layout, Windows videoprt validates that the
     * INT 10h vector resolves into the C0000h-CFFFFh video-ROM window before
     * it enables its x86 BIOS emulator.
     */
    stw_le_p(vector, IA64_INT10_ROM_HANDLER_OFFSET);
    stw_le_p(vector + 2, IA64_INT10_ROM_BASE >> 4);
    cpu_physical_memory_write(IA64_INT10_VECTOR_ADDR, vector,
                              sizeof(vector));
}

static void ia64_vpc_reset_int10(IA64VpcMachineState *s)
{
    memset(&s->int10_request, 0, sizeof(s->int10_request));
    memset(&s->int10_result, 0, sizeof(s->int10_result));
    s->int10_input_signature = 0;
    s->int10_input_signature_words = 0;
    ia64_int10_response_clear(s);
    s->int10_dpms_state = 0;
    s->int10_legacy_mode = 3;
    s->int10_legacy_columns = 80;
    ia64_vpc_install_int10(s);
}

static void ia64_vpc_init_int10(IA64VpcMachineState *s,
                                MemoryRegion *pci_io)
{
    memory_region_init_io(&s->int10_pci_io, OBJECT(s),
                          &ia64_int10_io_ops, s,
                          "ia64-vpc.int10-pci-io", IA64_INT10_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_INT10_IO_BASE,
                                &s->int10_pci_io);
    ia64_vpc_reset_int10(s);
}
#endif

static uint64_t ia64_vpc_rtc_read(void *opaque, hwaddr addr, unsigned size)
{
    struct tm tm;

    (void)opaque;
    if (addr != 0 || size != sizeof(uint64_t)) {
        return 0;
    }

    /*
     * Expose the QEMU-configured RTC as seconds since the Unix epoch.  A
     * single aligned 64-bit read is intrinsically coherent, unlike a bank of
     * calendar registers whose fields could straddle a second boundary.
     */
    qemu_get_timedate(&tm, 0);
    return mktimegm(&tm);
}

static void ia64_vpc_rtc_write(void *opaque, hwaddr addr, uint64_t value,
                               unsigned size)
{
    /* The platform RTC is a read-only seconds-since-epoch register. */
    (void)opaque;
    (void)addr;
    (void)value;
    (void)size;
}

static const MemoryRegionOps ia64_vpc_rtc_ops = {
    .read = ia64_vpc_rtc_read,
    .write = ia64_vpc_rtc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
};

static void ia64_vpc_init_rtc(IA64VpcMachineState *s)
{
    memory_region_init_io(&s->rtc_mmio, OBJECT(s),
                          &ia64_vpc_rtc_ops, s, "ia64-vpc.rtc",
                          IA64_RTC_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_RTC_BASE,
                                        &s->rtc_mmio, 2);
}

static void ia64_vpc_watchdog_expired(void *opaque)
{
    IA64VpcMachineState *s = opaque;

    warn_report("IA-64 firmware watchdog expired (code 0x%" PRIx64 ")",
                s->watchdog_code);
    s->watchdog_timeout = 0;
    watchdog_perform_action();
}

static uint64_t ia64_vpc_watchdog_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    IA64VpcMachineState *s = opaque;

    (void)size;

    switch (addr) {
    case IA64_WATCHDOG_TIMEOUT:
        return s->watchdog_timeout;
    case IA64_WATCHDOG_CODE:
        return s->watchdog_code;
    default:
        return 0;
    }
}

static void ia64_vpc_watchdog_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    IA64VpcMachineState *s = opaque;
    int64_t now;
    int64_t delta;

    if (size != sizeof(uint64_t)) {
        return;
    }

    switch (addr) {
    case IA64_WATCHDOG_CODE:
        s->watchdog_code = value;
        break;
    case IA64_WATCHDOG_TIMEOUT:
        s->watchdog_timeout = value;
        timer_del(s->watchdog_timer);
        if (value == 0) {
            break;
        }
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (value > (uint64_t)(INT64_MAX - now) / NANOSECONDS_PER_SECOND) {
            delta = INT64_MAX - now;
        } else {
            delta = value * NANOSECONDS_PER_SECOND;
        }
        timer_mod(s->watchdog_timer, now + delta);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ia64_vpc_watchdog_ops = {
    .read = ia64_vpc_watchdog_read,
    .write = ia64_vpc_watchdog_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
};

static void ia64_vpc_watchdog_reset(void *opaque)
{
    IA64VpcMachineState *s = opaque;

    timer_del(s->watchdog_timer);
    s->watchdog_timeout = 0;
    s->watchdog_code = 0;
}

static void ia64_vpc_init_watchdog(IA64VpcMachineState *s)
{
    s->watchdog_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                     ia64_vpc_watchdog_expired, s);
    memory_region_init_io(&s->watchdog_mmio, OBJECT(s),
                          &ia64_vpc_watchdog_ops, s,
                          "ia64-vpc.firmware-watchdog",
                          IA64_WATCHDOG_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_WATCHDOG_BASE,
                                        &s->watchdog_mmio, 2);
    qemu_register_reset(ia64_vpc_watchdog_reset, s);
}

static char *ia64_vpc_get_nvram(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->nvram_path ?: "auto");
}

static void ia64_vpc_set_nvram(Object *obj, const char *value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    g_free(s->nvram_path);
    s->nvram_path = g_strcmp0(value, "auto") == 0 ?
                    NULL : g_strdup(value);
}

static uint64_t ia64_vpc_nvram_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    IA64VpcMachineState *s = opaque;
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        value |= (uint64_t)s->nvram_data[addr + i] << (i * 8);
    }
    return value;
}

static void ia64_vpc_nvram_commit(IA64VpcMachineState *s)
{
    g_autoptr(GError) err = NULL;

    if (!s->nvram_resolved_path) {
        return;
    }
    if (!g_file_set_contents(s->nvram_resolved_path,
                             (const char *)s->nvram_data,
                             sizeof(s->nvram_data), &err) &&
        !s->nvram_write_warning) {
        warn_report("failed to save IA-64 NVRAM '%s': %s",
                    s->nvram_resolved_path,
                    err ? err->message : "unknown error");
        s->nvram_write_warning = true;
    }
}

static void ia64_vpc_nvram_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    IA64VpcMachineState *s = opaque;
    unsigned i;

    if (addr == IA64_NVRAM_COMMIT_OFFSET && size == 8 &&
        value == IA64_NVRAM_COMMIT_MAGIC) {
        ia64_vpc_nvram_commit(s);
        return;
    }
    for (i = 0; i < size; i++) {
        s->nvram_data[addr + i] = value >> (i * 8);
    }
}

static const MemoryRegionOps ia64_vpc_nvram_ops = {
    .read = ia64_vpc_nvram_read,
    .write = ia64_vpc_nvram_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
};

static void ia64_vpc_init_nvram(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
    g_autofree char *firmware_path = NULL;
    g_autofree char *directory = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    gsize length = 0;

    memset(s->nvram_data, 0, sizeof(s->nvram_data));
    g_clear_pointer(&s->nvram_resolved_path, g_free);
    s->nvram_write_warning = false;

    if (g_strcmp0(s->nvram_path, "none") != 0) {
        if (s->nvram_path) {
            s->nvram_resolved_path = g_strdup(s->nvram_path);
        } else if (machine->firmware) {
            firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS,
                                           machine->firmware);
            if (!firmware_path) {
                firmware_path = g_strdup(machine->firmware);
            }
            directory = g_path_get_dirname(firmware_path);
            s->nvram_resolved_path =
                g_build_filename(directory, "nvram", NULL);
        }
    }

    if (s->nvram_resolved_path &&
        g_file_get_contents(s->nvram_resolved_path, &contents,
                            &length, &err)) {
        if (length == sizeof(s->nvram_data)) {
            memcpy(s->nvram_data, contents, length);
        } else {
            warn_report("ignoring IA-64 NVRAM '%s': expected %zu bytes, "
                        "found %zu",
                        s->nvram_resolved_path,
                        sizeof(s->nvram_data), (size_t)length);
        }
    } else if (err && !g_error_matches(err, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)) {
        warn_report("failed to load IA-64 NVRAM '%s': %s",
                    s->nvram_resolved_path, err->message);
    }

    memory_region_init_io(&s->nvram_mmio, OBJECT(s),
                          &ia64_vpc_nvram_ops, s, "ia64-vpc.nvram",
                          IA64_NVRAM_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_NVRAM_BASE,
                                        &s->nvram_mmio, 2);
}

typedef struct IA64VpcCompatDefault {
    const char *driver;
    const char *property;
    const char *value;
} IA64VpcCompatDefault;

static const IA64VpcCompatDefault ia64_vpc_compat_defaults[] = {
    /*
     * Some IA-64 USB hub drivers use an alignment-requiring 32-bit load for
     * packed extended-property descriptors.  Do not expose the optional
     * selective-suspend property on HID input devices.
     */
    { "usb-kbd", "msos-desc", "off" },
    { "usb-mouse", "msos-desc", "off" },
    { "usb-tablet", "msos-desc", "off" },
    /*
     * Render the RAGE 128 hardware cursor into the framebuffer rather than as
     * a host overlay.  The chip has no hotspot register -- the driver bakes the
     * hotspot into CUR_HORZ_VERT_POSN/_OFF -- so a host overlay (which needs an
     * explicit hotspot) cannot place arbitrary cursors correctly: Windows XP
     * drives the hardware cursor at 8bpp and the overlay landed ~10px off, and
     * a per-cursor hotspot guess only works for the arrow, not centre-hotspot
     * cursors (I-beam, hourglass).  Compositing reproduces the exact hardware
     * pixels at the exact hardware position, so every cursor type is correct.
     */
    { "ati-vga", "guest_hwcursor", "on" },
    /* Same reasoning for the Mach64 hardware cursor. */
    { "mach64-vga", "guest_hwcursor", "on" },
};

static void ia64_vpc_add_compat_defaults(MachineClass *mc)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(ia64_vpc_compat_defaults); i++) {
        const IA64VpcCompatDefault *value = &ia64_vpc_compat_defaults[i];
        GlobalProperty *property = g_new0(GlobalProperty, 1);

        property->driver = value->driver;
        property->property = value->property;
        property->value = value->value;
        g_ptr_array_add(mc->compat_props, property);
    }
}

static bool ia64_vpc_get_i8042(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->i8042_enabled;
}

static void ia64_vpc_set_i8042(Object *obj, bool value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_PS2
    if (value) {
        error_setg(errp, "i8042 support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->i8042_enabled = value;
}

static bool ia64_vpc_get_ahci(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->ahci_enabled;
}

static void ia64_vpc_set_ahci(Object *obj, bool value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_STORAGE
    if (value) {
        error_setg(errp, "AHCI support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->ahci_enabled = value;
}

static bool ia64_vpc_get_ide(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->ide_enabled;
}

static void ia64_vpc_set_ide(Object *obj, bool value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_STORAGE
    if (value) {
        error_setg(errp, "IDE support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->ide_enabled = value;
}

static bool ia64_vpc_get_agp(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->agp_enabled;
}

static void ia64_vpc_set_agp(Object *obj, bool value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    s->agp_enabled = value;
}

static bool ia64_vpc_get_firmware_ide_dma(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return s->firmware_ide_dma;
}

static void ia64_vpc_set_firmware_ide_dma(Object *obj, bool value,
                                          Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifndef CONFIG_IA64_VPC_STORAGE
    if (value) {
        error_setg(errp,
                   "firmware IDE DMA support is not present in this build");
        return;
    }
#else
    (void)errp;
#endif

    s->firmware_ide_dma = value;
}

static char *ia64_vpc_get_firmware_console(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->firmware_console == IA64_FW_CONSOLE_VGA ?
                    "vga" : "serial");
}

static void ia64_vpc_set_firmware_console(Object *obj, const char *value,
                                          Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (g_strcmp0(value, "serial") == 0) {
        s->firmware_console = IA64_FW_CONSOLE_SERIAL;
        return;
    }
    if (g_strcmp0(value, "vga") == 0) {
#ifndef CONFIG_IA64_VPC_GRAPHICS
        error_setg(errp, "VGA support is not present in this build");
#else
        s->firmware_console = IA64_FW_CONSOLE_VGA;
#endif
        return;
    }

    error_setg(errp, "firmware-console must be 'serial' or 'vga'");
}

static char *ia64_vpc_get_vga(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->vga_model ? s->vga_model : "rage128");
}

static void ia64_vpc_set_vga(Object *obj, const char *value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (g_strcmp0(value, "rage128") != 0 &&
        g_strcmp0(value, "mach64") != 0 &&
        g_strcmp0(value, "std") != 0) {
        error_setg(errp, "vga must be 'rage128', 'mach64' or 'std'");
        return;
    }
    g_free(s->vga_model);
    s->vga_model = g_strdup(value);
}

static char *ia64_vpc_get_alat(Object *obj, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    (void)errp;

    return g_strdup(s->alat_full ? "full" : "zero");
}

static void ia64_vpc_set_alat(Object *obj, const char *value, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (g_strcmp0(value, "zero") == 0) {
        s->alat_full = false;
        return;
    }
    if (g_strcmp0(value, "full") == 0) {
        s->alat_full = true;
        return;
    }

    error_setg(errp, "alat must be 'zero' or 'full'");
}

static void ia64_vpc_acpi_update_sci(ACPIREGS *ar)
{
    IA64VpcMachineState *s = container_of(ar, IA64VpcMachineState,
                                          acpi_regs);

    acpi_update_sci(ar, s->acpi_sci_irq);
}

static uint64_t ia64_vpc_acpi_reset_read(void *opaque, hwaddr addr,
                                         unsigned size)
{
    (void)opaque;
    (void)addr;
    (void)size;
    return 0;
}

static void ia64_vpc_acpi_reset_write(void *opaque, hwaddr addr,
                                      uint64_t value, unsigned size)
{
    (void)opaque;
    if (addr == 0 && size == 1 &&
        (value & 0xff) == IA64_ACPI_PM_RESET_VALUE) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static const MemoryRegionOps ia64_vpc_acpi_reset_ops = {
    .read = ia64_vpc_acpi_reset_read,
    .write = ia64_vpc_acpi_reset_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static void ia64_vpc_init_acpi_pm(IA64VpcMachineState *s,
                                  DeviceState *iosapic,
                                  MemoryRegion *pci_io)
{
    s->acpi_sci_irq = qdev_get_gpio_in(iosapic, IA64_ACPI_SCI_IRQ);

    memory_region_init(&s->acpi_pm, OBJECT(s), "ia64-acpi-pm",
                       IA64_ACPI_PM_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_ACPI_PM_IO_BASE,
                                &s->acpi_pm);

    acpi_pm1_evt_init(&s->acpi_regs, ia64_vpc_acpi_update_sci,
                      &s->acpi_pm);
    acpi_pm1_cnt_init(&s->acpi_regs, &s->acpi_pm,
                      false, false, 0, true);
    acpi_pm_tmr_init(&s->acpi_regs, ia64_vpc_acpi_update_sci,
                     &s->acpi_pm);
    memory_region_init_io(&s->acpi_reset, OBJECT(s),
                          &ia64_vpc_acpi_reset_ops, s,
                          "ia64-acpi-reset", 1);
    memory_region_add_subregion(&s->acpi_pm,
                                IA64_ACPI_PM_RESET_OFFSET,
                                &s->acpi_reset);

    /*
     * acpi_update_sci() always folds in GPE status.  The current platform
     * exposes no GPE block to the guest, but the shared ACPI core still needs
     * backing storage for that internal zero-valued contribution.
     */
    acpi_gpe_init(&s->acpi_regs, 2);
}

static void ia64_vpc_powerdown_req(Notifier *n, void *opaque)
{
    IA64VpcMachineState *s = container_of(n, IA64VpcMachineState,
                                          powerdown_notifier);

    (void)opaque;

    if (s->acpi_regs.pm1.evt.en & ACPI_BITMASK_POWER_BUTTON_ENABLE) {
        acpi_pm1_evt_power_down(&s->acpi_regs);
    } else {
        /* Avoid making QEMU's powerdown action a no-op before ACPI is armed. */
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }
}

#ifdef CONFIG_IA64_VPC_GRAPHICS
static const VMStateDescription vmstate_ia64_int10_registers = {
    .name = "ia64-vpc/int10-registers",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT16(ax, IA64Int10Registers),
        VMSTATE_UINT16(bx, IA64Int10Registers),
        VMSTATE_UINT16(cx, IA64Int10Registers),
        VMSTATE_UINT16(dx, IA64Int10Registers),
        VMSTATE_UINT16(di, IA64Int10Registers),
        VMSTATE_UINT16(es, IA64Int10Registers),
        VMSTATE_END_OF_LIST()
    }
};
#endif

static int ia64_vpc_post_load(void *opaque, int version_id)
{
    IA64VpcMachineState *s = opaque;
    uint16_t pm_enable = s->acpi_regs.pm1.evt.en;

#ifdef CONFIG_IA64_VPC_GRAPHICS
    if (s->int10_response_length > sizeof(s->int10_response) ||
        s->int10_response_offset > s->int10_response_length ||
        s->int10_input_signature_words > 2) {
        return -EINVAL;
    }
#endif

    qemu_system_wakeup_enable(
        QEMU_WAKEUP_REASON_RTC,
        (pm_enable & ACPI_BITMASK_RT_CLOCK_ENABLE) != 0);
    qemu_system_wakeup_enable(
        QEMU_WAKEUP_REASON_PMTIMER,
        (pm_enable & ACPI_BITMASK_TIMER_ENABLE) != 0);
    ia64_vpc_acpi_update_sci(&s->acpi_regs);
    return 0;
}

static const VMStateDescription vmstate_ia64_vpc = {
    .name = "ia64-vpc",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = ia64_vpc_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(watchdog_timeout, IA64VpcMachineState),
        VMSTATE_UINT64(watchdog_code, IA64VpcMachineState),
        VMSTATE_TIMER_PTR(watchdog_timer, IA64VpcMachineState),
        VMSTATE_UINT8_ARRAY(nvram_data, IA64VpcMachineState,
                            IA64_NVRAM_SIZE),

        VMSTATE_UINT16(acpi_regs.pm1.evt.sts, IA64VpcMachineState),
        VMSTATE_UINT16(acpi_regs.pm1.evt.en, IA64VpcMachineState),
        VMSTATE_UINT16(acpi_regs.pm1.cnt.cnt, IA64VpcMachineState),
        VMSTATE_TIMER_PTR(acpi_regs.tmr.timer, IA64VpcMachineState),
        VMSTATE_INT64(acpi_regs.tmr.overflow_time, IA64VpcMachineState),
        VMSTATE_BUFFER_POINTER_UNSAFE(acpi_regs.gpe.sts,
                                      IA64VpcMachineState, 1, 2),
        VMSTATE_BUFFER_POINTER_UNSAFE(acpi_regs.gpe.en,
                                      IA64VpcMachineState, 1, 2),

#ifdef CONFIG_IA64_VPC_GRAPHICS
        VMSTATE_STRUCT(int10_request, IA64VpcMachineState, 1,
                       vmstate_ia64_int10_registers, IA64Int10Registers),
        VMSTATE_STRUCT(int10_result, IA64VpcMachineState, 1,
                       vmstate_ia64_int10_registers, IA64Int10Registers),
        VMSTATE_UINT32(int10_input_signature, IA64VpcMachineState),
        VMSTATE_UINT8_ARRAY(int10_response, IA64VpcMachineState, 512),
        VMSTATE_UINT16(int10_response_length, IA64VpcMachineState),
        VMSTATE_UINT16(int10_response_offset, IA64VpcMachineState),
        VMSTATE_UINT8(int10_input_signature_words, IA64VpcMachineState),
        VMSTATE_UINT8(int10_dpms_state, IA64VpcMachineState),
        VMSTATE_UINT8(int10_legacy_mode, IA64VpcMachineState),
        VMSTATE_UINT8(int10_legacy_columns, IA64VpcMachineState),
#endif
        VMSTATE_END_OF_LIST()
    }
};

static uint64_t ia64_vpc_lsapic_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    (void)opaque;

    if (addr == IA64_PIB_INTA_OFFSET && size == 1) {
        return 0;
    }
    return 0;
}

static void ia64_vpc_lsapic_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    CPUState *cs;
    unsigned delivery;
    uint8_t id;
    uint8_t eid;
    uint8_t vector;

    (void)opaque;
    /*
     * The upper half of the Processor Interrupt Block contains the XTP byte.
     * XTP is a platform hint; systems without XTP support must still accept
     * and discard the one-byte store.
     */
    if (addr == IA64_PIB_XTP_OFFSET && size == 1) {
        return;
    }

    if (addr >= IA64_PIB_IPI_LIMIT || size != 8 || (addr & 7)) {
        return;
    }

    /*
     * The lower half of the Processor Interrupt Block is the IPI delivery
     * region.  The address selects the target processor and the low data byte
     * carries the interrupt vector for INT delivery messages.
     */
    id = (addr >> 12) & 0xff;
    eid = (addr >> 4) & 0xff;
    delivery = (value >> 8) & 7;
    switch (delivery) {
    case IA64_SAPIC_DELIVERY_INT:
        vector = value & 0xff;
        if (!ia64_external_interrupt_vector_valid(vector)) {
            return;
        }
        break;
    case IA64_SAPIC_DELIVERY_NMI:
        vector = 2;
        break;
    case IA64_SAPIC_DELIVERY_EXTINT:
        vector = 0;
        break;
    default:
        return;
    }

    cs = ia64_cpu_by_sapic_id(id, eid);
    if (cs == NULL) {
        return;
    }

    ia64_sapic_set_irq(cs, vector);
}

static const MemoryRegionOps ia64_vpc_lsapic_ops = {
    .read = ia64_vpc_lsapic_read,
    .write = ia64_vpc_lsapic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static void ia64_vpc_map_lsapic(IA64VpcMachineState *s)
{
    if (s->lsapic_mmio != NULL) {
        return;
    }

    s->lsapic_mmio = g_new(MemoryRegion, 1);
    memory_region_init_io(s->lsapic_mmio, OBJECT(s),
                          &ia64_vpc_lsapic_ops, s,
                          "ia64-vpc.local-sapic",
                          IA64_LOCAL_SAPIC_SIZE);
    memory_region_add_subregion(get_system_memory(), IA64_LOCAL_SAPIC_PA,
                                s->lsapic_mmio);
}

static bool ia64_vpc_map_firmware_address_space(IA64VpcMachineState *s,
                                                Error **errp)
{
    Error *local_err = NULL;

    /*
     * IA-64 reserves the top 16 MiB below 4 GiB for PAL/SAL firmware
     * resources.  Decode it so firmware identity mappings can use the
     * platform address space directly.
     */
    memory_region_init_ram(&s->firmware_space, NULL,
                           "ia64-firmware-address-space",
                           IA64_FIRMWARE_ADDRESS_SPACE_SIZE, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return false;
    }
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_FIRMWARE_ADDRESS_SPACE_BASE,
                                        &s->firmware_space, 1);
    return true;
}

static uint64_t ia64_vpc_map_ram_alias(IA64VpcMachineState *s,
                                       hwaddr guest_base,
                                       uint64_t backing_offset,
                                       uint64_t remaining,
                                       uint64_t capacity,
                                       const char *name)
{
    MachineState *machine = MACHINE(s);
    MemoryRegion *alias;
    uint64_t size = MIN(remaining, capacity);

    if (size == 0) {
        return 0;
    }

    g_assert(s->ram_alias_count < ARRAY_SIZE(s->ram_aliases));
    alias = g_new(MemoryRegion, 1);
    s->ram_aliases[s->ram_alias_count++] = alias;
    memory_region_init_alias(alias, OBJECT(s), name, machine->ram,
                             backing_offset, size);
    memory_region_add_subregion(get_system_memory(), guest_base, alias);
    return size;
}

static void ia64_vpc_map_ram(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
    uint64_t remaining = machine->ram_size;
    uint64_t offset = 0;
    uint64_t size;

    if (machine->ram == NULL) {
        return;
    }

    /*
     * Real 460GX layout: DRAM is contiguous from 0 up to the top-of-memory
     * MMIO gap (the PCI aperture just below the fixed chipset/SAPIC/firmware
     * region at [0xFE000000, 4 GiB)), and only RAM displaced by that gap is
     * remapped above 4 GiB.  There is no DRAM island between the aperture and
     * the chipset region.  With the IOSAPIC no longer parked at 2 GiB the low
     * band is a single unbroken run, which also avoids the fragmented
     * single-DMA-zone layout that Linux 2.6.8 IA-64 mishandled.  Keep this in
     * lockstep with fw_init_guest_high_ram_ranges() in
     * roms/ia64-firmware/firmware.c.
     */
    size = ia64_vpc_map_ram_alias(s, 0, offset, remaining,
                                  IA64_LOW_RAM_LIMIT,
                                  "ia64-vpc.low-ram");
    offset += size;
    remaining -= size;

    ia64_vpc_map_ram_alias(s, IA64_HIGH_RAM_AFTER_FIRMWARE_BASE,
                           offset, remaining, remaining,
                           "ia64-vpc.high-ram-above-4g");
}

static void ia64_vpc_write_firmware_handoff(IA64VpcMachineState *s)
{
    MachineState *machine = MACHINE(s);
    IA64VpcHandoff handoff = { 0 };
    bool debug_port_present = debug_port_get_chardev() != NULL;

    _Static_assert(sizeof(IA64VpcHandoff) == 104,
                   "IA-64 firmware handoff ABI size changed");
    _Static_assert(offsetof(IA64VpcHandoff, ProcessorCount) == 64,
                   "IA-64 firmware handoff CPU count offset changed");
    _Static_assert(offsetof(IA64VpcHandoff, NvramPersistent) == 72,
                   "IA-64 firmware handoff NVRAM offset changed");
    _Static_assert(offsetof(IA64VpcHandoff, SocketCount) == 80,
                   "IA-64 firmware handoff socket count offset changed");
    _Static_assert(offsetof(IA64VpcHandoff, CoresPerSocket) == 88,
                   "IA-64 firmware handoff core count offset changed");
    _Static_assert(offsetof(IA64VpcHandoff, ThreadsPerCore) == 96,
                   "IA-64 firmware handoff thread count offset changed");

    handoff.Magic = cpu_to_le64(IA64_FW_HANDOFF_MAGIC);
    handoff.Version = cpu_to_le64(IA64_FW_HANDOFF_VERSION);
    handoff.RamSize = cpu_to_le64(machine->ram_size);
    handoff.ConsolePolicy = cpu_to_le64(s->firmware_console);
    handoff.IdeDmaEnabled = cpu_to_le64(s->firmware_ide_dma);
    handoff.DebugPortFlags = cpu_to_le64(
        debug_port_present ? IA64_FW_DEBUG_PORT_PRESENT : 0);
    handoff.DebugPortBase = cpu_to_le64(
        debug_port_present ? IA64_DEBUG_UART_BASE : 0);
    handoff.I8042Enabled = cpu_to_le64(s->i8042_enabled);
    handoff.ProcessorCount = cpu_to_le64(machine->smp.cpus);
    handoff.NvramPersistent = cpu_to_le64(
        s->nvram_resolved_path != NULL);
    handoff.SocketCount = cpu_to_le64(machine->smp.sockets);
    handoff.CoresPerSocket = cpu_to_le64(machine->smp.cores);
    handoff.ThreadsPerCore = cpu_to_le64(machine->smp.threads);
    cpu_physical_memory_write(IA64_FW_HANDOFF_ADDR, &handoff,
                              sizeof(handoff));
}

static void ia64_vpc_configure_pci_irq(PCIDevice *pci_dev)
{
    uint8_t pin;

    if (pci_dev == NULL) {
        return;
    }

    pin = pci_dev->config[PCI_INTERRUPT_PIN];
    if (pin >= 1 && pin <= PCI_NUM_PINS) {
        pci_default_write_config(pci_dev, PCI_INTERRUPT_LINE,
                                 ia64_pci_route_intx_gsi(pci_dev->devfn,
                                                         pin - 1), 1);
    }
}

static void ia64_vpc_configure_ahci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_4,
                             IA64_AHCI_IDP_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_5,
                             IA64_AHCI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_ohci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_OHCI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_uhci(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_4,
                             IA64_UHCI_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_lsi(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_LSI_IO_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_1,
                             IA64_LSI_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_2,
                             IA64_LSI_RAM_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

/*
 * Give the stock VGA BIOS the ATI data blocks a native Rage 128 driver looks
 * for.  Windows' videoprt reads the image through the PCI ROM BAR, and the
 * shipped vgabios-ati.bin is a SeaVGABIOS build with none of ATI's tables:
 * the signature " 761295520" that ATI drivers validate the ROM by occurs
 * nowhere in it, so Whistler build 2462's miniport leaves its BIOS table
 * pointer NULL and bugchecks 0x1E dereferencing it.
 *
 * The blocks written here are ours, not ATI's - the layout is the documented
 * one (signature at 30h, header pointer at 48h, PLL pointer at header+30h)
 * and the clock parameters are the Rage 128 Pro's published values, which is
 * also what the synthesised INT 10h ROM publishes.  Nothing is copied out of
 * a retail BIOS image.
 *
 * A user-supplied romfile that already carries the signature is left strictly
 * alone.
 */
static void ia64_vpc_install_ati_rom_tables(PCIDevice *pci_dev)
{
    static const char ati_signature[] = " 761295520";
    uint8_t *rom;
    uint64_t rom_size;
    uint32_t declared;
    uint32_t hdr;
    uint32_t pll;
    uint32_t pcir;
    uint32_t i;
    uint8_t checksum = 0;

    if (pci_get_word(pci_dev->config + PCI_VENDOR_ID) !=
            IA64_ATI_VENDOR_ID ||
        pci_get_word(pci_dev->config + PCI_DEVICE_ID) !=
            IA64_ATI_RAGE128_PF_ID) {
        return;
    }
    if (pci_dev->io_regions[PCI_ROM_SLOT].size == 0 || !pci_dev->has_rom) {
        return;
    }

    rom = memory_region_get_ram_ptr(&pci_dev->rom);
    rom_size = memory_region_size(&pci_dev->rom);
    if (rom == NULL || rom_size < 0x400 || rom[0] != 0x55 || rom[1] != 0xaa) {
        return;
    }

    declared = (uint32_t)rom[2] * 512U;
    if (declared == 0 || declared > rom_size) {
        return;
    }

    /* A real ATI image already has everything; do not touch it. */
    for (i = 0; i + sizeof(ati_signature) - 1 <= declared; i++) {
        if (memcmp(rom + i, ati_signature,
                   sizeof(ati_signature) - 1) == 0) {
            return;
        }
    }

    /* 30h..47h is padding in the shipped image; refuse if that changes. */
    for (i = 0x30; i < 0x48; i++) {
        if (rom[i] != 0) {
            return;
        }
    }

    hdr = declared;
    pll = hdr + 0x40U;
    if (pll + 0x20U > rom_size) {
        return;
    }

    memcpy(rom + 0x30, ati_signature, sizeof(ati_signature) - 1);
    stw_le_p(rom + 0x48, hdr);
    memset(rom + hdr, 0, 0x60);
    stw_le_p(rom + hdr + 0x30, pll);
    stw_le_p(rom + pll + 0x08, IA64_ATI_PLL_XCLK);
    stw_le_p(rom + pll + 0x0e, IA64_ATI_PLL_REFERENCE_FREQ);
    stw_le_p(rom + pll + 0x10, IA64_ATI_PLL_REFERENCE_DIV);
    stl_le_p(rom + pll + 0x12, IA64_ATI_PLL_MIN_FREQ);
    stl_le_p(rom + pll + 0x16, IA64_ATI_PLL_MAX_FREQ);

    /* Grow the declared image so a bounds-checking parser sees the tables. */
    declared = ROUND_UP(pll + 0x20U, 512U);
    if (declared > rom_size || declared / 512U > 0xffU) {
        return;
    }
    rom[2] = (uint8_t)(declared / 512U);
    pcir = lduw_le_p(rom + 0x18);
    if (pcir != 0 && pcir + 0x18U <= declared &&
        memcmp(rom + pcir, "PCIR", 4) == 0) {
        stw_le_p(rom + pcir + 0x10, declared / 512U);
        /*
         * The shipped image is a SeaVGABIOS build whose PCIR data structure
         * still advertises 1002:5159 (Radeon RV100).  EFI 1.10 §12.4 requires
         * the PCIR vendor/device ID to match the adapter's configuration
         * header, and a driver that validates the ROM against the device it
         * bound to will reject an image belonging to another chip.  We only
         * get here when the header really is 1002:5046, so restate that.
         */
        stw_le_p(rom + pcir + 0x04, IA64_ATI_VENDOR_ID);
        stw_le_p(rom + pcir + 0x06, IA64_ATI_RAGE128_PF_ID);
    }
    rom[declared - 1] = 0;
    for (i = 0; i < declared - 1U; i++) {
        checksum += rom[i];
    }
    rom[declared - 1] = (uint8_t)(-checksum);
}

/*
 * Restate a video BIOS's PCI Data Structure vendor/device id to match the
 * adapter's configuration header, and fix the ROM image checksum.  A real ATI
 * ROM carries the id of the exact board it shipped on (e.g. a Mach64 GT VBIOS
 * declares 1002:4754 in its PCIR), but we may present that same silicon under
 * a different, driver-friendlier id (the Rage XL 1002:4752, the one both XP
 * IA-64 builds auto-match).  EFI 1.10 12.4 requires the PCIR id to match the
 * device, and a driver that validates its ROM against the bound device rejects
 * a mismatch, so bring the two into agreement.  A no-op when they already
 * agree (e.g. the Rage 128 SeaBIOS path, whose PCIR is fixed up above).
 */
static void ia64_vpc_match_rom_pcir(PCIDevice *pci_dev)
{
    uint8_t *rom;
    uint64_t rom_size;
    uint32_t declared, pcir, i;
    uint16_t ven, dev;
    uint8_t checksum = 0;

    if (pci_dev->io_regions[PCI_ROM_SLOT].size == 0 || !pci_dev->has_rom) {
        return;
    }
    rom = memory_region_get_ram_ptr(&pci_dev->rom);
    rom_size = memory_region_size(&pci_dev->rom);
    if (rom == NULL || rom_size < 0x400 || rom[0] != 0x55 || rom[1] != 0xaa) {
        return;
    }
    declared = (uint32_t)rom[2] * 512U;
    if (declared == 0 || declared > rom_size) {
        return;
    }
    pcir = lduw_le_p(rom + 0x18);
    if (pcir == 0 || pcir + 0x18U > declared ||
        memcmp(rom + pcir, "PCIR", 4) != 0) {
        return;
    }
    ven = pci_get_word(pci_dev->config + PCI_VENDOR_ID);
    dev = pci_get_word(pci_dev->config + PCI_DEVICE_ID);
    if (lduw_le_p(rom + pcir + 0x04) == ven &&
        lduw_le_p(rom + pcir + 0x06) == dev) {
        return; /* already matches */
    }
    stw_le_p(rom + pcir + 0x04, ven);
    stw_le_p(rom + pcir + 0x06, dev);
    rom[declared - 1] = 0;
    for (i = 0; i < declared - 1U; i++) {
        checksum += rom[i];
    }
    rom[declared - 1] = (uint8_t)(-checksum);
}

static void ia64_vpc_configure_vga(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    /*
     * QEMU's generic 1af4:1100 subsystem ID is not a value this chip can
     * report.  A Rage 128 loads the subsystem ID from the video BIOS on an
     * add-in card; with none loaded the documented hardware fallback is
     * SVID = vendor, SID = device (RAGE 128 PRO Register Reference Guide,
     * configuration space chapter).  Drivers index board tables by it.
     */
    pci_set_word(pci_dev->config + PCI_SUBSYSTEM_VENDOR_ID,
                 pci_get_word(pci_dev->config + PCI_VENDOR_ID));
    pci_set_word(pci_dev->config + PCI_SUBSYSTEM_ID,
                 pci_get_word(pci_dev->config + PCI_DEVICE_ID));

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_VGA_FB_PCI_BASE, 4);
    if (pci_dev->io_regions[1].memory != NULL) {
        pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 4,
                                 IA64_VGA_IO_BASE, 4);
    }
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 8,
                             IA64_VGA_MMIO_PCI_BASE, 4);
    /*
     * Assign and enable the expansion ROM.  IA-64 has no architectural legacy
     * video BIOS shadow at 0xC0000, so Windows' videoprt reads the image
     * through the PCI ROM BAR (VideoPortGetRomImage).  Leaving BAR6
     * unassigned means a native display driver never sees a video BIOS at
     * all: Windows Whistler build 2462's Rage 128 miniport then leaves its
     * BIOS table pointer NULL and bugchecks 0x1E dereferencing it.  Every
     * other BAR on this machine is assigned by the machine model too.
     */
    if (pci_dev->io_regions[PCI_ROM_SLOT].size != 0) {
        ia64_vpc_install_ati_rom_tables(pci_dev);
        ia64_vpc_match_rom_pcir(pci_dev);
        /*
         * Assign the ROM BAR but leave its enable bit CLEAR.  With the bit
         * set at enumeration time, Windows' pci.sys generates a fourth
         * memory resource for the devnode (busdrv/pci device.c/enum.c), and
         * XP's inbox Rage 128 miniport calls VideoPortGetAccessRanges with a
         * three-entry array: videoprt's copy loop filters only legacy VGA
         * ranges, so the ROM range overflows the array and the call fails
         * with ERROR_MORE_DATA - silently, no event log - and HwFindAdapter
         * returns 234 (captured live: VideoPortGetAccessRanges RVA 0x33180
         * -> ati2mpaa .GetResources -> .FindAdapter -> Code 10).
         *
         * Readers of the ROM image do not need the bit set at handoff:
         * videoprt/pci.sys enable ROM decode transiently around
         * VideoPortGetRomImage (busdrv/pci romimage.c), which is how build
         * 2462's miniport reads the BIOS tables through BAR6.
         */
        pci_default_write_config(pci_dev, PCI_ROM_ADDRESS,
                                 IA64_VGA_ROM_PCI_BASE, 4);
    }
    /*
     * Both decodes on.  Windows XP's inbox Rage 128 miniport branches on
     * (Command & 3) == 3 in .GetResources (ati2mpaa.sys VMA 0x9375c) and only
     * then treats itself as the VGA device, so it is tempting to advertise
     * something else and take the "VGA disabled" path, which claims no legacy
     * VGA resources and reads the video BIOS from the ROM BAR instead of from
     * the 0xC0000 shadow (which this machine does provide - see
     * ia64_vpc_install_int10()).
     *
     * That does not work, and the reason is worth recording so it is not
     * retried: the miniport claims all three BARs as access ranges, and BAR1
     * is an I/O BAR.  videoprt's CheckIoEnabled (WSRV03 drivers/video/ms/port/
     * registry.c:2114) walks the claimed ranges and fails the whole call if a
     * RangeInIoSpace range is claimed while PCI_ENABLE_IO_SPACE is clear -
     * or, symmetrically, a memory range while PCI_ENABLE_MEMORY_SPACE is
     * clear.  VideoPortVerifyAccessRanges then returns ERROR_INVALID_PARAMETER
     * (registry.c:1966) *silently*, with no event logged, and the device stops
     * with Code 10 before touching a single register.  Any Command value that
     * satisfies CheckIoEnabled for a device with both I/O and memory BARs is
     * therefore exactly 3, which is also what real hardware presents.
     */
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY, 2);

}

static bool ia64_vpc_enable_vga_legacy_switch(PCIDevice *pci_dev,
                                               Error **errp)
{
    if (pci_dev == NULL ||
        !object_property_find(OBJECT(pci_dev),
                              "x-vbe-legacy-mode-switch")) {
        return true;
    }

    return object_property_set_bool(OBJECT(pci_dev),
                                    "x-vbe-legacy-mode-switch", true,
                                    errp);
}

/*
 * Program a network adapter's BARs from the machine's fixed NIC resource
 * pools.  Unlike the other platform devices the NIC model is user-selectable
 * (-nic model=...), so we cannot assume a single fixed BAR layout: the e1000
 * exposes one 128 KiB memory BAR plus a 64-byte I/O BAR, while the Intel
 * PRO/100 (i82557b, the adapter Windows IA-64 actually ships a driver for)
 * exposes a 4 KiB CSR memory BAR, a 64-byte I/O BAR, and a 1 MiB flash memory
 * BAR.  Walk the realised regions instead and hand each BAR a naturally
 * aligned slice of the per-index memory / I/O window.  The firmware advertises
 * these same windows through the PCI0 _CRS, so keep every BAR inside them.
 */
static void ia64_vpc_configure_nic(PCIDevice *pci_dev, unsigned int index)
{
    uint64_t mmio_cursor;
    uint32_t io_cursor;
    int i;

    if (pci_dev == NULL || index >= MAX_NICS) {
        return;
    }

    mmio_cursor = IA64_E1000_MMIO_PCI_BASE + index * IA64_NIC_MMIO_STRIDE;
    io_cursor = IA64_E1000_IO_BASE + index * IA64_NIC_IO_STRIDE;

    for (i = 0; i < PCI_NUM_REGIONS - 1; i++) {
        PCIIORegion *r = &pci_dev->io_regions[i];
        int offset = PCI_BASE_ADDRESS_0 + i * 4;

        if (r->size == 0) {
            continue;
        }

        if (r->type & PCI_BASE_ADDRESS_SPACE_IO) {
            io_cursor = QEMU_ALIGN_UP(io_cursor, r->size);
            pci_default_write_config(pci_dev, offset, io_cursor, 4);
            io_cursor += r->size;
        } else {
            mmio_cursor = QEMU_ALIGN_UP(mmio_cursor, r->size);
            pci_default_write_config(pci_dev, offset,
                                     (uint32_t)mmio_cursor |
                                     (r->type & ~PCI_BASE_ADDRESS_MEM_MASK), 4);
            mmio_cursor += r->size;
            if (r->type & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                pci_default_write_config(pci_dev, offset + 4, 0, 4);
                i++;
            }
        }
    }

    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_platform_pci(IA64VpcMachineState *s)
{
    ia64_vpc_configure_ahci(s->ahci_dev);
    ia64_vpc_configure_ohci(s->ohci_dev);
    ia64_vpc_configure_uhci(s->uhci_dev);
    ia64_vpc_configure_lsi(s->lsi_dev);
    ia64_vpc_configure_vga(s->vga_dev);
    for (unsigned int i = 0; i < s->nic_count; i++) {
        ia64_vpc_configure_nic(s->nic_devs[i], i);
    }
    ia64_vpc_configure_pci_irq(s->ahci_dev);
    ia64_vpc_configure_pci_irq(s->ide_dev);
    ia64_vpc_configure_pci_irq(s->ohci_dev);
    ia64_vpc_configure_pci_irq(s->uhci_dev);
    ia64_vpc_configure_pci_irq(s->lsi_dev);
    ia64_vpc_configure_pci_irq(s->vga_dev);
    for (unsigned int i = 0; i < s->nic_count; i++) {
        ia64_vpc_configure_pci_irq(s->nic_devs[i]);
    }
}

#ifdef CONFIG_IA64_VPC_NETWORK
static void ia64_vpc_record_nic(IA64VpcMachineState *s, PCIBus *bus,
                                PCIDevice *pci_dev)
{
    uint16_t class;

    if (pci_dev == NULL || s->nic_count >= MAX_NICS) {
        return;
    }

    class = pci_get_word(pci_dev->config + PCI_CLASS_DEVICE);
    if (class != PCI_CLASS_NETWORK_ETHERNET ||
        pci_get_bus(pci_dev) != bus) {
        return;
    }

    s->nic_devs[s->nic_count] = pci_dev;
    ia64_vpc_configure_nic(pci_dev, s->nic_count);
    ia64_vpc_configure_pci_irq(pci_dev);
    s->nic_count++;
}

static void ia64_vpc_init_network(IA64VpcMachineState *s, PCIBus *pci_bus)
{
    MachineState *machine = MACHINE(s);
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    unsigned int slot;

    s->nic_count = 0;
    memset(s->nic_devs, 0, sizeof(s->nic_devs));

    /* Keep the default adapter at a stable BDF after the built-in devices. */
    pci_init_nic_in_slot(pci_bus, mc->default_nic, NULL,
                         stringify(IA64_VPC_NIC_SLOT));
    pci_init_nic_devices(pci_bus, mc->default_nic);

    for (slot = IA64_VPC_NIC_SLOT; slot < PCI_SLOT_MAX; slot++) {
        ia64_vpc_record_nic(s, pci_bus,
                            pci_find_device(pci_bus, 0, PCI_DEVFN(slot, 0)));
    }
}
#endif

#define TYPE_IA64_PCI_FIXUP_RESET "ia64-pci-fixup-reset"
OBJECT_DECLARE_SIMPLE_TYPE(IA64PciFixupReset, IA64_PCI_FIXUP_RESET)

struct IA64PciFixupReset {
    Object parent;
    ResettableState reset_state;
    IA64VpcMachineState *machine;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(
    IA64PciFixupReset, ia64_pci_fixup_reset, IA64_PCI_FIXUP_RESET, OBJECT,
    { TYPE_RESETTABLE_INTERFACE }, { })

static ResettableState *ia64_pci_fixup_reset_get_state(Object *obj)
{
    IA64PciFixupReset *s = IA64_PCI_FIXUP_RESET(obj);

    return &s->reset_state;
}

static void ia64_pci_fixup_reset_exit(Object *obj, ResetType type)
{
    IA64PciFixupReset *r = IA64_PCI_FIXUP_RESET(obj);

    (void)type;

    ia64_vpc_configure_platform_pci(r->machine);
}

static void ia64_pci_fixup_reset_class_init(ObjectClass *klass,
                                            const void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    (void)data;
    rc->get_state = ia64_pci_fixup_reset_get_state;
    rc->phases.exit = ia64_pci_fixup_reset_exit;
}

static void ia64_pci_fixup_reset_init(Object *obj)
{
    (void)obj;
}

static void ia64_pci_fixup_reset_finalize(Object *obj)
{
    (void)obj;
}

static void ia64_vpc_map_vga_fixed_windows(IA64VpcMachineState *s,
                                           PCIDevice *pci_dev)
{
    PCIIORegion *fb;
    PCIIORegion *mmio;

    if (pci_dev == NULL) {
        return;
    }

    fb = &pci_dev->io_regions[0];
    mmio = &pci_dev->io_regions[2];
    if (fb->memory == NULL || mmio->memory == NULL ||
        fb->address_space == NULL || mmio->address_space == NULL) {
        return;
    }

    if (fb->address_space != mmio->address_space) {
        return;
    }

    if (s->vga_fb_alias == NULL) {
        s->vga_fb_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_fb_alias, OBJECT(s),
                                 "ia64-vga-fb-fixed", fb->memory, 0, fb->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_FB_PCI_BASE,
                                            s->vga_fb_alias, 1);
    }

    if (s->vga_mmio_alias == NULL) {
        s->vga_mmio_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_mmio_alias, OBJECT(s),
                                 "ia64-vga-mmio-fixed", mmio->memory, 0,
                                 mmio->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_MMIO_PCI_BASE,
                                            s->vga_mmio_alias, 1);
    }

    if (s->vga_legacy_alias == NULL) {
        s->vga_legacy_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(s->vga_legacy_alias,
                                 OBJECT(s),
                                 "ia64-vga-legacy-fixed",
                                 fb->address_space,
                                 IA64_VGA_LEGACY_BASE,
                                 IA64_VGA_LEGACY_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            IA64_VGA_LEGACY_BASE,
                                            s->vga_legacy_alias, 1);
    }
}

#ifdef CONFIG_IA64_VPC_USB
static bool ia64_vpc_init_usb(IA64VpcMachineState *s, PCIBus *pci_bus,
                              Error **errp)
{
    MachineState *machine = MACHINE(s);
    USBBus *usb_bus;
    bool add_default_input;

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    if (!machine->usb) {
        return true;
    }

    s->ohci_dev = pci_create_simple(pci_bus, -1, "pci-ohci");
    ia64_vpc_configure_ohci(s->ohci_dev);

    add_default_input = defaults_enabled() && !s->i8042_enabled;
    if (add_default_input) {
        /*
         * Attach default USB input only when PS/2 is disabled. HID keyboards
         * become QEMU's active input handler, which would otherwise hide
         * firmware-visible PS/2 input before a guest USB stack exists.  Use
         * an absolute pointer so graphical front ends do not require a
         * relative-pointer grab.
         */
        usb_bus = USB_BUS(object_resolve_type_unambiguous(TYPE_USB_BUS,
                                                          errp));
        if (usb_bus == NULL) {
            return false;
        }
        usb_create_simple(usb_bus, "usb-kbd");
        usb_create_simple(usb_bus, "usb-tablet");
    }

    s->uhci_dev = pci_create_simple(pci_bus, -1, TYPE_PIIX3_USB_UHCI);
    ia64_vpc_configure_uhci(s->uhci_dev);
    return true;
}
#endif

static IA64BootInfo ia64_vpc_boot_info(MachineState *machine,
                                       unsigned int cpu_index,
                                       uint64_t entry,
                                       uint64_t global_pointer)
{
    /*
     * The firmware's CPU-assist region (SAL re-entry slots, debug
     * contexts/stacks, early RSE backing stores, boot memory stacks) sits at
     * the top of installed low RAM, as real IA-64 firmware places its SAL
     * scratch; entry.S re-derives the same base from the handoff block.
     */
    uint64_t assist_base = IA64_FW_CPU_ASSIST_BASE_FOR(machine->ram_size);
    IA64BootInfo info = {
        .firmware_base = IA64_FW_BASE,
        .firmware_entry = entry,
        .global_pointer = global_pointer,
        .iva = IA64_IVT_BASE,
        .bsp = assist_base + IA64_FW_EARLY_RSE_OFFSET +
            cpu_index * IA64_FW_EARLY_RSE_SIZE,
        .stack_pointer = assist_base + IA64_FW_CPU_ASSIST_SIZE - 16 -
            cpu_index * IA64_FW_CPU_STACK_SIZE,
        .rsc = IA64_RSC_MODE,
        .fw_cpu_assist_base = assist_base,
        .powered_off = cpu_index != 0,
    };

    return info;
}

/*
 * CPU state initialization — called on every reset.
 *
 * Sets up the CPU in physical mode with firmware entry point.
 * Note: ROM content is loaded by rom_reset() which may run before or
 * after this handler, so we must NOT read ROM content here.  PE32+
 * plabel parsing is deferred to the machine_done notifier.
 */
static void ia64_vpc_reset(void *opaque)
{
    IA64VpcMachineState *s = opaque;
    CPUState *cs;

    CPU_FOREACH(cs) {
        /* The CPUs are not children of the platform system bus. */
        ia64_cpu_reset_to_boot_info(IA64_CPU(cs));
    }

    acpi_pm1_evt_reset(&s->acpi_regs);
    acpi_pm1_cnt_reset(&s->acpi_regs);
    acpi_pm_tmr_reset(&s->acpi_regs);
    acpi_gpe_reset(&s->acpi_regs);
#ifdef CONFIG_IA64_VPC_GRAPHICS
    if (s->vga_dev != NULL) {
        ia64_vpc_reset_int10(s);
    }
#endif
}

/*
 * Machine-done notifier — runs after the first reset cycle completes,
 * so ROM content is guaranteed to be in guest memory.  Parse a firmware
 * plabel only when the firmware image is a valid IA-64 PE32+ binary.
 */
static void ia64_vpc_machine_done(Notifier *notifier, void *data)
{
    IA64VpcMachineState *s = container_of(notifier, IA64VpcMachineState,
                                          done_notifier);
    g_autofree uint8_t *image = NULL;
    IA64FirmwareEntrypoint entrypoint;
    CPUState *cs;

    (void)data;
    ia64_vpc_configure_platform_pci(s);

    if (s->firmware_size == 0) {
        return;
    }

    /*
     * The project firmware is a flat raw binary (no DOS+PE header).
     * Without a strict PE signature gate, random bytes can be mistaken
     * for PE metadata and clobber startup registers (including gp).
     */
    image = g_malloc(s->firmware_size);
    cpu_physical_memory_read(IA64_FW_BASE, image, s->firmware_size);
    if (!ia64_loader_parse_pe_plabel(image, s->firmware_size,
                                     &entrypoint)) {
        return;
    }

    CPU_FOREACH(cs) {
        IA64BootInfo info = ia64_vpc_boot_info(MACHINE(s), cs->cpu_index,
                                               entrypoint.entry,
                                               entrypoint.global_pointer);

        ia64_cpu_set_boot_info(IA64_CPU(cs), &info);
        ia64_cpu_reset_to_boot_info(IA64_CPU(cs));
    }
}

static bool ia64_vpc_validate_configuration(MachineState *machine,
                                            IA64VpcMachineState *s,
                                            Error **errp)
{
    if (machine->ram_size < IA64_FW_LOW_RAM_MIN) {
        g_autofree char *size = size_to_str(IA64_FW_LOW_RAM_MIN);

        error_setg(errp, "Invalid RAM size, should be at least %s", size);
        return false;
    }
    if (s->alat_full && machine->smp.cpus > 1) {
        error_setg(errp, "full ALAT emulation is not SMP-safe");
        return false;
    }
    return true;
}

static bool ia64_vpc_load_firmware(IA64VpcMachineState *s,
                                   MachineState *machine, Error **errp)
{
    g_autofree char *firmware_path = NULL;
    const char *firmware = machine->firmware;
    Error *local_err = NULL;
    int64_t firmware_size;

    if (firmware == NULL) {
        /*
         * Fall back to the shipped image.  Not finding it is not an error:
         * qtest brings this machine up with no firmware at all.
         */
        firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS,
                                       IA64_VPC_DEFAULT_FIRMWARE);
        if (firmware_path == NULL) {
            return true;
        }
        firmware = IA64_VPC_DEFAULT_FIRMWARE;
    } else {
        firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS, firmware);
        if (firmware_path == NULL) {
            firmware_path = g_strdup(firmware);
        }
    }
    firmware_size = get_image_size(firmware_path, &local_err);
    if (local_err != NULL) {
        error_prepend(&local_err, "failed to inspect firmware '%s': ",
                      firmware);
        error_propagate(errp, local_err);
        return false;
    }
    if (firmware_size <= 0 ||
        (uint64_t)firmware_size > machine->ram_size - IA64_FW_BASE) {
        error_setg(errp, "invalid firmware image size for '%s'",
                   firmware);
        return false;
    }
    if (rom_add_file_fixed(firmware, IA64_FW_BASE, -1)) {
        error_setg(errp, "failed to load firmware '%s'", firmware);
        return false;
    }
    s->firmware_size = firmware_size;
    return true;
}

static bool ia64_vpc_build(MachineState *machine, Error **errp)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(machine);
    IA64CPU *cpu;
    DeviceState *pci_host;
    DeviceState *iosapic;
    PCIBus *pci_bus;
    ISABus *isa_bus;
    MemoryRegion *pci_io;
#ifdef CONFIG_IA64_VPC_STORAGE
    DriveInfo *sata_drives[6] = { NULL };
    AHCIPCIState *ahci;
#endif
    int i;

    if (!ia64_vpc_validate_configuration(machine, s, errp)) {
        return false;
    }

    ia64_vpc_map_ram(s);
    if (!ia64_vpc_map_firmware_address_space(s, errp)) {
        return false;
    }
    ia64_vpc_init_rtc(s);
    ia64_vpc_init_watchdog(s);
    ia64_vpc_init_nvram(s);
    ia64_vpc_write_firmware_handoff(s);

    for (i = 0; i < machine->smp.cpus; i++) {
        uint32_t threads = MAX(machine->smp.threads, 1U);
        uint32_t cores = MAX(machine->smp.cores, 1U);
        uint32_t per_socket = threads * cores;
        uint32_t package_base = (i / per_socket) * per_socket;
        IA64BootInfo boot_info = ia64_vpc_boot_info(machine, i,
                                                    IA64_FW_BASE,
                                                    IA64_FW_BASE);

        cpu = IA64_CPU(object_new(machine->cpu_type));
        cpu->alat_full = s->alat_full;
        cpu->socket_id = i / per_socket;
        cpu->core_id = (i / threads) % cores;
        cpu->thread_id = i % threads;
        cpu->cores_per_socket = cores;
        cpu->threads_per_core = threads;
        cpu->package_base = package_base;
        cpu->package_cpus = MIN(per_socket,
                                machine->smp.cpus - package_base);
        ia64_cpu_set_boot_info(cpu, &boot_info);
        if (!qdev_realize_and_unref(DEVICE(cpu), NULL, errp)) {
            return false;
        }
    }
    ia64_vpc_map_lsapic(s);

    iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(iosapic), errp)) {
        return false;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(iosapic), 0, IA64_IOSAPIC_BASE);

    serial_mm_init(get_system_memory(), IA64_UART_BASE, 0,
                   qdev_get_gpio_in(iosapic, 4),
                   115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    if (debug_port_get_chardev()) {
        s->debug_uart = serial_mm_init(get_system_memory(),
                                       IA64_DEBUG_UART_BASE, 0,
                                       qdev_get_gpio_in(iosapic, 3),
                                       115200, debug_port_get_chardev(),
                                       DEVICE_LITTLE_ENDIAN);
    }

    if (!ia64_vpc_load_firmware(s, machine, errp)) {
        return false;
    }

    /* Fill IVT with break bundles (one-time, before any reset) */
    {
        uint64_t break_bundle[2] = {0, 0};
        hwaddr offset;

        for (offset = 0; offset < IA64_IVT_SIZE; offset += 16) {
            cpu_physical_memory_write(IA64_IVT_BASE + offset,
                                      break_bundle, 16);
        }
    }

    /* Defer PE32+ plabel parsing until after ROM content is loaded */
    s->done_notifier.notify = ia64_vpc_machine_done;
    qemu_add_machine_init_done_notifier(&s->done_notifier);

    pci_host = qdev_new(TYPE_IA64_PCI_HOST_BRIDGE);
    if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(pci_host), errp)) {
        return false;
    }
    pci_bus = PCI_BUS(qdev_get_child_bus(pci_host, "pci"));

    /*
     * The 460GX GXB AGP host bridge + GART.  Created before any other PCI
     * device so its pci_setup_iommu() installs the per-devfn DMA routing before
     * any master's bus-master address space is resolved.  The GART translates
     * only the AGP graphics master (the Rage 128, deterministically at the fixed
     * graphics slot below); every other master identity-passes to memory, as on
     * the real 460GX where only the GXB AGP port carries a GART.  Parked at a
     * fixed high slot so it neither shifts the historical BDFs of the built-in
     * devices nor is mistaken for a NIC by the slot-6+ scan.
     */
    s->agp_dev = pci_new(PCI_DEVFN(PCI_SLOT_MAX - 1, 0), TYPE_IA64_AGP);
    object_property_set_int(OBJECT(s->agp_dev), "agp-master-devfn",
                            PCI_DEVFN(IA64_VPC_VGA_SLOT, 0), &error_abort);
    object_property_set_bool(OBJECT(s->agp_dev), "gart-enabled",
                            s->agp_enabled, &error_abort);
    if (!pci_realize_and_unref(s->agp_dev, pci_bus, errp)) {
        return false;
    }

    /*
     * Slot 0 is intentionally empty in the default machine.  Reserve it while
     * creating the built-in devices so their historical slot numbers remain
     * stable, then release it for an explicitly requested PCI controller.
     */
    pci_bus_set_slot_reserved_mask(pci_bus, 1U << 0);
    pci_io = pci_bus->address_space_io;
    ia64_vpc_init_acpi_pm(s, iosapic, pci_io);

    /*
     * Early IA-64 kernel debuggers predate the ACPI DBGP table and drive a
     * fixed legacy COM1 at I/O port 0x3f8 (Windows Whistler build 2462's
     * kdcom.dll hardcodes 0x3f8/0x2f8/0x3e8/0x2e8 and reaches them through
     * HAL's READ_PORT_UCHAR/WRITE_PORT_UCHAR).  Real Merced platforms carry a
     * Super I/O UART there, so alias the debug port's register window into
     * the legacy I/O range as well.  Aliasing rather than instantiating a
     * second UART keeps one device, one chardev and one interrupt line.
     */
    if (s->debug_uart != NULL) {
        memory_region_init_alias(&s->debug_uart_legacy_io, OBJECT(s),
                                 "ia64-vpc.debug-uart-legacy-io",
                                 &s->debug_uart->serial.io, 0,
                                 IA64_LEGACY_COM1_IO_SIZE);
        memory_region_add_subregion(pci_io, IA64_LEGACY_COM1_IO_BASE,
                                    &s->debug_uart_legacy_io);
    }

    /* Leave ISA/SCI lines in the legacy range and route PCI INTx above 15. */
    for (i = 0; i < IA64_PCI_INTX_LINES; i++) {
        qdev_connect_gpio_out(pci_host, i,
                              qdev_get_gpio_in(iosapic,
                                               IA64_PCI_INTX_GSI_BASE + i));
    }

    /*
     * AHCI remains available for guests that support SATA.  Firmware boot
     * storage is provided by the LSI SCSI HBA below.  ahci=off removes the
     * controller entirely: guests without a SATA driver (e.g. Windows XP
     * IA-64) then see neither an unknown PCI device nor its INTx line,
     * which the INTx swizzle would otherwise share with the VGA slot.
     * Slot 1 stays reserved so the remaining devices keep their BDFs.
     */
#ifdef CONFIG_IA64_VPC_STORAGE
    if (s->ahci_enabled) {
        s->ahci_dev = pci_create_simple(pci_bus, -1, TYPE_ICH9_AHCI);
        ia64_vpc_configure_ahci(s->ahci_dev);
        ahci = ICH9_AHCI(s->ahci_dev);
        g_assert(ahci->ahci.ports <= ARRAY_SIZE(sata_drives));
        /*
         * The AHCI ports and the cmd646 IDE controller both present an ATA
         * "if=ide" bus.  When ide=on the CMD646 owns those drives (below), so
         * only bind if=ide media to SATA when IDE is not the active owner;
         * a user can still attach disks to this controller explicitly.
         */
        if (!s->ide_enabled) {
            ide_drive_get(sata_drives, ahci->ahci.ports);
            ahci_ide_create_devs(&ahci->ahci, sata_drives);
        }
    } else {
        pci_bus_set_slot_reserved_mask(pci_bus, 1U << 1);
    }
#endif

    isa_bus = isa_bus_new(NULL, get_system_memory(), pci_io, errp);
    if (isa_bus == NULL) {
        return false;
    }
    for (i = 0; i < ISA_NUM_IRQS; i++) {
        s->isa_irqs[i] = qdev_get_gpio_in(iosapic, i);
    }
    isa_bus_register_input_irqs(isa_bus, s->isa_irqs);
#ifdef CONFIG_IA64_VPC_PS2
    if (s->i8042_enabled) {
        ISADevice *i8042 = isa_new(TYPE_I8042);

        /*
         * Model the PS/2 serial transfer latency of the Super I/O KBC (see
         * the LPC47B27 that real Merced platforms carry).  Presenting mouse
         * and keyboard bytes synchronously with the guest port access lets a
         * solicited AUX reply race the psmouse driver's unlocked command
         * bookkeeping across CPUs and fatally dereference a not-yet-installed
         * protocol_handler; the throttle spaces bytes at ~1 ms as on hardware.
         */
        object_property_set_bool(OBJECT(i8042), "kbd-throttle", true,
                                 &error_abort);
        if (!isa_realize_and_unref(i8042, isa_bus, errp)) {
            return false;
        }
    }
#endif

#ifdef CONFIG_IA64_VPC_USB
    if (!ia64_vpc_init_usb(s, pci_bus, errp)) {
        return false;
    }
#endif

    /* Put the SCSI HBA on device 4. */
#ifdef CONFIG_IA64_VPC_STORAGE
    s->lsi_dev = pci_new(PCI_DEVFN(4, 0), "lsi53c895a");
    qdev_prop_set_bit(DEVICE(s->lsi_dev),
                      "disconnect-on-data-wait", false);
    if (!pci_realize_and_unref(s->lsi_dev, pci_bus, errp)) {
        return false;
    }
    ia64_vpc_configure_lsi(s->lsi_dev);
    lsi53c8xx_handle_legacy_cmdline(DEVICE(s->lsi_dev));
#endif

#ifdef CONFIG_IA64_VPC_GRAPHICS
    if (g_strcmp0(s->vga_model, "mach64") == 0) {
        /*
         * The Mach64 3D Rage (DEV_4754): a PCI 2D adapter with no AGP, chosen
         * with -machine ia64-vpc,vga=mach64.  Create it explicitly at the VGA
         * slot rather than through pci_vga_init()/-vga.
         */
        s->vga_dev = pci_new(PCI_DEVFN(IA64_VPC_VGA_SLOT, 0), "mach64-vga");
        if (!pci_realize_and_unref(s->vga_dev, pci_bus, errp)) {
            return false;
        }
    } else {
        s->vga_dev = pci_vga_init(pci_bus);
    }
    /*
     * The GART scoping above assumes the graphics device is the AGP master at
     * IA64_VPC_VGA_SLOT.  pci_vga_init() auto-assigns the lowest free slot,
     * which is 5 given the built-in layout; fail loudly if that ever drifts.
     */
    if (s->vga_dev != NULL &&
        s->vga_dev->devfn != PCI_DEVFN(IA64_VPC_VGA_SLOT, 0)) {
        error_setg(errp, "graphics device landed at devfn %#x, expected %#x",
                   s->vga_dev->devfn, PCI_DEVFN(IA64_VPC_VGA_SLOT, 0));
        return false;
    }
#endif
    if (!ia64_vpc_enable_vga_legacy_switch(s->vga_dev, errp)) {
        return false;
    }
    ia64_vpc_configure_vga(s->vga_dev);
    ia64_vpc_map_vga_fixed_windows(s, s->vga_dev);
#ifdef CONFIG_IA64_VPC_GRAPHICS
    if (s->vga_dev != NULL) {
        ia64_vpc_init_int10(s, pci_io);
    }
#endif
#ifdef CONFIG_IA64_VPC_NETWORK
    ia64_vpc_init_network(s, pci_bus);
#endif
    pci_bus_clear_slot_reserved_mask(pci_bus, (1U << 0) | (1U << 1));

    /*
     * With ide=on, populate the reserved slot 0 with a dual-channel CMD646
     * PCI IDE controller.  Slot 0 is the platform-anticipated home for IDE:
     * the firmware's fixed PCI-I/O table and the DSDT _PRT both describe an
     * IDE function there, and it keeps every other device's BDF stable.  The
     * firmware assigns the controller's I/O BARs on demand, exactly as for a
     * hand-attached -device cmd646-ide.  secondary=1 enables both channels;
     * pci_ide_create_devs() auto-binds any if=ide media across them.
     */
#ifdef CONFIG_IA64_VPC_STORAGE
    if (s->ide_enabled) {
        s->ide_dev = pci_new(PCI_DEVFN(0, 0), "cmd646-ide");
        qdev_prop_set_uint32(DEVICE(s->ide_dev), "secondary", 1);
        if (!pci_realize_and_unref(s->ide_dev, pci_bus, errp)) {
            return false;
        }
        ia64_vpc_configure_pci_irq(s->ide_dev);
        pci_ide_create_devs(s->ide_dev);
    }
#endif

    s->powerdown_notifier.notify = ia64_vpc_powerdown_req;
    qemu_register_powerdown_notifier(&s->powerdown_notifier);

    qemu_register_reset(ia64_vpc_reset, s);
    s->pci_fixup_reset = object_new(TYPE_IA64_PCI_FIXUP_RESET);
    IA64_PCI_FIXUP_RESET(s->pci_fixup_reset)->machine = s;
    qemu_register_resettable(s->pci_fixup_reset);
    if (vmstate_register_with_alias_id(NULL, 0, &vmstate_ia64_vpc, s,
                                       -1, 0, errp) < 0) {
        return false;
    }
    s->vmstate_registered = true;
    return true;
}

static void ia64_vpc_init(MachineState *machine)
{
    Error *err = NULL;

    if (!ia64_vpc_build(machine, &err)) {
        error_propagate(&error_fatal, err);
    }
}

static void ia64_vpc_machine_instance_init(Object *obj)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

#ifdef CONFIG_IA64_VPC_PS2
    s->i8042_enabled = true;
#endif
#ifdef CONFIG_IA64_VPC_STORAGE
    /*
     * Default the SATA controller off: Windows XP/2003 IA-64 ship no inbox
     * AHCI driver and otherwise see an unidentified PCI device, so the guest
     * that most wants storage is better served booting off the LSI SCSI HBA.
     * Re-enable with ahci=on for SATA-aware guests.  IDE (cmd646) is likewise
     * opt-in via ide=on.
     */
    s->ahci_enabled = false;
    s->ide_enabled = false;
    s->firmware_ide_dma = true;
#endif
#ifdef CONFIG_IA64_VPC_GRAPHICS
    s->firmware_console = IA64_FW_CONSOLE_VGA;
#else
    s->firmware_console = IA64_FW_CONSOLE_SERIAL;
#endif
    /* The 460GX GXB AGP GART is on by default, as on real hardware. */
    s->agp_enabled = true;
    /* Default display adapter: the Rage 128 (honouring -vga); mach64 opt-in. */
    s->vga_model = g_strdup("rage128");
}

static void ia64_vpc_machine_instance_finalize(Object *obj)
{
    IA64VpcMachineState *s = IA64_VPC_MACHINE(obj);

    if (s->vmstate_registered) {
        vmstate_unregister(NULL, &vmstate_ia64_vpc, s);
    }
    g_free(s->nvram_path);
    g_free(s->nvram_resolved_path);
    g_free(s->vga_model);
}

static void ia64_vpc_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    (void)data;

    mc->desc = "IA-64 virtual PC platform";
    mc->init = ia64_vpc_init;
    mc->max_cpus = IA64_VPC_MAX_CPUS;
    mc->default_cpus = 1;
    mc->default_cpu_type = IA64_CPU_TYPE_NAME("madison");
    mc->smp_props.prefer_sockets = true;
    mc->default_ram_size = 2 * GiB;
    mc->default_ram_id = "ia64-vpc.ram";
#ifdef CONFIG_IA64_VPC_GRAPHICS
    mc->default_display = "ati";
#endif
#ifdef CONFIG_IA64_VPC_NETWORK
    /*
     * Default to the 82543GC: XP IA-64's inbox e1000 INF matches exactly
     * PCI\VEN_8086&DEV_1004&REV_02 (e1000w64.sys), giving the guests an
     * inbox *gigabit* adapter -- verified working in XP 2002 and Whistler
     * 2462.  The previous default, the 100 Mbit PRO/100 (i82557b,
     * NET557.IN_ / DEV_1229), remains available via -nic model=i82557b;
     * the plain e1000 (82540EM, DEV_100E) has no inbox IA-64 driver.
     */
    mc->default_nic = "e1000-82543gc";
#endif
#ifdef CONFIG_IA64_VPC_STORAGE
    mc->block_default_type = IF_SCSI;
#else
    mc->block_default_type = IF_NONE;
#endif
    mc->no_serial = 0;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;

    ia64_vpc_add_compat_defaults(mc);

    object_class_property_add_bool(oc, "i8042",
                                   ia64_vpc_get_i8042,
                                   ia64_vpc_set_i8042);
    object_class_property_set_description(oc, "i8042",
        "Set on/off to enable/disable the i8042 PS/2 controller");
    object_class_property_add_bool(oc, "ahci",
                                   ia64_vpc_get_ahci,
                                   ia64_vpc_set_ahci);
    object_class_property_set_description(oc, "ahci",
        "Set on/off to enable/disable the AHCI SATA controller (default off; "
        "on adds a PCI device that guests without a SATA driver cannot use)");
    object_class_property_add_bool(oc, "ide",
                                   ia64_vpc_get_ide,
                                   ia64_vpc_set_ide);
    object_class_property_set_description(oc, "ide",
        "Set on/off to enable/disable the CMD646 PCI IDE controller "
        "(default off; on adds a dual-channel ATA/ATAPI controller in slot 0 "
        "and auto-attaches if=ide drives)");
    object_class_property_add_bool(oc, "agp",
                                   ia64_vpc_get_agp,
                                   ia64_vpc_set_agp);
    object_class_property_set_description(oc, "agp",
        "Set on/off to enable/disable the 460GX AGP GART (default on, as on "
        "real hardware); off makes the Rage 128 fall back to its 32-bit PCI "
        "GART -- clean 2D, but graphics DMA cannot reach RAM above 4 GiB");
    object_class_property_add_str(oc, "vga",
                                  ia64_vpc_get_vga,
                                  ia64_vpc_set_vga);
    object_class_property_set_description(oc, "vga",
        "Display adapter: 'rage128' (default, ATI Rage 128, honours -vga), "
        "'mach64' (ATI Mach64 3D Rage, a PCI 2D adapter with no AGP), or "
        "'std'");
    object_class_property_add_bool(oc, "firmware-ide-dma",
                                   ia64_vpc_get_firmware_ide_dma,
                                   ia64_vpc_set_firmware_ide_dma);
    object_class_property_set_description(oc, "firmware-ide-dma",
        "Set on/off to enable/disable firmware IDE bus-master DMA");
    object_class_property_add_str(oc, "firmware-console",
                                  ia64_vpc_get_firmware_console,
                                  ia64_vpc_set_firmware_console);
    object_class_property_set_description(oc, "firmware-console",
        "Set firmware HCDP primary console to 'serial' or 'vga'");
    object_class_property_add_str(oc, "nvram",
                                  ia64_vpc_get_nvram,
                                  ia64_vpc_set_nvram);
    object_class_property_set_description(oc, "nvram",
        "Set the IA-64 EFI NVRAM file path, 'auto', or 'none'");
    object_class_property_add_str(oc, "alat",
                                  ia64_vpc_get_alat,
                                  ia64_vpc_set_alat);
    object_class_property_set_description(oc, "alat",
        "Set the IA-64 ALAT model to 'zero' (default) or 'full'");
}

static const TypeInfo ia64_vpc_machine_typeinfo = {
    .name = TYPE_IA64_VPC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(IA64VpcMachineState),
    .instance_init = ia64_vpc_machine_instance_init,
    .instance_finalize = ia64_vpc_machine_instance_finalize,
    .class_init = ia64_vpc_machine_class_init,
};

static void ia64_vpc_machine_register_types(void)
{
    type_register_static(&ia64_vpc_machine_typeinfo);
}

type_init(ia64_vpc_machine_register_types)
