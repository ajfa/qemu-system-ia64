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
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev-properties.h"
#include "hw/char/serial-mm.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ahci-pci.h"
#include "hw/ide/ide-dev.h"
#include "hw/input/i8042.h"
#include "hw/acpi/acpi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "net/net.h"
#include "hw/isa/isa.h"
#include "hw/usb/hcd-uhci.h"
#include "hw/usb/usb.h"
#include "hw/ia64/ia64_pci.h"
#include "hw/display/bochs-vbe.h"
#include "hw/display/edid.h"
#include "hw/display/vga_regs.h"
#include "hw/ia64/ia64_iosapic.h"
#include "system/address-spaces.h"
#include "system/rtc.h"
#include "system/runstate.h"
#include "system/system.h"
#include "system/reset.h"
#include "system/watchdog.h"
#include "target/ia64/cpu-qom.h"
#include "target/ia64/cpu.h"

#define IA64_UART_BASE  0x00000047f0000000ULL
#define IA64_DEBUG_UART_BASE 0x00000047f0001000ULL
#define IA64_FW_BASE    0x0000000000100000ULL
#define IA64_LOW_RAM_LIMIT 0x0000000080000000ULL
#define IA64_HIGH_RAM_BASE 0x0000000080200000ULL
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
#define IA64_FW_BOOTSTRAP_STACK_TOP (128 * MiB)
#define IA64_FW_LOW_RAM_MIN IA64_FW_BOOTSTRAP_STACK_TOP
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
#define IA64_VGA_FB_PCI_BASE    0x00000000c4000000ULL
#define IA64_VGA_MMIO_PCI_BASE  0x00000000c8000000ULL
#define IA64_VGA_LEGACY_BASE   0x000a0000U
#define IA64_VGA_LEGACY_SIZE   0x00020000U
#define IA64_IOSAPIC_BASE       0x0000000080110000ULL
#define IA64_IOSAPIC_SIZE       0x0000000000002000ULL
#define IA64_ACPI_PM_IO_BASE    0x00002000U
#define IA64_ACPI_PM_IO_SIZE    0x00000010U
#define IA64_ACPI_PM_RESET_OFFSET 0x0000000cU
#define IA64_ACPI_PM_RESET_VALUE  0x01U
#define IA64_ACPI_SCI_IRQ       9
#define IA64_FW_HANDOFF_ADDR         0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC        0x4d41523436414951ULL /* "QIA64RAM" */
#define IA64_FW_HANDOFF_VERSION      9ULL
#define IA64_FW_CONSOLE_SERIAL       0ULL
#define IA64_FW_CONSOLE_VGA          1ULL
#define IA64_FW_DEBUG_PORT_PRESENT   1ULL
#define IA64_PIB_IPI_LIMIT          0x00100000ULL
#define IA64_PIB_INTA_OFFSET        0x001e0000ULL
#define IA64_PIB_XTP_OFFSET         0x001e0008ULL
#define IA64_VPC_MAX_CPUS           4
#define IA64_VPC_NIC_SLOT           6
#define IA64_VPC_RSE_STACK_SIZE     0x8000ULL
#define IA64_VPC_EARLY_STACK_TOP    0x08000000ULL
#define IA64_VPC_AP_EARLY_STACK_TOP 0x00100000ULL
#define IA64_VPC_EARLY_STACK_STRIDE 0x10000ULL

#define IA64_SAPIC_DELIVERY_INT     0
#define IA64_SAPIC_DELIVERY_NMI     4
#define IA64_SAPIC_DELIVERY_EXTINT  7

static PCIDevice *ia64_vpc_ahci_dev;
static PCIDevice *ia64_vpc_ohci_dev;
static PCIDevice *ia64_vpc_uhci_dev;
static PCIDevice *ia64_vpc_lsi_dev;
static PCIDevice *ia64_vpc_vga_dev;
static PCIDevice *ia64_vpc_nic_devs[MAX_NICS];
static unsigned int ia64_vpc_nic_count;
static MemoryRegion *ia64_vpc_vga_fb_alias;
static MemoryRegion *ia64_vpc_vga_mmio_alias;
static MemoryRegion *ia64_vpc_vga_legacy_alias;
static Object *ia64_vpc_pci_fixup_reset;
static MemoryRegion *ia64_vpc_lsapic_mmio;
static MemoryRegion ia64_vpc_firmware_space;
static MemoryRegion ia64_vpc_rtc_mmio;
static MemoryRegion ia64_vpc_watchdog_mmio;
static MemoryRegion ia64_vpc_nvram_mmio;
static QEMUTimer *ia64_vpc_watchdog_timer;
static uint64_t ia64_vpc_watchdog_timeout;
static uint64_t ia64_vpc_watchdog_code;
static uint8_t ia64_vpc_nvram_data[IA64_NVRAM_SIZE];
static char *ia64_vpc_nvram_path;
static char *ia64_vpc_nvram_resolved_path;
static bool ia64_vpc_nvram_write_warning;
static MemoryRegion ia64_vpc_acpi_pm;
static MemoryRegion ia64_vpc_acpi_reset;
static ACPIREGS ia64_vpc_acpi_regs;
static qemu_irq ia64_vpc_acpi_sci_irq;
static Notifier ia64_vpc_powerdown_notifier;
static qemu_irq ia64_vpc_isa_irqs[ISA_NUM_IRQS];
static bool ia64_vpc_i8042_enabled = true;
static bool ia64_vpc_firmware_ide_dma = true;
static uint64_t ia64_vpc_firmware_console = IA64_FW_CONSOLE_VGA;
static bool ia64_vpc_alat_full;

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

static void ia64_vpc_init_rtc(MachineState *machine)
{
    memory_region_init_io(&ia64_vpc_rtc_mmio, OBJECT(machine),
                          &ia64_vpc_rtc_ops, NULL, "ia64-vpc.rtc",
                          IA64_RTC_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_RTC_BASE,
                                        &ia64_vpc_rtc_mmio, 2);
}

static void ia64_vpc_watchdog_expired(void *opaque)
{
    (void)opaque;

    warn_report("IA-64 firmware watchdog expired (code 0x%" PRIx64 ")",
                ia64_vpc_watchdog_code);
    ia64_vpc_watchdog_timeout = 0;
    watchdog_perform_action();
}

static uint64_t ia64_vpc_watchdog_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    (void)opaque;
    (void)size;

    switch (addr) {
    case IA64_WATCHDOG_TIMEOUT:
        return ia64_vpc_watchdog_timeout;
    case IA64_WATCHDOG_CODE:
        return ia64_vpc_watchdog_code;
    default:
        return 0;
    }
}

static void ia64_vpc_watchdog_write(void *opaque, hwaddr addr,
                                    uint64_t value, unsigned size)
{
    int64_t now;
    int64_t delta;

    (void)opaque;
    if (size != sizeof(uint64_t)) {
        return;
    }

    switch (addr) {
    case IA64_WATCHDOG_CODE:
        ia64_vpc_watchdog_code = value;
        break;
    case IA64_WATCHDOG_TIMEOUT:
        ia64_vpc_watchdog_timeout = value;
        timer_del(ia64_vpc_watchdog_timer);
        if (value == 0) {
            break;
        }
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (value > (uint64_t)(INT64_MAX - now) / NANOSECONDS_PER_SECOND) {
            delta = INT64_MAX - now;
        } else {
            delta = value * NANOSECONDS_PER_SECOND;
        }
        timer_mod(ia64_vpc_watchdog_timer, now + delta);
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
    (void)opaque;

    timer_del(ia64_vpc_watchdog_timer);
    ia64_vpc_watchdog_timeout = 0;
    ia64_vpc_watchdog_code = 0;
}

static void ia64_vpc_init_watchdog(MachineState *machine)
{
    ia64_vpc_watchdog_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           ia64_vpc_watchdog_expired, NULL);
    memory_region_init_io(&ia64_vpc_watchdog_mmio, OBJECT(machine),
                          &ia64_vpc_watchdog_ops, NULL,
                          "ia64-vpc.firmware-watchdog",
                          IA64_WATCHDOG_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_WATCHDOG_BASE,
                                        &ia64_vpc_watchdog_mmio, 2);
    qemu_register_reset(ia64_vpc_watchdog_reset, NULL);
}

static char *ia64_vpc_get_nvram(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return g_strdup(ia64_vpc_nvram_path ?: "auto");
}

static void ia64_vpc_set_nvram(Object *obj, const char *value, Error **errp)
{
    (void)obj;
    (void)errp;

    g_free(ia64_vpc_nvram_path);
    ia64_vpc_nvram_path = g_strcmp0(value, "auto") == 0 ?
                           NULL : g_strdup(value);
}

static uint64_t ia64_vpc_nvram_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    uint64_t value = 0;
    unsigned i;

    (void)opaque;
    for (i = 0; i < size; i++) {
        value |= (uint64_t)ia64_vpc_nvram_data[addr + i] << (i * 8);
    }
    return value;
}

static void ia64_vpc_nvram_commit(void)
{
    g_autoptr(GError) err = NULL;

    if (!ia64_vpc_nvram_resolved_path) {
        return;
    }
    if (!g_file_set_contents(ia64_vpc_nvram_resolved_path,
                             (const char *)ia64_vpc_nvram_data,
                             sizeof(ia64_vpc_nvram_data), &err) &&
        !ia64_vpc_nvram_write_warning) {
        warn_report("failed to save IA-64 NVRAM '%s': %s",
                    ia64_vpc_nvram_resolved_path,
                    err ? err->message : "unknown error");
        ia64_vpc_nvram_write_warning = true;
    }
}

static void ia64_vpc_nvram_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    unsigned i;

    (void)opaque;
    if (addr == IA64_NVRAM_COMMIT_OFFSET && size == 8 &&
        value == IA64_NVRAM_COMMIT_MAGIC) {
        ia64_vpc_nvram_commit();
        return;
    }
    for (i = 0; i < size; i++) {
        ia64_vpc_nvram_data[addr + i] = value >> (i * 8);
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

static void ia64_vpc_init_nvram(MachineState *machine)
{
    g_autofree char *firmware_path = NULL;
    g_autofree char *directory = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    gsize length = 0;

    memset(ia64_vpc_nvram_data, 0, sizeof(ia64_vpc_nvram_data));
    g_clear_pointer(&ia64_vpc_nvram_resolved_path, g_free);
    ia64_vpc_nvram_write_warning = false;

    if (g_strcmp0(ia64_vpc_nvram_path, "none") != 0) {
        if (ia64_vpc_nvram_path) {
            ia64_vpc_nvram_resolved_path =
                g_strdup(ia64_vpc_nvram_path);
        } else if (machine->firmware) {
            firmware_path = qemu_find_file(QEMU_FILE_TYPE_BIOS,
                                           machine->firmware);
            if (!firmware_path) {
                firmware_path = g_strdup(machine->firmware);
            }
            directory = g_path_get_dirname(firmware_path);
            ia64_vpc_nvram_resolved_path =
                g_build_filename(directory, "nvram", NULL);
        }
    }

    if (ia64_vpc_nvram_resolved_path &&
        g_file_get_contents(ia64_vpc_nvram_resolved_path, &contents,
                            &length, &err)) {
        if (length == sizeof(ia64_vpc_nvram_data)) {
            memcpy(ia64_vpc_nvram_data, contents, length);
        } else {
            warn_report("ignoring IA-64 NVRAM '%s': expected %zu bytes, "
                        "found %zu",
                        ia64_vpc_nvram_resolved_path,
                        sizeof(ia64_vpc_nvram_data), (size_t)length);
        }
    } else if (err && !g_error_matches(err, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)) {
        warn_report("failed to load IA-64 NVRAM '%s': %s",
                    ia64_vpc_nvram_resolved_path, err->message);
    }

    memory_region_init_io(&ia64_vpc_nvram_mmio, OBJECT(machine),
                          &ia64_vpc_nvram_ops, NULL, "ia64-vpc.nvram",
                          IA64_NVRAM_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), IA64_NVRAM_BASE,
                                        &ia64_vpc_nvram_mmio, 2);
}

static GlobalProperty ia64_vpc_compat_defaults[] = {
    /*
     * Some IA-64 USB hub drivers use an alignment-requiring 32-bit load for
     * packed extended-property descriptors.  Do not expose the optional
     * selective-suspend property on HID input devices.
     */
    { "usb-kbd", "msos-desc", "off" },
    { "usb-mouse", "msos-desc", "off" },
    { "usb-tablet", "msos-desc", "off" },
};

static uint16_t ia64_lduw(const uint8_t *p)
{
    return p[0] | (p[1] << 8);
}

static uint32_t ia64_ldl(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static bool ia64_vpc_get_i8042(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return ia64_vpc_i8042_enabled;
}

static void ia64_vpc_set_i8042(Object *obj, bool value, Error **errp)
{
    (void)obj;
    (void)errp;

    ia64_vpc_i8042_enabled = value;
}

static bool ia64_vpc_get_firmware_ide_dma(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return ia64_vpc_firmware_ide_dma;
}

static void ia64_vpc_set_firmware_ide_dma(Object *obj, bool value,
                                          Error **errp)
{
    (void)obj;
    (void)errp;

    ia64_vpc_firmware_ide_dma = value;
}

static char *ia64_vpc_get_firmware_console(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return g_strdup(ia64_vpc_firmware_console == IA64_FW_CONSOLE_VGA ?
                    "vga" : "serial");
}

static void ia64_vpc_set_firmware_console(Object *obj, const char *value,
                                          Error **errp)
{
    (void)obj;

    if (g_strcmp0(value, "serial") == 0) {
        ia64_vpc_firmware_console = IA64_FW_CONSOLE_SERIAL;
        return;
    }
    if (g_strcmp0(value, "vga") == 0) {
        ia64_vpc_firmware_console = IA64_FW_CONSOLE_VGA;
        return;
    }

    error_setg(errp, "firmware-console must be 'serial' or 'vga'");
}

static char *ia64_vpc_get_alat(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;

    return g_strdup(ia64_vpc_alat_full ? "full" : "zero");
}

static void ia64_vpc_set_alat(Object *obj, const char *value, Error **errp)
{
    (void)obj;

    if (g_strcmp0(value, "zero") == 0) {
        ia64_vpc_alat_full = false;
        return;
    }
    if (g_strcmp0(value, "full") == 0) {
        ia64_vpc_alat_full = true;
        return;
    }

    error_setg(errp, "alat must be 'zero' or 'full'");
}

static void ia64_vpc_acpi_update_sci(ACPIREGS *ar)
{
    acpi_update_sci(ar, ia64_vpc_acpi_sci_irq);
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

static void ia64_vpc_init_acpi_pm(MachineState *machine, DeviceState *iosapic,
                                  MemoryRegion *pci_io)
{
    ia64_vpc_acpi_sci_irq = qdev_get_gpio_in(iosapic, IA64_ACPI_SCI_IRQ);

    memory_region_init(&ia64_vpc_acpi_pm, OBJECT(machine), "ia64-acpi-pm",
                       IA64_ACPI_PM_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_ACPI_PM_IO_BASE,
                                &ia64_vpc_acpi_pm);

    acpi_pm1_evt_init(&ia64_vpc_acpi_regs, ia64_vpc_acpi_update_sci,
                      &ia64_vpc_acpi_pm);
    acpi_pm1_cnt_init(&ia64_vpc_acpi_regs, &ia64_vpc_acpi_pm,
                      false, false, 0, true);
    acpi_pm_tmr_init(&ia64_vpc_acpi_regs, ia64_vpc_acpi_update_sci,
                     &ia64_vpc_acpi_pm);
    memory_region_init_io(&ia64_vpc_acpi_reset, OBJECT(machine),
                          &ia64_vpc_acpi_reset_ops, NULL,
                          "ia64-acpi-reset", 1);
    memory_region_add_subregion(&ia64_vpc_acpi_pm,
                                IA64_ACPI_PM_RESET_OFFSET,
                                &ia64_vpc_acpi_reset);

    /*
     * acpi_update_sci() always folds in GPE status.  The current platform
     * exposes no GPE block to the guest, but the shared ACPI core still needs
     * backing storage for that internal zero-valued contribution.
     */
    acpi_gpe_init(&ia64_vpc_acpi_regs, 2);
}

static void ia64_vpc_powerdown_req(Notifier *n, void *opaque)
{
    (void)n;
    (void)opaque;

    if (ia64_vpc_acpi_regs.pm1.evt.en & ACPI_BITMASK_POWER_BUTTON_ENABLE) {
        acpi_pm1_evt_power_down(&ia64_vpc_acpi_regs);
    } else {
        /* Avoid making QEMU's powerdown action a no-op before ACPI is armed. */
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }
}

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

static void ia64_vpc_map_lsapic(void)
{
    if (ia64_vpc_lsapic_mmio != NULL) {
        return;
    }

    ia64_vpc_lsapic_mmio = g_new(MemoryRegion, 1);
    memory_region_init_io(ia64_vpc_lsapic_mmio, NULL,
                          &ia64_vpc_lsapic_ops, NULL,
                          "ia64-vpc.local-sapic",
                          IA64_LOCAL_SAPIC_SIZE);
    memory_region_add_subregion(get_system_memory(), IA64_LOCAL_SAPIC_PA,
                                ia64_vpc_lsapic_mmio);
}

static void ia64_vpc_map_firmware_address_space(void)
{
    /*
     * IA-64 reserves the top 16 MiB below 4 GiB for PAL/SAL firmware
     * resources.  Decode it so firmware identity mappings can use the
     * platform address space directly.
     */
    memory_region_init_ram(&ia64_vpc_firmware_space, NULL,
                           "ia64-firmware-address-space",
                           IA64_FIRMWARE_ADDRESS_SPACE_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        IA64_FIRMWARE_ADDRESS_SPACE_BASE,
                                        &ia64_vpc_firmware_space, 1);
}

static uint64_t ia64_vpc_map_ram_alias(MachineState *machine,
                                       hwaddr guest_base,
                                       uint64_t backing_offset,
                                       uint64_t remaining,
                                       uint64_t capacity,
                                       const char *name)
{
    MemoryRegion *alias;
    uint64_t size = MIN(remaining, capacity);

    if (size == 0) {
        return 0;
    }

    alias = g_new(MemoryRegion, 1);
    memory_region_init_alias(alias, OBJECT(machine), name, machine->ram,
                             backing_offset, size);
    memory_region_add_subregion(get_system_memory(), guest_base, alias);
    return size;
}

static void ia64_vpc_map_ram(MachineState *machine)
{
    uint64_t remaining = machine->ram_size;
    uint64_t offset = 0;
    uint64_t size;

    if (machine->ram == NULL) {
        return;
    }

    /*
     * Keep the RAM backing densely packed while leaving the platform's
     * firmware and PCI apertures free in the guest physical address space.
     * RAM displaced by those apertures is mapped above 4 GiB instead of
     * being hidden by higher-priority device regions.
     */
    size = ia64_vpc_map_ram_alias(machine, 0, offset, remaining,
                                  IA64_LOW_RAM_LIMIT,
                                  "ia64-vpc.low-ram");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(machine, IA64_HIGH_RAM_BASE, offset,
                                  remaining,
                                  IA64_PCI_MMIO_BASE - IA64_HIGH_RAM_BASE,
                                  "ia64-vpc.high-ram-below-pci");
    offset += size;
    remaining -= size;

    size = ia64_vpc_map_ram_alias(
        machine, IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE, offset, remaining,
        IA64_LOCAL_SAPIC_PA -
            (IA64_PCI_MMIO_BASE + IA64_PCI_MMIO_SIZE),
        "ia64-vpc.high-ram-above-pci");
    offset += size;
    remaining -= size;

    ia64_vpc_map_ram_alias(machine, IA64_HIGH_RAM_AFTER_FIRMWARE_BASE,
                           offset, remaining, remaining,
                           "ia64-vpc.high-ram-above-4g");
}

static void ia64_vpc_write_firmware_handoff(MachineState *machine)
{
    uint8_t handoff[80] = { 0 };
    bool debug_port_present = debug_port_get_chardev() != NULL;

    stq_le_p(handoff, IA64_FW_HANDOFF_MAGIC);
    stq_le_p(handoff + 8, IA64_FW_HANDOFF_VERSION);
    stq_le_p(handoff + 16, machine->ram_size);
    stq_le_p(handoff + 24, ia64_vpc_firmware_console);
    stq_le_p(handoff + 32, ia64_vpc_firmware_ide_dma);
    stq_le_p(handoff + 40,
             debug_port_present ? IA64_FW_DEBUG_PORT_PRESENT : 0);
    stq_le_p(handoff + 48, debug_port_present ? IA64_DEBUG_UART_BASE : 0);
    stq_le_p(handoff + 56, ia64_vpc_i8042_enabled);
    stq_le_p(handoff + 64, machine->smp.cpus);
    stq_le_p(handoff + 72, ia64_vpc_nvram_resolved_path != NULL);
    cpu_physical_memory_write(IA64_FW_HANDOFF_ADDR, handoff, sizeof(handoff));
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


/* ---- INT 10h video BIOS bridge (ported from main) ---- */

#define IA64_INT10_ROM_BASE     0x000c0000U
#define IA64_INT10_ROM_SIZE     0x00000200U
#define IA64_INT10_ROM_PCIR_OFFSET    0x0020U
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
#define IA64_ATI_PLL_XCLK         23000U
#define IA64_ATI_PLL_REFERENCE_FREQ 2700U
#define IA64_ATI_PLL_REFERENCE_DIV  4U
#define IA64_ATI_PLL_MIN_FREQ     12000U
#define IA64_ATI_PLL_MAX_FREQ     35000U

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
 *     push di
 *     add  dx, 2
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
    0xe3, 0x0a, 0x57, 0x83, 0xc2, 0x02, 0xfc, 0xed,
    0xab, 0xe2, 0xfc, 0x5f, 0xba, 0xe0, 0x01, 0xed,
    0x89, 0x46, 0xfe, 0x83, 0xc2, 0x02, 0xed, 0x89,
    0xc3, 0x83, 0xc2, 0x02, 0xed, 0x89, 0xc1, 0x83,
    0xc2, 0x02, 0xed, 0x89, 0xc2, 0x8b, 0x46, 0xfe,
    0x89, 0xec, 0x5d, 0xcf,
};

/* Option-ROM initialization entry: install C000:0100 as vector 10h. */
static const uint8_t ia64_int10_rom_init[] = {
    0x50, 0x1e, 0x31, 0xc0, 0x8e, 0xd8, 0xc7, 0x06,
    0x40, 0x00, 0x00, 0x01, 0xc7, 0x06, 0x42, 0x00,
    0x00, 0xc0, 0x1f, 0x58, 0xcb,
};


/*
 * INT 10h bridge state.  The option ROM installed at C0000h contains a
 * real-mode handler that forwards the caller's registers to the
 * ia64-vpc.int10-pci-io window; the machine services the request natively
 * and the handler reads back the results.
 */
typedef struct IA64Int10State {
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
} IA64Int10State;

static IA64Int10State ia64_vpc_int10;

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

static void ia64_int10_program_legacy_mode(IA64Int10State *s,
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

static bool ia64_int10_set_legacy_mode(IA64Int10State *s,
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

static void ia64_int10_response_clear(IA64Int10State *s)
{
    memset(s->int10_response, 0, sizeof(s->int10_response));
    s->int10_response_length = 0;
    s->int10_response_offset = 0;
}

static void ia64_int10_response_size(IA64Int10State *s, size_t size)
{
    g_assert(size <= sizeof(s->int10_response));
    g_assert((size & 1) == 0);
    memset(s->int10_response, 0, size);
    s->int10_response_length = size;
    s->int10_response_offset = 0;
}

static void ia64_int10_vbe_success(IA64Int10State *s)
{
    s->int10_result.ax = 0x004f;
}

static void ia64_int10_vbe_failure(IA64Int10State *s)
{
    s->int10_result.ax = 0x014f;
}

static void ia64_int10_vbe_unsupported(IA64Int10State *s)
{
    s->int10_result.ax = 0x024f;
}

static void ia64_int10_controller_info(IA64Int10State *s)
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

static void ia64_int10_mode_info(IA64Int10State *s)
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

static const IA64VbeMode *ia64_int10_current_mode(IA64Int10State *s,
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

static void ia64_int10_set_mode(IA64Int10State *s)
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
    ia64_int10_vbe_success(s);
}

static void ia64_int10_window_control(IA64Int10State *s)
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

static void ia64_int10_scanline(IA64Int10State *s)
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

static void ia64_int10_display_start(IA64Int10State *s)
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

static void ia64_int10_dpms(IA64Int10State *s)
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

static void ia64_int10_ddc(IA64Int10State *s)
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

static void ia64_int10_execute(IA64Int10State *s)
{
    uint16_t current_mode;

    s->int10_result = s->int10_request;
    ia64_int10_response_clear(s);

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
    IA64Int10State *s = opaque;
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
    IA64Int10State *s = opaque;
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
    if (vendor != IA64_ATI_VENDOR_ID || device != IA64_ATI_RAGE128_PF_ID) {
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

static void ia64_vpc_install_int10(IA64Int10State *s)
{
    uint8_t rom[IA64_INT10_ROM_SIZE] = { 0 };
    uint8_t vector[4];
    uint8_t checksum = 0;
    uint16_t vendor = pci_get_word(ia64_vpc_vga_dev->config + PCI_VENDOR_ID);
    uint16_t device = pci_get_word(ia64_vpc_vga_dev->config + PCI_DEVICE_ID);
    size_t i;

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

static void ia64_vpc_reset_int10(IA64Int10State *s)
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

static void ia64_vpc_init_int10(IA64Int10State *s,
                                MemoryRegion *pci_io)
{
    memory_region_init_io(&s->int10_pci_io, NULL,
                          &ia64_int10_io_ops, s,
                          "ia64-vpc.int10-pci-io", IA64_INT10_IO_SIZE);
    memory_region_add_subregion(pci_io, IA64_INT10_IO_BASE,
                                &s->int10_pci_io);
    ia64_vpc_reset_int10(s);
}

static void ia64_vpc_configure_vga(PCIDevice *pci_dev)
{
    if (pci_dev == NULL) {
        return;
    }

    if (object_property_find(OBJECT(pci_dev),
                             "x-vbe-legacy-mode-switch")) {
        object_property_set_bool(OBJECT(pci_dev),
                                 "x-vbe-legacy-mode-switch", true,
                                 &error_abort);
    }

    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0,
                             IA64_VGA_FB_PCI_BASE, 4);
    if (pci_dev->io_regions[1].memory != NULL) {
        pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 4,
                                 IA64_VGA_IO_BASE, 4);
    }
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0 + 8,
                             IA64_VGA_MMIO_PCI_BASE, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY, 2);

}

static void ia64_vpc_configure_nic(PCIDevice *pci_dev, unsigned int index)
{
    uint64_t mmio_base;
    uint32_t io_base;

    if (pci_dev == NULL || index >= MAX_NICS) {
        return;
    }

    mmio_base = IA64_E1000_MMIO_PCI_BASE +
                index * IA64_E1000_MMIO_SIZE;
    io_base = IA64_E1000_IO_BASE + index * IA64_E1000_IO_SIZE;
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_0, mmio_base, 4);
    pci_default_write_config(pci_dev, PCI_BASE_ADDRESS_1, io_base, 4);
    pci_default_write_config(pci_dev, PCI_COMMAND,
                             PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                             PCI_COMMAND_MASTER, 2);
}

static void ia64_vpc_configure_platform_pci(void)
{
    ia64_vpc_configure_ahci(ia64_vpc_ahci_dev);
    ia64_vpc_configure_ohci(ia64_vpc_ohci_dev);
    ia64_vpc_configure_uhci(ia64_vpc_uhci_dev);
    ia64_vpc_configure_lsi(ia64_vpc_lsi_dev);
    ia64_vpc_configure_vga(ia64_vpc_vga_dev);
    for (unsigned int i = 0; i < ia64_vpc_nic_count; i++) {
        ia64_vpc_configure_nic(ia64_vpc_nic_devs[i], i);
    }
    ia64_vpc_configure_pci_irq(ia64_vpc_ahci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_ohci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_uhci_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_lsi_dev);
    ia64_vpc_configure_pci_irq(ia64_vpc_vga_dev);
    for (unsigned int i = 0; i < ia64_vpc_nic_count; i++) {
        ia64_vpc_configure_pci_irq(ia64_vpc_nic_devs[i]);
    }
}

static void ia64_vpc_record_nic(PCIBus *bus, PCIDevice *pci_dev)
{
    uint16_t class;

    if (pci_dev == NULL || ia64_vpc_nic_count >= MAX_NICS) {
        return;
    }

    class = pci_get_word(pci_dev->config + PCI_CLASS_DEVICE);
    if (class != PCI_CLASS_NETWORK_ETHERNET ||
        pci_dev->io_regions[0].size != IA64_E1000_MMIO_SIZE ||
        pci_dev->io_regions[1].size != IA64_E1000_IO_SIZE ||
        pci_get_bus(pci_dev) != bus) {
        return;
    }

    ia64_vpc_nic_devs[ia64_vpc_nic_count] = pci_dev;
    ia64_vpc_configure_nic(pci_dev, ia64_vpc_nic_count);
    ia64_vpc_configure_pci_irq(pci_dev);
    ia64_vpc_nic_count++;
}

static void ia64_vpc_init_network(MachineState *machine, PCIBus *pci_bus)
{
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    unsigned int slot;

    ia64_vpc_nic_count = 0;
    memset(ia64_vpc_nic_devs, 0, sizeof(ia64_vpc_nic_devs));

    /* Keep the default adapter at a stable BDF after the built-in devices. */
    pci_init_nic_in_slot(pci_bus, mc->default_nic, NULL,
                         stringify(IA64_VPC_NIC_SLOT));
    pci_init_nic_devices(pci_bus, mc->default_nic);

    for (slot = IA64_VPC_NIC_SLOT; slot < PCI_SLOT_MAX; slot++) {
        ia64_vpc_record_nic(pci_bus,
                            pci_find_device(pci_bus, 0, PCI_DEVFN(slot, 0)));
    }
}

#define TYPE_IA64_PCI_FIXUP_RESET "ia64-pci-fixup-reset"
OBJECT_DECLARE_SIMPLE_TYPE(IA64PciFixupReset, IA64_PCI_FIXUP_RESET)

struct IA64PciFixupReset {
    Object parent;
    ResettableState reset_state;
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
    (void)obj;
    (void)type;

    ia64_vpc_configure_platform_pci();
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

static void ia64_vpc_map_vga_fixed_windows(PCIDevice *pci_dev)
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

    if (ia64_vpc_vga_fb_alias == NULL) {
        ia64_vpc_vga_fb_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_fb_alias, OBJECT(pci_dev),
                                 "ia64-vga-fb-fixed", fb->memory, 0, fb->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_FB_PCI_BASE,
                                            ia64_vpc_vga_fb_alias, 1);
    }

    if (ia64_vpc_vga_mmio_alias == NULL) {
        ia64_vpc_vga_mmio_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_mmio_alias, OBJECT(pci_dev),
                                 "ia64-vga-mmio-fixed", mmio->memory, 0,
                                 mmio->size);
        memory_region_add_subregion_overlap(fb->address_space,
                                            IA64_VGA_MMIO_PCI_BASE,
                                            ia64_vpc_vga_mmio_alias, 1);
    }

    if (ia64_vpc_vga_legacy_alias == NULL) {
        ia64_vpc_vga_legacy_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(ia64_vpc_vga_legacy_alias,
                                 OBJECT(pci_dev),
                                 "ia64-vga-legacy-fixed",
                                 fb->address_space,
                                 IA64_VGA_LEGACY_BASE,
                                 IA64_VGA_LEGACY_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            IA64_VGA_LEGACY_BASE,
                                            ia64_vpc_vga_legacy_alias, 1);
    }
}

static void ia64_vpc_init_usb(MachineState *machine, PCIBus *pci_bus)
{
    USBBus *usb_bus;
    bool add_default_input;

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    if (!machine->usb) {
        return;
    }

    ia64_vpc_ohci_dev = pci_create_simple(pci_bus, -1, "pci-ohci");
    ia64_vpc_configure_ohci(ia64_vpc_ohci_dev);

    add_default_input = defaults_enabled() && !ia64_vpc_i8042_enabled;
    if (add_default_input) {
        /*
         * Attach default USB input only when PS/2 is disabled. HID keyboards
         * become QEMU's active input handler, which would otherwise hide
         * firmware-visible PS/2 input before a guest USB stack exists.  Use
         * an absolute pointer so graphical front ends do not require a
         * relative-pointer grab.
         */
        usb_bus = USB_BUS(object_resolve_type_unambiguous(TYPE_USB_BUS,
                                                          &error_abort));
        usb_create_simple(usb_bus, "usb-kbd");
        usb_create_simple(usb_bus, "usb-tablet");
    }

    ia64_vpc_uhci_dev = pci_create_simple(pci_bus, -1, TYPE_PIIX3_USB_UHCI);
    ia64_vpc_configure_uhci(ia64_vpc_uhci_dev);
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
    CPUState *cs;

    (void)opaque;

    if (ia64_vpc_vga_dev != NULL) {
        ia64_vpc_reset_int10(&ia64_vpc_int10);
    }

    CPU_FOREACH(cs) {
        CPUIA64State *env = cpu_env(cs);
        uint64_t cpu_offset = cs->cpu_index;

        /* The CPUs are not children of the platform system bus. */
        cpu_reset(cs);

        /* Start in physical mode at the firmware entry point. */
        env->psr = 0;
        env->ip = IA64_FW_BASE;
        env->br[0] = IA64_FW_BASE;
        env->cr_iva = IA64_IVT_BASE;
        env->cr_pta = 0;
        env->cr[8] = 0x0000000000000030ULL; /* rr0: 256MB, RID 0 */
        env->cr_dcr = IA64_DCR_DM | IA64_DCR_DP;
        env->ar_kr0 = IA64_FW_BASE;
        env->ar_kr7 = 0;

        /* Give every processor independent early RSE and memory stacks. */
        env->ar_rsc = IA64_RSC_MODE;
        env->ar_bsp = 0x80000 + cpu_offset * IA64_VPC_RSE_STACK_SIZE;
        env->ar_bspstore = env->ar_bsp;
        env->ar_rnat = 0;
        env->cfm_sof = 0;
        env->cfm_sol = 0;
        env->cfm_sor = 0;
        env->cfm_rrb_gr = 0;
        env->gr[12] = cpu_offset == 0 ? IA64_VPC_EARLY_STACK_TOP - 16 :
                      IA64_VPC_AP_EARLY_STACK_TOP - 16 -
                      cpu_offset * IA64_VPC_EARLY_STACK_STRIDE;

        /* The flat firmware entry code derives its link-time GP. */
        env->gr[1] = IA64_FW_BASE;
        env->pal_halt_wake = cs->start_powered_off;
        ia64_itc_write(env, 0);
        env->ar_fpsr = IA64_FPSR_DEFAULT;
        set_float_rounding_mode(float_round_nearest_even, &env->fp_status);
        set_flush_to_zero(false, &env->fp_status);
        set_flush_inputs_to_zero(false, &env->fp_status);
        set_default_nan_mode(false, &env->fp_status);
    }

    acpi_pm1_evt_reset(&ia64_vpc_acpi_regs);
    acpi_pm1_cnt_reset(&ia64_vpc_acpi_regs);
    acpi_pm_tmr_reset(&ia64_vpc_acpi_regs);
    acpi_gpe_reset(&ia64_vpc_acpi_regs);
}

/*
 * Machine-done notifier — runs after the first reset cycle completes,
 * so ROM content is guaranteed to be in guest memory.  Parse a firmware
 * plabel only when the firmware image is a valid IA-64 PE32+ binary.
 */
typedef struct {
    Notifier notifier;
    MachineState *machine;
} IA64VpcDoneNotifier;

static void ia64_vpc_machine_done(Notifier *notifier, void *data)
{
    IA64VpcDoneNotifier *n = container_of(notifier,
                                            IA64VpcDoneNotifier, notifier);
    MachineState *machine = n->machine;
    CPUState *cs;

    ia64_vpc_configure_platform_pci();

    if (!machine->firmware) {
        return;
    }

    uint8_t mz_hdr[0x40];
    uint8_t pe_hdr[24];
    uint8_t opt_hdr[20];
    uint32_t e_lfanew, entry_rva;
    uint16_t machine_type, opt_magic;
    uint64_t plabel[2];

    /*
     * The project firmware is a flat raw binary (no DOS+PE header).
     * Without a strict PE signature gate, random bytes can be mistaken
     * for PE metadata and clobber startup registers (including gp).
     */
    cpu_physical_memory_read(IA64_FW_BASE, mz_hdr, sizeof(mz_hdr));
    if (ia64_lduw(mz_hdr) != 0x5a4d) {
        return;
    }

    /* Read PE header offset (e_lfanew at offset 0x3C in MZ header) */
    e_lfanew = ia64_ldl(mz_hdr + 0x3c);
    if (e_lfanew < sizeof(mz_hdr) || e_lfanew > 0x100000) {
        return;
    }

    cpu_physical_memory_read(IA64_FW_BASE + e_lfanew, pe_hdr, sizeof(pe_hdr));
    if (memcmp(pe_hdr, "PE\0\0", 4) != 0) {
        return;
    }

    machine_type = ia64_lduw(pe_hdr + 4);
    if (machine_type != 0x0200) {
        return;
    }

    cpu_physical_memory_read(IA64_FW_BASE + e_lfanew + 24, opt_hdr,
                             sizeof(opt_hdr));
    opt_magic = ia64_lduw(opt_hdr);
    if (opt_magic != 0x020b) {
        return;
    }

    /* PE32+ optional header: AddressOfEntryPoint at offset 16 */
    entry_rva = ia64_ldl(opt_hdr + 16);
    if (entry_rva == 0) {
        return;
    }

    /* Read plabel (function descriptor) at entry point RVA */
    cpu_physical_memory_read(IA64_FW_BASE + entry_rva, plabel, 16);

    {
        uint64_t entry_addr = le64_to_cpu(plabel[0]);
        uint64_t gp_val = le64_to_cpu(plabel[1]);

        /* Sanity: entry must be in a reasonable address range */
        if (entry_addr != 0 && entry_addr < 0x100000000ULL) {
            CPU_FOREACH(cs) {
                CPUIA64State *env = cpu_env(cs);

                env->ip = entry_addr;
                env->br[0] = entry_addr;
                env->gr[1] = gp_val;
            }
        }
    }
}

static IA64VpcDoneNotifier vpc_done_notifier;

static void ia64_vpc_init(MachineState *machine)
{
    IA64CPU *cpu;
    DeviceState *pci_host;
    DeviceState *iosapic;
    PCIBus *pci_bus;
    ISABus *isa_bus;
    MemoryRegion *pci_io;
    DriveInfo *sata_drives[6] = { NULL };
    AHCIPCIState *ahci;
    int i;

    if (machine->ram_size < IA64_FW_LOW_RAM_MIN) {
        char *sz = size_to_str(IA64_FW_LOW_RAM_MIN);

        error_report("Invalid RAM size, should be at least %s", sz);
        g_free(sz);
        exit(1);
    }

    if (ia64_vpc_alat_full && machine->smp.cpus > 1) {
        error_report("full ALAT emulation is not SMP-safe");
        exit(1);
    }

    ia64_vpc_map_ram(machine);
    ia64_vpc_map_firmware_address_space();
    ia64_vpc_init_rtc(machine);
    ia64_vpc_init_watchdog(machine);
    ia64_vpc_init_nvram(machine);
    ia64_vpc_write_firmware_handoff(machine);

    for (i = 0; i < machine->smp.cpus; i++) {
        uint32_t threads = MAX(machine->smp.threads, 1U);
        uint32_t cores = MAX(machine->smp.cores, 1U);
        uint32_t per_socket = threads * cores;
        uint32_t package_base = (i / per_socket) * per_socket;

        cpu = IA64_CPU(object_new(machine->cpu_type));
        cpu->alat_full = ia64_vpc_alat_full;
        cpu->env.alat_full = ia64_vpc_alat_full;
        cpu->socket_id = i / per_socket;
        cpu->core_id = (i / threads) % cores;
        cpu->thread_id = i % threads;
        cpu->cores_per_socket = cores;
        cpu->threads_per_core = threads;
        cpu->package_base = package_base;
        cpu->package_cpus = MIN(per_socket,
                                machine->smp.cpus - package_base);
        object_property_set_bool(OBJECT(cpu), "start-powered-off", i != 0,
                                 &error_abort);
        qdev_realize_and_unref(DEVICE(cpu), NULL, &error_fatal);
    }
    ia64_vpc_map_lsapic();

    iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(iosapic), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(iosapic), 0, IA64_IOSAPIC_BASE);

    serial_mm_init(get_system_memory(), IA64_UART_BASE, 0,
                   qdev_get_gpio_in(iosapic, 4),
                   115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    if (debug_port_get_chardev()) {
        serial_mm_init(get_system_memory(), IA64_DEBUG_UART_BASE, 0,
                       qdev_get_gpio_in(iosapic, 3),
                       115200, debug_port_get_chardev(),
                       DEVICE_LITTLE_ENDIAN);
    }

    if (machine->firmware) {
        if (rom_add_file_fixed(machine->firmware, IA64_FW_BASE, -1)) {
            error_report("failed to load firmware '%s'", machine->firmware);
            exit(1);
        }
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
    vpc_done_notifier.machine = machine;
    vpc_done_notifier.notifier.notify = ia64_vpc_machine_done;
    qemu_add_machine_init_done_notifier(&vpc_done_notifier.notifier);

    pci_host = qdev_new(TYPE_IA64_PCI_HOST_BRIDGE);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(pci_host), &error_fatal);
    pci_bus = PCI_BUS(qdev_get_child_bus(pci_host, "pci"));

    /*
     * Slot 0 is intentionally empty in the default machine.  Reserve it while
     * creating the built-in devices so their historical slot numbers remain
     * stable, then release it for an explicitly requested PCI controller.
     */
    pci_bus_set_slot_reserved_mask(pci_bus, 1U << 0);
    pci_io = pci_bus->address_space_io;
    ia64_vpc_init_acpi_pm(machine, iosapic, pci_io);

    /* Leave ISA/SCI lines in the legacy range and route PCI INTx above 15. */
    for (i = 0; i < IA64_PCI_INTX_LINES; i++) {
        qdev_connect_gpio_out(pci_host, i,
                              qdev_get_gpio_in(iosapic,
                                               IA64_PCI_INTX_GSI_BASE + i));
    }

    /*
     * AHCI remains available for guests that support SATA.  Firmware boot
     * storage is provided by the LSI SCSI HBA below.
     */
    ia64_vpc_ahci_dev = pci_create_simple(pci_bus, -1, TYPE_ICH9_AHCI);
    ia64_vpc_configure_ahci(ia64_vpc_ahci_dev);
    ahci = ICH9_AHCI(ia64_vpc_ahci_dev);
    g_assert(ahci->ahci.ports <= ARRAY_SIZE(sata_drives));
    ide_drive_get(sata_drives, ahci->ahci.ports);
    ahci_ide_create_devs(&ahci->ahci, sata_drives);

    isa_bus = isa_bus_new(NULL, get_system_memory(), pci_io, &error_fatal);
    for (i = 0; i < ISA_NUM_IRQS; i++) {
        ia64_vpc_isa_irqs[i] = qdev_get_gpio_in(iosapic, i);
    }
    isa_bus_register_input_irqs(isa_bus, ia64_vpc_isa_irqs);
    if (ia64_vpc_i8042_enabled) {
        isa_create_simple(isa_bus, TYPE_I8042);
    }

    ia64_vpc_init_usb(machine, pci_bus);

    /* Put the SCSI HBA on device 4. */
    ia64_vpc_lsi_dev = pci_new(PCI_DEVFN(4, 0), "lsi53c895a");
    qdev_prop_set_bit(DEVICE(ia64_vpc_lsi_dev),
                      "disconnect-on-data-wait", false);
    pci_realize_and_unref(ia64_vpc_lsi_dev, pci_bus, &error_fatal);
    ia64_vpc_configure_lsi(ia64_vpc_lsi_dev);
    lsi53c8xx_handle_legacy_cmdline(DEVICE(ia64_vpc_lsi_dev));

    ia64_vpc_vga_dev = pci_vga_init(pci_bus);
    ia64_vpc_configure_vga(ia64_vpc_vga_dev);
    if (ia64_vpc_vga_dev != NULL) {
        ia64_vpc_init_int10(&ia64_vpc_int10, pci_io);
    }
    ia64_vpc_map_vga_fixed_windows(ia64_vpc_vga_dev);
    ia64_vpc_init_network(machine, pci_bus);
    pci_bus_clear_slot_reserved_mask(pci_bus, 1U << 0);

    ia64_vpc_powerdown_notifier.notify = ia64_vpc_powerdown_req;
    qemu_register_powerdown_notifier(&ia64_vpc_powerdown_notifier);

    qemu_register_reset(ia64_vpc_reset, NULL);
    ia64_vpc_pci_fixup_reset = object_new(TYPE_IA64_PCI_FIXUP_RESET);
    qemu_register_resettable(ia64_vpc_pci_fixup_reset);
}

static void ia64_vpc_machine_init(MachineClass *mc)
{
    ObjectClass *oc = OBJECT_CLASS(mc);

    mc->desc = "IA-64 virtual PC platform";
    mc->init = ia64_vpc_init;
    mc->max_cpus = IA64_VPC_MAX_CPUS;
    mc->default_cpus = 1;
    mc->default_cpu_type = IA64_CPU_TYPE_NAME("montecito");
    mc->smp_props.prefer_sockets = true;
    mc->default_ram_size = 2 * GiB;
    mc->default_ram_id = "ia64-vpc.ram";
    mc->default_display = "ati";
    mc->default_nic = "e1000";
    mc->block_default_type = IF_SCSI;
    mc->no_serial = 0;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;

    compat_props_add(mc->compat_props, ia64_vpc_compat_defaults,
                     G_N_ELEMENTS(ia64_vpc_compat_defaults));

    object_class_property_add_bool(oc, "i8042",
                                   ia64_vpc_get_i8042,
                                   ia64_vpc_set_i8042);
    object_class_property_set_description(oc, "i8042",
        "Set on/off to enable/disable the i8042 PS/2 controller");
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

DEFINE_MACHINE("ia64-vpc", ia64_vpc_machine_init)
