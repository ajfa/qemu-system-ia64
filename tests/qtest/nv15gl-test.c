/*
 * QTest smoke test for the NVIDIA Quadro2 Pro (NV15GL) on the ia64-vpc machine.
 *
 * The card is opt-in (-machine ia64-vpc,vga=nv15gl); the machine maps its BARs
 * at fixed windows (ia64_vpc_map_vga_fixed_windows()), so the register aperture
 * and framebuffer are reachable without firmware.  This locks in the device's
 * PCI identity / BAR geometry contract and a couple of live-aperture reads, so
 * a future refactor cannot silently change them.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/generic-pcihost.h"
#include "libqos/pci.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"
#include "hw/ia64/ia64_vpc_abi.h"

/*
 * Fixed NVIDIA BAR windows inside the PCI0 MMIO aperture, matching
 * hw/ia64/ia64_vpc.c: FB at 0xF0000000 (128 MiB, BAR1), MMIO register aperture
 * at 0xF8000000 (16 MiB, BAR0), expansion ROM at 0xF9000000 (BAR6).
 */
#define IA64_NV15_FB_BASE     (IA64_PCI_MMIO_BASE + 0x02000000ULL)
#define IA64_NV15_MMIO_BASE   (IA64_PCI_MMIO_BASE + 0x0A000000ULL)
#define IA64_NV15_ROM_BASE    (IA64_PCI_MMIO_BASE + 0x0B000000ULL)
#define IA64_VPC_VGA_SLOT     5

#define NV15_VENDOR_ID        0x10deU
#define NV15_DEVICE_ID        0x0153U   /* Quadro2 Pro */
#define NV15_SUBSYS_VENDOR    0x10deU
#define NV15_SUBSYS_ID        0x006dU
/* PMC_BOOT_0 (MMIO offset 0): chipset id 0x15 (NV15) in bits [27:20]. */
#define NV15_PMC_BOOT_0       0x0000U
#define NV15_PMC_BOOT_0_VALUE 0x01500000U

static QTestState *nv15_start(void)
{
    return qtest_init("-machine ia64-vpc,vga=nv15gl -m 256M -S");
}

/* The device realizes and the machine reaches the qtest stub. */
static void nv15_smoke(void)
{
    QTestState *qts = nv15_start();

    qtest_quit(qts);
}

/* PCI identity, class, subsystem id and fixed BAR geometry. */
static void nv15_pci_contract(void)
{
    QTestState *qts = nv15_start();
    QGenericPCIBus gbus;
    QPCIDevice *dev;

    qpci_init_generic(&gbus, qts, NULL, false);
    gbus.ecam_alloc_ptr = IA64_PCI_CONFIG_BASE;
    gbus.gpex_pio_base = IA64_PCI_IO_BASE;

    dev = qpci_device_find(&gbus.bus, QPCI_DEVFN(IA64_VPC_VGA_SLOT, 0));
    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==, NV15_VENDOR_ID);
    g_assert_cmphex(qpci_config_readw(dev, PCI_DEVICE_ID), ==, NV15_DEVICE_ID);
    g_assert_cmphex(qpci_config_readw(dev, PCI_CLASS_DEVICE), ==,
                    PCI_CLASS_DISPLAY_VGA);
    g_assert_cmphex(qpci_config_readw(dev, PCI_SUBSYSTEM_VENDOR_ID), ==,
                    NV15_SUBSYS_VENDOR);
    g_assert_cmphex(qpci_config_readw(dev, PCI_SUBSYSTEM_ID), ==,
                    NV15_SUBSYS_ID);

    /* BAR0: non-prefetchable MMIO register aperture. */
    g_assert_cmphex(qpci_config_readl(dev, PCI_BASE_ADDRESS_0), ==,
                    (uint32_t)IA64_NV15_MMIO_BASE |
                    PCI_BASE_ADDRESS_SPACE_MEMORY);
    /* BAR1: prefetchable framebuffer aperture. */
    g_assert_cmphex(qpci_config_readl(dev, PCI_BASE_ADDRESS_1), ==,
                    (uint32_t)IA64_NV15_FB_BASE |
                    PCI_BASE_ADDRESS_SPACE_MEMORY |
                    PCI_BASE_ADDRESS_MEM_PREFETCH);
    /* Expansion ROM (the NV15GL video BIOS is read from the ROM BAR). */
    g_assert_cmphex(qpci_config_readl(dev, PCI_ROM_ADDRESS) &
                    PCI_ROM_ADDRESS_MASK, ==, (uint32_t)IA64_NV15_ROM_BASE);

    g_free(dev);
    qtest_quit(qts);
}

/* The MMIO register aperture is live and identifies the NV15 chip. */
static void nv15_pmc_boot0(void)
{
    QTestState *qts = nv15_start();

    g_assert_cmphex(qtest_readl(qts, IA64_NV15_MMIO_BASE + NV15_PMC_BOOT_0),
                    ==, NV15_PMC_BOOT_0_VALUE);
    qtest_quit(qts);
}

/* The framebuffer BAR maps VRAM: writes read back verbatim. */
static void nv15_framebuffer(void)
{
    QTestState *qts = nv15_start();
    const uint32_t magic = 0xa5c30f69U;

    qtest_writel(qts, IA64_NV15_FB_BASE, magic);
    qtest_writel(qts, IA64_NV15_FB_BASE + 0x1000, ~magic);
    g_assert_cmphex(qtest_readl(qts, IA64_NV15_FB_BASE), ==, magic);
    g_assert_cmphex(qtest_readl(qts, IA64_NV15_FB_BASE + 0x1000), ==, ~magic);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (g_str_equal(qtest_get_arch(), "ia64") &&
        qtest_has_device("nv15gl-vga")) {
        qtest_add_func("/nv15gl/smoke", nv15_smoke);
        qtest_add_func("/nv15gl/pci-contract", nv15_pci_contract);
        qtest_add_func("/nv15gl/pmc-boot0", nv15_pmc_boot0);
        qtest_add_func("/nv15gl/framebuffer", nv15_framebuffer);
    }

    return g_test_run();
}
