/*
 * IA-64 virtual platform machine tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/sockets.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "libqtest.h"
#include "libqos/generic-pcihost.h"
#include "libqos/pci.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"
#include "hw/net/e1000_regs.h"

#define IA64_LEGACY_IO_BASE          0x000000800010000000ULL
#define IA64_PCI_CONFIG_BASE         0x0000007ff0000000ULL
#define IA64_ACPI_PM_IO_BASE         0x00002000ULL
#define IA64_ACPI_PM1_CNT_OFFSET     0x04ULL
#define IA64_ACPI_PM_RESET_OFFSET    0x0cULL
#define IA64_ACPI_PM_RESET_VALUE     0x01U
#define IA64_RTC_BASE                0x00000000ffef0000ULL
#define IA64_NVRAM_BASE              0x00000000fff00000ULL
#define IA64_NVRAM_SIZE              (64 * KiB)
#define IA64_NVRAM_COMMIT_OFFSET     (IA64_NVRAM_SIZE - 8)
#define IA64_NVRAM_COMMIT_MAGIC      0x54494d4d4f43564eULL
#define IA64_IOSAPIC_BASE            0x0000000080110000ULL
#define IA64_IOSAPIC_IOREGSEL        0x00ULL
#define IA64_IOSAPIC_IOWIN           0x10ULL
#define IA64_IOSAPIC_EOI             0x40ULL
#define IA64_IOSAPIC_RTE_BASE        0x10U
#define IA64_IOSAPIC_RTE_LOWEST      BIT(8)
#define IA64_IOSAPIC_RTE_DELIVERY    BIT(12)
#define IA64_IOSAPIC_RTE_REMOTE_IRR  BIT(14)
#define IA64_IOSAPIC_RTE_LEVEL       BIT(15)
#define IA64_FW_HANDOFF_ADDR         0x00000000000ff000ULL
#define IA64_FW_HANDOFF_MAGIC        0x4d41523436414951ULL
#define IA64_FW_HANDOFF_VERSION      9ULL
#define IA64_FW_HANDOFF_RAM_SIZE     0x10ULL
#define IA64_FW_HANDOFF_CONSOLE      0x18ULL
#define IA64_FW_HANDOFF_IDE_DMA      0x20ULL
#define IA64_FW_HANDOFF_DEBUG        0x28ULL
#define IA64_FW_HANDOFF_DEBUG_BASE   0x30ULL
#define IA64_FW_HANDOFF_I8042        0x38ULL
#define IA64_FW_HANDOFF_CPUS         0x40ULL
#define IA64_FW_HANDOFF_NVRAM        0x48ULL
#define IA64_TEST_RAM_SIZE           (256 * MiB)

#define IA64_LSI_MMIO_BASE           0x00000000c1030000ULL
#define IA64_LSI_SCRIPT_ADDR         0x00100000U
#define IA64_LSI_MSGOUT_ADDR         0x00110000U
#define IA64_LSI_CDB_ADDR            0x00110010U
#define IA64_LSI_STATUS_ADDR         0x00110020U
#define IA64_LSI_COMPLETE_ADDR       0x00110030U
#define IA64_LSI_REG_DSTAT           0x0c
#define IA64_LSI_REG_ISTAT0          0x14
#define IA64_LSI_REG_DSP             0x2c
#define IA64_LSI_REG_SIST0           0x42
#define IA64_LSI_REG_SIST1           0x43
#define IA64_LSI_ISTAT0_DIP          0x01
#define IA64_LSI_ISTAT0_INTF         0x04
#define IA64_LSI_DSTAT_SIR           0x04
#define IA64_LSI_PHASE_CMD           2
#define IA64_LSI_PHASE_ST            3
#define IA64_LSI_PHASE_MO            6
#define IA64_LSI_PHASE_MI            7
#define IA64_LSI_SCRIPT_SELECT       0x40000008U
#define IA64_LSI_SCRIPT_DISCONNECT   0x48000000U
#define IA64_LSI_SCRIPT_INTERRUPT    0x98080000U
#define IA64_LSI_SCRIPT_MOVE(phase, count) \
    (((phase) << 24) | (count))

#define IA64_E1000_MMIO_BASE         0x00000000c1040000ULL
#define IA64_E1000_IO_BASE           0x0000c400U
#define IA64_E1000_SLOT              6U
#define IA64_E1000_GSI               18U
#define IA64_E1000_TX_DESC_ADDR      0x00120000U
#define IA64_E1000_TX_BUFFER_ADDR    0x00121000U
#define IA64_E1000_RX_DESC_ADDR      0x00122000U
#define IA64_E1000_RX_BUFFER_ADDR    0x00123000U
#define IA64_E1000_RING_SIZE         128U
#define IA64_E1000_TEST_TIMEOUT_MS   5000

typedef struct ExpectedPCIDevice {
    unsigned slot;
    uint16_t vendor;
    uint16_t device;
    uint16_t command;
    uint8_t irq_line;
    uint8_t irq_pin;
    uint32_t bars[6];
} ExpectedPCIDevice;

static const ExpectedPCIDevice expected_e1000 = {
    .slot = IA64_E1000_SLOT,
    .vendor = PCI_VENDOR_ID_INTEL,
    .device = E1000_DEV_ID_82540EM,
    .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
    .irq_line = IA64_E1000_GSI,
    .irq_pin = 1,
    .bars = {
        [0] = IA64_E1000_MMIO_BASE,
        [1] = IA64_E1000_IO_BASE | PCI_BASE_ADDRESS_SPACE_IO,
    },
};

/*
 * The default adapter is the Intel PRO/100 (i82557b), the model Windows
 * IA-64 ships an inbox driver for.  It exposes a 4 KiB prefetchable CSR BAR,
 * a 64-byte I/O BAR, and a 1 MiB flash BAR, all placed by the machine's
 * generic per-BAR NIC allocator inside the NIC memory / I/O windows.
 */
static const ExpectedPCIDevice expected_i82557b = {
    .slot = IA64_E1000_SLOT,
    .vendor = PCI_VENDOR_ID_INTEL,
    .device = 0x1229,
    .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
    .irq_line = IA64_E1000_GSI,
    .irq_pin = 1,
    .bars = {
        [0] = IA64_E1000_MMIO_BASE | PCI_BASE_ADDRESS_MEM_PREFETCH,
        [1] = IA64_E1000_IO_BASE | PCI_BASE_ADDRESS_SPACE_IO,
        [2] = 0xc1060000,
    },
};

static uint32_t iosapic_read(QTestState *qts, uint32_t reg);
static void iosapic_write(QTestState *qts, uint32_t reg, uint32_t value);

static QTestState *ia64_vpc_start(const char *extra_args)
{
    return qtest_initf("-machine ia64-vpc -m 256M -S %s",
                       extra_args ?: "");
}

static uint64_t ia64_sparse_io_offset(uint32_t port)
{
    return ((uint64_t)(port >> 2) << 12) | (port & 0xfff);
}

static void test_acpi_reset_register(void)
{
    QTestState *qts = ia64_vpc_start(NULL);

    qtest_writeb(qts,
                 IA64_LEGACY_IO_BASE + IA64_ACPI_PM_IO_BASE +
                 IA64_ACPI_PM_RESET_OFFSET,
                 IA64_ACPI_PM_RESET_VALUE);
    qtest_qmp_eventwait(qts, "RESET");
    qtest_quit(qts);
}

static void assert_firmware_handoff(QTestState *qts, uint64_t i8042,
                                    uint64_t cpus, uint64_t nvram)
{
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR), ==,
                    IA64_FW_HANDOFF_MAGIC);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR + 8), ==,
                    IA64_FW_HANDOFF_VERSION);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_RAM_SIZE), ==,
                    IA64_TEST_RAM_SIZE);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_CONSOLE), ==, 1);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_IDE_DMA), ==, 1);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_DEBUG), ==, 0);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_DEBUG_BASE), ==, 0);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_I8042), ==, i8042);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_CPUS), ==, cpus);
    g_assert_cmphex(qtest_readq(qts, IA64_FW_HANDOFF_ADDR +
                               IA64_FW_HANDOFF_NVRAM), ==, nvram);
}

static void test_firmware_handoff_defaults(void)
{
    QTestState *qts = ia64_vpc_start(NULL);

    assert_firmware_handoff(qts, 1, 1, 0);
    qtest_quit(qts);
}

static void test_firmware_handoff_i8042_off(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc,i8042=off "
                                 "-m 256M -S");

    assert_firmware_handoff(qts, 0, 1, 0);
    qtest_quit(qts);
}

static void test_smp_topology(gconstpointer opaque)
{
    uint64_t count = GPOINTER_TO_UINT(opaque);
    g_autofree char *args = g_strdup_printf("-smp %" PRIu64, count);
    QTestState *qts = ia64_vpc_start(args);
    g_autoptr(QDict) response = NULL;
    QList *cpus;

    assert_firmware_handoff(qts, 1, count, 0);
    response = qtest_qmp(qts, "{'execute':'query-cpus-fast'}");
    g_assert(qdict_haskey(response, "return"));
    cpus = qdict_get_qlist(response, "return");
    g_assert_cmpuint(qlist_size(cpus), ==, count);
    qtest_quit(qts);
}

static void test_smp_rejects_full_alat(void)
{
    const char *argv[] = {
        qtest_qemu_binary(NULL),
        "-machine", "ia64-vpc,alat=full",
        "-smp", "2",
        "-display", "none",
        NULL,
    };
    g_autofree char *stderr_text = NULL;
    g_autoptr(GError) error = NULL;
    int wait_status;

    g_assert_true(g_spawn_sync(NULL, (char **)argv, NULL,
                               G_SPAWN_STDOUT_TO_DEV_NULL,
                               NULL, NULL, NULL, &stderr_text,
                               &wait_status, &error));
    g_assert_no_error(error);
    g_assert_true(WIFEXITED(wait_status));
    g_assert_cmpint(WEXITSTATUS(wait_status), ==, 1);
    g_assert_nonnull(strstr(stderr_text,
                            "full ALAT emulation is not SMP-safe"));
}

static bool rtc_value_is_current(uint64_t value)
{
    int64_t now = time(NULL);

    return value >= now - 5 && value <= now + 5;
}

static void test_rtc_aligned_read(void)
{
    QTestState *qts = ia64_vpc_start(NULL);
    uint64_t before_write;
    uint64_t after_write;
    uint64_t after_reset;

    before_write = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(before_write));

    /* The RTC window is deliberately read-only. */
    qtest_writeq(qts, IA64_RTC_BASE, UINT64_MAX);
    after_write = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(after_write));

    qtest_system_reset(qts);
    after_reset = qtest_readq(qts, IA64_RTC_BASE);
    g_assert_true(rtc_value_is_current(after_reset));
    qtest_quit(qts);
}

static void test_nvram_commit_and_restart(void)
{
    const uint64_t test_value = 0x1122334455667788ULL;
    g_autofree char *tmpdir = NULL;
    g_autofree char *path = NULL;
    g_autofree char *quoted_path = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) error = NULL;
    gsize length = 0;
    QTestState *qts;

    tmpdir = g_dir_make_tmp("ia64-vpc-nvram-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(tmpdir);
    path = g_build_filename(tmpdir, "nvram.bin", NULL);
    quoted_path = g_shell_quote(path);

    qts = qtest_initf("-machine ia64-vpc,nvram=%s -m 256M -S",
                      quoted_path);
    qtest_writeq(qts, IA64_NVRAM_BASE, test_value);
    qtest_writeq(qts, IA64_NVRAM_BASE + IA64_NVRAM_COMMIT_OFFSET,
                 IA64_NVRAM_COMMIT_MAGIC);
    qtest_quit(qts);

    g_assert_true(g_file_get_contents(path, &contents, &length, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(length, ==, IA64_NVRAM_SIZE);
    g_assert_cmphex(ldq_le_p(contents), ==, test_value);

    qts = qtest_initf("-machine ia64-vpc,nvram=%s -m 256M -S",
                      quoted_path);
    g_assert_cmphex(qtest_readq(qts, IA64_NVRAM_BASE), ==, test_value);
    qtest_quit(qts);

    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(g_rmdir(tmpdir), ==, 0);
}

static void ia64_qpci_init(QGenericPCIBus *gbus, QTestState *qts)
{
    qpci_init_generic(gbus, qts, NULL, false);
    gbus->ecam_alloc_ptr = IA64_PCI_CONFIG_BASE;
    gbus->gpex_pio_base = IA64_LEGACY_IO_BASE;
}

static void assert_pci_device(QPCIBus *bus, const ExpectedPCIDevice *expected)
{
    QPCIDevice *dev = qpci_device_find(bus,
                                       QPCI_DEVFN(expected->slot, 0));
    unsigned bar;

    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==,
                    expected->vendor);
    g_assert_cmphex(qpci_config_readw(dev, PCI_DEVICE_ID), ==,
                    expected->device);
    g_assert_cmphex(qpci_config_readw(dev, PCI_COMMAND), ==,
                    expected->command);
    g_assert_cmphex(qpci_config_readb(dev, PCI_INTERRUPT_LINE), ==,
                    expected->irq_line);
    g_assert_cmphex(qpci_config_readb(dev, PCI_INTERRUPT_PIN), ==,
                    expected->irq_pin);
    for (bar = 0; bar < ARRAY_SIZE(expected->bars); bar++) {
        g_assert_cmphex(qpci_config_readl(dev,
                                         PCI_BASE_ADDRESS_0 + bar * 4),
                        ==, expected->bars[bar]);
    }
    g_free(dev);
}

static void test_pci_default_layout(void)
{
    static const ExpectedPCIDevice devices[] = {
        {
            .slot = 1, .vendor = 0x8086, .device = 0x2922,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                       PCI_COMMAND_MASTER,
            .irq_line = 17, .irq_pin = 1,
            .bars = { [4] = 0x0000c101, [5] = 0xc1020000 },
        }, {
            .slot = 2, .vendor = 0x106b, .device = 0x003f,
            .command = PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
            .irq_line = 18, .irq_pin = 1,
            .bars = { [0] = 0xc1010000 },
        }, {
            .slot = 3, .vendor = 0x8086, .device = 0x7020,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MASTER,
            .irq_line = 18, .irq_pin = 4,
            .bars = { [4] = 0x0000c121 },
        }, {
            .slot = 4, .vendor = 0x1000, .device = 0x0012,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                       PCI_COMMAND_MASTER,
            .irq_line = 16, .irq_pin = 1,
            .bars = {
                [0] = 0x0000c201,
                [1] = 0xc1030000,
                [2] = 0xc1032000,
            },
        }, {
            .slot = 5, .vendor = 0x1002, .device = 0x5046,
            .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY,
            .irq_line = 17, .irq_pin = 1,
            .bars = {
                [0] = 0xc4000008,
                [1] = 0x0000c301,
                [2] = 0xc8000000,
            },
        },
    };
    QTestState *qts = ia64_vpc_start(NULL);
    QGenericPCIBus gbus;
    unsigned i;

    ia64_qpci_init(&gbus, qts);
    for (i = 0; i < 8; i++) {
        QPCIDevice *empty = qpci_device_find(&gbus.bus, QPCI_DEVFN(0, i));

        g_assert_null(empty);
    }
    for (i = 0; i < ARRAY_SIZE(devices); i++) {
        assert_pci_device(&gbus.bus, &devices[i]);
    }
    {
        QPCIDevice *lsi = qpci_device_find(&gbus.bus, QPCI_DEVFN(4, 0));

        g_assert_nonnull(lsi);
        g_assert_cmphex(qpci_config_readw(lsi, PCI_SUBSYSTEM_VENDOR_ID), ==,
                        PCI_VENDOR_ID_LSI_LOGIC);
        g_assert_cmphex(qpci_config_readw(lsi, PCI_SUBSYSTEM_ID), ==,
                        PCI_VENDOR_ID_LSI_LOGIC);
        g_free(lsi);
    }
    assert_pci_device(&gbus.bus, &expected_i82557b);
    qtest_quit(qts);
}

static void test_e1000_resources_survive_reset(void)
{
    QTestState *qts = ia64_vpc_start("-nic user,model=e1000");
    QGenericPCIBus gbus;

    ia64_qpci_init(&gbus, qts);
    assert_pci_device(&gbus.bus, &expected_e1000);
    qtest_system_reset(qts);
    assert_pci_device(&gbus.bus, &expected_e1000);
    qtest_quit(qts);
}

static void test_e1000_intx_route(void)
{
    const uint8_t vector = 0x52;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + IA64_E1000_GSI * 2;
    QTestState *qts = ia64_vpc_start("-nic user,model=e1000");

    iosapic_write(qts, rte_low, vector | IA64_IOSAPIC_RTE_LEVEL);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_IMC, UINT32_MAX);
    (void)qtest_readl(qts, IA64_E1000_MMIO_BASE + E1000_ICR);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_IMS,
                 E1000_IMS_TXDW);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_ICS,
                 E1000_ICS_TXDW);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);

    g_assert_cmphex(qtest_readl(qts, IA64_E1000_MMIO_BASE + E1000_ICR) &
                    E1000_ICR_TXDW, !=, 0);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, ==, 0);
    qtest_quit(qts);
}

static bool e1000_wait_tx_done(QTestState *qts, struct e1000_tx_desc *desc)
{
    int i;

    for (i = 0; i < IA64_E1000_TEST_TIMEOUT_MS; i++) {
        qtest_memread(qts, IA64_E1000_TX_DESC_ADDR, desc, sizeof(*desc));
        if (le32_to_cpu(desc->upper.data) & E1000_TXD_STAT_DD) {
            return true;
        }
        qtest_clock_step(qts, 1000);
        g_usleep(1000);
    }
    return false;
}

static bool e1000_wait_rx_done(QTestState *qts, struct e1000_rx_desc *desc)
{
    int i;

    for (i = 0; i < IA64_E1000_TEST_TIMEOUT_MS; i++) {
        qtest_memread(qts, IA64_E1000_RX_DESC_ADDR, desc, sizeof(*desc));
        if (desc->status & E1000_RXD_STAT_DD) {
            return true;
        }
        qtest_clock_step(qts, 1000);
        g_usleep(1000);
    }
    return false;
}

static bool socket_receive_all(int fd, void *buffer, size_t length)
{
    uint8_t *next = buffer;

    while (length != 0) {
        GPollFD poll_fd = {
            .fd = fd,
            .events = G_IO_IN,
        };
        ssize_t received;

        if (g_poll(&poll_fd, 1, IA64_E1000_TEST_TIMEOUT_MS) != 1 ||
            !(poll_fd.revents & G_IO_IN)) {
            return false;
        }
        received = recv(fd, next, length, 0);
        if (received <= 0) {
            return false;
        }
        next += received;
        length -= received;
    }
    return true;
}

static void test_e1000_packet_transfer(void)
{
    static const uint8_t packet[64] = {
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        0x52, 0x54, 0x00, 0x65, 0x43, 0x21,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x32,
        0x12, 0x34, 0x00, 0x00, 0x40, 0x11,
        0x00, 0x00, 0x0a, 0x00, 0x02, 0x0f,
        0x0a, 0x00, 0x02, 0x02,
    };
    struct e1000_tx_desc tx_desc = { 0 };
    struct e1000_rx_desc rx_desc = { 0 };
    uint32_t frame_length;
    uint8_t received[sizeof(packet)];
    uint8_t rx_buffer[sizeof(packet)];
    g_autofree char *args = NULL;
    QTestState *qts;
    int sockets[2];

    g_assert_cmpint(qemu_socketpair(PF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
    qemu_clear_cloexec(sockets[1]);
    args = g_strdup_printf("-nic socket,fd=%d,model=e1000,"
                           "mac=52:54:00:12:34:56", sockets[1]);
    qts = qtest_initf("-machine ia64-vpc -m 256M %s", args);
    close(sockets[1]);

    qtest_memwrite(qts, IA64_E1000_TX_BUFFER_ADDR, packet, sizeof(packet));
    tx_desc.buffer_addr = cpu_to_le64(IA64_E1000_TX_BUFFER_ADDR);
    tx_desc.lower.data = cpu_to_le32(sizeof(packet) | E1000_TXD_CMD_EOP |
                                    E1000_TXD_CMD_IFCS |
                                    E1000_TXD_CMD_RS);
    qtest_memwrite(qts, IA64_E1000_TX_DESC_ADDR,
                   &tx_desc, sizeof(tx_desc));
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TDBAL,
                 IA64_E1000_TX_DESC_ADDR);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TDBAH, 0);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TDLEN,
                 IA64_E1000_RING_SIZE);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TDH, 0);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TCTL,
                 E1000_TCTL_EN | E1000_TCTL_PSP);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_TDT, 1);

    g_assert_true(e1000_wait_tx_done(qts, &tx_desc));
    g_assert_true(socket_receive_all(sockets[0], &frame_length,
                                     sizeof(frame_length)));
    g_assert_cmpuint(ntohl(frame_length), ==, sizeof(packet));
    g_assert_true(socket_receive_all(sockets[0], received, sizeof(received)));
    g_assert_cmpmem(received, sizeof(received), packet, sizeof(packet));

    rx_desc.buffer_addr = cpu_to_le64(IA64_E1000_RX_BUFFER_ADDR);
    qtest_memwrite(qts, IA64_E1000_RX_DESC_ADDR,
                   &rx_desc, sizeof(rx_desc));
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RDBAL,
                 IA64_E1000_RX_DESC_ADDR);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RDBAH, 0);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RDLEN,
                 IA64_E1000_RING_SIZE);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RDH, 0);
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RCTL,
                 E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE |
                 E1000_RCTL_BAM | E1000_RCTL_SECRC);
    frame_length = htonl(sizeof(packet));
    g_assert_cmpint(qemu_write_full(sockets[0], &frame_length,
                                    sizeof(frame_length)), ==,
                    sizeof(frame_length));
    g_assert_cmpint(qemu_write_full(sockets[0], packet, sizeof(packet)), ==,
                    sizeof(packet));
    qtest_writel(qts, IA64_E1000_MMIO_BASE + E1000_RDT, 1);
    qtest_clock_step(qts, NANOSECONDS_PER_SECOND);
    g_assert_true(e1000_wait_rx_done(qts, &rx_desc));
    g_assert_cmpuint(le16_to_cpu(rx_desc.length), ==, sizeof(packet));
    qtest_memread(qts, IA64_E1000_RX_BUFFER_ADDR,
                  rx_buffer, sizeof(rx_buffer));
    g_assert_cmpmem(rx_buffer, sizeof(rx_buffer), packet, sizeof(packet));

    qtest_quit(qts);
    close(sockets[0]);
}

static void test_pci_explicit_cmd646_slot0(void)
{
    QTestState *qts = ia64_vpc_start(
        "-device cmd646-ide,secondary=1,addr=0");
    QGenericPCIBus gbus;
    QPCIDevice *dev;

    ia64_qpci_init(&gbus, qts);
    dev = qpci_device_find(&gbus.bus, QPCI_DEVFN(0, 0));
    g_assert_nonnull(dev);
    g_assert_cmphex(qpci_config_readw(dev, PCI_VENDOR_ID), ==, 0x1095);
    g_assert_cmphex(qpci_config_readw(dev, PCI_DEVICE_ID), ==, 0x0646);
    g_assert_cmphex(qpci_config_readw(dev, PCI_CLASS_DEVICE), ==,
                    PCI_CLASS_STORAGE_IDE);
    g_free(dev);
    qtest_quit(qts);
}

static void lsi_write_script_insn(QTestState *qts, uint32_t *addr,
                                  uint32_t insn, uint32_t arg)
{
    qtest_writel(qts, *addr, insn);
    qtest_writel(qts, *addr + 4, arg);
    *addr += 8;
}

static bool lsi_run_nodata_command(QTestState *qts, const uint8_t *cdb,
                                   size_t cdb_len, uint8_t *status)
{
    const uint8_t identify = 0x80;
    uint32_t addr = IA64_LSI_SCRIPT_ADDR;
    uint8_t dstat = 0;
    unsigned int i;

    lsi_write_script_insn(qts, &addr, IA64_LSI_SCRIPT_SELECT, 0);
    lsi_write_script_insn(qts, &addr,
                          IA64_LSI_SCRIPT_MOVE(IA64_LSI_PHASE_MO, 1),
                          IA64_LSI_MSGOUT_ADDR);
    lsi_write_script_insn(qts, &addr,
                          IA64_LSI_SCRIPT_MOVE(IA64_LSI_PHASE_CMD,
                                               cdb_len),
                          IA64_LSI_CDB_ADDR);
    lsi_write_script_insn(qts, &addr,
                          IA64_LSI_SCRIPT_MOVE(IA64_LSI_PHASE_ST, 1),
                          IA64_LSI_STATUS_ADDR);
    lsi_write_script_insn(qts, &addr,
                          IA64_LSI_SCRIPT_MOVE(IA64_LSI_PHASE_MI, 1),
                          IA64_LSI_COMPLETE_ADDR);
    lsi_write_script_insn(qts, &addr, IA64_LSI_SCRIPT_DISCONNECT, 0);
    lsi_write_script_insn(qts, &addr, IA64_LSI_SCRIPT_INTERRUPT, 0);

    qtest_memwrite(qts, IA64_LSI_MSGOUT_ADDR, &identify, sizeof(identify));
    qtest_memwrite(qts, IA64_LSI_CDB_ADDR, cdb, cdb_len);
    qtest_writeb(qts, IA64_LSI_STATUS_ADDR, 0xff);
    qtest_writeb(qts, IA64_LSI_COMPLETE_ADDR, 0xff);

    qtest_readb(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_DSTAT);
    qtest_readb(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_SIST0);
    qtest_readb(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_SIST1);
    qtest_writeb(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_ISTAT0,
                 IA64_LSI_ISTAT0_INTF);
    qtest_writel(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_DSP,
                 IA64_LSI_SCRIPT_ADDR);

    for (i = 0; i < 1000; i++) {
        if (qtest_readb(qts, IA64_LSI_MMIO_BASE + IA64_LSI_REG_ISTAT0) &
            IA64_LSI_ISTAT0_DIP) {
            dstat = qtest_readb(qts,
                                IA64_LSI_MMIO_BASE + IA64_LSI_REG_DSTAT);
            if (dstat & IA64_LSI_DSTAT_SIR) {
                break;
            }
        }
        g_usleep(1000);
    }

    *status = qtest_readb(qts, IA64_LSI_STATUS_ADDR);
    return (dstat & IA64_LSI_DSTAT_SIR) != 0;
}

static void test_lsi_async_nodata_command(void)
{
    const uint8_t test_unit_ready[6] = { 0 };
    const uint8_t synchronize_cache[10] = { 0x35 };
    QTestState *qts;
    uint8_t status;
    unsigned int i;

    qts = ia64_vpc_start(
        "-blockdev driver=null-co,read-zeroes=on,"
                  "node-name=disk0,size=1048576 "
        "-device scsi-hd,drive=disk0,bus=scsi.0,scsi-id=0");

    /* Consume the initial unit attention before testing async completion. */
    g_assert_true(lsi_run_nodata_command(qts, test_unit_ready,
                                         sizeof(test_unit_ready), &status));
    for (i = 0; i < 8; i++) {
        g_assert_true(lsi_run_nodata_command(qts, synchronize_cache,
                                             sizeof(synchronize_cache),
                                             &status));
        g_assert_cmpuint(status, ==, 0);
    }
    qtest_quit(qts);
}

static void iosapic_select(QTestState *qts, uint32_t reg)
{
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOREGSEL, reg);
}

static uint32_t iosapic_read(QTestState *qts, uint32_t reg)
{
    iosapic_select(qts, reg);
    return qtest_readl(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOWIN);
}

static void iosapic_write(QTestState *qts, uint32_t reg, uint32_t value)
{
    iosapic_select(qts, reg);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_IOWIN, value);
}

static char *find_unattached_child(QTestState *qts, const char *qom_type)
{
    g_autoptr(QDict) response = NULL;
    g_autofree char *child_type = g_strdup_printf("child<%s>", qom_type);
    QList *children;
    QListEntry *entry;

    response = qtest_qmp(qts,
                         "{'execute':'qom-list','arguments':"
                         " {'path':'/machine/unattached'}}");
    g_assert(qdict_haskey(response, "return"));
    children = qdict_get_qlist(response, "return");
    QLIST_FOREACH_ENTRY(children, entry) {
        QDict *child = qobject_to(QDict, qlist_entry_obj(entry));

        if (g_str_equal(qdict_get_str(child, "type"), child_type)) {
            return g_strdup_printf("/machine/unattached/%s",
                                   qdict_get_str(child, "name"));
        }
    }

    g_error("QOM child of type %s was not found", qom_type);
    return NULL;
}

static unsigned count_unattached_children(QTestState *qts,
                                          const char *qom_type)
{
    g_autoptr(QDict) response = NULL;
    g_autofree char *child_type = g_strdup_printf("child<%s>", qom_type);
    QList *children;
    QListEntry *entry;
    unsigned count = 0;

    response = qtest_qmp(qts,
                         "{'execute':'qom-list','arguments':"
                         " {'path':'/machine/unattached'}}");
    g_assert(qdict_haskey(response, "return"));
    children = qdict_get_qlist(response, "return");
    QLIST_FOREACH_ENTRY(children, entry) {
        QDict *child = qobject_to(QDict, qlist_entry_obj(entry));

        if (g_str_equal(qdict_get_str(child, "type"), child_type)) {
            count++;
        }
    }
    return count;
}

static void test_default_usb_input(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc,i8042=off "
                                 "-m 256M -S");

    g_assert_cmpuint(count_unattached_children(qts, "usb-kbd"), ==, 1);
    g_assert_cmpuint(count_unattached_children(qts, "usb-tablet"), ==, 1);
    g_assert_cmpuint(count_unattached_children(qts, "usb-mouse"), ==, 0);
    qtest_quit(qts);
}

static void test_iosapic_level_remote_irr(void)
{
    const unsigned pin = 23;
    const uint8_t vector = 0x51;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    QTestState *qts = ia64_vpc_start(NULL);
    g_autofree char *iosapic_path =
        find_unattached_child(qts, "ia64-iosapic");
    uint32_t rte;

    /* Delivery status and Remote IRR are read-only guest-visible bits. */
    iosapic_write(qts, rte_low,
                  vector | IA64_IOSAPIC_RTE_LEVEL |
                  IA64_IOSAPIC_RTE_DELIVERY |
                  IA64_IOSAPIC_RTE_REMOTE_IRR);
    rte = iosapic_read(qts, rte_low);
    g_assert_cmphex(rte & (IA64_IOSAPIC_RTE_DELIVERY |
                          IA64_IOSAPIC_RTE_REMOTE_IRR), ==, 0);

    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    rte = iosapic_read(qts, rte_low);
    g_assert_cmphex(rte & IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);
    g_assert_cmphex(rte & IA64_IOSAPIC_RTE_DELIVERY, ==, 0);

    /* EOI while the level remains asserted immediately redelivers it. */
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);

    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 0);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, ==, 0);
    qtest_quit(qts);
}

static void test_iosapic_lowest_priority(void)
{
    const unsigned pin = 22;
    const uint8_t vector = 0x52;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    QTestState *qts = ia64_vpc_start(NULL);
    g_autofree char *iosapic_path =
        find_unattached_child(qts, "ia64-iosapic");

    iosapic_write(qts, rte_low,
                  vector | IA64_IOSAPIC_RTE_LOWEST |
                  IA64_IOSAPIC_RTE_LEVEL);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);

    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 0);
    qtest_writel(qts, IA64_IOSAPIC_BASE + IA64_IOSAPIC_EOI, vector);
    qtest_quit(qts);
}

static void test_sparse_io_pm_register(void)
{
    const uint32_t port = IA64_ACPI_PM_IO_BASE + IA64_ACPI_PM1_CNT_OFFSET;
    const uint64_t dense = IA64_LEGACY_IO_BASE + port;
    const uint64_t sparse = IA64_LEGACY_IO_BASE +
                            ia64_sparse_io_offset(port);
    QTestState *qts = ia64_vpc_start(NULL);

    g_assert_cmphex(sparse, ==, 0x000000800010801004ULL);

    qtest_writew(qts, dense, 0);
    g_assert_cmphex(qtest_readw(qts, sparse) & 1, ==, 0);

    qtest_writew(qts, sparse, 1);
    g_assert_cmphex(qtest_readw(qts, sparse) & 1, ==, 1);
    g_assert_cmphex(qtest_readw(qts, dense) & 1, ==, 1);

    qtest_writew(qts, sparse, 0);
    g_assert_cmphex(qtest_readw(qts, dense) & 1, ==, 0);
    qtest_quit(qts);
}

static void assert_cpu_model_type(const char *cpu_arg, const char *expect_type)
{
    g_autofree char *args = g_strdup_printf("-cpu %s", cpu_arg);
    QTestState *qts = ia64_vpc_start(args);
    g_autoptr(QDict) cpus_resp = NULL;
    QList *cpus;
    QListEntry *entry;
    const char *qom_path = NULL;

    /* The model instantiates and the firmware still hands off on ia64-vpc. */
    assert_firmware_handoff(qts, 1, 1, 0);

    cpus_resp = qtest_qmp(qts, "{'execute':'query-cpus-fast'}");
    g_assert(qdict_haskey(cpus_resp, "return"));
    cpus = qdict_get_qlist(cpus_resp, "return");
    g_assert_cmpuint(qlist_size(cpus), ==, 1);
    QLIST_FOREACH_ENTRY(cpus, entry) {
        qom_path = qdict_get_str(qobject_to(QDict, qlist_entry_obj(entry)),
                                 "qom-path");
        break;
    }
    g_assert_nonnull(qom_path);

    {
        g_autoptr(QDict) type_resp = qtest_qmp(qts,
            "{'execute':'qom-get','arguments':"
            "{'path':%s,'property':'type'}}", qom_path);
        g_assert(qdict_haskey(type_resp, "return"));
        g_assert_cmpstr(qdict_get_str(type_resp, "return"), ==, expect_type);
    }
    qtest_quit(qts);
}

static void test_cpu_merced(void)
{
    /* -cpu merced instantiates the original-Itanium model and boots. */
    assert_cpu_model_type("merced", "merced-ia64-cpu");
}

static void test_cpu_itanium_alias(void)
{
    /* "itanium" is the documented alias for the merced model. */
    assert_cpu_model_type("itanium", "itanium-ia64-cpu");
}

int main(int argc, char **argv)
{
    unsigned cpus;

    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-vpc/cpu/merced", test_cpu_merced);
    qtest_add_func("/ia64-vpc/cpu/itanium-alias", test_cpu_itanium_alias);
    qtest_add_func("/ia64-vpc/acpi-reset-register",
                   test_acpi_reset_register);
    qtest_add_func("/ia64-vpc/firmware-handoff/defaults",
                   test_firmware_handoff_defaults);
    qtest_add_func("/ia64-vpc/firmware-handoff/i8042-off",
                   test_firmware_handoff_i8042_off);
    for (cpus = 1; cpus <= 4; cpus++) {
        g_autofree char *path =
            g_strdup_printf("/ia64-vpc/smp/topology/%u", cpus);

        qtest_add_data_func(path, GUINT_TO_POINTER(cpus), test_smp_topology);
    }
    qtest_add_func("/ia64-vpc/smp/reject-full-alat",
                   test_smp_rejects_full_alat);
    qtest_add_func("/ia64-vpc/input/default-usb",
                   test_default_usb_input);
    qtest_add_func("/ia64-vpc/rtc/aligned-read", test_rtc_aligned_read);
    qtest_add_func("/ia64-vpc/nvram/commit-and-restart",
                   test_nvram_commit_and_restart);
    qtest_add_func("/ia64-vpc/pci/default-layout", test_pci_default_layout);
    qtest_add_func("/ia64-vpc/pci/explicit-cmd646-slot0",
                   test_pci_explicit_cmd646_slot0);
    qtest_add_func("/ia64-vpc/network/resources-survive-reset",
                   test_e1000_resources_survive_reset);
    qtest_add_func("/ia64-vpc/network/intx-route",
                   test_e1000_intx_route);
    qtest_add_func("/ia64-vpc/network/packet-transfer",
                   test_e1000_packet_transfer);
    qtest_add_func("/ia64-vpc/lsi/async-nodata-command",
                   test_lsi_async_nodata_command);
    qtest_add_func("/ia64-vpc/iosapic/level-remote-irr",
                   test_iosapic_level_remote_irr);
    qtest_add_func("/ia64-vpc/iosapic/lowest-priority",
                   test_iosapic_lowest_priority);
    qtest_add_func("/ia64-vpc/sparse-io/pm-register",
                   test_sparse_io_pm_register);

    return g_test_run();
}
