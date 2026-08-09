/*
 * IA-64 virtual platform machine tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
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
#include "hw/display/bochs-vbe.h"
#include "hw/display/vga_regs.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"
#include "hw/ia64/ia64_vpc_abi.h"
#include "hw/net/e1000_regs.h"

#define IA64_LEGACY_IO_BASE          0x000000800010000000ULL
#define IA64_PCI_CONFIG_BASE         0x0000007ff0000000ULL
#define IA64_ACPI_PM_IO_BASE         0x00002000ULL
#define IA64_ACPI_PM1_EVT_EN_OFFSET  0x02ULL
#define IA64_ACPI_PM1_CNT_OFFSET     0x04ULL
#define IA64_ACPI_PM_RESET_OFFSET    0x0cULL
#define IA64_ACPI_PM_RESET_VALUE     0x01U
#define IA64_RTC_BASE                0x00000000ffef0000ULL
#define IA64_WATCHDOG_BASE           0x00000000ffee0000ULL
#define IA64_WATCHDOG_CODE_OFFSET    0x08ULL
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
#define IA64_TEST_RAM_SIZE           (256 * MiB)
#define IA64_INT10_ROM_BASE          0x000c0000ULL
/*
 * 2 KB: the XP inbox Rage 128 miniport rejects option ROMs whose size byte
 * declares less than 2048 bytes.  Keep in sync with hw/ia64/ia64_vpc.c.
 */
#define IA64_INT10_ROM_SIZE          0x00000800U
#define IA64_INT10_VECTOR_ADDR       0x00000040ULL
#define IA64_INT10_ROM_PCIR_OFFSET   0x00e0U
#define IA64_INT10_ROM_ATI_SIG_OFFSET 0x0030U
#define IA64_INT10_ROM_ATI_HEADER_OFFSET 0x0080U
#define IA64_INT10_ROM_ATI_PLL_OFFSET 0x00c0U
#define IA64_INT10_ROM_HANDLER_OFFSET 0x0100U
#define IA64_INT10_HANDLER_SIZE      116U
#define IA64_INT10_ROM_OEM_OFFSET    0x0180U
#define IA64_INT10_ROM_MODES_OFFSET  0x01d0U
#define IA64_INT10_IO_BASE           0x01e0U
#define IA64_INT10_TRIGGER           0x4941U
#define IA64_VBE2_SIGNATURE          0x32454256U
#define IA64_VBE_IO_INDEX            0x01ceU
#define IA64_VBE_IO_DATA             0x01d0U
#define IA64_VGA_FB_BASE             0x00000000c4000000ULL
#define IA64_VGA_MMIO_BASE           0x00000000c8000000ULL
#define IA64_VGA_LEGACY_BASE         0x00000000000a0000ULL
#define IA64_ATI_BIOS_0_SCRATCH      0x0010U
#define IA64_BDA_VIDEO_MODE          0x00000449ULL
#define IA64_BDA_VIDEO_COLUMNS       0x0000044aULL
#define IA64_BDA_VIDEO_PAGE_SIZE     0x0000044cULL
#define IA64_BDA_VIDEO_ROWS          0x00000484ULL
#define IA64_BDA_CHARACTER_HEIGHT    0x00000485ULL
#define IA64_BDA_VIDEO_CONTROL       0x00000487ULL

enum TestInt10Register {
    TEST_INT10_AX,
    TEST_INT10_BX,
    TEST_INT10_CX,
    TEST_INT10_DX,
    TEST_INT10_DI,
    TEST_INT10_ES,
    TEST_INT10_EXEC,
    TEST_INT10_DATA,
};

typedef struct TestInt10Registers {
    uint16_t ax;
    uint16_t bx;
    uint16_t cx;
    uint16_t dx;
    uint16_t di;
    uint16_t es;
    uint32_t input_signature;
} TestInt10Registers;

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
 * The default adapter is the 82543GC, the device XP IA-64's inbox e1000
 * INF matches (DEV_1004 rev 02, e1000w64.sys).  Same e1000 core as the
 * 82540EM: a 128 KiB CSR memory BAR and a 64-byte I/O BAR, placed by the
 * machine's generic per-BAR NIC allocator inside the NIC windows.
 */
static const ExpectedPCIDevice expected_e1000_82543gc = {
    .slot = IA64_E1000_SLOT,
    .vendor = PCI_VENDOR_ID_INTEL,
    .device = E1000_DEV_ID_82543GC_COPPER,
    .command = PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
    .irq_line = IA64_E1000_GSI,
    .irq_pin = 1,
    .bars = {
        [0] = IA64_E1000_MMIO_BASE,
        [1] = IA64_E1000_IO_BASE | PCI_BASE_ADDRESS_SPACE_IO,
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

static void int10_outw(QTestState *qts, uint16_t port, uint16_t value)
{
    qtest_writew(qts, IA64_LEGACY_IO_BASE +
                 ia64_sparse_io_offset(port), value);
}

static uint16_t int10_inw(QTestState *qts, uint16_t port)
{
    return qtest_readw(qts, IA64_LEGACY_IO_BASE +
                       ia64_sparse_io_offset(port));
}

static size_t int10_call(QTestState *qts, TestInt10Registers *regs,
                         uint8_t *response, size_t response_size)
{
    static const size_t register_offsets[] = {
        [TEST_INT10_AX] = offsetof(TestInt10Registers, ax),
        [TEST_INT10_BX] = offsetof(TestInt10Registers, bx),
        [TEST_INT10_CX] = offsetof(TestInt10Registers, cx),
        [TEST_INT10_DX] = offsetof(TestInt10Registers, dx),
        [TEST_INT10_DI] = offsetof(TestInt10Registers, di),
        [TEST_INT10_ES] = offsetof(TestInt10Registers, es),
    };
    size_t word_count;
    size_t i;

    for (i = TEST_INT10_AX; i <= TEST_INT10_ES; i++) {
        uint16_t value;

        memcpy(&value, (uint8_t *)regs + register_offsets[i],
               sizeof(value));
        int10_outw(qts, IA64_INT10_IO_BASE + i * 2, value);
    }
    if (regs->input_signature != 0) {
        int10_outw(qts, IA64_INT10_IO_BASE + TEST_INT10_DATA * 2,
                   (uint16_t)regs->input_signature);
        int10_outw(qts, IA64_INT10_IO_BASE + TEST_INT10_DATA * 2,
                   (uint16_t)(regs->input_signature >> 16));
    }
    int10_outw(qts, IA64_INT10_IO_BASE + TEST_INT10_EXEC * 2,
               IA64_INT10_TRIGGER);
    word_count = int10_inw(qts,
                           IA64_INT10_IO_BASE + TEST_INT10_EXEC * 2);
    g_assert_cmpuint(word_count * 2, <=, response_size);
    for (i = 0; i < word_count; i++) {
        stw_le_p(response + i * 2, int10_inw(
            qts, IA64_INT10_IO_BASE + TEST_INT10_DATA * 2));
    }
    for (i = TEST_INT10_AX; i <= TEST_INT10_ES; i++) {
        uint16_t value = int10_inw(qts,
                                   IA64_INT10_IO_BASE + i * 2);

        memcpy((uint8_t *)regs + register_offsets[i], &value,
               sizeof(value));
    }
    return word_count * 2;
}

static uint32_t int10_far_to_linear(uint32_t pointer)
{
    return (pointer >> 16) * 16 + (pointer & 0xffff);
}

static uint16_t test_vbe_read(QTestState *qts, uint16_t index)
{
    qtest_writew(qts, IA64_LEGACY_IO_BASE + IA64_VBE_IO_INDEX, index);
    return qtest_readw(qts, IA64_LEGACY_IO_BASE + IA64_VBE_IO_DATA);
}

static uint8_t test_vga_indexed_read(QTestState *qts, uint16_t index_port,
                                     uint16_t data_port, uint8_t index)
{
    qtest_writeb(qts, IA64_LEGACY_IO_BASE + index_port, index);
    return qtest_readb(qts, IA64_LEGACY_IO_BASE + data_port);
}

static void test_assert_ppm_pixel(const char *filename, unsigned width,
                                  unsigned height, unsigned x, unsigned y,
                                  uint8_t red, uint8_t green, uint8_t blue)
{
    g_autofree char *contents = NULL;
    g_autoptr(GError) error = NULL;
    const uint8_t *pixel;
    char *end;
    unsigned actual_width;
    unsigned actual_height;
    unsigned maximum;
    gsize length;

    g_assert_true(g_file_get_contents(filename, &contents, &length, &error));
    g_assert_no_error(error);
    g_assert_true(g_str_has_prefix(contents, "P6\n"));
    actual_width = g_ascii_strtoull(contents + 3, &end, 10);
    actual_height = g_ascii_strtoull(end, &end, 10);
    maximum = g_ascii_strtoull(end, &end, 10);
    g_assert_cmpuint(actual_width, ==, width);
    g_assert_cmpuint(actual_height, ==, height);
    g_assert_cmpuint(maximum, ==, 255);
    g_assert_cmpuint(x, <, width);
    g_assert_cmpuint(y, <, height);
    g_assert_cmpuint(length - (end - contents), >,
                     (gsize)width * height * 3);
    g_assert_true(g_ascii_isspace(*end));
    if (*end++ == '\r' && *end == '\n') {
        end++;
    }
    pixel = (const uint8_t *)end + ((gsize)y * width + x) * 3;
    g_assert_cmphex(pixel[0], ==, red);
    g_assert_cmphex(pixel[1], ==, green);
    g_assert_cmphex(pixel[2], ==, blue);
}

static void test_int10_rom(void)
{
    uint8_t rom[IA64_INT10_ROM_SIZE];
    uint8_t zero[IA64_INT10_ROM_SIZE] = { 0 };
    uint8_t vector[4];
    uint32_t vector_linear;
    uint16_t ati_header;
    uint16_t ati_pll;
    unsigned checksum = 0;
    QTestState *qts = ia64_vpc_start(NULL);
    size_t i;

    qtest_memread(qts, IA64_INT10_ROM_BASE, rom, sizeof(rom));
    g_assert_cmphex(rom[0], ==, 0x55);
    g_assert_cmphex(rom[1], ==, 0xaa);
    g_assert_cmphex(rom[2], ==, IA64_INT10_ROM_SIZE / 512);
    g_assert_cmphex(lduw_le_p(rom + 0x0d), ==,
                    IA64_INT10_ROM_HANDLER_OFFSET);
    g_assert_cmphex(lduw_le_p(rom + 0x13), ==,
                    IA64_INT10_ROM_BASE >> 4);
    g_assert_cmphex(lduw_le_p(rom + 0x18), ==,
                    IA64_INT10_ROM_PCIR_OFFSET);
    g_assert_cmpmem(rom + IA64_INT10_ROM_PCIR_OFFSET, 4, "PCIR", 4);
    g_assert_cmphex(lduw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 4),
                    ==, 0x1002);
    g_assert_cmphex(lduw_le_p(rom + IA64_INT10_ROM_PCIR_OFFSET + 6),
                    ==, 0x5046);
    g_assert_cmpmem(rom + 0x60, 19, "QEMU IA64 VBE INT10", 19);
    /*
     * ATI's drivers validate the ROM by its signature at 30h before following
     * the pointer chain at 48h; PCIR must therefore stay clear of both.
     */
    g_assert_cmpmem(rom + IA64_INT10_ROM_ATI_SIG_OFFSET, 10,
                    " 761295520", 10);
    g_assert_cmpint(IA64_INT10_ROM_ATI_SIG_OFFSET + 10, <=, 0x48);
    g_assert_cmpint(IA64_INT10_ROM_PCIR_OFFSET, >=, 0x4a);
    ati_header = lduw_le_p(rom + 0x48);
    g_assert_cmphex(ati_header, ==, IA64_INT10_ROM_ATI_HEADER_OFFSET);
    ati_pll = lduw_le_p(rom + ati_header + 0x30);
    g_assert_cmphex(ati_pll, ==, IA64_INT10_ROM_ATI_PLL_OFFSET);
    /*
     * PLL values as published by real Rage 128 Pro BIOSes (identical in the
     * XPERT128 retail, Connect3D AGP and generic PCI dumps): XCLK 120.00 MHz,
     * 29.50 MHz reference with divider 65, 125-400 MHz VCO range.
     */
    g_assert_cmpuint(lduw_le_p(rom + ati_pll + 0x08), ==, 12000);
    g_assert_cmpuint(lduw_le_p(rom + ati_pll + 0x0e), ==, 2950);
    g_assert_cmpuint(lduw_le_p(rom + ati_pll + 0x10), ==, 65);
    g_assert_cmpuint(ldl_le_p(rom + ati_pll + 0x12), ==, 12500);
    g_assert_cmpuint(ldl_le_p(rom + ati_pll + 0x16), ==, 40000);
    g_assert_cmpmem(rom + IA64_INT10_ROM_OEM_OFFSET, 13,
                    "QEMU IA64 VBE", 13);
    g_assert_cmphex(lduw_le_p(rom + IA64_INT10_ROM_MODES_OFFSET),
                    ==, 0x111);
    g_assert_cmphex(rom[IA64_INT10_ROM_HANDLER_OFFSET], ==, 0x55);
    g_assert_cmphex(rom[IA64_INT10_ROM_HANDLER_OFFSET + 1], ==, 0x89);
    g_assert_cmphex(rom[IA64_INT10_ROM_HANDLER_OFFSET +
                       IA64_INT10_HANDLER_SIZE], ==, 0);
    for (i = 0; i < sizeof(rom); i++) {
        checksum += rom[i];
    }
    g_assert_cmphex(checksum & 0xff, ==, 0);

    qtest_memread(qts, IA64_INT10_VECTOR_ADDR, vector, sizeof(vector));
    g_assert_cmphex(lduw_le_p(vector), ==, IA64_INT10_ROM_HANDLER_OFFSET);
    g_assert_cmphex(lduw_le_p(vector + 2), ==,
                    IA64_INT10_ROM_BASE >> 4);
    vector_linear = lduw_le_p(vector + 2) * 16 + lduw_le_p(vector);
    g_assert_cmphex(vector_linear, ==,
                    IA64_INT10_ROM_BASE + IA64_INT10_ROM_HANDLER_OFFSET);

    qtest_memwrite(qts, IA64_INT10_ROM_BASE, zero, sizeof(zero));
    qtest_memwrite(qts, IA64_INT10_VECTOR_ADDR, zero, sizeof(vector));
    qtest_system_reset(qts);
    qtest_memread(qts, IA64_INT10_ROM_BASE, rom, sizeof(rom));
    qtest_memread(qts, IA64_INT10_VECTOR_ADDR, vector, sizeof(vector));
    g_assert_cmphex(rom[0], ==, 0x55);
    g_assert_cmphex(rom[1], ==, 0xaa);
    g_assert_cmphex(lduw_le_p(vector), ==, IA64_INT10_ROM_HANDLER_OFFSET);
    g_assert_cmphex(lduw_le_p(vector + 2), ==,
                    IA64_INT10_ROM_BASE >> 4);
    qtest_quit(qts);
}

static void test_int10_vbe_for_device(const char *extra_args)
{
    uint8_t response[512];
    TestInt10Registers regs = {
        .ax = 0x4f00,
        .di = 0x0100,
        .es = 0x2000,
    };
    uint32_t modes_linear;
    unsigned checksum = 0;
    size_t length;
    size_t i;
    QTestState *qts = ia64_vpc_start(extra_args);

    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 256);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmpmem(response, 4, "VESA", 4);

    regs = (TestInt10Registers) {
        .ax = 0x4f00,
        .di = 0x0100,
        .es = 0x2000,
        .input_signature = IA64_VBE2_SIGNATURE,
    };
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 512);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmpmem(response, 4, "VESA", 4);
    g_assert_cmphex(lduw_le_p(response + 4), ==, 0x0300);
    g_assert_cmphex(lduw_le_p(response + 18), ==, 256);
    modes_linear = int10_far_to_linear(ldl_le_p(response + 14));
    g_assert_cmphex(modes_linear,
                    ==, IA64_INT10_ROM_BASE + IA64_INT10_ROM_MODES_OFFSET);
    g_assert_cmphex(qtest_readw(qts, modes_linear), ==, 0x111);
    g_assert_cmphex(int10_far_to_linear(ldl_le_p(response + 6)),
                    ==, IA64_INT10_ROM_BASE + IA64_INT10_ROM_OEM_OFFSET);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f01;
    regs.cx = 0x144;
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 256);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(lduw_le_p(response) & 0x80, !=, 0);
    g_assert_cmphex(lduw_le_p(response + 16), ==, 4096);
    g_assert_cmphex(lduw_le_p(response + 18), ==, 1024);
    g_assert_cmphex(lduw_le_p(response + 20), ==, 768);
    g_assert_cmphex(response[25], ==, 32);
    g_assert_cmphex((uint32_t)ldl_le_p(response + 40), ==, 0xc4000000U);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f02;
    regs.bx = 0x4143;
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_XRES), ==, 800);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_YRES), ==, 600);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_BPP), ==, 32);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_ENABLE) & 0x41,
                    ==, 0x41);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f03;
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(regs.bx, ==, 0x4143);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f06;
    regs.bx = 1;
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(regs.bx, ==, 3200);
    g_assert_cmphex(regs.cx, ==, 800);
    g_assert_cmphex(regs.dx, >, 600);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f15;
    regs.bx = 1;
    length = int10_call(qts, &regs,
                        response, sizeof(response));
    g_assert_cmpuint(length, ==, 128);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(response[0], ==, 0x00);
    g_assert_cmphex(response[1], ==, 0xff);
    for (i = 0; i < length; i++) {
        checksum += response[i];
    }
    g_assert_cmphex(checksum & 0xff, ==, 0);
    qtest_quit(qts);
}

static void test_int10_vbe(void)
{
    test_int10_vbe_for_device(NULL);
}

static void test_int10_vbe_std(void)
{
    test_int10_vbe_for_device("-vga std");
}

static void test_int10_legacy_for_device(const char *extra_args)
{
    uint8_t response[2];
    uint8_t marker[16];
    uint8_t actual[sizeof(marker)];
    uint8_t zero[sizeof(marker)] = { 0 };
    TestInt10Registers regs;
    QTestState *qts = ia64_vpc_start(extra_args);
    g_autofree char *tmpdir = NULL;
    g_autofree char *ppm = NULL;
    g_autoptr(GError) error = NULL;
    size_t length;

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f02;
    regs.bx = 0x4143;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);

    memset(marker, 0xa5, sizeof(marker));
    qtest_memwrite(qts, IA64_VGA_FB_BASE, marker, sizeof(marker));
    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x0012;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_ENABLE), ==, 0);
    g_assert_cmphex(test_vga_indexed_read(qts, VGA_SEQ_I, VGA_SEQ_D,
                                          VGA_SEQ_MEMORY_MODE), ==, 0x06);
    g_assert_cmphex(test_vga_indexed_read(qts, VGA_CRT_IC, VGA_CRT_DC,
                                          VGA_CRTC_H_DISP), ==, 0x4f);
    g_assert_cmphex(test_vga_indexed_read(qts, VGA_CRT_IC, VGA_CRT_DC,
                                          VGA_CRTC_V_DISP_END), ==, 0xdf);
    g_assert_cmphex(test_vga_indexed_read(qts, VGA_GFX_I, VGA_GFX_D,
                                          VGA_GFX_MISC), ==, 0x05);
    qtest_memread(qts, IA64_VGA_FB_BASE, actual, sizeof(actual));
    g_assert_cmpmem(actual, sizeof(actual), zero, sizeof(zero));
    g_assert_cmphex(qtest_readb(qts, IA64_BDA_VIDEO_MODE), ==, 0x12);
    g_assert_cmphex(qtest_readw(qts, IA64_BDA_VIDEO_COLUMNS), ==, 80);
    g_assert_cmphex(qtest_readw(qts, IA64_BDA_VIDEO_PAGE_SIZE), ==,
                    0xa000);
    g_assert_cmphex(qtest_readb(qts, IA64_BDA_VIDEO_ROWS), ==, 29);
    g_assert_cmphex(qtest_readw(qts, IA64_BDA_CHARACTER_HEIGHT), ==, 16);
    g_assert_cmphex(qtest_readb(qts, IA64_BDA_VIDEO_CONTROL), ==, 0x60);

    /* Match bootvid.dll's planar write path and verify actual scanout. */
    qtest_writeb(qts, IA64_VGA_LEGACY_BASE, 0xff);
    tmpdir = g_dir_make_tmp("ia64-int10-legacy-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(tmpdir);
    ppm = g_build_filename(tmpdir, "mode12.ppm", NULL);
    qtest_qmp_assert_success(qts,
                             "{'execute':'screendump','arguments':"
                             " {'filename':%s}}", ppm);
    test_assert_ppm_pixel(ppm, 640, 480, 0, 0, 0xff, 0xff, 0xff);
    test_assert_ppm_pixel(ppm, 640, 480, 8, 0, 0, 0, 0);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x0f00;
    regs.bx = 0xabcd;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x5012);
    g_assert_cmphex(regs.bx, ==, 0x00cd);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f02;
    regs.bx = 0x4143;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    memset(marker, 0x5a, sizeof(marker));
    qtest_memwrite(qts, IA64_VGA_FB_BASE, marker, sizeof(marker));

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x0092;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    qtest_memread(qts, IA64_VGA_FB_BASE, actual, sizeof(actual));
    g_assert_cmpmem(actual, sizeof(actual), marker, sizeof(marker));
    g_assert_cmphex(qtest_readb(qts, IA64_BDA_VIDEO_CONTROL), ==, 0xe0);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x0f00;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x5012);

    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x4f02;
    regs.bx = 0x4143;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x004f);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_XRES), ==, 800);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_YRES), ==, 600);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_BPP), ==, 32);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_ENABLE) & 0x41,
                    ==, 0x41);
    memset(&regs, 0, sizeof(regs));
    regs.ax = 0x0f00;
    length = int10_call(qts, &regs, response, sizeof(response));
    g_assert_cmpuint(length, ==, 0);
    g_assert_cmphex(regs.ax, ==, 0x5003);
    qtest_quit(qts);

    g_assert_cmpint(g_unlink(ppm), ==, 0);
    g_assert_cmpint(g_rmdir(tmpdir), ==, 0);
}

static void test_int10_legacy(void)
{
    test_int10_legacy_for_device(NULL);
}

static void test_int10_legacy_std(void)
{
    test_int10_legacy_for_device("-vga std");
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
                                    uint64_t cpus, uint64_t nvram,
                                    uint64_t sockets, uint64_t cores,
                                    uint64_t threads)
{
    IA64VpcHandoff handoff;

    g_assert_cmpuint(sizeof(handoff), ==, 104);
    qtest_memread(qts, IA64_FW_HANDOFF_ADDR, &handoff, sizeof(handoff));
    g_assert_cmphex(le64_to_cpu(handoff.Magic), ==, IA64_FW_HANDOFF_MAGIC);
    g_assert_cmphex(le64_to_cpu(handoff.Version), ==,
                    IA64_FW_HANDOFF_VERSION);
    g_assert_cmphex(le64_to_cpu(handoff.RamSize), ==, IA64_TEST_RAM_SIZE);
    g_assert_cmphex(le64_to_cpu(handoff.ConsolePolicy), ==,
                    IA64_FW_CONSOLE_VGA);
    g_assert_cmphex(le64_to_cpu(handoff.IdeDmaEnabled), ==, 1);
    g_assert_cmphex(le64_to_cpu(handoff.DebugPortFlags), ==, 0);
    g_assert_cmphex(le64_to_cpu(handoff.DebugPortBase), ==, 0);
    g_assert_cmphex(le64_to_cpu(handoff.I8042Enabled), ==, i8042);
    g_assert_cmphex(le64_to_cpu(handoff.ProcessorCount), ==, cpus);
    g_assert_cmphex(le64_to_cpu(handoff.NvramPersistent), ==, nvram);
    g_assert_cmphex(le64_to_cpu(handoff.SocketCount), ==, sockets);
    g_assert_cmphex(le64_to_cpu(handoff.CoresPerSocket), ==, cores);
    g_assert_cmphex(le64_to_cpu(handoff.ThreadsPerCore), ==, threads);
}

static void test_firmware_handoff_defaults(void)
{
    static const uint8_t expected_v10[sizeof(IA64VpcHandoff)] = {
        0x51, 0x49, 0x41, 0x36, 0x34, 0x52, 0x41, 0x4d,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t actual[sizeof(IA64VpcHandoff)];
    QTestState *qts = ia64_vpc_start(NULL);

    assert_firmware_handoff(qts, 1, 1, 0, 1, 1, 1);
    qtest_memread(qts, IA64_FW_HANDOFF_ADDR, actual, sizeof(actual));
    g_assert_cmpmem(actual, sizeof(actual),
                    expected_v10, sizeof(expected_v10));
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
    assert_firmware_handoff(qts, 1, 1, 0, 1, 1, 1);

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

static void test_firmware_handoff_i8042_off(void)
{
    QTestState *qts = qtest_init("-machine ia64-vpc,i8042=off "
                                 "-m 256M -S");

    assert_firmware_handoff(qts, 0, 1, 0, 1, 1, 1);
    qtest_quit(qts);
}

static void test_smp_topology(gconstpointer opaque)
{
    uint64_t count = GPOINTER_TO_UINT(opaque);
    g_autofree char *args = g_strdup_printf("-smp %" PRIu64, count);
    QTestState *qts = ia64_vpc_start(args);
    g_autoptr(QDict) response = NULL;
    QList *cpus;

    assert_firmware_handoff(qts, 1, count, 0, count, 1, 1);
    response = qtest_qmp(qts, "{'execute':'query-cpus-fast'}");
    g_assert(qdict_haskey(response, "return"));
    cpus = qdict_get_qlist(response, "return");
    g_assert_cmpuint(qlist_size(cpus), ==, count);
    qtest_quit(qts);
}

static void test_smp_explicit_topology(void)
{
    QTestState *qts =
        ia64_vpc_start("-smp 4,sockets=1,cores=2,threads=2");

    assert_firmware_handoff(qts, 1, 4, 0, 1, 2, 2);
    qtest_quit(qts);
}

typedef struct TestSmpMulticoreTopology {
    const char *name;
    unsigned sockets;
    unsigned cores;
} TestSmpMulticoreTopology;

static const TestSmpMulticoreTopology smp_multicore_topologies[] = {
    { "4-sockets-2-cores", 4, 2 },
    { "1-socket-8-cores", 1, 8 },
    { "2-sockets-4-cores", 2, 4 },
};

static void test_smp_multicore_topology(gconstpointer opaque)
{
    const TestSmpMulticoreTopology *topology = opaque;
    unsigned count = topology->sockets * topology->cores;
    g_autofree char *args = g_strdup_printf(
        "-smp %u,sockets=%u,cores=%u,threads=1",
        count, topology->sockets, topology->cores);
    QTestState *qts = ia64_vpc_start(args);
    g_autoptr(QDict) response = NULL;
    QList *cpus;

    assert_firmware_handoff(qts, 1, count, 0, topology->sockets,
                            topology->cores, 1);
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

/*
 * ahci=off removes the AHCI controller at 0:1.0 without renumbering anything
 * else: an installed guest must not see the remaining devices move BDF.
 */
static void test_ahci_off(void)
{
    QTestState *qts = ia64_vpc_start("-machine ahci=off");
    QGenericPCIBus gbus;
    static const unsigned int kept_slots[] = { 2, 3, 4, 5, 6 };
    unsigned i;

    ia64_qpci_init(&gbus, qts);
    g_assert_null(qpci_device_find(&gbus.bus, QPCI_DEVFN(1, 0)));
    for (i = 0; i < ARRAY_SIZE(kept_slots); i++) {
        QPCIDevice *dev =
            qpci_device_find(&gbus.bus, QPCI_DEVFN(kept_slots[i], 0));

        g_assert_nonnull(dev);
        g_free(dev);
    }
    qtest_quit(qts);
}

static void test_ahci_on_default(void)
{
    QTestState *qts = ia64_vpc_start(NULL);
    QGenericPCIBus gbus;
    QPCIDevice *ahci;

    ia64_qpci_init(&gbus, qts);
    ahci = qpci_device_find(&gbus.bus, QPCI_DEVFN(1, 0));
    g_assert_nonnull(ahci);
    g_free(ahci);
    qtest_quit(qts);
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
    assert_pci_device(&gbus.bus, &expected_e1000_82543gc);
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
    QTestState *qts = ia64_vpc_start("-nic user,model=e1000");
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

static uint64_t cpu_sapic_irr_word(QTestState *qts, unsigned word)
{
    g_autofree char *out = qtest_hmp(qts, "info registers");
    char *line = strstr(out, "SAPIC IRR:");
    uint64_t w[4];

    g_assert_nonnull(line);
    g_assert_cmpint(sscanf(line, "SAPIC IRR: %" SCNx64 " %" SCNx64
                           " %" SCNx64 " %" SCNx64,
                           &w[0], &w[1], &w[2], &w[3]), ==, 4);
    g_assert_cmpuint(word, <, 4);
    return w[word];
}

/*
 * SAPIC delivery from the I/O SAPIC is queued to the target vCPU with
 * async_run_on_cpu(), so an immediate IRR readback races the (idle)
 * qtest vCPU thread draining its work queue.  Pulse a disambiguating
 * fence vector through a spare pin and wait for it to appear: the
 * per-CPU work queue is FIFO, so once the fence delivery is visible,
 * every delivery requested before it -- including an erroneous one --
 * is visible too, and both the ==0 and !=0 assertions below are exact.
 * IRR bits are never accepted (no code runs on a qtest vCPU), so each
 * fence needs a vector of its own.
 */
static void iosapic_irr_fence(QTestState *qts, const char *iosapic_path,
                              uint8_t fence_vector)
{
    const unsigned pin = 20;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    const unsigned word = fence_vector / 64;
    const uint64_t bit = 1ULL << (fence_vector % 64);
    gint64 deadline = g_get_monotonic_time() + 15 * G_USEC_PER_SEC;

    iosapic_write(qts, rte_low, fence_vector);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 0);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    while (!(cpu_sapic_irr_word(qts, word) & bit)) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
}

/*
 * A redirection-table write is not an interrupt request, and a redundant
 * assert of an already-high input is not a new edge: an edge-triggered
 * entry delivers only on a 0->1 input transition (460GX SSDM 248704-001
 * sec 2.6.2).  Windows rewrites RTEs continually during PnP enumeration,
 * so delivering on RTE writes injected interrupts no device had raised.
 */
static void test_iosapic_edge_rte_write_is_not_a_request(void)
{
    const unsigned pin = 21;
    const uint8_t vector = 0x53;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    const unsigned word = vector / 64;
    const uint64_t bit = 1ULL << (vector % 64);
    QTestState *qts = ia64_vpc_start(NULL);
    g_autofree char *iosapic_path =
        find_unattached_child(qts, "ia64-iosapic");

    /* Input already asserted before the route is programmed. */
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    iosapic_write(qts, rte_low, vector);
    iosapic_irr_fence(qts, iosapic_path, 0x60);
    g_assert_cmphex(cpu_sapic_irr_word(qts, word) & bit, ==, 0);

    /* Rewriting the entry is not a request either. */
    iosapic_write(qts, rte_low, vector);
    iosapic_irr_fence(qts, iosapic_path, 0x61);
    g_assert_cmphex(cpu_sapic_irr_word(qts, word) & bit, ==, 0);

    /* Nor is a redundant assert of the already-high input. */
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    iosapic_irr_fence(qts, iosapic_path, 0x62);
    g_assert_cmphex(cpu_sapic_irr_word(qts, word) & bit, ==, 0);

    /* The 0->1 transition is. */
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 0);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    iosapic_irr_fence(qts, iosapic_path, 0x63);
    g_assert_cmphex(cpu_sapic_irr_word(qts, word) & bit, !=, 0);
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

static bool sapic_irr_has_vector(QTestState *qts, uint8_t vector)
{
    g_autofree char *registers = qtest_hmp(qts, "info registers");
    const char *line = strstr(registers, "SAPIC IRR:");
    uint64_t irr[4];

    g_assert_nonnull(line);
    g_assert_cmpint(sscanf(line, "SAPIC IRR: %" SCNx64 " %" SCNx64
                          " %" SCNx64 " %" SCNx64,
                          &irr[0], &irr[1], &irr[2], &irr[3]), ==, 4);
    return (irr[vector / 64] & BIT_ULL(vector % 64)) != 0;
}

/*
 * SAPIC delivery is asynchronous; a single readback races it under host
 * load.  Spin like the other interrupt tests do.
 */
static bool sapic_wait_irr_vector(QTestState *qts, uint8_t vector)
{
    int i;

    for (i = 0; i < 1000; i++) {
        if (sapic_irr_has_vector(qts, vector)) {
            return true;
        }
        g_usleep(1000);
    }
    return false;
}

static void test_savevm_restores_platform_state(void)
{
    const char *machine = "ia64-vpc";
    const uint64_t ram_addr = 0x00300000;
    const uint64_t saved_ram = 0x0123456789abcdefULL;
    const uint64_t changed_ram = 0xfedcba9876543210ULL;
    const uint64_t saved_nvram = 0x1020304050607080ULL;
    const uint64_t changed_nvram = 0x8877665544332211ULL;
    const uint64_t saved_watchdog = 0xa5a55a5ac3c33c3cULL;
    const uint64_t changed_watchdog = 0x55aa55aa66996699ULL;
    const uint16_t saved_pm_enable = 0x0100;
    const uint16_t changed_pm_enable = 0x0400;
    const uint32_t saved_vram = 0x00112233;
    const uint32_t changed_vram = 0x00aabbcc;
    const uint32_t saved_ati_scratch = 0x13579bdf;
    const uint32_t changed_ati_scratch = 0x2468ace0;
    const unsigned pin = 23;
    const uint8_t saved_vector = 0x55;
    const uint8_t changed_vector = 0x56;
    const uint32_t rte_low = IA64_IOSAPIC_RTE_BASE + pin * 2;
    const uint64_t pm_enable_addr =
        IA64_LEGACY_IO_BASE +
        ia64_sparse_io_offset(IA64_ACPI_PM_IO_BASE +
                              IA64_ACPI_PM1_EVT_EN_OFFSET);
    g_autofree char *tmpdir = NULL;
    g_autofree char *disk_path = NULL;
    g_autofree char *quoted_disk_path = NULL;
    g_autofree char *args = NULL;
    g_autofree char *iosapic_path = NULL;
    g_autofree char *response = NULL;
    g_autoptr(GError) error = NULL;
    uint8_t int10_response[2];
    TestInt10Registers int10_regs;
    QTestState *qts;

    if (!have_qemu_img()) {
        g_test_skip("qemu-img is required for internal snapshot testing");
        return;
    }

    tmpdir = g_dir_make_tmp("ia64-vpc-savevm-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(tmpdir);
    disk_path = g_build_filename(tmpdir, "snapshot.qcow2", NULL);
    g_assert_true(mkimg(disk_path, "qcow2", 64));
    quoted_disk_path = g_shell_quote(disk_path);
    args = g_strdup_printf("-drive file=%s,format=qcow2,if=scsi",
                           quoted_disk_path);

    qts = qtest_initf("-machine %s -m 256M -smp 4 -S %s",
                      machine, args);
    iosapic_path = find_unattached_child(qts, "ia64-iosapic");

    qtest_writeq(qts, ram_addr, saved_ram);
    qtest_writeq(qts, IA64_NVRAM_BASE, saved_nvram);
    qtest_writeq(qts, IA64_WATCHDOG_BASE + IA64_WATCHDOG_CODE_OFFSET,
                 saved_watchdog);
    qtest_writew(qts, pm_enable_addr, saved_pm_enable);
    int10_regs = (TestInt10Registers) {
        .ax = 0x4f02,
        .bx = 0x4143,
    };
    g_assert_cmpuint(int10_call(qts, &int10_regs,
                                int10_response, sizeof(int10_response)), ==, 0);
    g_assert_cmphex(int10_regs.ax, ==, 0x004f);
    qtest_writel(qts, IA64_VGA_FB_BASE, saved_vram);
    qtest_writel(qts, IA64_VGA_MMIO_BASE + IA64_ATI_BIOS_0_SCRATCH,
                 saved_ati_scratch);
    iosapic_write(qts, rte_low,
                  saved_vector | IA64_IOSAPIC_RTE_LEVEL);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    g_assert_true(sapic_wait_irr_vector(qts, saved_vector));
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);

    response = qtest_hmp(qts, "savevm platform-state");
    g_assert_cmpstr(response, ==, "");
    g_clear_pointer(&response, g_free);

    /*
     * Reset first so that the CPU's Local SAPIC state differs as well as
     * the memory-mapped machine and IOSAPIC state.
     */
    qtest_system_reset(qts);
    qtest_writeq(qts, ram_addr, changed_ram);
    qtest_writeq(qts, IA64_NVRAM_BASE, changed_nvram);
    qtest_writeq(qts, IA64_WATCHDOG_BASE + IA64_WATCHDOG_CODE_OFFSET,
                 changed_watchdog);
    qtest_writew(qts, pm_enable_addr, changed_pm_enable);
    int10_regs = (TestInt10Registers) {
        .ax = 0x4f02,
        .bx = 0x4144,
    };
    g_assert_cmpuint(int10_call(qts, &int10_regs,
                                int10_response, sizeof(int10_response)), ==, 0);
    g_assert_cmphex(int10_regs.ax, ==, 0x004f);
    qtest_writel(qts, IA64_VGA_FB_BASE, changed_vram);
    qtest_writel(qts, IA64_VGA_MMIO_BASE + IA64_ATI_BIOS_0_SCRATCH,
                 changed_ati_scratch);
    iosapic_write(qts, rte_low,
                  changed_vector | IA64_IOSAPIC_RTE_LEVEL);
    qtest_set_irq_in(qts, iosapic_path, NULL, pin, 1);
    g_assert_true(sapic_wait_irr_vector(qts, changed_vector));
    g_assert_false(sapic_irr_has_vector(qts, saved_vector));

    response = qtest_hmp(qts, "loadvm platform-state");
    g_assert_cmpstr(response, ==, "");

    g_assert_cmphex(qtest_readq(qts, ram_addr), ==, saved_ram);
    g_assert_cmphex(qtest_readq(qts, IA64_NVRAM_BASE), ==, saved_nvram);
    g_assert_cmphex(qtest_readq(qts, IA64_WATCHDOG_BASE +
                               IA64_WATCHDOG_CODE_OFFSET),
                    ==, saved_watchdog);
    g_assert_cmphex(qtest_readw(qts, pm_enable_addr), ==, saved_pm_enable);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_XRES), ==, 800);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_YRES), ==, 600);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_BPP), ==, 32);
    g_assert_cmphex(test_vbe_read(qts, VBE_DISPI_INDEX_ENABLE) & 0x41,
                    ==, 0x41);
    g_assert_cmphex(qtest_readl(qts, IA64_VGA_FB_BASE), ==, saved_vram);
    g_assert_cmphex(qtest_readl(qts,
                               IA64_VGA_MMIO_BASE +
                               IA64_ATI_BIOS_0_SCRATCH),
                    ==, saved_ati_scratch);
    g_assert_cmphex(iosapic_read(qts, rte_low) & 0xff, ==, saved_vector);
    g_assert_cmphex(iosapic_read(qts, rte_low) &
                    IA64_IOSAPIC_RTE_REMOTE_IRR, !=, 0);
    g_assert_true(sapic_irr_has_vector(qts, saved_vector));
    g_assert_false(sapic_irr_has_vector(qts, changed_vector));

    qtest_quit(qts);
    g_assert_cmpint(g_unlink(disk_path), ==, 0);
    g_assert_cmpint(g_rmdir(tmpdir), ==, 0);
}

/*
 * ATI RAGE 128 (Rage 128 Pro, 1002:5046) device-model regression tests.
 *
 * These drive the emulated adapter directly over its PCI BARs and lock in the
 * fork's ATI fixes and the register behaviour documented in the RAGE 128 PRO
 * Register Reference Guide: the indirect PLL register file, DAC load-sense,
 * MM_INDEX/MM_DATA indirection, the PCI-ROM-BAR ATI-table patch, and 2D solid
 * fills at every supported depth (including the 24bpp path that used to abort
 * on 3-byte pixel accesses).
 */
#define ATI_SLOT                5

/* Register offsets (RAGE 128 PRO RRG / hw/display/ati_regs.h). */
#define ATI_MM_INDEX            0x0000
#define ATI_MM_DATA             0x0004
#define ATI_CLOCK_CNTL_INDEX    0x0008
#define ATI_CLOCK_CNTL_DATA     0x000c
#define ATI_DAC_CNTL            0x0058
#define ATI_DST_OFFSET          0x1404
#define ATI_DST_PITCH           0x1408
#define ATI_DST_Y_X             0x1438
#define ATI_DST_HEIGHT_WIDTH    0x143c
#define ATI_DP_GUI_MASTER_CNTL  0x146c
#define ATI_DP_BRUSH_FRGD_CLR   0x147c
#define ATI_DP_CNTL             0x16c0
#define ATI_DEFAULT_SC_BR       0x16e8

/* Bit / field values. */
#define ATI_PLL_WR_EN           0x00000080
#define ATI_DAC_CMP_EN          0x00000008
#define ATI_DAC_CMP_OUTPUT      0x00000080
#define ATI_MM_INDEX_VRAM       0x80000000
#define ATI_DP_LEFT_TO_RIGHT    0x00000001
#define ATI_DP_TOP_TO_BOTTOM    0x00000002
#define ATI_GMC_DST_POC         0x00000002 /* DST pitch/offset from registers */
#define ATI_GMC_BRUSH_SOLID     0x000000d0
#define ATI_GMC_ROP3_PATCOPY    0x00f00000

typedef struct {
    QTestState *qts;
    QGenericPCIBus gbus;
    QPCIDevice *dev;
    uint64_t mmio;                     /* BAR2 - MMIO register aperture */
    uint64_t fb;                       /* BAR0 - linear framebuffer      */
} ATITestDev;

static void ati_dev_open(ATITestDev *a, const char *extra)
{
    a->qts = extra ? ia64_vpc_start(extra) : ia64_vpc_start(NULL);
    ia64_qpci_init(&a->gbus, a->qts);
    a->dev = qpci_device_find(&a->gbus.bus, QPCI_DEVFN(ATI_SLOT, 0));
    g_assert_nonnull(a->dev);
    g_assert_cmphex(qpci_config_readw(a->dev, PCI_VENDOR_ID), ==, 0x1002);
    g_assert_cmphex(qpci_config_readw(a->dev, PCI_DEVICE_ID), ==, 0x5046);
    a->mmio = qpci_config_readl(a->dev, PCI_BASE_ADDRESS_2) & 0xfffffff0;
    a->fb = qpci_config_readl(a->dev, PCI_BASE_ADDRESS_0) & 0xfffffff0;
    g_assert_cmphex(a->mmio, ==, 0xc8000000);
    g_assert_cmphex(a->fb, ==, 0xc4000000);
}

static void ati_dev_close(ATITestDev *a)
{
    g_free(a->dev);
    qtest_quit(a->qts);
}

static inline void ati_wr(ATITestDev *a, uint32_t off, uint32_t v)
{
    qtest_writel(a->qts, a->mmio + off, v);
}

static inline uint32_t ati_rd(ATITestDev *a, uint32_t off)
{
    return qtest_readl(a->qts, a->mmio + off);
}

/* Read PLL register 'idx' through the CLOCK_CNTL_INDEX/DATA window. */
static uint32_t ati_pll_rd(ATITestDev *a, uint32_t idx)
{
    ati_wr(a, ATI_CLOCK_CNTL_INDEX, idx & 0x3f);
    return ati_rd(a, ATI_CLOCK_CNTL_DATA);
}

/* Write PLL register 'idx' with PLL_WR_EN asserted. */
static void ati_pll_wr(ATITestDev *a, uint32_t idx, uint32_t v)
{
    ati_wr(a, ATI_CLOCK_CNTL_INDEX, ATI_PLL_WR_EN | (idx & 0x3f));
    ati_wr(a, ATI_CLOCK_CNTL_DATA, v);
}

/* Config space: the machine reports the documented SVID=vendor/SID=device. */
static void test_ati_config_ids(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);
    g_assert_cmphex(qpci_config_readw(a.dev, PCI_SUBSYSTEM_VENDOR_ID), ==,
                    0x1002);
    g_assert_cmphex(qpci_config_readw(a.dev, PCI_SUBSYSTEM_ID), ==, 0x5046);
    ati_dev_close(&a);
}

/*
 * Indirect PLL register file: power-up defaults, PLL_WR_EN gating, the 6-bit
 * index mask, and the PPLL_ATOMIC_UPDATE "update pending" bit (bit 15 of
 * indices 0x03..0x07) that hardware reports as clear once settled.
 */
static void test_ati_pll_regfile(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);

    /* documented power-up values */
    g_assert_cmphex(ati_pll_rd(&a, 0x01), ==, 0x000000f7);
    g_assert_cmphex(ati_pll_rd(&a, 0x02), ==, 0x0000cc03);
    g_assert_cmphex(ati_pll_rd(&a, 0x10), ==, 0x7a770000);

    /* a write without PLL_WR_EN is dropped */
    ati_wr(&a, ATI_CLOCK_CNTL_INDEX, 0x02);           /* no WR_EN */
    ati_wr(&a, ATI_CLOCK_CNTL_DATA, 0xdeadbeef);
    g_assert_cmphex(ati_pll_rd(&a, 0x02), ==, 0x0000cc03);

    /* with PLL_WR_EN it sticks; the index masks to 6 bits on read-back */
    ati_pll_wr(&a, 0x02, 0x00001234);
    ati_wr(&a, ATI_CLOCK_CNTL_INDEX, 0x40 | 0x02);    /* high bits ignored */
    g_assert_cmphex(ati_rd(&a, ATI_CLOCK_CNTL_DATA), ==, 0x00001234);

    /* PPLL_ATOMIC_UPDATE: bit 15 of idx 0x03 reads back cleared */
    ati_pll_wr(&a, 0x03, 0x0000800c);
    g_assert_cmphex(ati_pll_rd(&a, 0x03), ==, 0x0000000c);
    /* a non-atomic index keeps bit 15 */
    ati_pll_wr(&a, 0x02, 0x00008111);
    g_assert_cmphex(ati_pll_rd(&a, 0x02), ==, 0x00008111);

    ati_dev_close(&a);
}

/*
 * DAC load-sense: with the comparator enabled the model reports a connected
 * CRT (DAC_CMP_OUTPUT set); with it disabled the bit stays clear.
 */
static void test_ati_dac_load_sense(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);
    ati_wr(&a, ATI_DAC_CNTL, 0);
    g_assert_cmphex(ati_rd(&a, ATI_DAC_CNTL) & ATI_DAC_CMP_OUTPUT, ==, 0);
    ati_wr(&a, ATI_DAC_CNTL, ATI_DAC_CMP_EN);
    g_assert_cmphex(ati_rd(&a, ATI_DAC_CNTL) & ATI_DAC_CMP_OUTPUT, ==,
                    ATI_DAC_CMP_OUTPUT);
    ati_dev_close(&a);
}

/* MM_INDEX/MM_DATA indirection to both the register file and to VRAM. */
static void test_ati_mm_index_indirect(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);

    /* register indirection: reach DAC_CNTL through MM_DATA */
    ati_wr(&a, ATI_DAC_CNTL, ATI_DAC_CMP_EN);
    ati_wr(&a, ATI_MM_INDEX, ATI_DAC_CNTL);
    g_assert_cmphex(ati_rd(&a, ATI_MM_DATA) & ATI_DAC_CMP_OUTPUT, ==,
                    ATI_DAC_CMP_OUTPUT);

    /* VRAM indirection (MM_INDEX bit 31): write then read back, and confirm
     * it really landed in VRAM as seen through the framebuffer BAR. */
    ati_wr(&a, ATI_MM_INDEX, ATI_MM_INDEX_VRAM | 0x40000);
    ati_wr(&a, ATI_MM_DATA, 0xcafef00d);
    ati_wr(&a, ATI_MM_INDEX, ATI_MM_INDEX_VRAM | 0x40000);
    g_assert_cmphex(ati_rd(&a, ATI_MM_DATA), ==, 0xcafef00d);
    g_assert_cmphex(qtest_readl(a.qts, a.fb + 0x40000), ==, 0xcafef00d);

    ati_dev_close(&a);
}

/*
 * PCI ROM BAR: the machine patches the stock SeaVGABIOS with the ATI tables a
 * native Rage 128 driver validates (ia64_vpc_install_ati_rom_tables): the
 * " 761295520" signature at 0x30, a PCIR structure restated to 1002:5046, and
 * a valid overall checksum over the (grown) declared image.
 */
static void test_ati_rom_bar_tables(void)
{
    ATITestDev a;
    uint32_t rom_bar;
    uint64_t rom_base;
    uint8_t *rom;
    uint32_t declared, pcir, i;
    uint8_t checksum = 0;
    int sig_at = -1;

    ati_dev_open(&a, NULL);
    /*
     * The machine assigns the ROM BAR but deliberately leaves decode OFF (an
     * XP VideoPortGetAccessRanges workaround); readers enable it transiently,
     * exactly as videoprt/pci.sys do around VideoPortGetRomImage.
     */
    rom_bar = qpci_config_readl(a.dev, PCI_ROM_ADDRESS);
    rom_base = rom_bar & 0xfffff800;
    g_assert_cmphex(rom_base, ==, 0xc9000000);
    qpci_config_writel(a.dev, PCI_ROM_ADDRESS, rom_base | 1); /* enable decode */

    rom = g_malloc(0x10000);
    qtest_memread(a.qts, rom_base, rom, 0x10000);
    g_assert_cmphex(rom[0], ==, 0x55);
    g_assert_cmphex(rom[1], ==, 0xaa);
    declared = (uint32_t)rom[2] * 512;
    g_assert_cmpuint(declared, >, 0);
    g_assert_cmpuint(declared, <=, 0x10000);

    /* signature the ATI drivers look for, at the documented 0x30 */
    g_assert_cmpmem(rom + 0x30, 10, " 761295520", 10);
    for (i = 0; i + 10 <= declared; i++) {
        if (memcmp(rom + i, " 761295520", 10) == 0) {
            sig_at = i;
            break;
        }
    }
    g_assert_cmpint(sig_at, ==, 0x30);

    /* PCIR restated to this adapter (EFI 1.10 wants it to match the header) */
    pcir = lduw_le_p(rom + 0x18);
    g_assert_cmpuint(pcir + 0x18, <=, declared);
    g_assert_cmpmem(rom + pcir, 4, "PCIR", 4);
    g_assert_cmphex(lduw_le_p(rom + pcir + 4), ==, 0x1002);
    g_assert_cmphex(lduw_le_p(rom + pcir + 6), ==, 0x5046);
    g_assert_cmphex(lduw_le_p(rom + pcir + 0x10), ==, declared / 512);

    /* the grown image checksums to zero */
    for (i = 0; i < declared; i++) {
        checksum += rom[i];
    }
    g_assert_cmphex(checksum, ==, 0);

    g_free(rom);
    ati_dev_close(&a);
}

/*
 * Program a solid-colour rectangle through the 2D engine and read it back out
 * of VRAM.  Exercises the DP_GUI_MASTER_CNTL datatype decode, the RAGE 128
 * DST_PITCH*bpp byte-stride rule, the brush/ROP fill path and ati_stpix.  At
 * 24bpp this is the case that used to abort in stn_he_p on a 3-byte store.
 */
static void ati_do_fill(ATITestDev *a, unsigned datatype, unsigned bypp,
                        uint32_t pitch_regs, uint32_t color)
{
    const uint32_t dst_off = 0x100000;
    const unsigned width = 32, height = 4;
    unsigned x, y, b;
    uint32_t gmc = (datatype << 8) | ATI_GMC_BRUSH_SOLID |
                   ATI_GMC_ROP3_PATCOPY | ATI_GMC_DST_POC;

    ati_wr(a, ATI_DEFAULT_SC_BR, 0x3fff3fff);         /* no clipping */
    ati_wr(a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(a, ATI_DST_OFFSET, dst_off);
    ati_wr(a, ATI_DST_PITCH, pitch_regs);
    ati_wr(a, ATI_DP_BRUSH_FRGD_CLR, color);
    ati_wr(a, ATI_DP_GUI_MASTER_CNTL, gmc);
    ati_wr(a, ATI_DST_Y_X, 0);
    /* the DST_HEIGHT_WIDTH write triggers the blit */
    ati_wr(a, ATI_DST_HEIGHT_WIDTH, (height << 16) | width);

    /* every pixel of the rectangle carries the fill colour, byte-exact */
    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            uint64_t p = a->fb + dst_off + y * (width * bypp) + x * bypp;

            for (b = 0; b < bypp; b++) {
                g_assert_cmphex(qtest_readb(a->qts, p + b), ==,
                                (color >> (b * 8)) & 0xff);
            }
        }
    }
}

static void test_ati_2d_solid_fill(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);
    /* DST_PITCH is in units of 8 pixels; byte stride = pitch * bpp. */
    ati_do_fill(&a, 2, 1, 32 / 8,     0x0000005a);     /* 8bpp  */
    ati_do_fill(&a, 3, 2, 32 / 8,     0x00001234);     /* 16bpp */
    ati_do_fill(&a, 6, 4, 32 / 8,     0x11223344);     /* 32bpp */
    ati_dev_close(&a);
}

/*
 * 24bpp fill: the RAGE 128 treats the surface as byte-wide, so the driver
 * pre-triples the pitch register; the model must store 3-byte pixels without
 * tripping stn_he_p (fixed in 605127d/d2140f0) and land them contiguously.
 */
static void test_ati_2d_fill_24bpp(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);
    /* 24bpp: driver folds the *3 into the register -> (width/8)*3. */
    ati_do_fill(&a, 5, 3, (32 / 8) * 3, 0x00334455);
    ati_dev_close(&a);
}

/* Extra setup-engine / 2D-engine register offsets. */
#define ATI_DP_BRUSH_BKGD_CLR   0x1478
#define ATI_BRUSH_Y_X           0x1474
#define ATI_BRUSH_DATA0         0x1480
#define ATI_BRUSH_DATA1         0x1484
#define ATI_SRC_OFFSET          0x15ac
#define ATI_SRC_PITCH           0x15b0
#define ATI_SRC_Y_X             0x1434
#define ATI_SC_TOP_LEFT         0x16ec
#define ATI_SCALE_3D_CNTL       0x1a00
#define ATI_SETUP_CNTL          0x1bc4
#define ATI_SU_DDA_BASE         0x1a40      /* per-channel {dx,dy,val}, 12B/ch */
#define ATI_GMC_SRC_POC         0x00000001
#define ATI_ROP3_SRCCOPY        0x00cc0000
#define ATI_ROP3_SRCINVERT      0x00660000
#define ATI_ROP3_SRCPAINT       0x00ee0000

static inline void ati_vram_wr32(ATITestDev *a, uint32_t off, uint32_t v)
{
    qtest_writel(a->qts, a->fb + off, v);
}

static inline uint32_t ati_vram_rd32(ATITestDev *a, uint32_t off)
{
    return qtest_readl(a->qts, a->fb + off);
}

/*
 * Caption gradient: the ati2draa driver programs the 2D setup engine's
 * per-channel colour DDA (0x1a40..) and issues a solid rectangle paint with
 * SCALE_3D_CNTL enabled and SETUP_CNTL COLOR_FCN = Gouraud; the engine then
 * interpolates the colour across the rectangle instead of using the brush.
 * Colour_c(x,y) = val_c + dx_c*(x-x0)*xstep + dy_c*(y-y0), clamped, where
 * xstep is 3 at 24bpp (the DDA advances once per byte) and 1 otherwise.  The
 * test programs a known plane and checks the engine reproduces the formula.
 */
static void ati_run_gradient(ATITestDev *a, unsigned datatype, unsigned bypp,
                             int xstep, const int32_t val[3],
                             const int32_t dx[3], const int32_t dy[3])
{
    const uint32_t dst_off = 0x100000;
    const unsigned w = 32, h = 4, pitch = (bypp == 3) ? (w / 8) * 3 : w / 8;
    const uint32_t stride = pitch * ((bypp == 3) ? 8 : bypp * 8);
    unsigned ch, x, y, b;

    ati_wr(a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(a, ATI_SC_TOP_LEFT, 0);
    ati_wr(a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(a, ATI_DST_OFFSET, dst_off);
    ati_wr(a, ATI_DST_PITCH, pitch);
    ati_wr(a, ATI_DP_GUI_MASTER_CNTL, (datatype << 8) | ATI_GMC_DST_POC);
    ati_wr(a, ATI_SCALE_3D_CNTL, 0x40);               /* setup block enable */
    ati_wr(a, ATI_SETUP_CNTL, 4 << 3);                /* COLOR_FCN = Gouraud */
    for (ch = 0; ch < 3; ch++) {
        ati_wr(a, ATI_SU_DDA_BASE + ch * 0xc + 0, (uint32_t)dx[ch]);
        ati_wr(a, ATI_SU_DDA_BASE + ch * 0xc + 4, (uint32_t)dy[ch]);
        ati_wr(a, ATI_SU_DDA_BASE + ch * 0xc + 8, (uint32_t)val[ch]);
    }
    ati_wr(a, ATI_DST_Y_X, 0);
    ati_wr(a, ATI_DST_HEIGHT_WIDTH, (h << 16) | w);   /* triggers the paint */

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            uint8_t exp[3];                            /* R,G,B */
            uint64_t p = a->fb + dst_off + y * stride + x * bypp;

            for (ch = 0; ch < 3; ch++) {
                int64_t v = (int64_t)val[ch] +
                            (int64_t)dx[ch] * (int)x * xstep +
                            (int64_t)dy[ch] * (int)y;
                int iv = (int)(v >> 16);

                exp[ch] = iv < 0 ? 0 : iv > 255 ? 255 : iv;
            }
            if (bypp >= 3) {                            /* stored B,G,R(,A) */
                g_assert_cmphex(qtest_readb(a->qts, p + 0), ==, exp[2]);
                g_assert_cmphex(qtest_readb(a->qts, p + 1), ==, exp[1]);
                g_assert_cmphex(qtest_readb(a->qts, p + 2), ==, exp[0]);
            } else if (bypp == 2) {                     /* RGB565 */
                uint16_t px = qtest_readw(a->qts, p);
                g_assert_cmpuint((px >> 11) & 0x1f, ==, exp[0] >> 3);
                g_assert_cmpuint((px >> 5) & 0x3f, ==, exp[1] >> 2);
                g_assert_cmpuint(px & 0x1f, ==, exp[2] >> 3);
            }
            (void)b;
        }
    }
}

static void test_ati_gradient_32bpp(void)
{
    ATITestDev a;
    /* horizontal ramp on R, flat G/B (16.16). */
    const int32_t val[3] = { 16 << 16, 64 << 16, 128 << 16 };
    const int32_t dx[3]  = { 1 << 16, 0, 0 };
    const int32_t dy[3]  = { 0, 0, 0 };

    ati_dev_open(&a, NULL);
    ati_run_gradient(&a, 6, 4, 1, val, dx, dy);
    ati_dev_close(&a);
}

static void test_ati_gradient_24bpp(void)
{
    ATITestDev a;
    /* dx is programmed at ~1/3 the slope; the engine multiplies by xstep=3. */
    const int32_t val[3] = { 16 << 16, 64 << 16, 128 << 16 };
    const int32_t dx[3]  = { (1 << 16) / 3, 0, 0 };
    const int32_t dy[3]  = { 0, 0, 0 };

    ati_dev_open(&a, NULL);
    ati_run_gradient(&a, 5, 3, 3, val, dx, dy);
    ati_dev_close(&a);
}

/*
 * 8x8 monochrome pattern brush (PATCOPY, brush type 0): the pattern bit at
 * (x,y) selects foreground vs background.  Regresses the pattern-brush fill.
 */
static void test_ati_pattern_brush(void)
{
    ATITestDev a;
    const uint32_t dst_off = 0x100000;
    const unsigned w = 8, h = 4;
    unsigned x, y;

    ati_dev_open(&a, NULL);
    ati_wr(&a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(&a, ATI_SC_TOP_LEFT, 0);
    ati_wr(&a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(&a, ATI_DST_OFFSET, dst_off);
    ati_wr(&a, ATI_DST_PITCH, w / 8);
    ati_wr(&a, ATI_DP_BRUSH_FRGD_CLR, 0xaa);
    ati_wr(&a, ATI_DP_BRUSH_BKGD_CLR, 0xbb);
    ati_wr(&a, ATI_BRUSH_Y_X, 0);
    ati_wr(&a, ATI_BRUSH_DATA0, 0x55555555);          /* each row 0b01010101 */
    ati_wr(&a, ATI_BRUSH_DATA1, 0x55555555);
    /* datatype 8bpp, brush field 0 (8x8 mono), ROP PATCOPY, dst from regs */
    ati_wr(&a, ATI_DP_GUI_MASTER_CNTL,
           (2 << 8) | ATI_GMC_ROP3_PATCOPY | ATI_GMC_DST_POC);
    ati_wr(&a, ATI_DST_Y_X, 0);
    ati_wr(&a, ATI_DST_HEIGHT_WIDTH, (h << 16) | w);

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            uint8_t exp = (x & 1) ? 0xbb : 0xaa;       /* bit0 set on even x */
            g_assert_cmphex(qtest_readb(a.qts, a.fb + dst_off + y * w + x),
                            ==, exp);
        }
    }
    ati_dev_close(&a);
}

/*
 * Source/destination ROP blits (32bpp): the engine combines a source and the
 * existing destination per the ROP3 code.  Regresses the general-ROP path
 * (SRCINVERT was the XOR-trail case, SRCPAINT the OR case).
 */
static void ati_rop_case(ATITestDev *a, uint32_t rop3, uint32_t sc,
                         uint32_t dc, uint32_t expect)
{
    const uint32_t src_off = 0x200000, dst_off = 0x100000;
    const unsigned w = 8, h = 2;
    const uint32_t stride = (w / 8) * 32;              /* 32bpp byte stride */
    unsigned x, y;

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            ati_vram_wr32(a, src_off + y * stride + x * 4, sc);
            ati_vram_wr32(a, dst_off + y * stride + x * 4, dc);
        }
    }
    ati_wr(a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(a, ATI_SC_TOP_LEFT, 0);
    ati_wr(a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(a, ATI_SRC_OFFSET, src_off);
    ati_wr(a, ATI_SRC_PITCH, w / 8);
    ati_wr(a, ATI_SRC_Y_X, 0);
    ati_wr(a, ATI_DST_OFFSET, dst_off);
    ati_wr(a, ATI_DST_PITCH, w / 8);
    ati_wr(a, ATI_DP_GUI_MASTER_CNTL,
           (6 << 8) | rop3 | ATI_GMC_SRC_POC | ATI_GMC_DST_POC);
    ati_wr(a, ATI_DST_Y_X, 0);
    ati_wr(a, ATI_DST_HEIGHT_WIDTH, (h << 16) | w);

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            g_assert_cmphex(ati_vram_rd32(a, dst_off + y * stride + x * 4),
                            ==, expect);
        }
    }
}

static void test_ati_rop_src_dst(void)
{
    ATITestDev a;

    ati_dev_open(&a, NULL);
    ati_rop_case(&a, ATI_ROP3_SRCCOPY, 0x11223344, 0x55667788, 0x11223344);
    ati_rop_case(&a, ATI_ROP3_SRCINVERT, 0x11223344, 0x0f0f0f0f, 0x1e2d3c4b);
    ati_rop_case(&a, ATI_ROP3_SRCPAINT, 0x11002200, 0x00330044, 0x11332244);
    ati_dev_close(&a);
}

/*
 * Overlapping same-surface SRCCOPY (a window move / scroll): pixman shears
 * overlapping copies, so the model memmoves each row walking away from the
 * destination.  Copy a strip of distinct-per-row values down by two rows and
 * confirm no row is clobbered before it is read.  Regresses the drag smear.
 */
static void test_ati_overlap_copy(void)
{
    ATITestDev a;
    const uint32_t off = 0x100000;
    const unsigned w = 8, h = 4;
    const uint32_t stride = (w / 8) * 32;
    unsigned x, y;

    ati_dev_open(&a, NULL);
    for (y = 0; y < 6; y++) {                          /* seed 6 distinct rows */
        for (x = 0; x < w; x++) {
            ati_vram_wr32(&a, off + y * stride + x * 4, 0x1000 + y);
        }
    }
    ati_wr(&a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(&a, ATI_SC_TOP_LEFT, 0);
    ati_wr(&a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(&a, ATI_SRC_OFFSET, off);
    ati_wr(&a, ATI_SRC_PITCH, w / 8);
    ati_wr(&a, ATI_SRC_Y_X, 0);                        /* src rows 0..3 */
    ati_wr(&a, ATI_DST_OFFSET, off);
    ati_wr(&a, ATI_DST_PITCH, w / 8);
    ati_wr(&a, ATI_DP_GUI_MASTER_CNTL,
           (6 << 8) | ATI_ROP3_SRCCOPY | ATI_GMC_SRC_POC | ATI_GMC_DST_POC);
    ati_wr(&a, ATI_DST_Y_X, 2 << 16);                  /* dst rows 2..5 */
    ati_wr(&a, ATI_DST_HEIGHT_WIDTH, (h << 16) | w);

    /* rows 0,1 untouched; rows 2..5 are the copied old rows 0..3 */
    for (x = 0; x < w; x++) {
        g_assert_cmphex(ati_vram_rd32(&a, off + 0 * stride + x * 4), ==,
                        0x1000);
        g_assert_cmphex(ati_vram_rd32(&a, off + 1 * stride + x * 4), ==,
                        0x1001);
        g_assert_cmphex(ati_vram_rd32(&a, off + 2 * stride + x * 4), ==,
                        0x1000);
        g_assert_cmphex(ati_vram_rd32(&a, off + 3 * stride + x * 4), ==,
                        0x1001);
        g_assert_cmphex(ati_vram_rd32(&a, off + 4 * stride + x * 4), ==,
                        0x1002);
        g_assert_cmphex(ati_vram_rd32(&a, off + 5 * stride + x * 4), ==,
                        0x1003);
    }
    ati_dev_close(&a);
}

/*
 * 14-bit SIGNED destination coordinates (ati_sext14): a caption whose left
 * edge is off-screen is encoded as a negative 14-bit X.  Exercised on the
 * gradient path, which is where it matters (an off-origin caption ramp).
 * Without sign extension DST_X = 0x3ffe reads as +16382, placing the whole
 * rectangle past the right scissor edge so columns 0..3 stay clear; with it
 * the origin is -2 and those columns render, interpolated from x0 = -2.
 */
static void test_ati_sext14_coord(void)
{
    ATITestDev a;
    const uint32_t dst_off = 0x100000;
    const int x0 = -2;
    const int32_t val[3] = { 16 << 16, 64 << 16, 128 << 16 };
    const int32_t dx[3]  = { 1 << 16, 0, 0 };
    unsigned x, ch;

    ati_dev_open(&a, NULL);
    for (x = 0; x < 8; x++) {                          /* clear the row */
        ati_vram_wr32(&a, dst_off + x * 4, 0);
    }
    ati_wr(&a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(&a, ATI_SC_TOP_LEFT, 0);
    ati_wr(&a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(&a, ATI_DST_OFFSET, dst_off);
    ati_wr(&a, ATI_DST_PITCH, 8 / 8);
    ati_wr(&a, ATI_DP_GUI_MASTER_CNTL, (6 << 8) | ATI_GMC_DST_POC);
    ati_wr(&a, ATI_SCALE_3D_CNTL, 0x40);
    ati_wr(&a, ATI_SETUP_CNTL, 4 << 3);
    for (ch = 0; ch < 3; ch++) {
        ati_wr(&a, ATI_SU_DDA_BASE + ch * 0xc + 0, (uint32_t)dx[ch]);
        ati_wr(&a, ATI_SU_DDA_BASE + ch * 0xc + 4, 0);
        ati_wr(&a, ATI_SU_DDA_BASE + ch * 0xc + 8, (uint32_t)val[ch]);
    }
    ati_wr(&a, ATI_DST_Y_X, 0x3ffe);                   /* x = -2 (sext14) */
    ati_wr(&a, ATI_DST_HEIGHT_WIDTH, (1 << 16) | 6);   /* covers x -2..3 */

    /* columns 0..3 render with R interpolated from the negative origin */
    for (x = 0; x < 4; x++) {
        int r = 16 + ((int)x - x0);                    /* val_R + dx_R*(x-x0) */
        g_assert_cmphex(ati_vram_rd32(&a, dst_off + x * 4), ==,
                        0xff000000u | (uint32_t)r << 16 | (64 << 8) | 128);
    }
    for (x = 4; x < 8; x++) {                          /* untouched */
        g_assert_cmphex(ati_vram_rd32(&a, dst_off + x * 4), ==, 0);
    }
    ati_dev_close(&a);
}

#define ATI_CLR_CMP_CLR_SRC     0x15c4
#define ATI_CLR_CMP_MASK        0x15cc
#define ATI_CLR_CMP_CNTL        0x15c0
#define ATI_GMC_CLR_CMP_FCN_CLR 0x10000000 /* DP_GUI_MASTER_CNTL bit 28 */

/*
 * A GUI-master-control write with GMC_CLR_CMP_CNTL_DIS (bit 28) must clear the
 * colour-compare function (CLR_CMP_CNTL FN_SRC/FN_DST).  The XFree86 r128
 * driver sets this bit in the base control word of every op, so a colour key
 * enabled by a transparent (window-decoration) blit does not leak into the
 * following text/fill ops.  Without this, a stale key drops keyed pixels and
 * corrupts KDE's terminal text and window frames.
 */
static void test_ati_clr_cmp_clear(void)
{
    ATITestDev a;
    const uint32_t src_off = 0x200000, dst_off = 0x100000;
    const unsigned w = 4, h = 1;
    const uint32_t stride = (w / 8 ? w / 8 : 1) * 32;
    const uint32_t key = 0x00aaaaaa, other = 0x00112233;
    unsigned x;

    ati_dev_open(&a, NULL);

    /* src: [key, other, key, other]; dst pre-cleared to 0 */
    ati_vram_wr32(&a, src_off + 0 * 4, key);
    ati_vram_wr32(&a, src_off + 1 * 4, other);
    ati_vram_wr32(&a, src_off + 2 * 4, key);
    ati_vram_wr32(&a, src_off + 3 * 4, other);
    for (x = 0; x < w; x++) {
        ati_vram_wr32(&a, dst_off + x * 4, 0);
    }

    /* Enable a NEQ colour key on 'key' (draw only where src != key). */
    ati_wr(&a, ATI_CLR_CMP_CLR_SRC, key);
    ati_wr(&a, ATI_CLR_CMP_MASK, 0xffffffff);
    ati_wr(&a, ATI_CLR_CMP_CNTL, 5);              /* FN_SRC = CMP_NEQ */

    ati_wr(&a, ATI_DEFAULT_SC_BR, 0x3fff3fff);
    ati_wr(&a, ATI_SC_TOP_LEFT, 0);
    ati_wr(&a, ATI_DP_CNTL, ATI_DP_LEFT_TO_RIGHT | ATI_DP_TOP_TO_BOTTOM);
    ati_wr(&a, ATI_SRC_OFFSET, src_off);
    ati_wr(&a, ATI_SRC_PITCH, 1);
    ati_wr(&a, ATI_SRC_Y_X, 0);
    ati_wr(&a, ATI_DST_OFFSET, dst_off);
    ati_wr(&a, ATI_DST_PITCH, 1);
    /*
     * This control write carries GMC_CLR_CMP_CNTL_DIS, so it must clear the
     * key first: the copy then draws ALL four source pixels, key ones included.
     */
    ati_wr(&a, ATI_DP_GUI_MASTER_CNTL,
           (6 << 8) | ATI_ROP3_SRCCOPY | ATI_GMC_SRC_POC | ATI_GMC_DST_POC |
           ATI_GMC_CLR_CMP_FCN_CLR);
    ati_wr(&a, ATI_DST_Y_X, 0);
    ati_wr(&a, ATI_DST_HEIGHT_WIDTH, (h << 16) | w);

    /* every source pixel copied, including the two that matched the key */
    g_assert_cmphex(ati_vram_rd32(&a, dst_off + 0 * 4), ==, key);
    g_assert_cmphex(ati_vram_rd32(&a, dst_off + 1 * 4), ==, other);
    g_assert_cmphex(ati_vram_rd32(&a, dst_off + 2 * 4), ==, key);
    g_assert_cmphex(ati_vram_rd32(&a, dst_off + 3 * 4), ==, other);

    (void)stride;
    ati_dev_close(&a);
}

int main(int argc, char **argv)
{
    unsigned cpus;

    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-vpc/acpi-reset-register",
                   test_acpi_reset_register);
    qtest_add_func("/ia64-vpc/vga/int10-rom", test_int10_rom);
    qtest_add_func("/ia64-vpc/vga/int10-vbe", test_int10_vbe);
    qtest_add_func("/ia64-vpc/vga/int10-vbe-std", test_int10_vbe_std);
    qtest_add_func("/ia64-vpc/vga/int10-legacy", test_int10_legacy);
    qtest_add_func("/ia64-vpc/vga/int10-legacy-std",
                   test_int10_legacy_std);
    qtest_add_func("/ia64-vpc/firmware-handoff/defaults",
                   test_firmware_handoff_defaults);
    qtest_add_func("/ia64-vpc/ahci/off", test_ahci_off);
    qtest_add_func("/ia64-vpc/ahci/on-default", test_ahci_on_default);
    qtest_add_func("/ia64-vpc/cpu/merced", test_cpu_merced);
    qtest_add_func("/ia64-vpc/cpu/itanium-alias", test_cpu_itanium_alias);
    qtest_add_func("/ia64-vpc/firmware-handoff/i8042-off",
                   test_firmware_handoff_i8042_off);
    for (cpus = 1; cpus <= 8; cpus++) {
        g_autofree char *path =
            g_strdup_printf("/ia64-vpc/smp/topology/%u", cpus);

        qtest_add_data_func(path, GUINT_TO_POINTER(cpus), test_smp_topology);
    }
    qtest_add_func("/ia64-vpc/smp/explicit-topology",
                   test_smp_explicit_topology);
    {
        unsigned i;

        for (i = 0; i < G_N_ELEMENTS(smp_multicore_topologies); i++) {
            const TestSmpMulticoreTopology *topology =
                &smp_multicore_topologies[i];
            g_autofree char *path = g_strdup_printf(
                "/ia64-vpc/smp/multicore/%s", topology->name);

            qtest_add_data_func(path, topology,
                                test_smp_multicore_topology);
        }
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
    qtest_add_func("/ia64-vpc/iosapic/edge-rte-write-not-a-request",
                   test_iosapic_edge_rte_write_is_not_a_request);
    qtest_add_func("/ia64-vpc/sparse-io/pm-register",
                   test_sparse_io_pm_register);
    qtest_add_func("/ia64-vpc/savevm/platform-state",
                   test_savevm_restores_platform_state);
    qtest_add_func("/ia64-vpc/ati/config-ids", test_ati_config_ids);
    qtest_add_func("/ia64-vpc/ati/pll-regfile", test_ati_pll_regfile);
    qtest_add_func("/ia64-vpc/ati/dac-load-sense", test_ati_dac_load_sense);
    qtest_add_func("/ia64-vpc/ati/mm-index-indirect",
                   test_ati_mm_index_indirect);
    qtest_add_func("/ia64-vpc/ati/rom-bar-tables", test_ati_rom_bar_tables);
    qtest_add_func("/ia64-vpc/ati/2d-solid-fill", test_ati_2d_solid_fill);
    qtest_add_func("/ia64-vpc/ati/2d-fill-24bpp", test_ati_2d_fill_24bpp);
    qtest_add_func("/ia64-vpc/ati/gradient-32bpp", test_ati_gradient_32bpp);
    qtest_add_func("/ia64-vpc/ati/gradient-24bpp", test_ati_gradient_24bpp);
    qtest_add_func("/ia64-vpc/ati/pattern-brush", test_ati_pattern_brush);
    qtest_add_func("/ia64-vpc/ati/rop-src-dst", test_ati_rop_src_dst);
    qtest_add_func("/ia64-vpc/ati/overlap-copy", test_ati_overlap_copy);
    qtest_add_func("/ia64-vpc/ati/sext14-coord", test_ati_sext14_coord);
    qtest_add_func("/ia64-vpc/ati/clr-cmp-clear", test_ati_clr_cmp_clear);

    return g_test_run();
}
