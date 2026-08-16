/*
 * QEMU ATI Mach64 "3D Rage" (DEV_4754) emulation
 *
 * A PCI display adapter with a VGA-compatible core (VGACommonState) plus the
 * classic Mach64 GUI (2D) engine.  Unlike the Rage 128 (hw/display/ati.c) this
 * chip has no command processor, ring, DMA or AGP: 2D is driven entirely by
 * synchronous MMIO register writes, so it never touches the 460GX AGP GART and
 * cannot hit the >4 GiB AGP-DRI hazard.  Guaranteed inbox drivers exist on
 * Windows XP SP1 / Server 2003 (ati.sys, PCI\VEN_1002&DEV_4754) and Debian
 * (atimisc/atyfb).  See plans/mach64-design.md.
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 */

#include "qemu/osdep.h"
#include "mach64_int.h"
#include "mach64_regs.h"
#include "hw/core/qdev-properties.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "ui/console.h"

enum { VGA_MODE, EXT_MODE };

#ifdef CONFIG_PIXMAN
#define MACH64_DEFAULT_PIXMAN 3
#else
#define MACH64_DEFAULT_PIXMAN 0
#endif

/* Bytes per pixel for a Mach64 PIX_WIDTH code. */
static int mach64_pixw_bytes(unsigned code)
{
    switch (code) {
    case PIX_WIDTH_8BPP:
        return 1;
    case PIX_WIDTH_15BPP:
    case PIX_WIDTH_16BPP:
        return 2;
    case PIX_WIDTH_24BPP:
        return 3;
    case PIX_WIDTH_32BPP:
        return 4;
    default:
        return 0;
    }
}

int mach64_dst_bpp(const Mach64VGAState *s)
{
    return mach64_pixw_bytes(s->regs[DP_PIX_WIDTH] & DP_DST_PIX_WIDTH) * 8;
}

uint32_t mach64_dst_base(const Mach64VGAState *s)
{
    return (s->regs[DST_OFF_PITCH] & 0x000fffff) * 8;
}

int mach64_dst_pitch_bytes(const Mach64VGAState *s)
{
    int pitch_px = ((s->regs[DST_OFF_PITCH] >> CRTC_PITCH_SHIFT) & 0x3ff) * 8;
    int bypp = mach64_pixw_bytes(s->regs[DP_PIX_WIDTH] & DP_DST_PIX_WIDTH);

    return pitch_px * bypp;
}

void mach64_2d_set_dirty(Mach64VGAState *s, uint32_t base, int x, int y,
                         int w, int h)
{
    int bypp = mach64_pixw_bytes(s->regs[DP_PIX_WIDTH] & DP_DST_PIX_WIDTH);
    int pitch = mach64_dst_pitch_bytes(s);
    hwaddr start, end;

    if (w <= 0 || h <= 0 || bypp == 0 || pitch == 0) {
        return;
    }
    start = base + (hwaddr)y * pitch + (hwaddr)x * bypp;
    end = start + (hwaddr)(h - 1) * pitch + (hwaddr)w * bypp;
    if (end > s->vga.vram_size) {
        end = s->vga.vram_size;
    }
    if (start >= end) {
        return;
    }
    memory_region_set_dirty(&s->vga.vram, start, end - start);
}

/*
 * Translate the extended-CRTC registers into a linear-framebuffer mode by
 * driving the VGACommonState VBE machinery, exactly as hw/display/ati.c does.
 * When the extended display enable is clear we fall back to the VGA core.
 */
static void mach64_switch_mode(Mach64VGAState *s)
{
    VGACommonState *vga = &s->vga;

    if (!(s->regs[CRTC_GEN_CNTL] & CRTC_EXT_DISP_EN) ||
        !(s->regs[CRTC_GEN_CNTL] & CRTC_EN)) {
        s->mode = VGA_MODE;
        vbe_ioport_write_index(vga, 0, VBE_DISPI_INDEX_ENABLE);
        vbe_ioport_write_data(vga, 0, VBE_DISPI_DISABLED);
        return;
    }

    s->mode = EXT_MODE;

    uint32_t htd = s->regs[CRTC_H_TOTAL_DISP];
    uint32_t vtd = s->regs[CRTC_V_TOTAL_DISP];
    int h = (((htd & CRTC_H_DISP) >> 16) + 1) * 8;
    int v = ((vtd & CRTC_V_DISP) >> 16) + 1;
    int pitch_px = ((s->regs[CRTC_OFF_PITCH] >> CRTC_PITCH_SHIFT) & 0x3ff) * 8;
    uint32_t offs = (s->regs[CRTC_OFF_PITCH] & CRTC_OFFSET_MASK) * 8;
    unsigned pw = (s->regs[CRTC_GEN_CNTL] & CRTC_PIX_WIDTH) >> CRTC_PIX_WIDTH_SHIFT;
    int bpp;

    switch (pw) {
    case PIX_WIDTH_8BPP:
        bpp = 8;
        break;
    case PIX_WIDTH_15BPP:
        bpp = 15;
        break;
    case PIX_WIDTH_16BPP:
        bpp = 16;
        break;
    case PIX_WIDTH_24BPP:
        bpp = 24;
        break;
    case PIX_WIDTH_32BPP:
        bpp = 32;
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "mach64: unsupported CRTC pix width %u\n", pw);
        return;
    }
    if (h <= 0 || v <= 0) {
        return;
    }
    if (pitch_px <= 0) {
        pitch_px = h;
    }

    vbe_ioport_write_index(vga, 0, VBE_DISPI_INDEX_ENABLE);
    vbe_ioport_write_data(vga, 0, VBE_DISPI_DISABLED);
    vga->vbe_regs[VBE_DISPI_INDEX_XRES] = h;
    vga->vbe_regs[VBE_DISPI_INDEX_YRES] = v;
    vga->vbe_regs[VBE_DISPI_INDEX_BPP] = bpp;
    vbe_ioport_write_index(vga, 0, VBE_DISPI_INDEX_ENABLE);
    vbe_ioport_write_data(vga, 0, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED |
                          VBE_DISPI_NOCLEARMEM |
                          (s->regs[DAC_CNTL] & DAC_8BIT_EN ?
                           VBE_DISPI_8BIT_DAC : 0));
    if (pitch_px) {
        vbe_ioport_write_index(vga, 0, VBE_DISPI_INDEX_VIRT_WIDTH);
        vbe_ioport_write_data(vga, 0, pitch_px);
    }
    int bypp = DIV_ROUND_UP(vga->vbe_regs[VBE_DISPI_INDEX_BPP], 8);
    if (bypp && (uint64_t)v * pitch_px * bypp + offs <= vga->vbe_size) {
        vga->vbe_start_addr = offs / 4;
    }
}

/* ---- hardware cursor (64x64 2bpp AND/XOR, identical model to the Rage 128) ---- */

static void mach64_cursor_define(Mach64VGAState *s)
{
    uint64_t data[128];
    uint32_t srcoff;
    unsigned hoff, voff;

    if (s->cursor_guest_mode) {
        return;
    }
    hoff = s->regs[CUR_HORZ_VERT_OFF] & 0x3f;
    voff = (s->regs[CUR_HORZ_VERT_OFF] >> 16) & 0x3f;
    srcoff = (s->regs[CUR_OFFSET] & 0x000fffff) * 8;
    if (srcoff > s->vga.vram_size - 64 * 16) {
        return;
    }
    for (unsigned i = 0; i < 64; i++) {
        uint64_t and_row = ~0ULL, xor_row = 0;

        if (i + voff < 64) {
            const uint8_t *src = &s->vga.vram_ptr[srcoff + i * 16];

            and_row = ldq_be_p(src);
            xor_row = ldq_be_p(src + 8);
            if (hoff) {
                and_row = (and_row << hoff) | ((1ULL << hoff) - 1);
                xor_row <<= hoff;
            }
        }
        stq_be_p(&data[i], and_row);
        stq_be_p(&data[i + 64], xor_row);
    }
    if (!s->cursor) {
        s->cursor = cursor_alloc(64, 64);
    }
    cursor_set_mono(s->cursor, s->regs[CUR_CLR1], s->regs[CUR_CLR0],
                    (uint8_t *)&data[64], 1, (uint8_t *)&data[0]);
    dpy_cursor_define(s->vga.con, s->cursor);
}

static bool mach64_cursor_enabled(Mach64VGAState *s)
{
    return !!(s->regs[GEN_TEST_CNTL] & GEN_CUR_EN);
}

static void mach64_cursor_invalidate(VGACommonState *vga)
{
    Mach64VGAState *s = container_of(vga, Mach64VGAState, vga);
    int size = mach64_cursor_enabled(s) ? 64 : 0;
    int x = s->regs[CUR_HORZ_VERT_POSN] & 0xffff;
    int y = (s->regs[CUR_HORZ_VERT_POSN] >> 16) & 0xffff;
    uint32_t off = (s->regs[CUR_OFFSET] & 0x000fffff) * 8;

    if (s->cursor_size != size || vga->hw_cursor_x != x ||
        vga->hw_cursor_y != y || s->cursor_offset != off) {
        vga_invalidate_scanlines(vga, vga->hw_cursor_y, vga->hw_cursor_y + 63);
        vga->hw_cursor_x = x;
        vga->hw_cursor_y = y;
        s->cursor_offset = off;
        s->cursor_size = size;
        if (size) {
            vga_invalidate_scanlines(vga, y, y + 63);
        }
    }
}

static void mach64_cursor_draw_line(VGACommonState *vga, uint8_t *d, int scr_y)
{
    Mach64VGAState *s = container_of(vga, Mach64VGAState, vga);
    uint32_t srcoff, color, h;
    uint64_t abits, xbits, mask;
    uint32_t *dp = (uint32_t *)d;
    unsigned hoff = s->regs[CUR_HORZ_VERT_OFF] & 0x3f;
    unsigned voff = (s->regs[CUR_HORZ_VERT_OFF] >> 16) & 0x3f;
    int row = scr_y - vga->hw_cursor_y;

    if (!mach64_cursor_enabled(s) || row < 0 || row >= 64) {
        return;
    }
    if ((unsigned)row + voff >= 64) {
        return;
    }
    srcoff = (s->regs[CUR_OFFSET] & 0x000fffff) * 8 + row * 16;
    if (srcoff > s->vga.vram_size - 16) {
        return;
    }
    dp = &dp[vga->hw_cursor_x];
    h = (((s->regs[CRTC_H_TOTAL_DISP] & CRTC_H_DISP) >> 16) + 1) * 8;
    abits = ldq_be_p(&vga->vram_ptr[srcoff]);
    xbits = ldq_be_p(&vga->vram_ptr[srcoff + 8]);
    if (hoff) {
        abits = (abits << hoff) | ((1ULL << hoff) - 1);
        xbits <<= hoff;
    }
    mask = BIT_ULL(63);
    for (int i = 0; i < 64; i++, mask >>= 1) {
        if (vga->hw_cursor_x + i >= h) {
            return;
        }
        if (abits & mask) {
            if (xbits & mask) {
                color = dp[i] ^ 0xffffffff;
            } else {
                continue;
            }
        } else {
            color = (xbits & mask ? s->regs[CUR_CLR1] :
                                    s->regs[CUR_CLR0]) | 0xff000000;
        }
        dp[i] = color;
    }
}

/* ---- DAC palette access via the MMIO DAC_REGS byte window ---- */

static void mach64_dac_write(Mach64VGAState *s, unsigned byte, uint8_t val)
{
    VGACommonState *vga = &s->vga;

    switch (byte) {
    case 0: /* DAC_W_INDEX */
        vga->dac_write_index = val;
        vga->dac_sub_index = 0;
        break;
    case 1: /* DAC_DATA */
        vga->palette[vga->dac_write_index * 3 + vga->dac_sub_index] = val;
        if (++vga->dac_sub_index == 3) {
            vga->dac_sub_index = 0;
            vga->dac_write_index++;
        }
        break;
    case 2: /* DAC_MASK */
        break;
    case 3: /* DAC_R_INDEX */
        vga->dac_read_index = val;
        vga->dac_sub_index = 0;
        break;
    }
}

static uint8_t mach64_dac_read(Mach64VGAState *s, unsigned byte)
{
    VGACommonState *vga = &s->vga;
    uint8_t v = 0;

    if (byte == 1) {
        v = vga->palette[vga->dac_read_index * 3 + vga->dac_sub_index];
        if (++vga->dac_sub_index == 3) {
            vga->dac_sub_index = 0;
            vga->dac_read_index++;
        }
    }
    return v;
}

/* Synthetic current scanline, so drivers polling CRTC_VLINE make progress. */
static uint32_t mach64_crtc_vline(Mach64VGAState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int lines = ((s->regs[CRTC_V_TOTAL_DISP] & 0x7ff) + 1) ? : 525;
    int64_t frame_ns = NANOSECONDS_PER_SECOND / 60;

    return (now % frame_ns) * lines / frame_ns;
}

/* ---- MMIO register access ---- */

static uint64_t mach64_mm_read(void *opaque, hwaddr addr, unsigned size)
{
    Mach64VGAState *s = opaque;
    unsigned reg = MACH64_OFF_TO_REG(addr);
    unsigned byte = addr & 3;
    uint32_t val;

    if (reg >= MACH64_NREGS) {
        return 0; /* Block 1 (overlay/scaler): not modelled yet */
    }

    switch (reg) {
    case CONFIG_CHIP_ID:
        val = s->dev_id;   /* type = PCI device id; class/rev left 0 */
        break;
    case CONFIG_STAT0:
        val = 0;
        break;
    case GUI_STAT:
    case FIFO_STAT:
        val = 0;           /* engine idle, FIFO empty: WaitForIdle/FIFO pass */
        break;
    case CRTC_VLINE_CRNT_VLINE:
        val = mach64_crtc_vline(s) << 16;
        break;
    case DAC_REGS:
        if (size == 1) {
            return mach64_dac_read(s, byte);
        }
        val = s->regs[reg];
        break;
    default:
        val = s->regs[reg];
        break;
    }

    if (size < 4) {
        val = (val >> (byte * 8)) & ((1u << (size * 8)) - 1);
    }
    return val;
}

static void mach64_reg_store(Mach64VGAState *s, unsigned reg, unsigned byte,
                             unsigned size, uint32_t data)
{
    if (size >= 4) {
        s->regs[reg] = data;
        return;
    }
    uint32_t mask = ((1u << (size * 8)) - 1) << (byte * 8);
    s->regs[reg] = (s->regs[reg] & ~mask) | ((data << (byte * 8)) & mask);
}

static void mach64_mm_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    Mach64VGAState *s = opaque;
    unsigned reg = MACH64_OFF_TO_REG(addr);
    unsigned byte = addr & 3;

    if (reg >= MACH64_NREGS) {
        return; /* Block 1 (overlay/scaler): not modelled yet */
    }

    /* Host-data stream: any of HOST_DATA0..F feeds the active blit. */
    if (reg >= HOST_DATA0 && reg <= HOST_DATAF) {
        s->regs[reg] = data;
        mach64_2d_host_data(s, data);
        return;
    }

    switch (reg) {
    case DAC_REGS:
        if (size == 1) {
            mach64_dac_write(s, byte, data & 0xff);
            return;
        }
        mach64_reg_store(s, reg, byte, size, data);
        return;
    case CONFIG_CHIP_ID:
    case CONFIG_STAT0:
    case GUI_STAT:
    case FIFO_STAT:
        return; /* read-only */
    }

    mach64_reg_store(s, reg, byte, size, data);

    switch (reg) {
    case CRTC_GEN_CNTL:
    case CRTC_H_TOTAL_DISP:
    case CRTC_V_TOTAL_DISP:
    case CRTC_OFF_PITCH:
    case DAC_CNTL:
        mach64_switch_mode(s);
        break;
    case GEN_TEST_CNTL: {
        bool en = mach64_cursor_enabled(s);

        if (s->cursor_guest_mode) {
            s->vga.force_shadow = en;
            graphic_hw_invalidate(s->vga.con);
        } else if (en) {
            mach64_cursor_define(s);
            dpy_mouse_set(s->vga.con, s->regs[CUR_HORZ_VERT_POSN] & 0xffff,
                          (s->regs[CUR_HORZ_VERT_POSN] >> 16) & 0xffff, 1);
        } else {
            dpy_mouse_set(s->vga.con, 0, 0, 0);
        }
        break;
    }
    case CUR_HORZ_VERT_POSN:
        if (!s->cursor_guest_mode) {
            dpy_mouse_set(s->vga.con, s->regs[reg] & 0xffff,
                          (s->regs[reg] >> 16) & 0xffff,
                          mach64_cursor_enabled(s));
        }
        break;
    case CUR_OFFSET:
    case CUR_HORZ_VERT_OFF:
    case CUR_CLR0:
    case CUR_CLR1:
        if (!s->cursor_guest_mode && mach64_cursor_enabled(s)) {
            mach64_cursor_define(s);
        }
        break;

    /*
     * Fold the separate and alternate-order destination / scissor registers
     * into the canonical DST_Y_X (X high, Y low), DST_HEIGHT_WIDTH (W high,
     * H low) and SC_LEFT/RIGHT/TOP/BOTTOM that the engine reads, so a guest
     * may program the engine through whichever aliases it prefers.
     */
    case DST_X:
        s->regs[DST_Y_X] = (s->regs[DST_Y_X] & 0x0000ffff) |
                           ((s->regs[reg] & 0x1fff) << 16);
        break;
    case DST_Y:
        s->regs[DST_Y_X] = (s->regs[DST_Y_X] & 0xffff0000) |
                           (s->regs[reg] & 0x1fff);
        break;
    case DST_X_Y:  /* X low, Y high */
        s->regs[DST_Y_X] = ((s->regs[reg] & 0x1fff) << 16) |
                           ((s->regs[reg] >> 16) & 0x1fff);
        break;
    case DST_WIDTH:
        s->regs[DST_HEIGHT_WIDTH] = (s->regs[DST_HEIGHT_WIDTH] & 0x0000ffff) |
                                    ((s->regs[reg] & 0x3fff) << 16);
        break;
    case SC_LEFT_RIGHT:  /* LEFT low, RIGHT high */
        s->regs[SC_LEFT] = s->regs[reg] & 0x3fff;
        s->regs[SC_RIGHT] = (s->regs[reg] >> 16) & 0x3fff;
        break;
    case SC_TOP_BOTTOM:  /* TOP low, BOTTOM high */
        s->regs[SC_TOP] = s->regs[reg] & 0x3fff;
        s->regs[SC_BOTTOM] = (s->regs[reg] >> 16) & 0x3fff;
        break;

    /* Trajectory launches. */
    case DST_HEIGHT:  /* separate-register rect: W already set, H triggers */
        s->regs[DST_HEIGHT_WIDTH] = (s->regs[DST_HEIGHT_WIDTH] & 0xffff0000) |
                                    (s->regs[reg] & 0x3fff);
        mach64_2d_dst_trigger(s);
        break;
    case DST_WIDTH_HEIGHT:  /* W low, H high */
        s->regs[DST_HEIGHT_WIDTH] = ((s->regs[reg] & 0x3fff) << 16) |
                                    ((s->regs[reg] >> 16) & 0x3fff);
        mach64_2d_dst_trigger(s);
        break;
    case DST_HEIGHT_WIDTH:
        mach64_2d_dst_trigger(s);
        break;
    case DST_BRES_LNTH:
        mach64_2d_line_trigger(s);
        break;
    }
}

static const MemoryRegionOps mach64_mm_ops = {
    .read = mach64_mm_read,
    .write = mach64_mm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/* ---- vmstate ---- */

static int mach64_post_load(void *opaque, int version_id)
{
    Mach64VGAState *s = opaque;

    s->mode = (s->regs[CRTC_GEN_CNTL] & CRTC_EXT_DISP_EN) ? EXT_MODE : VGA_MODE;
    s->vga.graphic_mode = -1;
    if (s->cursor_guest_mode) {
        s->vga.force_shadow = mach64_cursor_enabled(s);
        s->cursor_size = UINT16_MAX;
    } else if (mach64_cursor_enabled(s)) {
        mach64_cursor_define(s);
    }
    graphic_hw_invalidate(s->vga.con);
    return 0;
}

static const VMStateDescription vmstate_mach64_host_data = {
    .name = "mach64-vga/host-data",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(active, Mach64HostData),
        VMSTATE_BOOL(mono, Mach64HostData),
        VMSTATE_UINT32(x, Mach64HostData),
        VMSTATE_UINT32(y, Mach64HostData),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_mach64_vga = {
    .name = "mach64-vga",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = mach64_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, Mach64VGAState),
        VMSTATE_STRUCT(vga, Mach64VGAState, 0, vmstate_vga_common,
                       VGACommonState),
        VMSTATE_UINT32_ARRAY(regs, Mach64VGAState, MACH64_NREGS),
        VMSTATE_STRUCT(host_data, Mach64VGAState, 0, vmstate_mach64_host_data,
                       Mach64HostData),
        VMSTATE_END_OF_LIST()
    },
};

/* ---- realize / reset ---- */

static void mach64_vga_realize(PCIDevice *dev, Error **errp)
{
    Mach64VGAState *s = MACH64_VGA(dev);
    VGACommonState *vga = &s->vga;

    if (s->dev_id != PCI_DEVICE_ID_ATI_MACH64_GT) {
        error_setg(errp, "mach64: only device id 0x4754 is supported");
        return;
    }
    pci_set_word(dev->config + PCI_DEVICE_ID, s->dev_id);

    if (!vga_common_init(vga, OBJECT(s), errp)) {
        return;
    }
    vga->vbe_legacy_mode_switch = true;
    vga_init(vga, OBJECT(s), pci_address_space(dev),
             pci_address_space_io(dev), true);
    vga->con = graphic_console_init(DEVICE(s), 0, vga->hw_ops, vga);
    if (s->cursor_guest_mode) {
        vga->cursor_invalidate = mach64_cursor_invalidate;
        vga->cursor_draw_line = mach64_cursor_draw_line;
    }

    /* MMIO register block (BAR2). */
    memory_region_init_io(&s->mm, OBJECT(s), &mach64_mm_ops, s,
                          "mach64.mmregs", MACH64_MMIO_SIZE);
    /* Block-I/O alias (BAR1): the first 256 bytes of the register window. */
    memory_region_init_alias(&s->io, OBJECT(s), "mach64.io", &s->mm, 0, 0x100);

    /* Linear framebuffer aperture (BAR0). */
    memory_region_init(&s->linear_aper, OBJECT(dev), "mach64.vram",
                       MACH64_LINEAR_APER_SIZE);
    memory_region_add_subregion(&s->linear_aper, 0, &vga->vram);

    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->linear_aper);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &s->io);
    pci_register_bar(dev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mm);

    dev->config[PCI_INTERRUPT_PIN] = 1;
}

static void mach64_vga_reset(DeviceState *dev)
{
    Mach64VGAState *s = MACH64_VGA(dev);

    memset(s->regs, 0, sizeof(s->regs));
    memset(&s->host_data, 0, sizeof(s->host_data));
    s->mode = VGA_MODE;
    s->cursor_size = 0;
    s->cursor_offset = 0;
    /* Engine out of reset on 264xT parts. */
    s->regs[GEN_TEST_CNTL] = GEN_GUI_RESETB;
}

static void mach64_vga_exit(PCIDevice *dev)
{
    Mach64VGAState *s = MACH64_VGA(dev);

    graphic_console_close(s->vga.con);
    if (s->cursor) {
        cursor_unref(s->cursor);
        s->cursor = NULL;
    }
}

static const Property mach64_vga_properties[] = {
    DEFINE_PROP_UINT32("vgamem_mb", Mach64VGAState, vga.vram_size_mb, 8),
    DEFINE_PROP_UINT16("x-device-id", Mach64VGAState, dev_id,
                       PCI_DEVICE_ID_ATI_MACH64_GT),
    DEFINE_PROP_BOOL("guest_hwcursor", Mach64VGAState, cursor_guest_mode,
                     false),
    DEFINE_PROP_UINT8("x-pixman", Mach64VGAState, use_pixman,
                      MACH64_DEFAULT_PIXMAN),
};

static void mach64_vga_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, mach64_vga_reset);
    device_class_set_props(dc, mach64_vga_properties);
    dc->vmsd = &vmstate_mach64_vga;
    dc->hotpluggable = false;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);

    k->class_id = PCI_CLASS_DISPLAY_VGA;
    k->vendor_id = PCI_VENDOR_ID_ATI;
    k->device_id = PCI_DEVICE_ID_ATI_MACH64_GT;
    k->romfile = "vgabios-mach64.bin";
    k->realize = mach64_vga_realize;
    k->exit = mach64_vga_exit;
}

static const TypeInfo mach64_vga_info = {
    .name = TYPE_MACH64_VGA,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(Mach64VGAState),
    .class_init = mach64_vga_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void mach64_vga_register_types(void)
{
    type_register_static(&mach64_vga_info);
}

type_init(mach64_vga_register_types)
