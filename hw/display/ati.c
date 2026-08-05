/*
 * QEMU ATI SVGA emulation
 *
 * Copyright (c) 2019 BALATON Zoltan
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 */

/*
 * WARNING:
 * This is very incomplete and only enough for Linux console and some
 * unaccelerated X output at the moment.
 * Currently it's little more than a frame buffer with minimal functions,
 * other more advanced features of the hardware are yet to be implemented.
 * We only aim for Rage 128 Pro (and some RV100) and 2D only at first,
 * No 3D at all yet (maybe after 2D works, but feel free to improve it)
 */

#include "qemu/osdep.h"
#include "ati_int.h"
#include "ati_regs.h"
#include "vga-access.h"
#include "hw/core/qdev-properties.h"
#include "vga_regs.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "ui/console.h"
#include "trace.h"

#define ATI_DEBUG_HW_CURSOR 0

#ifdef CONFIG_PIXMAN
#define DEFAULT_X_PIXMAN 3
#else
#define DEFAULT_X_PIXMAN 0
#endif

static const struct {
    const char *name;
    uint16_t dev_id;
} ati_model_aliases[] = {
    { "rage128p", PCI_DEVICE_ID_ATI_RAGE128_PF },
    { "rv100", PCI_DEVICE_ID_ATI_RADEON_QY },
};

enum { VGA_MODE, EXT_MODE };

static void ati_vga_set_offset(VGACommonState *vga, uint32_t offs)
{
    int bypp = DIV_ROUND_UP(vga->vbe_regs[VBE_DISPI_INDEX_BPP], BITS_PER_BYTE);

    if (!bypp ||
        vga->vbe_regs[VBE_DISPI_INDEX_YRES] *
        vga->vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH] * bypp + offs >
        vga->vbe_size) {
        return;
    }
    vga->vbe_start_addr = offs / 4;
}

static void ati_vga_switch_mode(ATIVGAState *s)
{
    DPRINTF("%d -> %d\n",
            s->mode, !!(s->regs.crtc_gen_cntl & CRTC2_EXT_DISP_EN));
    if (s->regs.crtc_gen_cntl & CRTC2_EXT_DISP_EN) {
        /* Extended mode enabled */
        s->mode = EXT_MODE;
        if (s->regs.crtc_gen_cntl & CRTC2_EN) {
            /* CRT controller enabled, use CRTC values */
            /* FIXME Should these be the same as VGA CRTC regs? */
            uint32_t offs = s->regs.crtc_offset & 0x07ffffff;
            int stride = (s->regs.crtc_pitch & 0x7ff) * 8;
            int bpp = 0;
            int h, v;

            if (s->regs.crtc_h_total_disp == 0) {
                s->regs.crtc_h_total_disp = ((640 / 8) - 1) << 16;
            }
            if (s->regs.crtc_v_total_disp == 0) {
                s->regs.crtc_v_total_disp = (480 - 1) << 16;
            }
            h = ((s->regs.crtc_h_total_disp >> 16) + 1) * 8;
            v = (s->regs.crtc_v_total_disp >> 16) + 1;
            switch (s->regs.crtc_gen_cntl & CRTC_PIX_WIDTH_MASK) {
            case CRTC_PIX_WIDTH_4BPP:
                bpp = 4;
                break;
            case CRTC_PIX_WIDTH_8BPP:
                bpp = 8;
                break;
            case CRTC_PIX_WIDTH_15BPP:
                bpp = 15;
                break;
            case CRTC_PIX_WIDTH_16BPP:
                bpp = 16;
                break;
            case CRTC_PIX_WIDTH_24BPP:
                bpp = 24;
                break;
            case CRTC_PIX_WIDTH_32BPP:
                bpp = 32;
                break;
            default:
                qemu_log_mask(LOG_UNIMP, "Unsupported bpp value\n");
                return;
            }
            DPRINTF("Switching to %dx%d %d %d @ %x\n", h, v, stride, bpp, offs);
            vbe_ioport_write_index(&s->vga, 0, VBE_DISPI_INDEX_ENABLE);
            vbe_ioport_write_data(&s->vga, 0, VBE_DISPI_DISABLED);
            s->vga.big_endian_fb = (s->regs.config_cntl & APER_0_ENDIAN ||
                                    s->regs.config_cntl & APER_1_ENDIAN ?
                                    true : false);
            /* reset VBE regs then set up mode */
            s->vga.vbe_regs[VBE_DISPI_INDEX_XRES] = h;
            s->vga.vbe_regs[VBE_DISPI_INDEX_YRES] = v;
            s->vga.vbe_regs[VBE_DISPI_INDEX_BPP] = bpp;
            /* enable mode via ioport so it updates vga regs */
            vbe_ioport_write_index(&s->vga, 0, VBE_DISPI_INDEX_ENABLE);
            vbe_ioport_write_data(&s->vga, 0, VBE_DISPI_ENABLED |
                VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM |
                (s->regs.dac_cntl & DAC_8BIT_EN ? VBE_DISPI_8BIT_DAC : 0));
            /* now set offset and stride because enable resets these */
            if (stride) {
                vbe_ioport_write_index(&s->vga, 0, VBE_DISPI_INDEX_VIRT_WIDTH);
                vbe_ioport_write_data(&s->vga, 0, stride);
            }
            ati_vga_set_offset(&s->vga, offs);
        }
    } else {
        /* VGA mode enabled */
        s->mode = VGA_MODE;
        vbe_ioport_write_index(&s->vga, 0, VBE_DISPI_INDEX_ENABLE);
        vbe_ioport_write_data(&s->vga, 0, VBE_DISPI_DISABLED);
    }
}

/* Used by host side hardware cursor */
static void ati_cursor_define(ATIVGAState *s)
{
    uint64_t data[128];
    uint32_t srcoff;

    if ((s->regs.cur_offset & BIT(31)) || s->cursor_guest_mode) {
        return; /* Do not update cursor if locked or rendered by guest */
    }
    /* FIXME handle cur_hv_offs correctly */
    srcoff = (s->regs.cur_offset & 0x07fffff0) - (s->regs.cur_hv_offs >> 16) -
             (s->regs.cur_hv_offs & 0xffff) * 16;
    if (srcoff > s->vga.vram_size - 64 * 16) {
        return;
    }
    for (int i = 0; i < 64; i++, srcoff += 16) {
        data[i] = ldq_le_p(&s->vga.vram_ptr[srcoff]);
        data[i + 64] = ldq_le_p(&s->vga.vram_ptr[srcoff + 8]);
    }
    if (!s->cursor) {
        s->cursor = cursor_alloc(64, 64);
    }
    cursor_set_mono(s->cursor, s->regs.cur_color1, s->regs.cur_color0,
                    (uint8_t *)&data[64], 1, (uint8_t *)&data[0]);
    dpy_cursor_define(s->vga.con, s->cursor);
}

/* Alternatively support guest rendered hardware cursor */
static void ati_cursor_invalidate(VGACommonState *vga)
{
    ATIVGAState *s = container_of(vga, ATIVGAState, vga);
    int size = (s->regs.crtc_gen_cntl & CRTC2_CUR_EN) ? 64 : 0;

    if (s->regs.cur_offset & BIT(31)) {
        return; /* Do not update cursor if locked */
    }
    if (s->cursor_size != size ||
        vga->hw_cursor_x != s->regs.cur_hv_pos >> 16 ||
        vga->hw_cursor_y != (s->regs.cur_hv_pos & 0xffff) ||
        s->cursor_offset != (s->regs.cur_offset & 0x07fffff0) -
        (s->regs.cur_hv_offs >> 16) -
        (s->regs.cur_hv_offs & 0xffff) * 16) {
        /* Remove old cursor then update and show new one if needed */
        vga_invalidate_scanlines(vga, vga->hw_cursor_y, vga->hw_cursor_y + 63);
        vga->hw_cursor_x = s->regs.cur_hv_pos >> 16;
        vga->hw_cursor_y = s->regs.cur_hv_pos & 0xffff;
        s->cursor_offset = (s->regs.cur_offset & 0x07fffff0) -
                           (s->regs.cur_hv_offs >> 16) -
                           (s->regs.cur_hv_offs & 0xffff) * 16;
        s->cursor_size = size;
        if (size) {
            vga_invalidate_scanlines(vga,
                                     vga->hw_cursor_y, vga->hw_cursor_y + 63);
        }
    }
}

static void ati_cursor_draw_line(VGACommonState *vga, uint8_t *d, int scr_y)
{
    ATIVGAState *s = container_of(vga, ATIVGAState, vga);
    uint32_t h, srcoff, color;
    uint64_t abits, xbits, mask;
    uint32_t *dp = (uint32_t *)d;

    if (!(s->regs.crtc_gen_cntl & CRTC2_CUR_EN) ||
        scr_y < vga->hw_cursor_y || scr_y >= vga->hw_cursor_y + 64 ||
        scr_y > s->regs.crtc_v_total_disp >> 16) {
        return;
    }
    /* FIXME handle cur_hv_offs correctly */
    srcoff = s->cursor_offset + (scr_y - vga->hw_cursor_y) * 16;
    if (srcoff > s->vga.vram_size - 16) {
        return;
    }
    dp = &dp[vga->hw_cursor_x];
    h = ((s->regs.crtc_h_total_disp >> 16) + 1) * 8;
    abits = ldq_be_p(&vga->vram_ptr[srcoff]);
    xbits = ldq_be_p(&vga->vram_ptr[srcoff + 8]);
    mask = BIT_ULL(63);
    for (int i = 0; i < 64; i++, mask >>= 1) {
        if (vga->hw_cursor_x + i >= h) {
            return; /* end of screen, don't span to next line */
        }
        if (abits & mask) {
            if (xbits & mask) {
                color = dp[i] ^ 0xffffffff; /* complement */
            } else {
                continue; /* transparent, no change */
            }
        } else {
            color = (xbits & mask ? s->regs.cur_color1 :
                                    s->regs.cur_color0) | 0xff000000;
        }
        dp[i] = color;
    }
}

static uint64_t ati_i2c(bitbang_i2c_interface *i2c, uint64_t data, int base)
{
    bool c = (data & BIT(base + 17) ? !!(data & BIT(base + 1)) : 1);
    bool d = (data & BIT(base + 16) ? !!(data & BIT(base)) : 1);

    bitbang_i2c_set(i2c, BITBANG_I2C_SCL, c);
    d = bitbang_i2c_set(i2c, BITBANG_I2C_SDA, d);

    data &= ~0xf00ULL;
    if (c) {
        data |= BIT(base + 9);
    }
    if (d) {
        data |= BIT(base + 8);
    }
    return data;
}

static void ati_vga_update_irq(ATIVGAState *s)
{
    pci_set_irq(&s->dev, !!(s->regs.gen_int_status & s->regs.gen_int_cntl));
}

static void ati_vga_vblank_irq(void *opaque)
{
    ATIVGAState *s = opaque;

    timer_mod(&s->vblank_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              NANOSECONDS_PER_SECOND / 60);
    s->regs.gen_int_status |= CRTC_VBLANK_INT;
    ati_vga_update_irq(s);
}

/*
 * Synthetic CRTC raster timing, derived from virtual time: a fixed 60 Hz
 * frame of 525 lines with the last 45 in vertical blank (VGA-ish 480-line
 * visible raster).  Drivers poll these instead of taking the vblank
 * interrupt: XP's ati2draa spins on CRTC_STATUS (0x5C) waiting for the
 * vblank bits to change, and a constant readback becomes bugcheck 0xEA.
 */
#define ATI_FRAME_NS   (NANOSECONDS_PER_SECOND / 60)
#define ATI_FRAME_LINES 525
#define ATI_VISIBLE_LINES 480

static uint64_t ati_crtc_frame_count(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / ATI_FRAME_NS;
}

static uint32_t ati_crtc_current_line(void)
{
    uint64_t in_frame = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) % ATI_FRAME_NS;

    return in_frame * ATI_FRAME_LINES / ATI_FRAME_NS;
}

static uint32_t ati_crtc_status(ATIVGAState *s)
{
    uint32_t val = 0;

    /* bit 0: currently inside vertical blank */
    if (ati_crtc_current_line() >= ATI_VISIBLE_LINES) {
        val |= 1;
    }
    /* bit 1: a vblank happened since it was last acknowledged (W1C) */
    if ((uint32_t)ati_crtc_frame_count() != s->regs.crtc_vblank_ack_frame) {
        val |= 2;
    }
    return val;
}

static inline uint32_t ati_reg_read_offs(uint32_t reg, int offs,
                                         unsigned int size)
{
    if (offs == 0 && size == 4) {
        return reg;
    } else {
        return extract32(reg, offs * BITS_PER_BYTE, size * BITS_PER_BYTE);
    }
}

/*
 * Registers the XP inbox Rage 128 miniport programs during HwFindAdapter /
 * HwInitialize that carry no device-visible behaviour we model yet.  They
 * must store writes and read them back (the driver programs the memory
 * controller and PLL and verifies by readback); silently dropping the
 * writes made the init fail.  Offsets and reset values follow the RAGE 128
 * PRO Register Reference Guide.
 */
static const uint16_t ati_init_aux_offs[] = {
    0x0030, /* BUS_CNTL          */
    0x0034, /* BUS_CNTL1         */
    0x00f0, /* GEN_RESET_CNTL    */
    0x0120, 0x0124, 0x0128,
    0x0130, /* HOST_PATH_CNTL    */
    0x0140, /* MEM_CNTL          */
    0x0144, /* MEM_TIMING_CNTL   */
    0x0148, /* MC_FB_LOCATION    */
    0x014c, /* MC_AGP_LOCATION   */
    0x0150, 0x0154,
    0x0158, /* MEM_SDRAM_MODE_REG */
    0x0168,
    0x0170, /* AGP_BASE          */
    0x0174, /* AGP_CNTL          */
    0x0180, /* PC_NGUI_MODE      */
    0x0184, /* PC_NGUI_CTLSTAT   */
    0x02e0, 0x02e4, 0x02e8, 0x02ec, /* BIOS header scratch group */
    0x0700, /* PM4_BUFFER_OFFSET  */
    0x0704, /* PM4_BUFFER_CNTL    */
    0x0708, /* PM4_BUFFER_WM_CTL  */
    0x070c, /* PM4_BUFFER_DL_RPTR_ADDR */
    0x07d4, /* PM4_MICRO_CNTL     */
    0x07dc, /* PM4_MICROCODE_ADDR */
    0x07e0, /* PM4_MICRODE_DATAH/L group */
    0x0b00,
};

static int ati_init_aux_slot(hwaddr addr)
{
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(ati_init_aux_offs); i++) {
        if (ati_init_aux_offs[i] == (addr & ~3ULL)) {
            return i;
        }
    }
    return -1;
}

/*
 * CLOCK_CNTL_INDEX (0x08) / CLOCK_CNTL_DATA (0x0c) indirect PLL file.
 * Index layout on Rage 128: PLL_ADDR in the low bits (drivers mask 0x1f or
 * 0x3f), PLL_WR_EN at bit 7, PPLL_DIV_SEL at bits 9:8.  The only handshake
 * on this chip is PPLL_ATOMIC_UPDATE: bit 15 of PPLL_REF_DIV (0x03) and of
 * PPLL_DIV_0..3 (0x04..0x07) reads as "update pending" and hardware clears
 * it when the divider update lands; we complete updates instantly, so those
 * reads mask bit 15.
 */
static uint32_t ati_pll_read(ATIVGAState *s)
{
    unsigned idx = s->regs.clock_cntl_index & 0x3f;
    uint32_t val;

    if (idx >= ARRAY_SIZE(s->regs.pll_regs)) {
        return 0;
    }
    val = s->regs.pll_regs[idx];
    if (idx >= 0x03 && idx <= 0x07) {
        val &= ~0x8000u;
    }
    return val;
}

static void ati_mm_write(void *opaque, hwaddr addr, uint64_t data,
                         unsigned int size);

#define R128_PM4_BUFFER_DL_DONE  (1u << 31)

/*
 * Concurrent Command Engine ring buffer.
 *
 * The XP inbox display driver (ati2draa) and the r128 DRM submit most 2D
 * work as PM4 packets through a ring buffer in bus-addressable memory:
 * PM4_BUFFER_OFFSET holds the ring base, PM4_BUFFER_CNTL carries the mode
 * bits plus log2(ring size in qwords), and PM4_BUFFER_DL_WPTR (a dword
 * index, bit 31 = "list done" flag) advances the tail.  Type-0/1 packets
 * are register writes and replay through the ordinary MMIO path, driving
 * the same blitter the PIO path uses.  Unknown type-3 opcodes are skipped
 * by their length field.  Packet encodings follow the RAGE 128 PM4
 * specification as used by XFree86 4.x r128_reg.h and the Linux r128 DRM.
 */
static uint32_t ati_cce_ring_dword(ATIVGAState *s, uint32_t base,
                                   uint32_t mask, uint32_t idx)
{
    uint32_t le;

    pci_dma_read(&s->dev, base + ((idx & mask) << 2), &le, sizeof(le));
    return le32_to_cpu(le);
}

static void ati_cce_execute(ATIVGAState *s, uint32_t rptr, uint32_t wptr)
{
    int off_slot = ati_init_aux_slot(0x0700);
    int cntl_slot = ati_init_aux_slot(0x0704);
    uint32_t base, mask;
    unsigned l2qw;

    if (off_slot < 0 || cntl_slot < 0) {
        return;
    }
    base = s->regs.init_aux[off_slot] & ~0x03u;
    l2qw = s->regs.init_aux[cntl_slot] & 0x3f;
    if (!base || l2qw > 17) {
        return;
    }
    mask = (2u << l2qw) - 1;    /* ring size in dwords, power of two */
    rptr &= mask;
    wptr &= mask;

    while (rptr != wptr) {
        uint32_t hdr = ati_cce_ring_dword(s, base, mask, rptr++);
        uint32_t count = ((hdr >> 16) & 0x3fff) + 1;
        unsigned i;

        switch (hdr >> 30) {
        case 0: /* type 0: write count registers starting at bits 12:0 */
        {
            uint32_t reg = (hdr & 0x1fff) << 2;
            bool one_reg = hdr & 0x8000; /* all data to the same register */

            for (i = 0; i < count && rptr != wptr; i++) {
                uint32_t data = ati_cce_ring_dword(s, base, mask, rptr++);

                ati_mm_write(s, reg + (one_reg ? 0 : i * 4), data, 4);
            }
            break;
        }
        case 1: /* type 1: two scattered register writes */
        {
            uint32_t reg0 = (hdr & 0x7ff) << 2;
            uint32_t reg1 = ((hdr >> 11) & 0x7ff) << 2;

            if (rptr != wptr) {
                ati_mm_write(s, reg0, ati_cce_ring_dword(s, base, mask,
                                                         rptr++), 4);
            }
            if (rptr != wptr) {
                ati_mm_write(s, reg1, ati_cce_ring_dword(s, base, mask,
                                                         rptr++), 4);
            }
            break;
        }
        case 2: /* type 2: filler */
            break;
        case 3: /* type 3: engine command, skip by length */
        {
            static uint32_t warned[8];
            uint32_t op = (hdr >> 8) & 0xff;

            if (!(warned[op >> 5] & (1u << (op & 31)))) {
                warned[op >> 5] |= 1u << (op & 31);
                qemu_log_mask(LOG_UNIMP,
                              "ati: unhandled CCE type-3 packet 0x%02x\n",
                              op);
            }
            rptr = (rptr + count) & mask;
            break;
        }
        }
        rptr &= mask;
    }
}

static void ati_pll_write(ATIVGAState *s, uint32_t data)
{
    unsigned idx = s->regs.clock_cntl_index & 0x3f;

    if ((s->regs.clock_cntl_index & 0x80) &&
        idx < ARRAY_SIZE(s->regs.pll_regs)) {
        s->regs.pll_regs[idx] = data;
    }
}

static uint64_t ati_mm_read(void *opaque, hwaddr addr, unsigned int size)
{
    ATIVGAState *s = opaque;
    uint32_t val = 0;

    /* Register Aperture 1: the upper half of BAR2 mirrors the register file
     * (RRG 2.2.1; CONFIG_REG_APER_SIZE reports 8 KB, the BAR covers 16). */
    if (addr >= 0x2000 && addr < 0x4000) {
        addr -= 0x2000;
    }

    switch (addr) {
    case MM_INDEX:
        val = s->regs.mm_index;
        break;
    case CLOCK_CNTL_INDEX ... CLOCK_CNTL_INDEX + 3:
        val = ati_reg_read_offs(s->regs.clock_cntl_index,
                                addr - CLOCK_CNTL_INDEX, size);
        break;
    case CLOCK_CNTL_DATA ... CLOCK_CNTL_DATA + 3:
        val = ati_reg_read_offs(ati_pll_read(s), addr - CLOCK_CNTL_DATA,
                                size);
        break;
    case 0x710 ... 0x713: /* PM4_BUFFER_DL_RPTR */
        val = ati_reg_read_offs(s->regs.pm4_dl_rptr, addr - 0x710, size);
        break;
    case 0x714 ... 0x717: /* PM4_BUFFER_DL_WPTR */
        val = ati_reg_read_offs(s->regs.pm4_dl_wptr, addr - 0x714, size);
        break;
    case 0x05c ... 0x05f: /* CRTC_STATUS */
        val = ati_reg_read_offs(ati_crtc_status(s), addr - 0x05c, size);
        break;
    case 0x210 ... 0x213: /* CRTC_VLINE_CRNT_VLINE */
        val = ati_reg_read_offs(ati_crtc_current_line() << 16,
                                addr - 0x210, size);
        break;
    case 0x214 ... 0x217: /* CRTC_CRNT_FRAME */
        val = ati_reg_read_offs(ati_crtc_frame_count() & 0x1fffff,
                                addr - 0x214, size);
        break;
    case MM_DATA ... MM_DATA + 3:
        /* indexed access to regs or memory */
        if (s->regs.mm_index & BIT(31)) {
            uint32_t idx = s->regs.mm_index & ~BIT(31);
            if (idx <= s->vga.vram_size - size) {
                val = ldn_le_p(s->vga.vram_ptr + idx, size);
            }
        } else if (s->regs.mm_index > MM_DATA + 3) {
            val = ati_mm_read(s, s->regs.mm_index + addr - MM_DATA, size);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                "ati_mm_read: mm_index too small: %u\n", s->regs.mm_index);
        }
        break;
    case BIOS_0_SCRATCH ... BUS_CNTL - 1:
    {
        int i = (addr - BIOS_0_SCRATCH) / 4;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF && i > 3) {
            break;
        }
        val = ati_reg_read_offs(s->regs.bios_scratch[i],
                                addr - (BIOS_0_SCRATCH + i * 4), size);
        break;
    }
    case GEN_INT_CNTL:
        val = s->regs.gen_int_cntl;
        break;
    case GEN_INT_STATUS:
        val = s->regs.gen_int_status;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            /*
             * GUI_IDLE_INT_STAT (bit 19) is a level-ish engine-idle status:
             * it powers up set - the only GEN_INT_STATUS bit that does - and
             * reasserts whenever the engine is idle (RAGE 128 PRO Register
             * Reference Guide).  Every operation in this model completes
             * synchronously, so the engine is always idle; a driver that
             * acknowledges the bit and waits for it to come back (the XP
             * display driver's engine-liveness test) must see it set again.
             */
            val |= BIT(19);
        }
        break;
    case CRTC_GEN_CNTL ... CRTC_GEN_CNTL + 3:
        val = ati_reg_read_offs(s->regs.crtc_gen_cntl,
                                addr - CRTC_GEN_CNTL, size);
        break;
    case CRTC_EXT_CNTL ... CRTC_EXT_CNTL + 3:
        val = ati_reg_read_offs(s->regs.crtc_ext_cntl,
                                addr - CRTC_EXT_CNTL, size);
        break;
    case DAC_CNTL:
        val = s->regs.dac_cntl;
        break;
    case GPIO_VGA_DDC ... GPIO_VGA_DDC + 3:
        val = ati_reg_read_offs(s->regs.gpio_vga_ddc,
                                addr - GPIO_VGA_DDC, size);
        break;
    case GPIO_DVI_DDC ... GPIO_DVI_DDC + 3:
        val = ati_reg_read_offs(s->regs.gpio_dvi_ddc,
                                addr - GPIO_DVI_DDC, size);
        break;
    case GPIO_MONID ... GPIO_MONID + 3:
        val = ati_reg_read_offs(s->regs.gpio_monid,
                                addr - GPIO_MONID, size);
        break;
    case PALETTE_INDEX:
        /* FIXME unaligned access */
        val = vga_ioport_read(&s->vga, VGA_PEL_IR) << 16;
        val |= vga_ioport_read(&s->vga, VGA_PEL_IW) & 0xff;
        break;
    case PALETTE_DATA:
        val = vga_ioport_read(&s->vga, VGA_PEL_D);
        break;
    case PALETTE_30_DATA:
        val = s->regs.palette[vga_ioport_read(&s->vga, VGA_PEL_IR)];
        break;
    case CNFG_CNTL:
        val = s->regs.config_cntl;
        break;
    case CNFG_MEMSIZE:
        val = s->vga.vram_size;
        break;
    case CONFIG_APER_0_BASE:
    case CONFIG_APER_1_BASE:
        val = pci_default_read_config(&s->dev,
                                      PCI_BASE_ADDRESS_0, size) & 0xfffffff0;
        break;
    case CONFIG_APER_SIZE:
        val = memory_region_size(&s->linear_aper) / 2;
        break;
    case CONFIG_REG_1_BASE:
        val = pci_default_read_config(&s->dev,
                                      PCI_BASE_ADDRESS_2, size) & 0xfffffff0;
        break;
    case CONFIG_REG_APER_SIZE:
        val = memory_region_size(&s->mm) / 2;
        break;
    case HOST_PATH_CNTL:
        val = BIT(23); /* Radeon HDP_APER_CNTL */
        break;
    case MC_STATUS:
        val = 5;
        break;
    case MEM_SDRAM_MODE_REG:
        if (s->dev_id != PCI_DEVICE_ID_ATI_RAGE128_PF) {
            val = BIT(28) | BIT(20);
        }
        break;
    case RBBM_STATUS:
    case GUI_STAT:
        val = 64; /* free CMDFIFO entries */
        break;
    case PM4_STAT:
        /*
         * Every GUI operation in this model completes synchronously, so
         * the CCE never has queued work: report the PM4 command FIFO as
         * fully free (PM4_FIFOCNT, bits 11:0) with PM4_BUSY (bit 16) and
         * PM4_GUI_ACTIVE (bit 31) clear.  Linux's r128 DRM requires
         * FIFOCNT >= its configured FIFO size (up to 192 depending on the
         * CCE mode) with both busy bits clear before r128_do_cce_idle()
         * succeeds; a constant 0 here made every such ioctl spin for its
         * full 10 ms usec_timeout and XFree86 4.x with the DRI module
         * loaded crawled at minutes per screen repaint.
         */
        val = 0xfff;
        break;
    case CRTC_H_TOTAL_DISP:
        val = s->regs.crtc_h_total_disp;
        break;
    case CRTC_H_SYNC_STRT_WID:
        val = s->regs.crtc_h_sync_strt_wid;
        break;
    case CRTC_V_TOTAL_DISP:
        val = s->regs.crtc_v_total_disp;
        break;
    case CRTC_V_SYNC_STRT_WID:
        val = s->regs.crtc_v_sync_strt_wid;
        break;
    case CRTC_OFFSET:
        val = s->regs.crtc_offset;
        break;
    case CRTC_OFFSET_CNTL:
        val = s->regs.crtc_offset_cntl;
        break;
    case CRTC_PITCH:
        val = s->regs.crtc_pitch;
        break;
    case 0xf00 ... 0xfff:
        val = pci_default_read_config(&s->dev, addr - 0xf00, size);
        break;
    case CUR_OFFSET ... CUR_OFFSET + 3:
        val = ati_reg_read_offs(s->regs.cur_offset, addr - CUR_OFFSET, size);
        break;
    case CUR_HORZ_VERT_POSN ... CUR_HORZ_VERT_POSN + 3:
        val = ati_reg_read_offs(s->regs.cur_hv_pos,
                                addr - CUR_HORZ_VERT_POSN, size);
        if (addr + size > CUR_HORZ_VERT_POSN + 3) {
            val |= (s->regs.cur_offset & BIT(31)) >> (4 - size);
        }
        break;
    case CUR_HORZ_VERT_OFF ... CUR_HORZ_VERT_OFF + 3:
        val = ati_reg_read_offs(s->regs.cur_hv_offs,
                                addr - CUR_HORZ_VERT_OFF, size);
        if (addr + size > CUR_HORZ_VERT_OFF + 3) {
            val |= (s->regs.cur_offset & BIT(31)) >> (4 - size);
        }
        break;
    case CUR_CLR0 ... CUR_CLR0 + 3:
        val = ati_reg_read_offs(s->regs.cur_color0, addr - CUR_CLR0, size);
        break;
    case CUR_CLR1 ... CUR_CLR1 + 3:
        val = ati_reg_read_offs(s->regs.cur_color1, addr - CUR_CLR1, size);
        break;
    case DST_OFFSET:
        val = s->regs.dst_offset;
        break;
    case DST_PITCH:
        val = s->regs.dst_pitch;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            val |= s->regs.dst_tile << 16;
        }
        break;
    case DST_WIDTH:
        val = s->regs.dst_width;
        break;
    case DST_HEIGHT:
        val = s->regs.dst_height;
        break;
    case SRC_X:
        val = s->regs.src_x;
        break;
    case SRC_Y:
        val = s->regs.src_y;
        break;
    case DST_X:
        val = s->regs.dst_x;
        break;
    case DST_Y:
        val = s->regs.dst_y;
        break;
    case DP_GUI_MASTER_CNTL:
        /* DP_GUI_MASTER_CNTL aliases fields from DP_MIX and DP_DATATYPE */
        val = s->regs.dp_gui_master_cntl |
              ((s->regs.dp_datatype & DP_BRUSH_DATATYPE) >> 4) |
              ((s->regs.dp_datatype & DP_DST_DATATYPE) << 8) |
              ((s->regs.dp_datatype & DP_SRC_DATATYPE) >> 4) |
              (s->regs.dp_mix & DP_ROP3) |
              ((s->regs.dp_mix & DP_SRC_SOURCE) << 16);
        break;
    case SRC_OFFSET:
        val = s->regs.src_offset;
        break;
    case SRC_PITCH:
        val = s->regs.src_pitch;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            val |= s->regs.src_tile << 16;
        }
        break;
    case DP_BRUSH_BKGD_CLR:
        val = s->regs.dp_brush_bkgd_clr;
        break;
    case DP_BRUSH_FRGD_CLR:
        val = s->regs.dp_brush_frgd_clr;
        break;
    case DP_SRC_FRGD_CLR:
        val = s->regs.dp_src_frgd_clr;
        break;
    case DP_SRC_BKGD_CLR:
        val = s->regs.dp_src_bkgd_clr;
        break;
    case DP_CNTL:
        val = s->regs.dp_cntl;
        break;
    case DP_DATATYPE:
        val = s->regs.dp_datatype;
        break;
    case DP_MIX:
        val = s->regs.dp_mix;
        break;
    case DP_WRITE_MASK:
        val = s->regs.dp_write_mask;
        break;
    case DEFAULT_OFFSET:
        val = s->regs.default_offset;
        if (s->dev_id != PCI_DEVICE_ID_ATI_RAGE128_PF) {
            val >>= 10;
            val |= s->regs.default_pitch << 16;
            val |= s->regs.default_tile << 30;
        }
        break;
    case DEFAULT_PITCH:
        val = s->regs.default_pitch;
        val |= s->regs.default_tile << 16;
        break;
    case DEFAULT_SC_BOTTOM_RIGHT:
        val = s->regs.default_sc_right;
        val |= s->regs.default_sc_bottom << 16;
        break;
    case SC_TOP:
        val = s->regs.sc_top;
        break;
    case SC_LEFT:
        val = s->regs.sc_left;
        break;
    case SC_BOTTOM:
        val = s->regs.sc_bottom;
        break;
    case SC_RIGHT:
        val = s->regs.sc_right;
        break;
    case SRC_SC_BOTTOM:
        val = s->regs.src_sc_bottom;
        break;
    case SRC_SC_RIGHT:
        val = s->regs.src_sc_right;
        break;
    case SC_TOP_LEFT:
    case SC_BOTTOM_RIGHT:
    case SRC_SC_BOTTOM_RIGHT:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Read from write-only register 0x%x\n", (unsigned)addr);
        break;
    default:
    {
        int aux = ati_init_aux_slot(addr);

        if (aux >= 0) {
            val = ati_reg_read_offs(s->regs.init_aux[aux], addr & 3, size);
        }
        break;
    }
    }
    if (addr < CUR_OFFSET || addr > CUR_CLR1 || ATI_DEBUG_HW_CURSOR) {
        trace_ati_mm_read(size, addr, ati_reg_name(addr & ~3ULL), val);
    }
    return val;
}

static inline void ati_reg_write_offs(uint32_t *reg, int offs,
                                      uint64_t data, unsigned int size)
{
    if (offs == 0 && size == 4) {
        *reg = data;
    } else {
        *reg = deposit32(*reg, offs * BITS_PER_BYTE, size * BITS_PER_BYTE,
                         data);
    }
}

static void ati_mm_write(void *opaque, hwaddr addr,
                           uint64_t data, unsigned int size)
{
    ATIVGAState *s = opaque;

    if (addr >= 0x2000 && addr < 0x4000) {
        addr -= 0x2000; /* Register Aperture 1 mirror */
    }

    if (addr < CUR_OFFSET || addr > CUR_CLR1 || ATI_DEBUG_HW_CURSOR) {
        trace_ati_mm_write(size, addr, ati_reg_name(addr & ~3ULL), data);
    }
    switch (addr) {
    case CLOCK_CNTL_INDEX ... CLOCK_CNTL_INDEX + 3:
        ati_reg_write_offs(&s->regs.clock_cntl_index,
                           addr - CLOCK_CNTL_INDEX, data, size);
        break;
    case CLOCK_CNTL_DATA ... CLOCK_CNTL_DATA + 3:
    {
        uint32_t cur = ati_pll_read(s);

        ati_reg_write_offs(&cur, addr - CLOCK_CNTL_DATA, data, size);
        ati_pll_write(s, cur);
        break;
    }
    case 0x710 ... 0x713: /* PM4_BUFFER_DL_RPTR */
        ati_reg_write_offs(&s->regs.pm4_dl_rptr, addr - 0x710, data, size);
        break;
    case 0x05c: /* CRTC_STATUS: bit 1 is write-1-to-clear */
        if (data & 2) {
            s->regs.crtc_vblank_ack_frame = ati_crtc_frame_count();
        }
        break;
    case 0x714 ... 0x717: /* PM4_BUFFER_DL_WPTR */
        /*
         * CCE ring-buffer submission.  This model executes nothing from the
         * ring yet; consume it instantly so a driver polling the read
         * pointer (XP's ati2draa spins on PM4_BUFFER_DL_RPTR until it
         * catches up with its write pointer, and the kernel watchdog turns
         * a stall into bugcheck 0xEA) sees the engine keep up.  Mirror the
         * new read pointer through the ring read-pointer writeback address
         * if the driver configured one (PM4_BUFFER_DL_RPTR_ADDR).
         */
        ati_reg_write_offs(&s->regs.pm4_dl_wptr, addr - 0x714, data, size);
        ati_cce_execute(s, s->regs.pm4_dl_rptr,
                        s->regs.pm4_dl_wptr & ~R128_PM4_BUFFER_DL_DONE);
        s->regs.pm4_dl_rptr = s->regs.pm4_dl_wptr & ~R128_PM4_BUFFER_DL_DONE;
        {
            int slot = ati_init_aux_slot(0x070c);
            uint32_t wb = slot >= 0 ? s->regs.init_aux[slot] : 0;

            if (wb & ~3u) {
                uint32_t le = cpu_to_le32(s->regs.pm4_dl_rptr);

                pci_dma_write(&s->dev, wb & ~3u, &le, sizeof(le));
            }
        }
        break;
    case MM_INDEX:
        s->regs.mm_index = data & ~3;
        break;
    case MM_DATA ... MM_DATA + 3:
        /* indexed access to regs or memory */
        if (s->regs.mm_index & BIT(31)) {
            uint32_t idx = s->regs.mm_index & ~BIT(31);
            if (idx <= s->vga.vram_size - size) {
                stn_le_p(s->vga.vram_ptr + idx, size, data);
            }
        } else if (s->regs.mm_index > MM_DATA + 3) {
            ati_mm_write(s, s->regs.mm_index + addr - MM_DATA, data, size);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                "ati_mm_write: mm_index too small: %u\n", s->regs.mm_index);
        }
        break;
    case BIOS_0_SCRATCH ... BUS_CNTL - 1:
    {
        int i = (addr - BIOS_0_SCRATCH) / 4;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF && i > 3) {
            break;
        }
        ati_reg_write_offs(&s->regs.bios_scratch[i],
                           addr - (BIOS_0_SCRATCH + i * 4), data, size);
        break;
    }
    case GEN_INT_CNTL:
        s->regs.gen_int_cntl = data;
        if (data & CRTC_VBLANK_INT) {
            ati_vga_vblank_irq(s);
        } else {
            timer_del(&s->vblank_timer);
            ati_vga_update_irq(s);
        }
        break;
    case GEN_INT_STATUS:
        data &= (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF ?
                 0x000f040fUL : 0xfc080effUL);
        s->regs.gen_int_status &= ~data;
        ati_vga_update_irq(s);
        break;
    case CRTC_GEN_CNTL ... CRTC_GEN_CNTL + 3:
    {
        uint32_t val = s->regs.crtc_gen_cntl;
        ati_reg_write_offs(&s->regs.crtc_gen_cntl,
                           addr - CRTC_GEN_CNTL, data, size);
        if ((val & CRTC2_CUR_EN) != (s->regs.crtc_gen_cntl & CRTC2_CUR_EN)) {
            ati_vga_switch_mode(s);
            if (s->cursor_guest_mode) {
                s->vga.force_shadow = !!(s->regs.crtc_gen_cntl & CRTC2_CUR_EN);
            } else {
                if (s->regs.crtc_gen_cntl & CRTC2_CUR_EN) {
                    ati_cursor_define(s);
                }
                dpy_mouse_set(s->vga.con, s->regs.cur_hv_pos >> 16,
                              s->regs.cur_hv_pos & 0xffff,
                              (s->regs.crtc_gen_cntl & CRTC2_CUR_EN) != 0);
            }
        }
        if ((val & (CRTC2_EXT_DISP_EN | CRTC2_EN)) !=
            (s->regs.crtc_gen_cntl & (CRTC2_EXT_DISP_EN | CRTC2_EN))) {
            ati_vga_switch_mode(s);
        }
        break;
    }
    case CRTC_EXT_CNTL ... CRTC_EXT_CNTL + 3:
    {
        uint32_t val = s->regs.crtc_ext_cntl;
        ati_reg_write_offs(&s->regs.crtc_ext_cntl,
                           addr - CRTC_EXT_CNTL, data, size);
        if (s->regs.crtc_ext_cntl & CRT_CRTC_DISPLAY_DIS) {
            DPRINTF("Display disabled\n");
            s->vga.ar_index &= ~BIT(5);
        } else {
            DPRINTF("Display enabled\n");
            s->vga.ar_index |= BIT(5);
            ati_vga_switch_mode(s);
        }
        if ((val & CRT_CRTC_DISPLAY_DIS) !=
            (s->regs.crtc_ext_cntl & CRT_CRTC_DISPLAY_DIS)) {
            ati_vga_switch_mode(s);
        }
        break;
    }
    case DAC_CNTL:
        s->regs.dac_cntl = data & 0xffffe3ff;
        s->vga.dac_8bit = !!(data & DAC_8BIT_EN);
        break;
    /*
     * GPIO regs for DDC access. Because some drivers access these via
     * multiple byte writes we have to be careful when we send bits to
     * avoid spurious changes in bitbang_i2c state. Only do it when either
     * the enable bits are changed or output bits changed while enabled.
     */
    case GPIO_VGA_DDC ... GPIO_VGA_DDC + 3:
        if (s->dev_id != PCI_DEVICE_ID_ATI_RAGE128_PF) {
            /* FIXME: Maybe add a property to select VGA or DVI port? */
        }
        break;
    case GPIO_DVI_DDC ... GPIO_DVI_DDC + 3:
        if (s->dev_id != PCI_DEVICE_ID_ATI_RAGE128_PF) {
            ati_reg_write_offs(&s->regs.gpio_dvi_ddc,
                               addr - GPIO_DVI_DDC, data, size);
            if ((addr <= GPIO_DVI_DDC + 2 && addr + size > GPIO_DVI_DDC + 2) ||
                (addr == GPIO_DVI_DDC && (s->regs.gpio_dvi_ddc & 0x30000))) {
                s->regs.gpio_dvi_ddc = ati_i2c(&s->bbi2c,
                                               s->regs.gpio_dvi_ddc, 0);
            }
        }
        break;
    case GPIO_MONID ... GPIO_MONID + 3:
        /* FIXME What does Radeon have here? */
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            /* Rage128p accesses DDC via MONID(1-2) with additional mask bit */
            ati_reg_write_offs(&s->regs.gpio_monid,
                               addr - GPIO_MONID, data, size);
            if ((s->regs.gpio_monid & BIT(25)) &&
                ((addr <= GPIO_MONID + 2 && addr + size > GPIO_MONID + 2) ||
                 (addr == GPIO_MONID && (s->regs.gpio_monid & 0x60000)))) {
                s->regs.gpio_monid = ati_i2c(&s->bbi2c, s->regs.gpio_monid, 1);
            }
        }
        break;
    case PALETTE_INDEX ... PALETTE_INDEX + 3:
        if (size == 4) {
            vga_ioport_write(&s->vga, VGA_PEL_IR, (data >> 16) & 0xff);
            vga_ioport_write(&s->vga, VGA_PEL_IW, data & 0xff);
        } else {
            if (addr == PALETTE_INDEX) {
                vga_ioport_write(&s->vga, VGA_PEL_IW, data & 0xff);
            } else {
                vga_ioport_write(&s->vga, VGA_PEL_IR, data & 0xff);
            }
        }
        break;
    case PALETTE_DATA ... PALETTE_DATA + 3:
        data <<= addr - PALETTE_DATA;
        data = bswap32(data) >> 8;
        vga_ioport_write(&s->vga, VGA_PEL_D, data & 0xff);
        data >>= 8;
        vga_ioport_write(&s->vga, VGA_PEL_D, data & 0xff);
        data >>= 8;
        vga_ioport_write(&s->vga, VGA_PEL_D, data & 0xff);
        break;
    case PALETTE_30_DATA:
        s->regs.palette[vga_ioport_read(&s->vga, VGA_PEL_IW)] = data;
        vga_ioport_write(&s->vga, VGA_PEL_D, (data >> 22) & 0xff);
        vga_ioport_write(&s->vga, VGA_PEL_D, (data >> 12) & 0xff);
        vga_ioport_write(&s->vga, VGA_PEL_D, (data >> 2) & 0xff);
        break;
    case CNFG_CNTL:
        s->regs.config_cntl = data;
        break;
    case CRTC_H_TOTAL_DISP:
        s->regs.crtc_h_total_disp = data & 0x07ff07ff;
        break;
    case CRTC_H_SYNC_STRT_WID:
        s->regs.crtc_h_sync_strt_wid = data & 0x17bf1fff;
        break;
    case CRTC_V_TOTAL_DISP:
        s->regs.crtc_v_total_disp = data & 0x0fff0fff;
        break;
    case CRTC_V_SYNC_STRT_WID:
        s->regs.crtc_v_sync_strt_wid = data & 0x9f0fff;
        break;
    case CRTC_OFFSET:
        s->regs.crtc_offset = data & 0x87fffff8;
        ati_vga_set_offset(&s->vga, s->regs.crtc_offset & 0x07ffffff);
        break;
    case CRTC_OFFSET_CNTL:
        s->regs.crtc_offset_cntl = data; /* FIXME */
        break;
    case CRTC_PITCH:
        data &= 0x07ff07ff;
        if (s->regs.crtc_pitch != data) {
            s->regs.crtc_pitch = data;
            ati_vga_switch_mode(s);
        }
        break;
    case 0xf00 ... 0xfff:
        /* read-only copy of PCI config space so ignore writes */
        break;
    case CUR_OFFSET ... CUR_OFFSET + 3:
    {
        uint32_t t = s->regs.cur_offset;

        ati_reg_write_offs(&t, addr - CUR_OFFSET, data, size);
        t &= 0x87fffff0;
        if (s->regs.cur_offset != t) {
            s->regs.cur_offset = t;
            ati_cursor_define(s);
        }
        break;
    }
    case CUR_HORZ_VERT_POSN ... CUR_HORZ_VERT_POSN + 3:
    {
        uint32_t t = s->regs.cur_hv_pos | (s->regs.cur_offset & BIT(31));

        ati_reg_write_offs(&t, addr - CUR_HORZ_VERT_POSN, data, size);
        s->regs.cur_hv_pos = t & 0x3fff0fff;
        if (t & BIT(31)) {
            s->regs.cur_offset |= t & BIT(31);
        } else if (s->regs.cur_offset & BIT(31)) {
            s->regs.cur_offset &= ~BIT(31);
            ati_cursor_define(s);
        }
        /*
         * Push the new position to the display even when CUR_LOCK (BIT 31) is
         * set. The lock only exists to make a CUR_HORZ_VERT_OFF / _POSN /
         * _OFFSET update atomic on real hardware; there is no tearing to guard
         * against in this model. XFree86's r128 driver sets CUR_LOCK on *every*
         * R128SetCursorPosition write (r128_cursor.c), so gating on !lock left
         * the overlay cursor frozen at its last enable-time position while the
         * pointer moved -- it looked like the hardware cursor was not rendering
         * at all. Only the shape reload (ati_cursor_define) needs to respect
         * the lock, which it still does above.
         */
        if (!s->cursor_guest_mode &&
            (s->regs.crtc_gen_cntl & CRTC2_CUR_EN)) {
            dpy_mouse_set(s->vga.con, s->regs.cur_hv_pos >> 16,
                          s->regs.cur_hv_pos & 0xffff, true);
        }
        break;
    }
    case CUR_HORZ_VERT_OFF:
    {
        uint32_t t = s->regs.cur_hv_offs | (s->regs.cur_offset & BIT(31));

        ati_reg_write_offs(&t, addr - CUR_HORZ_VERT_OFF, data, size);
        s->regs.cur_hv_offs = t & 0x3f003f;
        if (t & BIT(31)) {
            s->regs.cur_offset |= t & BIT(31);
        } else if (s->regs.cur_offset & BIT(31)) {
            s->regs.cur_offset &= ~BIT(31);
            ati_cursor_define(s);
        }
        break;
    }
    case CUR_CLR0 ... CUR_CLR0 + 3:
    {
        uint32_t t = s->regs.cur_color0;

        ati_reg_write_offs(&t, addr - CUR_CLR0, data, size);
        t &= 0xffffff;
        if (s->regs.cur_color0 != t) {
            s->regs.cur_color0 = t;
            ati_cursor_define(s);
        }
        break;
    }
    case CUR_CLR1 ... CUR_CLR1 + 3:
        /*
         * Update cursor unconditionally here because some clients set up
         * other registers before actually writing cursor data to memory at
         * offset so we would miss cursor change unless always updating here
         */
        ati_reg_write_offs(&s->regs.cur_color1, addr - CUR_CLR1, data, size);
        s->regs.cur_color1 &= 0xffffff;
        ati_cursor_define(s);
        break;
    case DST_OFFSET:
            s->regs.dst_offset = data & 0xfffffff0;
        break;
    case DST_PITCH:
            s->regs.dst_pitch = data & 0x3fff;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.dst_tile = (data >> 16) & 1;
        }
        break;
    case DST_TILE:
        if (s->dev_id == PCI_DEVICE_ID_ATI_RADEON_QY) {
            s->regs.dst_tile = data & 3;
        }
        break;
    case DST_WIDTH:
        s->regs.dst_width = data & 0x3fff;
        ati_2d_blt(s);
        break;
    case DST_HEIGHT:
        s->regs.dst_height = data & 0x3fff;
        break;
    case SRC_X:
        s->regs.src_x = data & 0x3fff;
        break;
    case SRC_Y:
        s->regs.src_y = data & 0x3fff;
        break;
    case DST_X:
        s->regs.dst_x = data & 0x3fff;
        break;
    case DST_Y:
        s->regs.dst_y = data & 0x3fff;
        break;
    case SRC_PITCH_OFFSET:
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.src_offset = (data & 0x1fffff) << 5;
            s->regs.src_pitch = (data & 0x7fe00000) >> 21;
            s->regs.src_tile = data >> 31;
        } else {
            s->regs.src_offset = (data & 0x3fffff) << 10;
            s->regs.src_pitch = (data & 0x3fc00000) >> 16;
            s->regs.src_tile = (data >> 30) & 1;
        }
        break;
    case DST_PITCH_OFFSET:
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.dst_offset = (data & 0x1fffff) << 5;
            s->regs.dst_pitch = (data & 0x7fe00000) >> 21;
            s->regs.dst_tile = data >> 31;
        } else {
            s->regs.dst_offset = (data & 0x3fffff) << 10;
            s->regs.dst_pitch = (data & 0x3fc00000) >> 16;
            s->regs.dst_tile = data >> 30;
        }
        break;
    case SRC_Y_X:
        s->regs.src_x = data & 0x3fff;
        s->regs.src_y = (data >> 16) & 0x3fff;
        break;
    case DST_Y_X:
        s->regs.dst_x = data & 0x3fff;
        s->regs.dst_y = (data >> 16) & 0x3fff;
        break;
    case DST_HEIGHT_WIDTH:
        s->regs.dst_width = data & 0x3fff;
        s->regs.dst_height = (data >> 16) & 0x3fff;
        ati_2d_blt(s);
        break;
    case DP_GUI_MASTER_CNTL:
        s->regs.dp_gui_master_cntl = data & 0xf800000f;
        s->regs.dp_datatype = (data & 0x0f00) >> 8 | (data & 0x30f0) << 4 |
                              (data & 0x4000) << 16;
        s->regs.dp_mix = (data & GMC_ROP3_MASK) | (data & 0x7000000) >> 16;

        if (!(data & GMC_SRC_PITCH_OFFSET_CNTL)) {
            s->regs.src_offset = s->regs.default_offset;
            s->regs.src_pitch = s->regs.default_pitch;
        }
        if (!(data & GMC_DST_PITCH_OFFSET_CNTL)) {
            s->regs.dst_offset = s->regs.default_offset;
            s->regs.dst_pitch = s->regs.default_pitch;
        }
        if (!(data & GMC_SRC_CLIPPING)) {
            s->regs.src_sc_right = s->regs.default_sc_right;
            s->regs.src_sc_bottom = s->regs.default_sc_bottom;
        }
        if (!(data & GMC_DST_CLIPPING)) {
            s->regs.sc_top = 0;
            s->regs.sc_left = 0;
            s->regs.sc_right = s->regs.default_sc_right;
            s->regs.sc_bottom = s->regs.default_sc_bottom;
        }
        break;
    case DST_WIDTH_X:
        s->regs.dst_x = data & 0x3fff;
        s->regs.dst_width = (data >> 16) & 0x3fff;
        ati_2d_blt(s);
        break;
    case SRC_X_Y:
        s->regs.src_y = data & 0x3fff;
        s->regs.src_x = (data >> 16) & 0x3fff;
        break;
    case DST_X_Y:
        s->regs.dst_y = data & 0x3fff;
        s->regs.dst_x = (data >> 16) & 0x3fff;
        break;
    case DST_WIDTH_HEIGHT:
        s->regs.dst_height = data & 0x3fff;
        s->regs.dst_width = (data >> 16) & 0x3fff;
        ati_2d_blt(s);
        break;
    case DST_HEIGHT_Y:
        s->regs.dst_y = data & 0x3fff;
        s->regs.dst_height = (data >> 16) & 0x3fff;
        break;
    case SRC_OFFSET:
            s->regs.src_offset = data & 0xfffffff0;
        break;
    case SRC_PITCH:
            s->regs.src_pitch = data & 0x3fff;
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.src_tile = (data >> 16) & 1;
        }
        break;
    case DP_BRUSH_BKGD_CLR:
        s->regs.dp_brush_bkgd_clr = data;
        break;
    case DP_BRUSH_FRGD_CLR:
        s->regs.dp_brush_frgd_clr = data;
        break;
    case DP_CNTL:
        s->regs.dp_cntl = data;
        break;
    case DP_SRC_FRGD_CLR:
        s->regs.dp_src_frgd_clr = data;
        break;
    case DP_SRC_BKGD_CLR:
        s->regs.dp_src_bkgd_clr = data;
        break;
    case DP_DATATYPE:
        s->regs.dp_datatype = data & 0xe0070f0f;
        break;
    case DP_MIX:
        s->regs.dp_mix = data & 0x00ff0700;
        break;
    case DP_WRITE_MASK:
        s->regs.dp_write_mask = data;
        break;
    case DEFAULT_OFFSET:
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.default_offset = data & 0xfffffff0;
        } else {
            /* Radeon has DEFAULT_PITCH_OFFSET here like DST_PITCH_OFFSET */
            s->regs.default_offset = (data & 0x3fffff) << 10;
            s->regs.default_pitch = (data & 0x3fc00000) >> 16;
            s->regs.default_tile = data >> 30;
        }
        break;
    case DEFAULT_PITCH:
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->regs.default_pitch = data & 0x3fff;
            s->regs.default_tile = (data >> 16) & 1;
        }
        break;
    case DEFAULT_SC_BOTTOM_RIGHT:
        s->regs.default_sc_right = data & 0x3fff;
        s->regs.default_sc_bottom = (data >> 16) & 0x3fff;
        break;
    case SC_TOP_LEFT:
        s->regs.sc_left = data & 0x3fff;
        s->regs.sc_top = (data >> 16) & 0x3fff;
        break;
    case SC_LEFT:
        s->regs.sc_left = data & 0x3fff;
        break;
    case SC_TOP:
        s->regs.sc_top = data & 0x3fff;
        break;
    case SC_BOTTOM_RIGHT:
        s->regs.sc_right = data & 0x3fff;
        s->regs.sc_bottom = (data >> 16) & 0x3fff;
        break;
    case SC_RIGHT:
        s->regs.sc_right = data & 0x3fff;
        break;
    case SC_BOTTOM:
        s->regs.sc_bottom = data & 0x3fff;
        break;
    case SRC_SC_BOTTOM_RIGHT:
        s->regs.src_sc_right = data & 0x3fff;
        s->regs.src_sc_bottom = (data >> 16) & 0x3fff;
        break;
    case SRC_SC_RIGHT:
        s->regs.src_sc_right = data & 0x3fff;
        break;
    case SRC_SC_BOTTOM:
        s->regs.src_sc_bottom = data & 0x3fff;
        break;
    case HOST_DATA0:
    case HOST_DATA1:
    case HOST_DATA2:
    case HOST_DATA3:
    case HOST_DATA4:
    case HOST_DATA5:
    case HOST_DATA6:
    case HOST_DATA7:
    case HOST_DATA_LAST:
        if (!s->host_data.active) {
            break;
        }
        s->host_data.acc[s->host_data.next++] = data;
        if (addr == HOST_DATA_LAST) {
            ati_host_data_finish(s);
            s->host_data.next = 0;
        } else if (s->host_data.next >= 4) {
            ati_host_data_flush(s);
            s->host_data.next = 0;
        }
        break;
    default:
    {
        int aux = ati_init_aux_slot(addr);

        if (aux >= 0) {
            ati_reg_write_offs(&s->regs.init_aux[aux], addr & 3, data, size);
        }
        break;
    }
    }
}

static const MemoryRegionOps ati_mm_ops = {
    .read = ati_mm_read,
    .write = ati_mm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static bool ati_init_regs_needed(void *opaque)
{
    ATIVGARegs *r = opaque;
    unsigned i;

    if (r->clock_cntl_index) {
        return true;
    }
    for (i = 0; i < ARRAY_SIZE(r->pll_regs); i++) {
        if (r->pll_regs[i]) {
            return true;
        }
    }
    for (i = 0; i < ARRAY_SIZE(r->init_aux); i++) {
        if (r->init_aux[i]) {
            return true;
        }
    }
    return r->pm4_dl_rptr || r->pm4_dl_wptr;
}

static const VMStateDescription vmstate_ati_vga_init_regs = {
    .name = "ati-vga/regs/init",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ati_init_regs_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(clock_cntl_index, ATIVGARegs),
        VMSTATE_UINT32_ARRAY(pll_regs, ATIVGARegs, 32),
        VMSTATE_UINT32_ARRAY(init_aux, ATIVGARegs, 40),
        VMSTATE_UINT32(pm4_dl_rptr, ATIVGARegs),
        VMSTATE_UINT32(pm4_dl_wptr, ATIVGARegs),
        VMSTATE_UINT32(crtc_vblank_ack_frame, ATIVGARegs),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_ati_vga_regs = {
    .name = "ati-vga/regs",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(mm_index, ATIVGARegs),
        VMSTATE_UINT32_ARRAY(bios_scratch, ATIVGARegs, 8),
        VMSTATE_UINT32(gen_int_cntl, ATIVGARegs),
        VMSTATE_UINT32(gen_int_status, ATIVGARegs),
        VMSTATE_UINT32(crtc_gen_cntl, ATIVGARegs),
        VMSTATE_UINT32(crtc_ext_cntl, ATIVGARegs),
        VMSTATE_UINT32(dac_cntl, ATIVGARegs),
        VMSTATE_UINT32(gpio_vga_ddc, ATIVGARegs),
        VMSTATE_UINT32(gpio_dvi_ddc, ATIVGARegs),
        VMSTATE_UINT32(gpio_monid, ATIVGARegs),
        VMSTATE_UINT32(config_cntl, ATIVGARegs),
        VMSTATE_UINT32_ARRAY(palette, ATIVGARegs, 256),
        VMSTATE_UINT32(crtc_h_total_disp, ATIVGARegs),
        VMSTATE_UINT32(crtc_h_sync_strt_wid, ATIVGARegs),
        VMSTATE_UINT32(crtc_v_total_disp, ATIVGARegs),
        VMSTATE_UINT32(crtc_v_sync_strt_wid, ATIVGARegs),
        VMSTATE_UINT32(crtc_offset, ATIVGARegs),
        VMSTATE_UINT32(crtc_offset_cntl, ATIVGARegs),
        VMSTATE_UINT32(crtc_pitch, ATIVGARegs),
        VMSTATE_UINT32(cur_offset, ATIVGARegs),
        VMSTATE_UINT32(cur_hv_pos, ATIVGARegs),
        VMSTATE_UINT32(cur_hv_offs, ATIVGARegs),
        VMSTATE_UINT32(cur_color0, ATIVGARegs),
        VMSTATE_UINT32(cur_color1, ATIVGARegs),
        VMSTATE_UINT32(dst_offset, ATIVGARegs),
        VMSTATE_UINT32(dst_pitch, ATIVGARegs),
        VMSTATE_UINT32(dst_tile, ATIVGARegs),
        VMSTATE_UINT32(dst_width, ATIVGARegs),
        VMSTATE_UINT32(dst_height, ATIVGARegs),
        VMSTATE_UINT32(src_offset, ATIVGARegs),
        VMSTATE_UINT32(src_pitch, ATIVGARegs),
        VMSTATE_UINT32(src_tile, ATIVGARegs),
        VMSTATE_UINT32(src_x, ATIVGARegs),
        VMSTATE_UINT32(src_y, ATIVGARegs),
        VMSTATE_UINT32(dst_x, ATIVGARegs),
        VMSTATE_UINT32(dst_y, ATIVGARegs),
        VMSTATE_UINT32(dp_gui_master_cntl, ATIVGARegs),
        VMSTATE_UINT32(dp_brush_bkgd_clr, ATIVGARegs),
        VMSTATE_UINT32(dp_brush_frgd_clr, ATIVGARegs),
        VMSTATE_UINT32(dp_src_frgd_clr, ATIVGARegs),
        VMSTATE_UINT32(dp_src_bkgd_clr, ATIVGARegs),
        VMSTATE_UINT16(sc_top, ATIVGARegs),
        VMSTATE_UINT16(sc_left, ATIVGARegs),
        VMSTATE_UINT16(sc_bottom, ATIVGARegs),
        VMSTATE_UINT16(sc_right, ATIVGARegs),
        VMSTATE_UINT16(src_sc_bottom, ATIVGARegs),
        VMSTATE_UINT16(src_sc_right, ATIVGARegs),
        VMSTATE_UINT32(dp_cntl, ATIVGARegs),
        VMSTATE_UINT32(dp_datatype, ATIVGARegs),
        VMSTATE_UINT32(dp_mix, ATIVGARegs),
        VMSTATE_UINT32(dp_write_mask, ATIVGARegs),
        VMSTATE_UINT32(default_offset, ATIVGARegs),
        VMSTATE_UINT32(default_pitch, ATIVGARegs),
        VMSTATE_UINT16(default_sc_bottom, ATIVGARegs),
        VMSTATE_UINT16(default_sc_right, ATIVGARegs),
        VMSTATE_UINT32(default_tile, ATIVGARegs),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_ati_vga_init_regs,
        NULL
    }
};

static const VMStateDescription vmstate_ati_host_data = {
    .name = "ati-vga/host-data",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(active, ATIHostDataState),
        VMSTATE_UINT32(row, ATIHostDataState),
        VMSTATE_UINT32(col, ATIHostDataState),
        VMSTATE_UINT32(next, ATIHostDataState),
        VMSTATE_UINT32_ARRAY(acc, ATIHostDataState, 4),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_ati_bitbang_i2c = {
    .name = "ati-vga/bitbang-i2c",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_SINGLE(state, bitbang_i2c_interface, 0,
                       vmstate_info_int32, bitbang_i2c_state),
        VMSTATE_INT32(last_data, bitbang_i2c_interface),
        VMSTATE_INT32(last_clock, bitbang_i2c_interface),
        VMSTATE_INT32(device_out, bitbang_i2c_interface),
        VMSTATE_UINT8(buffer, bitbang_i2c_interface),
        VMSTATE_INT32(current_addr, bitbang_i2c_interface),
        VMSTATE_END_OF_LIST()
    },
};

static int ati_vga_post_load(void *opaque, int version_id)
{
    ATIVGAState *s = opaque;
    bool cursor_enabled = s->regs.crtc_gen_cntl & CRTC2_CUR_EN;

    if (s->host_data.next >= ARRAY_SIZE(s->host_data.acc) ||
        s->bbi2c.state < STOPPED || s->bbi2c.state > SENT_NACK) {
        return -EINVAL;
    }

    s->mode = s->regs.crtc_gen_cntl & CRTC2_EXT_DISP_EN ?
              EXT_MODE : VGA_MODE;
    s->vga.graphic_mode = -1;
    if (s->cursor_guest_mode) {
        s->vga.force_shadow = cursor_enabled;
        s->cursor_size = UINT16_MAX;
    } else {
        s->vga.force_shadow = false;
        if (cursor_enabled) {
            ati_cursor_define(s);
        }
        dpy_mouse_set(s->vga.con, s->regs.cur_hv_pos >> 16,
                      s->regs.cur_hv_pos & 0xffff, cursor_enabled);
    }
    ati_vga_update_irq(s);
    graphic_hw_invalidate(s->vga.con);
    return 0;
}

static const VMStateDescription vmstate_ati_vga = {
    .name = "ati-vga",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = ati_vga_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, ATIVGAState),
        VMSTATE_STRUCT(vga, ATIVGAState, 0,
                       vmstate_vga_common, VGACommonState),
        VMSTATE_STRUCT(regs, ATIVGAState, 0,
                       vmstate_ati_vga_regs, ATIVGARegs),
        VMSTATE_STRUCT(host_data, ATIVGAState, 0,
                       vmstate_ati_host_data, ATIHostDataState),
        VMSTATE_STRUCT(bbi2c, ATIVGAState, 0,
                       vmstate_ati_bitbang_i2c, bitbang_i2c_interface),
        VMSTATE_TIMER(vblank_timer, ATIVGAState),
        VMSTATE_END_OF_LIST()
    },
};

static void ati_vga_realize(PCIDevice *dev, Error **errp)
{
    ATIVGAState *s = ATI_VGA(dev);
    VGACommonState *vga = &s->vga;
    I2CBus *i2cbus;

#ifndef CONFIG_PIXMAN
    if (s->use_pixman != 0) {
        warn_report("x-pixman != 0, not effective without PIXMAN");
    }
#endif

    if (s->model) {
        int i;
        for (i = 0; i < ARRAY_SIZE(ati_model_aliases); i++) {
            if (!strcmp(s->model, ati_model_aliases[i].name)) {
                s->dev_id = ati_model_aliases[i].dev_id;
                break;
            }
        }
        if (i >= ARRAY_SIZE(ati_model_aliases)) {
            warn_report("Unknown ATI VGA model name, "
                        "using default rage128p");
        }
    }
    if (s->dev_id != PCI_DEVICE_ID_ATI_RAGE128_PF &&
        s->dev_id != PCI_DEVICE_ID_ATI_RADEON_QY) {
        error_setg(errp, "Unknown ATI VGA device id, "
                   "only 0x5046 and 0x5159 are supported");
        return;
    }
    pci_set_word(dev->config + PCI_DEVICE_ID, s->dev_id);

    if (s->dev_id == PCI_DEVICE_ID_ATI_RADEON_QY &&
        s->vga.vram_size_mb < 16) {
        warn_report("Too small video memory for device id");
        s->vga.vram_size_mb = 16;
    }

    /* init vga bits */
    if (!vga_common_init(vga, OBJECT(s), errp)) {
        return;
    }
    vga->vbe_legacy_mode_switch = true;
    vga_init(vga, OBJECT(s), pci_address_space(dev),
             pci_address_space_io(dev), true);
    vga->con = graphic_console_init(DEVICE(s), 0, s->vga.hw_ops, vga);
    if (s->cursor_guest_mode) {
        vga->cursor_invalidate = ati_cursor_invalidate;
        vga->cursor_draw_line = ati_cursor_draw_line;
    }

    /* ddc, edid */
    i2cbus = i2c_init_bus(DEVICE(s), "ati-vga.ddc");
    bitbang_i2c_init(&s->bbi2c, i2cbus);
    i2c_slave_set_address(I2C_SLAVE(&s->i2cddc), 0x50);
    qdev_realize(DEVICE(&s->i2cddc), BUS(i2cbus), &error_abort);

    /* mmio register space */
    memory_region_init_io(&s->mm, OBJECT(s), &ati_mm_ops, s,
                          "ati.mmregs", 0x4000);
    /* io space is alias to beginning of mmregs */
    memory_region_init_alias(&s->io, OBJECT(s), "ati.io", &s->mm, 0, 0x100);

    /*
     * The framebuffer is at the beginning of the linear aperture. For
     * Rage128 the upper half of the aperture is reserved for an AGP
     * window (which we do not emulate.)
     */
    if (!s->linear_aper_sz) {
        if (s->dev_id == PCI_DEVICE_ID_ATI_RAGE128_PF) {
            s->linear_aper_sz = ATI_RAGE128_LINEAR_APER_SIZE;
        } else {
            s->linear_aper_sz = ATI_R100_LINEAR_APER_SIZE;
        }
    }
    if (s->linear_aper_sz > 256 * MiB) {
        error_setg(errp, "x-linear-aper-size is too large (maximum 256 MiB)");
        return;
    }
    if (s->linear_aper_sz < 16 * MiB) {
        error_setg(errp, "x-linear-aper-size is too small (minimum 16 MiB)");
        return;
    }
    memory_region_init(&s->linear_aper, OBJECT(dev), "ati-linear-aperture0",
                       s->linear_aper_sz);
    memory_region_add_subregion(&s->linear_aper, 0, &vga->vram);

    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->linear_aper);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &s->io);
    pci_register_bar(dev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mm);

    /* most interrupts are not yet emulated but MacOS needs at least VBlank */
    dev->config[PCI_INTERRUPT_PIN] = 1;
    timer_init_ns(&s->vblank_timer, QEMU_CLOCK_VIRTUAL, ati_vga_vblank_irq, s);
}

static void ati_vga_reset(DeviceState *dev)
{
    ATIVGAState *s = ATI_VGA(dev);

    timer_del(&s->vblank_timer);
    ati_vga_update_irq(s);

    /*
     * PLL and init-register power-up values from the RAGE 128 PRO Register
     * Reference Guide.  PLL indices follow the chip's PLL address space:
     * 0x01 CLK_PIN_CNTL, 0x02 PPLL_CNTL, 0x0b XPLL_CNTL, 0x0c XDLL_CNTL,
     * 0x0e MPLL_CNTL, 0x10 AGP_PLL_CNTL.
     */
    s->regs.clock_cntl_index = 0;
    memset(s->regs.pll_regs, 0, sizeof(s->regs.pll_regs));
    s->regs.pll_regs[0x01] = 0x000000f7;
    s->regs.pll_regs[0x02] = 0x0000cc03;
    s->regs.pll_regs[0x0b] = 0x0000cc03;
    s->regs.pll_regs[0x0c] = 0x000b000b;
    s->regs.pll_regs[0x0e] = 0x0000cc03;
    s->regs.pll_regs[0x10] = 0x7a770000;
    memset(s->regs.init_aux, 0, sizeof(s->regs.init_aux));
    s->regs.init_aux[ati_init_aux_slot(0x0030)] = 0x880f0f41; /* BUS_CNTL */
    s->regs.init_aux[ati_init_aux_slot(0x0034)] = 0x0000001f; /* BUS_CNTL1 */

    /* reset vga */
    vga_common_reset(&s->vga);
    s->mode = VGA_MODE;

    s->host_data.active = false;
    s->host_data.next = 0;
    s->host_data.row = 0;
    s->host_data.col = 0;
}

static void ati_vga_exit(PCIDevice *dev)
{
    ATIVGAState *s = ATI_VGA(dev);

    timer_del(&s->vblank_timer);
    graphic_console_close(s->vga.con);
}

static const Property ati_vga_properties[] = {
    DEFINE_PROP_UINT32("vgamem_mb", ATIVGAState, vga.vram_size_mb, 16),
    DEFINE_PROP_STRING("model", ATIVGAState, model),
    DEFINE_PROP_UINT16("x-device-id", ATIVGAState, dev_id,
                       PCI_DEVICE_ID_ATI_RAGE128_PF),
    DEFINE_PROP_BOOL("guest_hwcursor", ATIVGAState, cursor_guest_mode, false),
    /* this is a debug option, prefer PROP_UINT over PROP_BIT for simplicity */
    DEFINE_PROP_UINT8("x-pixman", ATIVGAState, use_pixman, DEFAULT_X_PIXMAN),
    DEFINE_PROP_UINT64("x-linear-aper-size", ATIVGAState, linear_aper_sz, 0),
    DEFINE_EDID_PROPERTIES(ATIVGAState, i2cddc.edid_info),
};

static void ati_vga_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);


    device_class_set_legacy_reset(dc, ati_vga_reset);
    device_class_set_props(dc, ati_vga_properties);
    dc->vmsd = &vmstate_ati_vga;
    dc->hotpluggable = false;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);

    k->class_id = PCI_CLASS_DISPLAY_VGA;
    k->vendor_id = PCI_VENDOR_ID_ATI;
    k->device_id = PCI_DEVICE_ID_ATI_RAGE128_PF;
    k->romfile = "vgabios-ati.bin";
    k->realize = ati_vga_realize;
    k->exit = ati_vga_exit;
}

static void ati_vga_init(Object *o)
{
    ATIVGAState *s = ATI_VGA(o);

    object_initialize_child(o, "edid", &s->i2cddc, TYPE_I2CDDC);
    object_property_set_description(o, "x-pixman", "Use pixman for: "
                                    "1: fill, 2: blit");
}

static const TypeInfo ati_vga_info = {
    .name = TYPE_ATI_VGA,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ATIVGAState),
    .class_init = ati_vga_class_init,
    .instance_init = ati_vga_init,
    .interfaces = (const InterfaceInfo[]) {
          { INTERFACE_CONVENTIONAL_PCI_DEVICE },
          { },
    },
};

static void ati_vga_register_types(void)
{
    type_register_static(&ati_vga_info);
}

type_init(ati_vga_register_types)
