/*
 * QEMU ATI Mach64 "3D Rage" (DEV_4754) emulation - internal header
 *
 * A minimal-but-growing model of the classic Mach64 GUI (2D) engine: a
 * synchronous MMIO rectangle/line/host blitter over a linear framebuffer,
 * with a VGA-compatible core provided by VGACommonState.  There is no command
 * processor, ring, DMA or AGP on this chip, so none of the r128 CCE machinery
 * applies.  See plans/mach64-design.md.
 *
 * This work is licensed under the GNU GPL license version 2 or later.
 */

#ifndef MACH64_INT_H
#define MACH64_INT_H

#include "qemu/units.h"
#include "hw/pci/pci_device.h"
#include "vga_int.h"
#include "qom/object.h"
#include "ui/console.h"
#include "mach64_regs.h"

#define PCI_VENDOR_ID_ATI            0x1002
/* Mach64 GR = Rage XL (the default: the one id XP 2002 *and* XP 2003 auto-match) */
#define PCI_DEVICE_ID_ATI_MACH64_GR  0x4752
/* Mach64 GT = "3D Rage II"; XP 2002 only, and only with a matching REV */
#define PCI_DEVICE_ID_ATI_MACH64_GT  0x4754

/* Auto-selected revision sentinel for the x-revision property. */
#define MACH64_REV_AUTO              0x100
/* Plausible per-chip PCI revisions.  For Rage XL the inbox INFs carry no REV
 * qualifier so any value matches; for 3D Rage II XP 2002 requires one of
 * {01,19,1A,41,5A,9A} (display.inf), 9A = "3D RAGE II+ PCI". */
#define MACH64_REV_RAGE_XL           0x27
#define MACH64_REV_3DRAGE_II         0x9a

#define MACH64_LINEAR_APER_SIZE      (8 * MiB)

#define TYPE_MACH64_VGA "mach64-vga"
OBJECT_DECLARE_SIMPLE_TYPE(Mach64VGAState, MACH64_VGA)

/*
 * Host-data (CPU-to-screen) blit state.  A blit whose foreground source is
 * SRC_HOST (or whose mono source is HOST) is set up by the DST_HEIGHT_WIDTH
 * write, then consumes dwords the guest streams into HOST_DATA*.  We walk the
 * destination rectangle pixel by pixel as the data arrives.
 */
typedef struct Mach64HostData {
    bool active;
    bool mono;            /* 1bpp expansion vs. colour copy */
    unsigned x;           /* current dst column within the rectangle */
    unsigned y;           /* current dst row within the rectangle */
} Mach64HostData;

struct Mach64VGAState {
    PCIDevice dev;
    VGACommonState vga;

    uint16_t dev_id;
    uint16_t revision;            /* x-revision property; MACH64_REV_AUTO = pick */
    uint8_t chip_rev;             /* effective PCI revision, resolved in realize */
    uint8_t mode;                 /* VGA_MODE or EXT_MODE */
    uint8_t use_pixman;
    bool cursor_guest_mode;

    /* Hardware cursor host-overlay bookkeeping (see mach64.c). */
    uint16_t cursor_size;
    uint32_t cursor_offset;
    QEMUCursor *cursor;

    MemoryRegion linear_aper;
    MemoryRegion io;
    MemoryRegion mm;

    /* Block-0 register file, indexed by Mach64 block index (see mach64_regs.h). */
    uint32_t regs[MACH64_NREGS];

    Mach64HostData host_data;
};

/* mach64_2d.c */
void mach64_2d_dst_trigger(Mach64VGAState *s);
void mach64_2d_line_trigger(Mach64VGAState *s);
void mach64_2d_host_data(Mach64VGAState *s, uint32_t data);

/* mach64.c helpers shared with the engine. */
int mach64_dst_bpp(const Mach64VGAState *s);
uint32_t mach64_dst_base(const Mach64VGAState *s);
int mach64_dst_pitch_bytes(const Mach64VGAState *s);
void mach64_2d_set_dirty(Mach64VGAState *s, uint32_t base, int x, int y,
                         int w, int h);

#endif /* MACH64_INT_H */
