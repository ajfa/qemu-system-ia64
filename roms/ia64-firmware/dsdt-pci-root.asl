// SPDX-License-Identifier: GPL-2.0-or-later
//
// Source for the DSDT AML byte array in firmware.c (mDsdt).  Recompile with
//     iasl -on -oi dsdt-pci-root.asl
// (-on suppresses the \_SB -> _SB name optimisation so the encoding stays
// byte-identical to what is shipping) and splice the AML body back in; see
// plans/runbook.md.
//
// -oi, and the 0x00 constants inside _S5 and _PRT below, are load-bearing:
// together they keep every *package element* encoded as a typed literal
// (BytePrefix/WordPrefix/DWordPrefix) rather than the ZeroOp/OneOp constant
// opcodes iasl prefers.  The ACPI CA in Linux 2.4 (20011018, what Debian 3.0's
// 2.4.17-mckinley kernel carries) types a constant opcode as
// INTERNAL_TYPE_REFERENCE, not ACPI_TYPE_INTEGER
// (acpi_ds_map_opcode_to_data_type(), dispatcher/dsutils.c), and converts it
// only while *resolving a value*.  Code that walks package elements raw never
// resolves them and so rejects the whole object:
// acpi_rs_create_pci_routing_table() fails the _PRT with AE_BAD_DATA on the
// first entry whose Pin or Source is ZeroOp, and
// acpi_hw_obtain_sleep_type_register_data() fails _S5 the same way.  A failed
// _PRT leaves Linux with *no* PCI interrupt routes: no IOSAPIC RTE is
// programmed for any PCI device, so the SCSI HBA's interrupt is never
// delivered and every command dies on a timeout.  Scalar names (_SEG, _BBN,
// _UID, _CCA) are read through acpi_evaluate_object(), which does resolve
// constants, so they are unaffected and stay as Zero/One.
//
// The root bridge _HID must be PNP0A03 (conventional PCI), not PNP0A08: some
// guest OS installers validate every ancestor device of the install disk
// against a fixed hardware-compatibility list that predates PCI Express and
// only recognizes *PNP0A03 root bridges, and a string _CID is not matched in
// its wildcard form there.  The emulated root bus is conventional PCI, so
// PNP0A03 is also the accurate identifier.

DefinitionBlock ("", "DSDT", 2, "QEMU  ", "IA64DSDT", 0x00000001)
{
    Name (_S5, Package (0x04)
    {
        0x00,
        0x00,
        0x00,
        0x00
    })

    Scope (\_SB)
    {
        Device (PCI0)
        {
            // _HID must be the EisaId *integer*, not the string "PNP0A03".
            // Both are legal ACPI and modern guests take either, but AIX 5L
            // for IA-64 does not: its libacpi wrapper acpi_dvc_get_hid()
            // returns error 44 for a string-encoded _HID, and cfgsys_ia64's
            // define_acpi_children() then abandons the device.  Since PCI0 is
            // the only child of \_SB_, the walk ends with no PNP0A03 found, no
            // bus/ia64/pci is created, cfgpci never runs and cfgmgr configures
            // nothing below sysplanar0.
            //
            // Measured by trapping on the call sites inside cfgsys_ia64
            // (AIX_WATCH, target/ia64/arch/firmware.c).  With the string:
            //   acpi_get_device_by_name("\_SB_") -> 0    (found)
            //   acpi_dvc_get_child_set()         -> 0    (one child, PCI0)
            //   acpi_dvc_get_hid()               -> 44   (skip, end of walk)
            // With EisaId the same walk runs to completion: the _CID path is
            // taken, acpi_get_sta() answers 38 ("no _STA method", assumed
            // present), get_or_create_cudv() returns 0, and the child name is
            // handed to cfgmgr.  The guest's CuDv then really does contain
            // pci0 (bus/ia64/pci, parent sysplanar0, driver pci/pci_busdd) and
            // configuration continues into vga0 and the other PCI children.
            //
            // ★The obvious check -- "did /usr/lib/methods/cfgpci get exec'd"
            // -- is NOT reliable: a short-lived process's argv/envp is reused
            // within seconds, so the first attempt at this change looked like
            // it did nothing and was wrongly reverted.  Trap the call sites,
            // or look for the device in CuDv.
            Name (_HID, EisaId ("PNP0A03"))
            // Left as a string on purpose: _CID is only consulted as a
            // fallback and this spelling is what some guest installers match.
            Name (_CID, "PNP0A03")
            Name (_SEG, Zero)
            Name (_BBN, Zero)
            Name (_UID, Zero)
            Name (_CCA, One)
            // Tried and reverted: an explicit Method (_STA) { Return (0x0F) }
            // here.  The theory was that the 2000-vintage ACPI CA in AIX
            // 5L/IA-64 treats a missing _STA as "not present" where the spec
            // says "assume present".  Measured: identical boot, identical
            // port-I/O profile, cfgmgr still on LED 0538.  Not the gate.
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed,
                    PosDecode, 0, 0, 0x00FF, 0, 0x0100)
                // PCI I/O space is 16 bits wide, so the producer window must
                // stop at 0xFFFF.  Declaring 16 MB here let Windows' PnP I/O
                // arbiter believe it owned 0x000000-0xFFFFFF and rebalance the
                // display adapter's I/O BAR to 0x00FFFF00 - a port number no
                // PCI device can decode and that does not exist in the IA-64
                // 64 KB I/O port space either.  The miniport then fails to map
                // its access ranges and the device stops with Code 10.
                //
                // The window is declared the way every real IA-64 root bridge
                // declares it: ports are reached through a sparse memory-
                // mapped window (4 KB page per 4 ports, SDM vol 2 10.7), so
                // the translation offset carries the window's physical base
                // (= the EfiMemoryMappedIoPortSpace descriptor, see
                // LEGACY_IO_BASE) and the type is Translation + Sparse.
                // Windows' acpi.sys builds its bridge translator windows and
                // the HAL port-range handles ((RangeId << 16) | port) from
                // exactly these fields; Linux fills io_space[] from them.
                //
                // ★★★★★But it must be a DWord descriptor here, not a QWord
                // one: AIX 5L for IA-64 IGNORES every 64-bit ACPI address
                // space descriptor.  libcfg_ia64.so's parse_acpi_res_info()
                // dispatches on the ACPI CA resource id through a 15-entry
                // jump table, and the entry for ACPI_RSTYPE_ADDRESS64 (13)
                // points at the "no handler, keep walking" label -- the same
                // one DMA, START_DPF, END_DPF, VENDOR and END_TAG use.  Only
                // ADDRESS16 (11) and ADDRESS32 (12) reach
                // process_acpi_address_ranges_info().  A QWordIO window is
                // therefore invisible to AIX and the host bridge ends up with
                // no I/O producer at all.
                //
                // The cost of the DWord form is the translation offset: it no
                // longer fits, so the sparse-window base is gone.  AIX does
                // not need it (its port I/O goes through planar_pal_ia64's
                // pal_command, and get_system_addresses() hardcodes the
                // 0xFFFFC000000 legacy window), but Windows and Linux do --
                // if this firmware is ever pointed at them again, restore the
                // QWord form.  The XP rig (~/xpia64) has its own tree and is
                // untouched by this.
                DWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    EntireRange, 0, 0, 0x0000FFFF, 0, 0x00010000)
                // The legacy VGA aperture is decoded to the PCI bus and must
                // be declared, or the root bridge claims no producer window
                // covering the range its VGA child reports in _CRS/BARs.
                // This is the conventional descriptor upstream QEMU emits for
                // the same hole on i440fx/q35.
                DWordMemory (ResourceProducer, PosDecode, MinFixed,
                    MaxFixed, Cacheable, ReadWrite,
                    0, 0x000A0000, 0x000BFFFF, 0, 0x00020000)
                // The option-ROM segment must be a producer window too.
                // Windows' pci.sys validates every HalTranslateBusAddress
                // against the complement of the root bridge windows
                // (busdrv/pci/hookhal.c PciTranslateBusAddress: an address
                // intersecting an Owner==NULL arbiter range "is not on our
                // bus"), and the inbox ATI miniport's VGA-enabled path maps
                // its video BIOS at 0xC0000 through exactly that call.
                // Without this window the translation is refused,
                // VideoPortGetDeviceBase returns NULL (ati2mpaa event
                // 0xC1010002 UniqueId 25) and the adapter stops with Code 10.
                DWordMemory (ResourceProducer, PosDecode, MinFixed,
                    MaxFixed, Cacheable, ReadWrite,
                    0, 0x000C0000, 0x000DFFFF, 0, 0x00020000)
                // The PCI MMIO window.  DWord for the same reason as the I/O
                // window above, and it has to stay NonCacheable: AIX keeps a
                // memory producer only when the cache attribute byte its
                // parser writes is 'c' (NonCacheable) or 'P' (Prefetchable).
                // get_host_bus_possible_ranges() drops 'C' (Cacheable) and
                // 'W' (WriteCombining) on the floor, so the two legacy holes
                // above -- declared Cacheable for Windows' benefit -- are not
                // producers as far as AIX is concerned.  This descriptor is
                // the only memory window AIX will see.
                DWordMemory (ResourceProducer, PosDecode, MinFixed,
                    MaxFixed, NonCacheable, ReadWrite,
                    0, 0xEE000000, 0xFDFFFFFF, 0, 0x10000000)
            })
            Name (_PRT, Package ()
            {
                Package () { 0x0000FFFF, 0, 0x00, 16 },
                Package () { 0x0000FFFF, 1, 0x00, 17 },
                Package () { 0x0000FFFF, 2, 0x00, 18 },
                Package () { 0x0000FFFF, 3, 0x00, 19 },
                Package () { 0x0001FFFF, 0, 0x00, 17 },
                Package () { 0x0001FFFF, 1, 0x00, 18 },
                Package () { 0x0001FFFF, 2, 0x00, 19 },
                Package () { 0x0001FFFF, 3, 0x00, 16 },
                Package () { 0x0002FFFF, 0, 0x00, 18 },
                Package () { 0x0002FFFF, 1, 0x00, 19 },
                Package () { 0x0002FFFF, 2, 0x00, 16 },
                Package () { 0x0002FFFF, 3, 0x00, 17 },
                Package () { 0x0003FFFF, 0, 0x00, 19 },
                Package () { 0x0003FFFF, 1, 0x00, 16 },
                Package () { 0x0003FFFF, 2, 0x00, 17 },
                Package () { 0x0003FFFF, 3, 0x00, 18 },
                Package () { 0x0004FFFF, 0, 0x00, 16 },
                Package () { 0x0004FFFF, 1, 0x00, 17 },
                Package () { 0x0004FFFF, 2, 0x00, 18 },
                Package () { 0x0004FFFF, 3, 0x00, 19 },
                Package () { 0x0005FFFF, 0, 0x00, 17 },
                Package () { 0x0005FFFF, 1, 0x00, 18 },
                Package () { 0x0005FFFF, 2, 0x00, 19 },
                Package () { 0x0005FFFF, 3, 0x00, 16 },
                Package () { 0x0006FFFF, 0, 0x00, 18 },
                Package () { 0x0006FFFF, 1, 0x00, 19 },
                Package () { 0x0006FFFF, 2, 0x00, 16 },
                Package () { 0x0006FFFF, 3, 0x00, 17 }
            })

            // ★TRIED AND REVERTED (2026-08-28): bare Device(SCSI)/Device(VGAD)
            // child nodes here with _ADR = (device << 16) | function -- the
            // exact key cfgpci's match_acpi_dvc() computes (measured at
            // 0x10004e00).  The theory: acpi_dvc_get_child_objs() on the PCI0
            // handle would then return these, match_acpi_dvc would bind each
            // PCI leaf, acpi_dvc_correlate would run, and the osname<->handle
            // map the keyboard and bootinfo need would populate.  Measured
            // result: match_acpi_dvc still returns 0 for every leaf (watched
            // 0x10004200, gp=cfgpci) and the keyboard prompt is still
            // unanswerable.  The PCI0 child list stays empty even with valid
            // _ADR Device() nodes declared, so the wall is inside AIX's
            // 2000-vintage ACPI CA namespace walk (AcpiGetNextObject with a
            // TYPE_DEVICE filter on the PCI0 handle), not in these
            // declarations.  Left out of the tree.

        }
    }
}
