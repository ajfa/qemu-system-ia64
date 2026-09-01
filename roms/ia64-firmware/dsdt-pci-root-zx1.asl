// SPDX-License-Identifier: GPL-2.0-or-later
//
// zx1-profile DSDT: the PCI root bridge PCI0 is nested inside the HP zx1 SBA
// IOC device SBA0 (HWP0001), because Linux sba_iommu's sba_connect_bus() finds
// the IOC by walking *up* the ACPI parent chain from each PCI root ("the IOC
// scope encloses PCI root bridges in the ACPI namespace").  A sibling SBA0
// would make the device appear but never associate, so DMA would fall back to
// swiotlb.  This variant is published only when the machine selects
// chipset=zx1; the flat dsdt-pci-root.asl still serves the 460gx/E8870 guests
// (and XP 2002 / build 2600, which does not support zx1).
//
// Recompile with:  iasl -on -oi dsdt-pci-root-zx1.asl
//
// The -oi flag and the 0x00 constants inside _S5 and _PRT are load-bearing:
// they keep every *package element* a typed literal rather than a
// ZeroOp/OneOp constant opcode, which older Linux ACPI-CA rejects when walking
// package elements raw (see dsdt-pci-root.asl for the full rationale).  The
// PCI0 body below is copied verbatim from that file so the Windows-driven _CRS
// producer windows and _PRT behave identically; only the enclosing SBA0 device
// is new.
//
// PCI0 keeps _HID "PNP0A03" (not HWP0002): Windows XP 3790 / Server 2003 -- the
// Windows releases that support zx1 -- validate the install disk's ancestor
// bridges against a fixed list that only accepts a PNP0A03 _HID.  sba_iommu
// matches the HWP0001 ancestor, not the root's own _HID, so PNP0A03 is safe.

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
        Device (SBA0)
        {
            // HP zx1 System Bus Adapter / IOC (the IOMMU).  PNP0A05 makes the
            // OS enumerate the nested PCI root(s).
            Name (_HID, EisaId ("HWP0001"))
            Name (_CID, EisaId ("PNP0A05"))
            Name (_UID, Zero)
            Name (_CCA, One)
            // The IOC CSR block.  Linux sba_iommu locates the IOC base NOT from
            // a memory descriptor but from an HP-specific "CCSR" vendor-defined
            // resource: hp_acpi_csr_space() -> acpi_find_vendor_resource() looks
            // for a Vendor-Defined Large (0x84) resource whose data is
            //   guid_id=0x02, GUID 69e9adf9-924f-ab5f-f64a-24d201370ead,
            //   then u64 csr_base + u64 csr_length (16-byte payload).
            // It then reads the IOC registers at csr_base + ZX1_IOC_OFFSET
            // (0x1000) + IBASE(0x300); the model maps the IOMMU register window
            // at CSR offset 0x1300.  Emitting only a memory descriptor (as a
            // first attempt did) leaves the IOC uninitialised.  The GUID bytes
            // below are the EFI_GUID(0x69e9adf9,0x924f,0xab5f,f6,4a,24,d2,01,37,
            // 0e,ad) little-endian encoding.  Keep the base/length in lockstep
            // with IA64_SBA_CSR_BASE / IA64_SBA_CSR_SIZE.
            Name (_CRS, ResourceTemplate ()
            {
                VendorLong ()
                {
                    0x02,                                           // guid_id
                    0xF9, 0xAD, 0xE9, 0x69, 0x4F, 0x92, 0x5F, 0xAB, // GUID[0:7]
                    0xF6, 0x4A, 0x24, 0xD2, 0x01, 0x37, 0x0E, 0xAD, // GUID[8:15]
                    0x00, 0x00, 0xD0, 0xFE, 0x00, 0x00, 0x00, 0x00, // base 0xFED00000
                    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00  // length 0x10000
                }
                Memory32Fixed (ReadWrite, 0xFED00000, 0x00010000)
            })

            Device (PCI0)
            {
                Name (_HID, "PNP0A03")
                Name (_CID, "PNP0A03")
                Name (_SEG, Zero)
                Name (_BBN, Zero)
                Name (_UID, Zero)
                Name (_CCA, One)
                Name (_CRS, ResourceTemplate ()
                {
                    WordBusNumber (ResourceProducer, MinFixed, MaxFixed,
                        PosDecode, 0, 0, 0x00FF, 0, 0x0100)
                    QWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                        EntireRange, 0, 0, 0x0000FFFF, 0xFFFFC000000,
                        0x00010000, , , , TypeTranslation, SparseTranslation)
                    DWordMemory (ResourceProducer, PosDecode, MinFixed,
                        MaxFixed, Cacheable, ReadWrite,
                        0, 0x000A0000, 0x000BFFFF, 0, 0x00020000)
                    DWordMemory (ResourceProducer, PosDecode, MinFixed,
                        MaxFixed, Cacheable, ReadWrite,
                        0, 0x000C0000, 0x000DFFFF, 0, 0x00020000)
                    QWordMemory (ResourceProducer, PosDecode, MinFixed,
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
            }
        }
    }
}
