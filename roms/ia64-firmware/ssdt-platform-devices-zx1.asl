// SPDX-License-Identifier: GPL-2.0-or-later
//
// zx1-profile SSDT.  Identical to ssdt-platform-devices.asl except that the
// PCI-scoped devices hang off \_SB.SBA0.PCI0 instead of \_SB.PCI0, because the
// zx1 DSDT nests the PCI root inside the HP zx1 SBA IOC (see
// dsdt-pci-root-zx1.asl).  The Processor objects stay at \_SB.  Published only
// when the machine selects chipset=zx1.
//
// Recompile with:  iasl -on -oi ssdt-platform-devices-zx1.asl
// Keep the CxEN/P2EN enable bytes as AML BytePrefix objects; the firmware
// patches the payload (see ssdt-platform-devices.asl).

DefinitionBlock ("", "SSDT", 2, "QEMU  ", "IA64SSDT", 0x00000001)
{
    External (\_SB.SBA0.PCI0, DeviceObj)

    Scope (\_SB)
    {
        Name (C0EN, 0x0F)
        Name (C1EN, 0x0F)
        Name (C2EN, 0x0F)
        Name (C3EN, 0x0F)
        Name (C4EN, 0x0F)
        Name (C5EN, 0x0F)
        Name (C6EN, 0x0F)
        Name (C7EN, 0x0F)

        Processor (CPU0, 0, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C0EN)
            }
        }

        Processor (CPU1, 1, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C1EN)
            }
        }

        Processor (CPU2, 2, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C2EN)
            }
        }

        Processor (CPU3, 3, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C3EN)
            }
        }

        Processor (CPU4, 4, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C4EN)
            }
        }

        Processor (CPU5, 5, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C5EN)
            }
        }

        Processor (CPU6, 6, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C6EN)
            }
        }

        Processor (CPU7, 7, 0, 0)
        {
            Method (_STA, 0, NotSerialized)
            {
                Return (C7EN)
            }
        }

    }

    Scope (\_SB.SBA0.PCI0)
    {
        Name (P2EN, 0x0F)

        Device (UAR0)
        {
            Name (_HID, "PNP0501")
            Name (_UID, Zero)
            Name (_CRS, ResourceTemplate ()
            {
                QWordMemory (ResourceConsumer, PosDecode, MinFixed,
                    MaxFixed, NonCacheable, ReadWrite,
                    0, 0x00000047F0000000, 0x00000047F0000007,
                    0, 8)
                Interrupt (ResourceConsumer, Level, ActiveLow, Shared, ,,)
                {
                    4
                }
            })
        }

        Device (PS2K)
        {
            Name (_HID, EisaId ("PNP0303"))
            Method (_STA, 0, NotSerialized)
            {
                Return (P2EN)
            }
            Name (_CRS, ResourceTemplate ()
            {
                IO (Decode16, 0x0060, 0x0060, 1, 1)
                IO (Decode16, 0x0064, 0x0064, 1, 1)
                IRQNoFlags () {1}
            })
        }

        Device (PS2M)
        {
            Name (_HID, EisaId ("PNP0F13"))
            Method (_STA, 0, NotSerialized)
            {
                Return (P2EN)
            }
            Name (_CRS, ResourceTemplate ()
            {
                IRQNoFlags () {12}
            })
        }
    }
}
