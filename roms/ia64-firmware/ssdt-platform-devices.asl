// SPDX-License-Identifier: GPL-2.0-or-later

DefinitionBlock ("", "SSDT", 2, "QEMU  ", "IA64SSDT", 0x00000001)
{
    Scope (\_SB)
    {
        Name (C0EN, 0x0F)
        // Keep these as AML BytePrefix objects; firmware patches the payload.
        Name (C1EN, 0x0F)
        Name (C2EN, 0x0F)
        Name (C3EN, 0x0F)

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

        // Motherboard legacy devices live directly under \_SB, not under the
        // PCI root: the UART sits at a fixed platform address (0x47F0000000)
        // outside every PCI0 _CRS producer window, and the PS/2 controller is
        // an LPC/SIO device.  Parenting them under \_SB.PCI0 made Windows'
        // PCI memory arbiter account COM1's out-of-window resource against the
        // PCI window, which broke placement of large PCI BARs (ATI Code 12).
        Name (P2EN, 0x0F)

        Device (UAR0)
        {
            Name (_HID, "PNP0501")
            Name (_UID, 0)
            Name (_CRS, ResourceTemplate ()
            {
                QWordMemory (ResourceConsumer, PosDecode, MinFixed,
                    MaxFixed, NonCacheable, ReadWrite,
                    0, 0x00000047F0000000, 0x00000047F0000007,
                    0, 8)
                IRQNoFlags () {4}
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
