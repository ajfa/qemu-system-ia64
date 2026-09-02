// SPDX-License-Identifier: GPL-2.0-or-later
//
// Source for the SSDT AML byte array in firmware.c (mSsdt).  Regenerate with
//     amlembed.py ssdt-platform-devices.asl -on
// and splice the rows into mSsdt.Aml.  Two things about that path are
// load-bearing:
//
// -on (and NOT -oi) reproduces the shipped encoding byte for byte.  Unlike the
// DSDT, nothing here is read as a raw package element, so the _UID scalars are
// free to stay ZeroOp/OneOp and must, or the array no longer matches.
//
// The `External` below must not survive into the AML.  iasl >= 2015 compiles
// every External into an `If (Zero) { ExternalOp ... }` block, and ExternalOp
// is AML opcode 0x15, introduced with ACPI 6.0.  An interpreter older than
// that has no case for the opcode, falls through to "an unrecognised byte
// begins a NameString", and chokes on the `\` and `.` of the pathname.  AIX 5L
// for IA-64 carries a 2000-vintage Intel ACPI CA and does precisely this:
//
//     nssearch-0430: *** Error: NsSearchAndEnter: Bad character in ACPI Name
//
// printed once per namespace-load pass.  AcpiLoadTables then gives up, the
// namespace stays empty, and cfgsys_ia64 -- which walks \_SB_ for a PNP0A03
// to turn into bus/ia64/pci -- finds nothing, so cfgmgr never gets as far as
// the SCSI adapter and the machine sits on LED 0538 forever.  The declaration
// is compiler-side only; amlembed.py strips the block after compiling.

DefinitionBlock ("", "SSDT", 2, "QEMU  ", "IA64SSDT", 0x00000001)
{
    External (\_SB.PCI0, DeviceObj)

    Scope (\_SB)
    {
        Name (C0EN, 0x0F)
        // Keep these as AML BytePrefix objects; firmware patches the payload.
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

    Scope (\_SB.PCI0)
    {
        Name (P2EN, 0x0F)
        // Patched to 0 when no -debug-port chardev backs the legacy COM1.
        Name (S1EN, 0x0F)

        // UAR0 (the memory-mapped 16550 at 0x47F0000000) is deliberately NOT
        // declared in the namespace.  Two measured reasons:
        //
        //  1. With a STRING _HID it made acpi_dvc_get_hid() return 44, and
        //     acpi_get_child_dvc_info() (libacpi 0x3f7c..0x3fac) tolerates only
        //     0 and 38 -- it PROPAGATES anything else.  That single bad _HID
        //     poisoned the whole PCI0 child list: get_child_objs returned 44,
        //     match_acpi_dvc cached an EMPTY list, acpi_dvc_correlate never ran
        //     and cfgisa never reached PS2K.  No keyboard.
        //  2. With a VALID EisaId _HID the enumeration works (correlate went
        //     from 0 to 91 calls; sioka0, kbd0 and isa/kbddd finally appear)
        //     but AIX's devices.isa_sio.PNP0501 driver then tries to CLAIM it,
        //     and that driver only knows I/O-port 16550s, not a QWordMemory
        //     resource -- cfgmgr never finishes (LED stuck alternating
        //     0538/0539, its own run_rules/wait_on_queue loop).
        //
        // AIX cannot drive this UART either way, so the node buys nothing and
        // costs the entire ACPI child enumeration.  The HCDP table still points
        // at it for the firmware's own console; only the ACPI Device is gone.
        // The UART AIX *can* drive is UAR1 (I/O port 0x3F8) inside ISAB.

        // The PCI-ISA bridge node, matching the config-space-only bridge
        // function the machine's isa-bridge=on option places at device 6.
        // The legacy devices live INSIDE it on purpose: AIX 5L finds its
        // ISA bus by scanning PCI for class 0601 (PdDv bus/pci/isa,
        // devid "0x060100"), correlates the function to this node by _ADR,
        // and then cfgisa enumerates the CHILDREN OF THIS NODE with
        // acpi_dvc_get_child_objs(), matching _HIDs against PNP0303 /
        // PNP0501 / PNP0F03 / PNP0F13 (read from the cfgisa binary).  With
        // the devices declared directly under PCI0 -- measured -- isa0 was
        // defined but childless: no sioka0 keyboard, RTE 1 left masked with
        // vector 0, and the installer's console prompt could not be
        // answered.
        Device (ISAB)
        {
            Name (_ADR, 0x00060000)

            // Legacy COM1: the debug UART's registers aliased at I/O port
            // 0x3F8.  AIX 5L/IA-64's serial driver (devices.isa_sio.PNP0501)
            // claims only I/O-port 16550s, so UAR0's QWordMemory resource is
            // invisible to it; this is the UART that OS's Super-I/O stack
            // can actually drive.
            //
            // _HID as EisaId, NOT as a string: AIX's acpi_dvc_get_hid()
            // returns 44 for string _HIDs (the same defect fix 12 hit on
            // PCI0), and the ISA child walk of cfgisa gives up on the first
            // failing child -- with a string here, PS2K behind it was never
            // reached and no keyboard was ever defined.
            Device (UAR1)
            {
                Name (_HID, EisaId ("PNP0501"))
                Name (_UID, 1)
                Method (_STA, 0, NotSerialized)
                {
                    Return (S1EN)
                }
                Name (_CRS, ResourceTemplate ()
                {
                    IO (Decode16, 0x03F8, 0x03F8, 1, 8)
                    // The machine wires the debug UART to IOSAPIC GSI 3.
                    Interrupt (ResourceConsumer, Level, ActiveLow, Shared, ,,)
                    {
                        3
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
}
