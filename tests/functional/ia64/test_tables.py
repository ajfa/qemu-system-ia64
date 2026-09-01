#!/usr/bin/env python3
"""Guest-visible EFI, ACPI, SAL, and SMBIOS table validation."""

# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from qemu_test import QemuSystemTest

from ia64.console import Ia64FirmwareTest
from ia64.efi_build import app_path
from ia64.media import make_fat_disk


TABLE_CASES = {
    "configuration-tables", "acpi-root-tables", "acpi-table-bounds",
    "acpi-fadt-links-gas", "acpi-topology", "acpi-mcfg",
    "acpi-console-tables", "acpi-aml-crs", "acpi-pci-routing",
    "platform-memory-descriptors", "pci-root-resources",
    "debug-image-info", "sal-smbios-tables",
}


class Ia64PlatformTables(Ia64FirmwareTest):
    def test_runtime_tables(self):
        disk = Path(self.scratch_file("tables.img"))
        debug_log = self.scratch_file("debugcon.log")
        nvram = self.make_nvram()
        make_fat_disk(disk, app_path("tables"))
        # The default machine (ia64-vpc == zx1) advertises MCFG/ECAM and the
        # nested HWP0001 IOC DSDT, so this validates the full table set against
        # the zx1 profile.  The 460gx machine deliberately omits MCFG (SAL
        # config), so the MCFG-requiring table suite does not apply there.
        vm = self.launch_ia64(
            media=disk, smp=4,
            machine_options=f"firmware-console=serial,nvram={nvram}",
            extra_args=("-debug-port", f"file:{debug_log}"))
        result = self.wait_ia64_suite(
            vm, "tables", TABLE_CASES, timeout=35.0)
        self.assertSetEqual(set(result.cases), TABLE_CASES)


if __name__ == "__main__":
    QemuSystemTest.main()
