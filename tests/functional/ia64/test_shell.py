#!/usr/bin/env python3
"""IA-64 firmware boot manager and interactive EFI shell tests."""

# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path

from qemu_test import QemuSystemTest, wait_for_console_pattern

from ia64.console import Ia64FirmwareTest
from ia64.efi_build import app_path
from ia64.media import make_fat_disk
from ia64.protocol import select_default_boot, wait_for_menu


class Ia64BootShell(Ia64FirmwareTest):
    # 'EFI Shell [Built-in]' is the second boot-menu entry (after 'Removable
    # Media Boot'); the third is the maintenance menu.
    SHELL_BANNER = "EFI Shell version 1.10"

    def _open_shell(self, vm):
        """Open the built-in EFI shell from the boot menu over the serial
        console: move the highlight down one entry and press Enter."""
        wait_for_menu(vm.console_socket)
        vm.console_socket.sendall(b"\x1b[B\r")   # Down (VT100), then Enter
        wait_for_console_pattern(self, self.SHELL_BANNER, vm=vm)

    def _command(self, vm, command, expected):
        vm.console_socket.sendall((command + "\r").encode("ascii"))
        return wait_for_console_pattern(self, expected, vm=vm)

    def test_shell_commands_and_persistence(self):
        disk = Path(self.scratch_file("shell.img"))
        nvram = self.make_nvram("shell.nvram")
        make_fat_disk(disk, app_path("smoke"))

        vm = self.launch_ia64(
            name="shell-first", media=disk,
            machine_options=f"firmware-console=serial,nvram={nvram}")
        self._open_shell(vm)
        self._command(vm, "info", "NVRAM backing:  persistent")
        self._command(vm, "map", "fs0:")
        self._command(vm, r"ls fs0:\EFI\BOOT", "BOOTIA64.EFI")
        self._command(vm, "date 2024-02-29", "2024-02-29")
        self._command(vm, "time 12:34:56", "12:34:56")
        self._command(vm, "bootorder Boot0000",
                      "BootOrder saved to persistent NVRAM")
        self._command(vm, "bootnext Boot0000",
                      "BootNext saved to persistent NVRAM")
        self._command(vm, r"cd fs0:\EFI\BOOT", r"fs0:\EFI\BOOT>")
        self._command(vm, "pwd", r"fs0:\EFI\BOOT")
        self._command(vm, "run BOOTIA64.EFI",
                      "IA64TEST suite=smoke status=DONE")
        wait_for_console_pattern(self, r"fs0:\EFI\BOOT>", vm=vm)
        vm.shutdown()

        contents = nvram.read_bytes()
        self.assertIn("BootOrder".encode("utf-16le") + b"\0\0", contents)
        self.assertIn(b"IRT64OFT", contents)

        vm = self.launch_ia64(
            name="shell-second", media=disk,
            machine_options=f"firmware-console=serial,nvram={nvram}")
        self._open_shell(vm)
        self._command(vm, "date", "2024-02-29")
        self._command(vm, "time", "12:34:")
        self._command(vm, "bootorder", "BootOrder: Boot0000")
        self._command(vm, "bootnext", "BootNext: Boot0000")
        # 'exit' resumes the boot flow, which returns to the wait-forever menu;
        # selecting the default boots the smoke app.
        vm.console_socket.sendall(b"exit\r")
        select_default_boot(vm.console_socket)
        wait_for_console_pattern(
            self, "IA64TEST suite=smoke status=DONE", vm=vm)
        vm.shutdown()
        # NB: BootNext one-shot consumption is not verified here.  The boot
        # manager only deletes BootNext when it auto-boots via
        # boot_image_from_boot_order(); with the wait-forever menu (Timeout
        # 0xFFFF, the sample default) a manually selected option does not run
        # that path, so BootNext is not consumed.  Whether the menu should
        # honour/consume BootNext per the UEFI spec is a firmware decision.

    def test_usb_menu_and_device_boot(self):
        # Drive the menu with a USB keyboard (i8042 disabled): open the shell
        # from the menu, then boot a device from the shell.
        disk = Path(self.scratch_file("device-boot.img"))
        make_fat_disk(disk, app_path("smoke"))
        vm = self.launch_ia64(
            name="device-boot", media=disk,
            machine_options="i8042=off,firmware-console=serial,nvram=none")
        wait_for_menu(vm.console_socket)
        for qcode in ("down", "ret"):
            vm.cmd("send-key", keys=[{"type": "qcode", "data": qcode}],
                   hold_time=50)
        wait_for_console_pattern(self, self.SHELL_BANNER, vm=vm)
        self._command(vm, "boot fs0:",
                      "IA64TEST suite=smoke status=DONE")


if __name__ == "__main__":
    QemuSystemTest.main()
