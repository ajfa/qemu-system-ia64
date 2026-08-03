# qemu-system-ia64

Experimental QEMU full-system emulation target for IA-64/Itanium guests. Forked from [syunnPC/qemu-system-ia64](https://github.com/syunnPC/qemu-system-ia64
)

**DISCLAMER: This codebase is written using AI LLMs.**

## Emulated Platform

The default machine is `ia64-vpc`.
It models an IA-64 virtual PC profile intended for firmware, boot loader, and operating-system bring-up:

- Montecito CPU model by default, with Merced and Madison selection available.
  All models use TCG translation and provide PAL/SAL helpers, the register stack engine, TLB/VHPT paths, and architectural floating-point state.
- 1 vCPU by default, configurable from 1 to 4 vCPUs; MTTCG is supported with `-accel tcg,thread=multi`
- 2 GiB default RAM
- project-owned IA-64 EFI firmware built from source under `roms/ia64-firmware/`
- EFI boot/runtime services, an interactive pre-boot shell, PE/COFF and EBC image loading, decompression, filesystems, graphics, storage, USB/input, and debug-support protocols
- local SAPIC, I/O SAPIC, ACPI platform tables, RTC, watchdog, persistent NVRAM, and serial/debug ports
- PCI root bus with LSI53C895A SCSI boot storage, ICH9 AHCI, Intel gigabit Ethernet, OHCI/UHCI USB, and optional CMD646 IDE/ATAPI
- ATI-compatible PCI graphics by default, with standard VGA available as an alternative
- PS/2 input by default, or an automatically attached USB keyboard and absolute USB tablet when `i8042=off` is selected

### Machine options

Beyond the standard QEMU machine properties, `-machine ia64-vpc,<option>=<value>` accepts:

- `ahci=on|off` enables or disables the AHCI SATA controller.
  Use `ahci=off` for guests that have no driver for it, such as Windows XP.
- `i8042=on|off` enables or disables the PS/2 controller.
  With `i8042=off` the machine attaches a USB keyboard and an absolute USB tablet instead.
- `nvram=<path>|auto|none` selects the EFI variable store.
- `firmware-console=serial|vga` selects the HCDP primary console the firmware advertises.
- `firmware-ide-dma=on|off` enables or disables firmware IDE bus-master DMA.
- `alat=zero|full` selects the ALAT model.

## Guest support

These guest operating systems have been tested and are confirmed working:

| Guest | CPU model | State |
|---|---|---|
| Windows XP 64-bit Edition, RTM and SP1 | `merced` | Installs and runs, single- and multi-processor |
| Windows XP 64-bit Edition, Version 2003 | `merced` or `madison` | Installs and runs, single- and multi-processor |
| Windows Server 2003, RTM (build 3790) | `merced` or `madison` | Installs and runs, single- and multi-processor |
| Windows Whistler Server beta 2 (build 2462) | `merced` | Installs and runs, single- and multi-processor |

Multiprocessor guests need `-smp N` together with `-accel tcg,thread=multi`.

More operating systems (including Linux and more) will be tested and supported in the future.


## Known issues

- The ATI Rage 128 Pro may report Code 10 or 12 in Device Manager on XP-family guests, although the display itself works.
- `Communications Port (COM1)` in Windows may be flagged for a memory claim that the PnP arbiter cannot satisfy.
- When using USB for HID, the keyboard may sometimes stop working in Windows. Removing it and searching for new devices in device manager fixes this.
- Windows XP does not use more than 2 CPUs or Cores - this is a hard limitation in Windows with no simple workaround.

## Run

Pre-compiled binaries are available via the GitHub Actions of this repository: https://github.com/makuhlmann/qemu-system-ia64/actions/workflows/ci.yml

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -drive file=/path/to/guest-media.iso,media=cdrom,format=raw,readonly=on \
  -display gtk
```

If QEMU does not launch due to the error `failed to find romfile "vgabios-ati.bin"`, try setting the path to the folder containing the roms with `-L <path>`, i.e. `-L share` for the Windows artifacts build.

### CPU model selection

The `ia64-vpc` machine uses the `montecito` CPU model by default.
Select a different model with `-cpu`.
CPU selection changes guest-visible CPUID and PAL information as well as the available instruction set.

Both `madison` and `merced` provide the processor's hardware IA-32 execution environment; `montecito` does not.
Use `-cpu merced` for first-generation guests such as Windows XP 64-bit Edition:

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc \
  -cpu merced \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  ...
```

#### `montecito` (default)

Montecito implements the later 16-byte operations `ld16`, `ld16.acq`, `st16`, `st16.rel`, `cmp8xchg16.acq`, and `cmp8xchg16.rel`.
It has no hardware IA-32 execution engine, so an eligible `br.ia` or `rfi` request to enter IA-32 mode raises a Disabled ISA Transition fault.
The `vmsw.0` and `vmsw.1` encodings are recognized as virtualization instructions.
Because this emulator does not provide an IA-64 virtual-machine environment, these instructions produce the architecturally appropriate Privileged Operation or Virtualization fault instead of executing a mode switch.

#### `madison`

Madison provides the hardware IA-32 execution environment.
Eligible `br.ia` and `rfi` transitions execute IA-32 code, and IA-32 `JMPE` returns to IA-64.
The later 16-byte operations and virtualization instructions are not available and raise an Illegal Operation fault.

#### `merced`

Merced models the original Itanium and reports the generation-specific CPUID, PAL, cache, translation-cache, page-size, address, protection-key, performance-monitor, and register-stack characteristics.
It provides the hardware IA-32 execution environment, which identifies itself as x86 family 7.
`CPUID[4]` reads zero, so `brl` is not implemented and raises an Illegal Operation fault.
Windows keys its `KF_BRL` check off that bit and emulates the instruction, which is the behavior first-generation guests expect.
The translation-register file is asymmetric: 8 instruction and 48 data registers.
Later long-branch, 16-byte atomic, and virtualization facilities are not available.

`-cpu help` lists the available names.
The generic `ia64-cpu` entry is retained for compatibility and currently has Madison-like capabilities.
Use an explicit generation name for predictable guest-visible behavior.

For four vCPUs, MTTCG, 8 GiB of RAM, and USB input without the PS/2 controller:

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc,i8042=off,nvram=/path/to/guest.nvram \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -drive file=/path/to/guest-media.iso,media=cdrom,format=raw,readonly=on \
  -accel tcg,thread=multi \
  -smp 4 \
  -m 8G \
  -display gtk
```

The machine automatically attaches a USB keyboard and absolute USB tablet when `i8042=off` is used, so `-usb` is not required.
Omitting `-vga` selects the default ATI-compatible display. This is recommended for graphical guests; use `-vga std` only when standard VGA compatibility is specifically needed.

### Networking

An Intel gigabit Ethernet controller is attached by default.
It uses the 82543GC device identity that drivers shipped with early IA-64 Windows releases, so the guest has a working network adapter without additional drivers.
Other models are selectable with `-nic model=`:

- `e1000-82543gc` (default): gigabit
- `i82557b`: Intel PRO/100, 100 Mbit
- `e1000`: 82540EM

When QEMU is built with libslirp, connect the default controller to user-mode networking with:

```sh
-nic user
```

For a host TAP interface, use:

```sh
-nic tap,ifname=tap0,script=no,downscript=no
```

Use `-nic none` to omit the controller.
EFI network boot is not currently provided; the controller is available to the guest operating system.

### Console and debugging

Use `-serial stdio` to view serial output.
The `-debug-port` option publishes the guest debug transport described by the ACPI DBGP table; for example, `-debug-port tcp::4444,server=on,wait=on,nodelay=on`.

It is this project's own option and is unrelated to QEMU's `-debugcon`.

Three logging categories are useful when bringing up a guest:

- `-d guest_errors` prints decoded guest debug output, including the assertion and `DbgPrint` text produced by Windows checked builds
- `-d ia64_fault` logs rare or fatal IA-64 fault classes (illegal operation, NaT consumption, unaligned reference, privileged operation, break) and excludes routine TLB, paging, and external-interrupt activity
- `-d ia32_fault` logs IA-32 execution-layer faults and instruction intercepts with EIP, opcode bytes, and registers

### EFI variables

EFI variables are persistent.
By default, `ia64-vpc` loads and saves a 64 KiB file named `nvram` in the directory containing the firmware selected by `-bios`.
Use a separate file for each virtual machine with `-machine ia64-vpc,nvram=<path>`, or specify `nvram=none` for volatile EFI variables.
Relative paths are resolved from QEMU's current working directory.


At each startup, the firmware waits three seconds for F2, F12, or Delete before continuing normal boot. Any of these keys opens the embedded EFI shell on the graphical and serial consoles. The shell can inspect the machine and its filesystems, launch an EFI application, select a boot target, update the boot order, and set the real-time clock. For example:

```text
info
map
ls fs0:\EFI\BOOT
run fs0:\EFI\BOOT\TOOL.EFI argument
boot
boot Boot0001
boot fs0:
bootorder Boot0001 Boot0000
bootnext Boot0001
date 2026-07-17
time 12:34:56
exit
```

`boot fsN:` launches `\EFI\BOOT\BOOTIA64.EFI` from that filesystem. `bootnext` is consumed by the next automatic boot attempt. Boot order, next-boot selection, and clock changes survive a reset when the machine has NVRAM backing; with `nvram=none`, they remain valid only for the current process.

An installed EFI system can be attached with an ordinary disk drive:

```sh
-drive file=/path/to/guest-disk.qcow2,format=qcow2
```

The firmware supports persistent EFI boot entries, including short-form hard drive device paths, and can boot supported loaders from FAT partitions.

## Tests

Run the behavior-oriented IA-64 unit, TCG, and machine tests after building:

```sh
build/pyvenv/bin/meson test -C build --suite ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite qtest-ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite func-ia64 --print-errorlogs
build/pyvenv/bin/meson test -C build --suite func-ia64-thorough --print-errorlogs
```

Use the build-local Meson shown above.

It is the same version selected by QEMU's configure process; a host `meson` of another version may be unable to read `build/meson-private/build.dat`.

Plain `meson test` from the source directory is not valid because the Meson build data lives under `build`.

The TCG registry currently contains 1238 architectural microprograms divided between core, memory/NaT, floating-point, RSE, MMU, interruption, and PAL groups.
Each group run reports its own case count, so that total can be re-derived after adding cases.
Machine tests cover platform wiring and display behavior.

The functional suite builds project-owned EFI applications and boots them from deterministic FAT, GPT, MBR, El Torito, and UDF media. It also exercises the firmware shell through PS/2, USB, and serial input, including direct application execution and NVRAM persistence across restarts.

## Build

Configure and build the IA-64 target with GTK:

```sh
./configure --enable-gtk
ninja -C build qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

The firmware build requires an IA-64 ELF cross toolchain named `ia64-linux-gnu-*` in `PATH`.

### Performance builds

For guest-performance measurements, use an IA-64-only build without the compiler hardening passes that add substantial overhead to TCG helper calls.
Build it in its own directory, and keep the default `build/` for development and correctness testing:

```sh
mkdir build-perf
cd build-perf
../configure --target-list=ia64-softmmu \
  --enable-lto \
  --disable-qom-cast-debug \
  --disable-stack-protector \
  --extra-cflags='-fno-stack-protector -fzero-call-used-regs=skip -ftrivial-auto-var-init=uninitialized' \
  -Doptimization=2 \
  --enable-gtk
ninja qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

Set the optimization level with `-Doptimization=`, not with `-O` in `--extra-cflags`, so that only one level reaches the compiler.
`-Doptimization=3` together with `--extra-cflags='-march=native -mtune=native ...'` produces a faster binary that only runs on hosts of the same processor generation.

The commands elsewhere in this file assume the default `build/` directory.
With a second build tree, pass its path to `ninja -C`, to `meson test -C`, and to the binary and firmware arguments.

For profile-guided optimization, use a dedicated build directory and the same compiler for both stages:

```sh
mkdir build-pgo
cd build-pgo
../configure --target-list=ia64-softmmu \
  --enable-lto \
  --disable-qom-cast-debug \
  --disable-stack-protector \
  --extra-cflags='-fno-stack-protector -fzero-call-used-regs=skip -ftrivial-auto-var-init=uninitialized' \
  -Doptimization=2 \
  --enable-gtk \
  -Db_pgo=generate
ninja qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

Run representative guest workloads with the instrumented binary.
The training set should cover boot, integer, floating-point, SIMD, MMU-intensive, and RSE-intensive code paths; a guest boot to the desktop plus the microprogram suites covers all of them.
Then consume the generated profiles:

```sh
meson configure -Db_pgo=use
ninja qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

Profiles are tied to the exact build tree, compiler, and source revision; do not copy stale profile data between builds.

On hosts that all support the x86-64-v3 ISA level, add `--x86-version=3` to a separate comparison build.
This changes the minimum host ISA for QEMU and its C helpers; TCG-generated guest code still selects host vector features at runtime.

## Legal disclaimer

This repository does not include third-party operating system images, disk images, firmware images, machine ROM dumps, proprietary firmware blobs, or operating system binaries.

Guest operating system images, firmware, installation media, and other third-party materials must be supplied by users under their own applicable licenses.

This project is an independent experimental QEMU IA-64 system emulation project. It is not affiliated with, endorsed by, sponsored by, or supported by Intel, HPE, the QEMU Project or Microsoft Corporation.

QEMU is used as the upstream base for this fork. QEMU as a whole is licensed under the GNU General Public License, version 2. See the license files in this repository for details.

Microsoft and Windows are trademarks of the Microsoft group of companies.

All other product names, project names, company names, and trademarks are the property of their respective owners.
