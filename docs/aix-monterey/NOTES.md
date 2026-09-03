# AIX 5L for Itanium on qemu-system-ia64

How AIX 5L V5.1.0.0 for IA-64, the shipped product of Project Monterey, was
brought up on this emulator: what broke, how each failure was measured, and
what the fix turned out to be.

Project Monterey was the joint IBM, SCO, Sequent and Intel effort to put AIX
on Itanium. IBM released the IA-64 build in 2001 and cancelled the programme
the following year. Very few machines ever ran it, and until now there was no
public record of any emulator running it either: a 2022 survey of the state of
Itanium emulation listed Simics, QEMU's old IA-64 target and XEN/KVM ia64 as
all having failed.

The guest now installs unattended onto `hdisk0`, reboots from disk, and reaches
a console you can log into and type at, with the keyboard and the mouse both
configured.

---

## Method

Two working rules produced almost all of the progress here, and their absence
produced almost all of the wasted time.

**Measure the thing itself, not something adjacent to it.** Every dead end in
this bring-up was a case of reading a signal that could not distinguish the
hypothesis from its negation. Eight separate false conclusions were signed off
and later retracted, and in every case the instrument, not the theory, was at
fault. They are listed at the end because they are the most reusable part of
this document.

**A conclusion written down is not evidence; the measurement behind it is.**
Before building on an inherited finding, identify the single measurement it
rests on and take it again. One thesis in these notes survived six experiments
built on top of it before anyone checked its premise, which turned out to be
false, and the "fixes" built on it had broken a path that already worked.

The instrumentation described further down exists because AIX at this stage has
no console, no debugger and no shell. The only way to ask it a question is to
watch the emulator.

---

## The bring-up, in order

### 1. The firmware could not load the guest's boot loader

AIX's `BOOTIA64.EFI` has its relocations stripped and a fixed `ImageBase` of
`0x1ff000`, which the firmware's own 1 MiB image overlapped. Relinking the
firmware to 3 MiB and moving the identity map to match got the loader running.

### 2. The machine reported 1 MB of memory

The loader takes `pib_base` and `io_base` from the **SAL system table**, not
from the EFI memory map, and AIX sizes the machine from that table's `REGULAR`
descriptors. Publishing `IPI` (type 2, `0xFEE00000`), `IOSPACE` (type 3,
`0xFFFFC000000`, length the whole sparse window shifted right by 12) and
`REGULAR` for DRAM changed `Memory : 1MB` into `Memory : 2049MB`.

The type names are carried by the loader itself, at `*(gp+152)`: REGULAR, MMIO,
IPI, IOSPACE, FIRMWARE, UNK0..3, BAD, HOLE. Reading them out of the guest was
faster than guessing the encoding.

### 3. The kernel faulted forever on its first store

`ia64_tlb_effective_perm()` computed the privilege level 0 column of access
rights 4, 5 and 6 with `access_level < pl`, which is never true for a page whose
own PL is 0. An `ar=4, pl=0` page came out read only at every level, and AIX
puts exactly that on its kernel data: the first store to a kernel global took an
endless Data Access Rights fault at cpl 0.

Rights 4, 5 and 6 are promotion and demotion rights. They give privilege level 0,
and only privilege level 0, a different set of rights from every other permitted
level, and unlike rights 0 to 3 they do not vary with the page's own PL. Linux
names them that way in `arch/ia64/include/asm/pgtable.h`: `_PAGE_AR_R_RW` is
"read only, read & write (privilege level 0)". The second half of each name is
the PL 0 column, which is also why right 6 deliberately withholds execute from
the kernel.

This one is not AIX specific. It is a plain emulator bug that any IA-64 guest
using those rights would hit.

### 4. The ACPI namespace collapsed

The SSDT began with `If (Zero) { External (\_SB.PCI0, DeviceObj) }`. Modern
`iasl` compiles `External` to `ExternalOp`, AML opcode `0x15`, which arrived in
ACPI 6.0. The ACPI CA of 2000 that AIX ships has no case for it, falls into "not
an opcode, so this starts a NameString", and chokes on the backslash. The whole
namespace goes down with it.

The guest says so out loud, on the serial port, twice (once per load pass):

```
nssearch-0430: *** Error: NsSearchAndEnter: Bad character in ACPI Name
```

That message was sitting in the log for a long time before anyone read it.
Reading the guest's own diagnostics beats instrumenting the emulator.

### 5. The SCSI adapter was invisible

The `devices.pci.00100c00` fileset claims a single PCI device ID, and the list
that `get_ncr_scsi_name()` accepts is `0001`, `0002`, `0003`, `000b`, `000c`,
`000f`, `1010`. The emulator's LSI model presents `0012`, a 53C895A, which falls
through to an error return. The `scsi-895` machine option rewrites the device ID
to `000c` after realize, and `scsi0` appears in the guest's device database,
with `cd0` and `hdisk0` behind it.

### 6. The SCSI driver could not map its own registers

`io_map_init()` returned NULL, and inside the kernel `io_map_validate()` was
rejecting the request. The rejection is not a coverage check, it is a
**collision** check: overlapping any registered range is a refusal. The address
being asked for was `0x01000000`, which on this machine is RAM.

That address is the placeholder default in the adapter's predefined attributes:

```
PdAt: uniquetype = "adapter/pci/sym895"
      attribute = "bus_mem_addr"   deflt = "0x01000000"
```

A placeholder, meant to be overwritten by the resolved resources. Its presence
in the driver's device structure proved the resources had never been resolved.

### 7. Why they were never resolved: 64-bit ACPI descriptors

The jump table of `parse_acpi_res_info()` in the guest's `libcfg_ia64.so` sends
`ACPI_RSTYPE_ADDRESS64` (13) to the same destination as END_TAG, which is
nowhere. Only ADDRESS16 (11) and ADDRESS32 (12) reach the range processor.

The PCI root's `_CRS` used `QWordIO` and `QWordMemory`, so the root bus had no
producers at all, `get_host_bus_possible_ranges()` failed, the resolved
addresses never reached the guest's configuration database, and the driver was
handed the placeholder. Changing them to `DWordIO` and `DWordMemory` fixed the
whole chain.

There is a cost, and anyone retargeting this firmware should know it: the port
window's translation offset (`0x800010000000`) does not fit in 32 bits. AIX does
not care, because it reaches ports through `pal_command` and hardcodes
`0xFFFFC000000`, but Windows and Linux need the QWord form back.

The memory producer must also stay `NonCacheable`. AIX accepts only producers
with attribute `c` or `P`; `C`acheable and `W` are discarded, which is why the
legacy holes at `0xA0000` and `0xC0000` do not count.

### 8. Interrupts stopped arriving, and the guest idled forever

Mid-install the guest froze in `waitproc`. The measurement: the HBA's interrupt
had been delivered to the SAPIC IRR 314 times and acknowledged 313 times, and
`psr.i` was 1, TPR was 0, ISR was 0, and the IRR was holding both the pending
HBA vector and the timer vector.

An external interrupt that arrives while `psr.i` is 0 is rejected and left
pending. Only the main loop re-examines `interrupt_request`, so the instruction
that re-enables `psr.i` has to end its translation block by returning there.
Two sites chained to the next block instead: `IA64_DISAS_EXIT`, which fell
through to the `DISAS_TOO_MANY` arm and used a direct jump, and `rfi`, which
used `lookup_and_goto_ptr`. Once the `ssm psr.i` block chained straight into an
already chained idle loop, no block entry ever returned to the main loop and the
pending vector was never taken. A lost wakeup.

Also not AIX specific.

### 9. The installer stopped at "Please define the System Console"

With no keyboard, that prompt is a wall. The way past it turned out not to
require a keyboard at all.

`bi_main`, the installer's main program, is a **plain Korn shell script, in the
clear, on the CD**, at `/usr/lpp/bosinst/bi_main`. When booting from CD it
copies `/SPOT/usr/lpp/bosinst/bosinst.template`, a file that is also on the CD,
to `/bosinst.data`, and it does so **before** it calls `Set_Console`. So the
answer file can be edited on the medium rather than in the guest.

The edit is done in place: the file is rewritten inside its own ISO9660 extent
at exactly its original length, absorbing the size delta in its own comment
header, so the directory record stays valid and the image does not have to be
rebuilt.

Three separate locks had to be opened, not one:

1. **The console.** `PROMPT=no` together with `CONSOLE=/dev/lft0` makes
   `Set_Console` call `chcons` directly instead of running the console finder.
2. **A request for CD volume 2.** The disc carries two tables of contents, and
   the multivolume one encodes the volume per package as `vol%N/ia64/...`. The
   only volume 2 fileset in the default selection is `sysmgt.help.en_US.websm`,
   pulled in by `BOS.autoi`, which `INSTALL_CONFIGURATION = Minimal` does not
   use.
3. **The post install assistant.** It is only avoided with `RUN_STARTUP=no`
   **and** `ACCEPT_LICENSES=yes`.

With those, the install runs to completion unattended in about 54 minutes and
the machine reboots into `Console login:` on its own.

### 10. The keyboard, part one: a string where a number belonged

`UAR0`, a memory mapped serial port in the SSDT, declared
`Name (_HID, "PNP0501")` as a **string**. `acpi_get_child_dvc_info()` in the
guest's `libacpi.so` tolerates only statuses 0 and 38 when it fetches the `_HID`
of each child of `PCI0`. A string produces 44, the 44 propagated out,
`match_acpi_dvc()` cached an **empty child list** and never retried, and so no
device leaf was ever correlated with its ACPI node. The keyboard was one of the
casualties.

Spelling it `EisaId` instead fixes the enumeration and then hangs `cfgmgr`,
because `devices.isa_sio.PNP0501` tries to claim a memory mapped UART that it
cannot drive. Removing the device from the namespace fixes both at once and
costs nothing, because AIX has no way to use that port. `UAR1`, the port mapped
16550 at `0x3f8`, stays and is what the guest actually uses.

Measured across that change: correlation calls 0 to 91, child list iterations
0 to 91, matches 0 to 7, and the keyboard adapter, the keyboard and its driver
went from absent to present.

### 11. The keyboard, part two: a scan code list cut short

With the keyboard enumerated, AIX initialised the i8042 and then a key press
produced **no port activity at all**. The obvious reading was that the interrupt
was never unmasked.

That reading was wrong, and reading the trace as a **sequence** rather than
looking at its last event showed why. The nine command block

```
f5  f3 25  f0 03  fa  fc 39 19
```

repeats **nine times, identically**, and only then does AIX write `0x30` to the
command byte, which disables both port clocks and the keyboard interrupt. That
is not a missing interrupt. It is a retry loop giving up. The final `0x30`
looked like the cause and was the consequence.

The handshake is polled, so the answer was measurable: after each write there is
a status read and a data read. The port trace was printing the port but not the
value, which is the difference between "the guest polled 0x60" and "the guest
read `0xfe` from 0x60", the same log line and opposite diagnoses. With the value
added:

| written | read back | |
|---|---|---|
| `f5` reset and disable | `fa` | ACK |
| `f3` `25` set typematic rate | `fa` `fa` | ACK |
| `f0` `03` select scan code set 3 | `fa` `fa` | ACK |
| `fa` set all keys typematic make/break | `fa` | ACK |
| `fc` set key type make/break | `fa` | ACK |
| `39` first scan code of the list | `fa` | ACK |
| **`19` second scan code of the list** | **`fe`** | **Resend** |

In scan code set 3, `0xfb`, `0xfc` and `0xfd` are followed by a **list** of scan
codes, each acknowledged, and the list has no count and no terminator: it runs
until the keyboard receives its next command. The emulator consumed exactly one
byte, so the second scan code of the list fell through to the unknown command
arm and was answered Resend. The three "set all keys" commands `0xf7`, `0xf8`
and `0xf9` were not recognised at all either.

Set 3 scan codes never reach `0xed`, so keeping the list open until a byte in
the command range arrives is unambiguous.

After the fix: retries 9 to 0, total port accesses 330 to 197, the sequence runs
on through `ed 00` (LEDs) to `f4`, enable scanning, acknowledged. A press of F1
now produces `07`, `f0`, `07`, which is make and break of F1 in set 3, where
before it produced nothing.

This is a general emulator bug, not an IA-64 one. Any guest that programs a
keyboard in set 3 hits it.

### 12. The result

Reinstalled with the corrected firmware, the guest boots from `hdisk0` and
reports:

```
sioka0   Available 64-A0         Keyboard Adapter
kbd0     Available 64-A0-00-00   P/S 2 keyboard
siona0   Available 64-B0         Mouse Adapter
mouse0   Available 64-B0-00-00   3 button mouse
```

All four Available rather than Defined, so the install detected them and pulled
in their support. The mouse was never chased; it came with the same fileset as
the keyboard.

---

## Instrumentation

All of it is compiled in but inert unless the matching environment variable is
set, and none of it changes guest visible behaviour.

| variable | what it does |
|---|---|
| `AIX_WATCH` | dump registers at chosen instruction addresses |
| `AIX_WATCH_GP` | only when the global pointer matches, to tell processes apart |
| `AIX_WATCH_AT`, `_PTR`, `_DEREF` | dump memory at a register, or one level through a pointer |
| `AIX_WATCH_ALL`, `_MAX`, `_STR` | widen the dump, raise the per address hit cap, print as text |
| `AIX_MEMFIND` | search guest RAM for a string, with `_HEX`, `_BEFORE`, `_MAX` |
| `AIX_POKE` | rewrite a string in guest RAM, repeatedly |
| `AIX_HEXPOKE` | rewrite raw bytes by pattern, invalidating translation blocks |
| `AIX_TRACE_PCI` | trace port and configuration accesses, with values |
| `AIX_TRACE_IOSAPIC` | trace redirection table writes, deliveries and EOIs |

Notes that cost time to learn:

- Watch addresses must be **bundle aligned**, a multiple of 16. An unaligned
  address simply never fires, which reads as "that code never runs".
- A watch dumps at the **start** of a bundle, so registers that bundle writes
  are not set yet.
- The hit cap is **per address**, and unrelated processes share code addresses,
  because every AIX executable is linked at the same base. If a watch comes back
  empty, raising the cap is the first thing to try.
- The runtime global pointer of a method is its `__GLOB_DATA_PTR` plus
  `0x20000`. Without that filter the watches are unusable.
- Patching code through the host pointer leaves stale translation blocks alive.
  `AIX_HEXPOKE` invalidates them; anything else must too.
- Scanning all of RAM per rule per tick slows the guest by roughly ten times,
  which can push the target outside the window you are trying to patch. The
  scan backs off once every rule has matched.

---

## Building

The emulator builds like upstream QEMU. The firmware needs an **IA-64 cross
toolchain**, which Ubuntu does not package. Fedora does:

```sh
dnf install -y gcc-ia64-linux-gnu binutils-ia64-linux-gnu
```

which is what this repository's CI uses. A self built `ia64-linux-gnu-`
toolchain works as well; the firmware's Makefile takes `CROSS` to point at one.

```sh
mkdir build && cd build
../configure --target-list=ia64-softmmu --enable-gtk --enable-slirp \
             --disable-docs --disable-werror
ninja qemu-system-ia64 roms/ia64-firmware/ia64-firmware.bin
```

## Running AIX

The machine needs three non default options, and one of them forces a fourth.

```sh
./build/qemu-system-ia64 \
  -machine ia64-vpc,ahci=off,scsi-895=on,isa-bridge=on,nvram=aix.nvram \
  -cpu merced \
  -bios ./build/roms/ia64-firmware/ia64-firmware.bin \
  -m 2G \
  -drive file=aix.qcow2,format=qcow2 \
  -drive file=AIX-VOLUME1.iso,media=cdrom,format=raw,readonly=on \
  -nic none \
  -display gtk
```

- `scsi-895=on` presents the HBA as a 53C895, which is the only LSI device ID
  the shipped driver claims.
- `isa-bridge=on` adds the bridge the guest expects the i8042 behind.
- `ahci=off` because the guest has no driver for it.
- `-nic none` is **required** with `isa-bridge=on`: the bridge stub and the
  default network adapter both want PCI devfn 6, and the machine will refuse to
  start otherwise.
- `-cpu merced`. The guest predates Madison.

Drop the `-drive` for the ISO once the system is installed.

### Unattended install

The installer stops at the console prompt unless the answer file on the medium
says otherwise. Rewrite `/SPOT/usr/lpp/bosinst/bosinst.template` inside the ISO,
in place and at the same length, with at least:

```
control_flow:
    CONSOLE = /dev/lft0
    PROMPT = no
    ACCEPT_LICENSES = yes
    INSTALL_CONFIGURATION = Minimal
    EXISTING_SYSTEM_OVERWRITE = yes
    RUN_STARTUP = no
target_disk_data:
    HDISKNAME = hdisk0
```

`INSTALL_CONFIGURATION = Minimal` is what keeps the installer from asking for
CD volume 2. The install takes about 54 minutes and reboots itself.

The installation media is IBM's and is not distributed here.

---

## What is still open

- No network. The bridge stub and the default adapter collide at devfn 6, so the
  guest currently runs with `-nic none`. Moving one of them is the fix. Until
  then, [PORTS.md](PORTS.md) is how to get software onto the guest anyway: a CD
  image built on the host from the precompiled packages that
  [johnsonjh](https://github.com/johnsonjh) maintains in
  [johnsonjh/AIX5-IA64](https://github.com/johnsonjh/AIX5-IA64).
- The serial console has not been exercised; the guest runs on the graphical
  console.
- **X starts but renders no text.** The X11 filesets install, the native ATI
  driver binds with `ati-rage128=on`, and `xinit` brings up a Motif desktop:
  frames are drawn, the clock draws its hands, the pointer tracks. But no
  glyph appears anywhere, so the desktop cannot be used. A missing font
  package is ruled out: `100dpi` and `75dpi` carry 338 fonts each and `misc`
  64, all indexed, and `misc` is where `fixed` lives. It is either the
  server's font path or text being drawn in the background colour on the path
  where the native driver replaced the generic VGA.
  [PORTS.md](PORTS.md) has the evidence and how to probe a session that
  cannot report on itself.

- **The branch does not pass this project's own test gate.** Five suites fail:
  `firmware-layout`, `source-includes`, `tcg-mmu`, `tcg-rse` and `tcg-pal`.
  Upstream `develop` passes, so these are this branch's doing, and two of them
  are real invariants rather than stale expectations:

  - The firmware must start exactly at `FW_LOAD_BASE` (`0x00100000`), and the
    relink that makes room for the AIX loader moves the base to `0x00300000`.
    The window itself runs to `0x00800000`, so there is room to grow upward,
    just not to move the base. The conflict is genuine: `BOOTIA64.EFI` has a
    fixed `ImageBase` of `0x1ff000` with its relocations stripped, and a
    firmware starting at 1 MiB covers it. Freeing that region rather than
    moving the base is the fix, and it is a redesign.
  - `target/ia64/arch/` may not call TCG implementation APIs nor use raw
    architectural register indexes. The `AIX_WATCH` instrumentation in
    `arch/firmware.c` does both, in twelve places. That one is mechanical:
    move the instrumentation out of `arch/`, or use the named constants.

  Whoever picks this up should run the gate first for a baseline:
  `meson test` in the build directory, with an IA-64 cross toolchain on the
  path (Fedora packages `gcc-ia64-linux-gnu`; Ubuntu has none).
- Only the `merced` CPU model has been tested.

---

## The instrument traps, collected

Every one of these produced a confident wrong answer that had to be retracted.
They are all the same mistake in different clothes: **choosing a signal that
cannot tell the hypothesis from its negation**.

1. **A trace without the value is useless for a handshake.** "The guest polled
   0x60" and "the guest read `0xfe` from 0x60" are the same log line and
   opposite diagnoses.
2. **Read the whole sequence before the last event.** The final `0x30` that
   disabled the keyboard looked like the cause; the nine identical repeats
   before it were the cause, and they had been in the log all along.
3. **A pattern that only covers part of the range answers for the whole range.**
   A trace that started at pin 16 answered "no interrupt" for a device on pin 1,
   and a stale comment claiming that limit is what kept the wrong belief alive
   after the code had changed. An out of date comment misleads exactly like a
   badly chosen instrument.
4. **Grep the tool's real output format.** Counting `port=0x60` in a log that
   says `port 060/1` reports zero accesses where there were 330. Always confirm
   the instrument produces **anything** before trusting a zero.
5. **Addresses have alignment rules.** Unaligned watch addresses never fire, and
   never firing looks exactly like never executing.
6. **The instrument's own cost can move the target.** Scanning 2 GiB per rule
   per tick slowed the guest tenfold and pushed the event outside the window,
   which read as "the pattern is not there".
7. **Patching code is not patching memory.** Without invalidating translation
   blocks the old code keeps running and the patch reads as ineffective.
8. **A comparison against a constant tells you what the code expects, not what
   it receives.** A thesis built on `cmp4.eq 44` survived six experiments before
   anyone checked whether the other side ever sends anything else. It did not:
   the 44 arrived as data and the comparison already matched. The two minute
   check that would have caught it is to search the binary for an instruction
   that generates the constant, and notice there is none.

And one that is not about instruments at all: **`git checkout <file>` does not
undo part of an edit.** It returns the file to HEAD, which here meant upstream
without any of the fixes, and nearly produced a triumphant wrong conclusion
about which change mattered.
