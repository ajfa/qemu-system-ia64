#!/usr/bin/env python3
"""Enforce IA-64 source and subsystem boundaries."""

from __future__ import annotations

import pathlib
import re
import sys


OWNED_PATHS = (
    "target/ia64",
    "hw/ia64",
    "include/hw/ia64",
    "roms/ia64-firmware",
    "tests/unit/ia64",
    "tests/functional/ia64",
)
SOURCE_INCLUDE = re.compile(
    r'^\s*#\s*include\s+"[^"]+\.c"', re.MULTILINE
)
# The IA-32 engine is built by wrapping upstream's i386 translation units:
# each target/ia64/ia32/*.c file sets up macro redirections and then
# includes the corresponding target/i386 source.  The wrapper *is* the
# translation-unit boundary there, so those includes are the design, not a
# violation of it.
IA32_ENGINE_INCLUDE = re.compile(
    r'^\s*#\s*include\s+"target/i386/[^"]+\.c"'
)
IA32_ENGINE_DIR = "target/ia64/ia32/"
ARCH_TCG_DEPENDENCY = re.compile(
    r'#\s*include\s+"accel/tcg/'
    r'|\b(?:TCGv\w*|GETPC|HELPER\s*\(|tcg_\w+)'
    r'|\b(?:cpu_mmu_index|cpu_loop_exit_atomic|probe_access_\w+|probe_write)\b'
    r'|\bcpu_(?:ld|st|atomic_cmpxchg)\w*\b'
    r'|\b(?:cpu_memory_rw_debug|cpu_physical_memory_\w+|address_space_\w+)\b'
    r'|\bhelper_\w+\b'
)
RAW_DECODER_VIEW = re.compile(r'\boperands\.decoder\b')
# The IA-32 engine's private CPUX86State is always accessed through a
# variable named xenv; its cr[]/dr[] files keep upstream i386's numeric
# indexing, where the number is the architectural name (cr[0] is CR0).
# Only bare IA-64 register-file indexes need named constants.
NUMERIC_REGISTER_INDEX = re.compile(
    r'(?<!xenv->)'
    r'\b(?:gr|br|pr|ar|cr|fr|rr|pkr|dbr|ibr)\s*\[\s*'
    r'(?:0[xX][0-9a-fA-F]+|[0-9]+)\s*\]'
)


def regex_violations(
    source_root: pathlib.Path,
    roots: tuple[str, ...],
    pattern: re.Pattern[str],
    allowed: frozenset[str] = frozenset(),
    exempt=None,
) -> list[str]:
    result = []
    for relative_root in roots:
        root = source_root / relative_root
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = str(path.relative_to(source_root))
            if relative in allowed:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for match in pattern.finditer(text):
                if exempt is not None and exempt(relative, match.group(0)):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                result.append(f"{relative}:{line}")
    return result


def report(index: int, description: str, found: list[str]) -> bool:
    if found:
        print(f"not ok {index} - {description}")
        for item in found:
            print(f"# {item}")
        return False
    print(f"ok {index} - {description}")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Bail out! usage: test-ia64-source-includes.py SOURCE_ROOT")
        return 1

    source_root = pathlib.Path(sys.argv[1])
    print("TAP version 13")
    print("1..4")
    passed = [
        report(
            1,
            "IA-64 sources use translation-unit boundaries",
            regex_violations(
                source_root,
                OWNED_PATHS,
                SOURCE_INCLUDE,
                exempt=lambda relative, matched: (
                    relative.startswith(IA32_ENGINE_DIR)
                    and IA32_ENGINE_INCLUDE.match(matched) is not None
                ),
            ),
        ),
        report(
            2,
            "IA-64 arch code is independent of TCG implementation APIs",
            regex_violations(
                source_root, ("target/ia64/arch",), ARCH_TCG_DEPENDENCY
            ),
        ),
        report(
            3,
            "raw decoder operands stay inside the decoder",
            regex_violations(
                source_root,
                ("target/ia64",),
                RAW_DECODER_VIEW,
                frozenset({"target/ia64/decode/decode.c"}),
            ),
        ),
        report(
            4,
            "architectural register indexes use named constants",
            regex_violations(
                source_root, ("target/ia64",), NUMERIC_REGISTER_INDEX
            ),
        ),
    ]
    return 0 if all(passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
