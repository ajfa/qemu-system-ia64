#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 BIN ELF MAP SECTIONS SOURCE_DIR DEPFILE" >&2
    exit 2
fi

OUT_BIN="$1"
FW_ELF="$2"
FW_MAP="$3"
FW_SECTIONS="$4"
SRC_DIR="$5"
DEPFILE="$6"
OUT_DIR="$(dirname "$OUT_BIN")"
INCLUDE_DIR="${SRC_DIR}/../../include"
MANIFEST="${SRC_DIR}/firmware.sources"

AS="${AS:-ia64-linux-gnu-as}"
CC="${CC:-ia64-linux-gnu-gcc}"
LD="${LD:-ia64-linux-gnu-ld}"
OBJCOPY="${OBJCOPY:-ia64-linux-gnu-objcopy}"
SIZE="${SIZE:-ia64-linux-gnu-size}"
IASL="${IASL:-iasl}"
LIBGCC="$("$CC" -print-libgcc-file-name)"

set --
LINKER_SCRIPT=
DEPFILES=
ASL_SOURCES=
ACPI_SIZES_H="${OUT_DIR}/ia64-fw-acpi-aml.h"

# Compile the ACPI table sources first: the generated .inc/.h fragments are
# included by firmware.c, so the AML byte arrays can never drift from the
# .asl sources again.  -on -oi keep integer literals as typed opcodes
# (Linux 2.4's ACPI CA rejects ZeroOp/OneOp *package elements* -- see
# plans/status.md 2.3).
: > "$ACPI_SIZES_H"
while IFS= read -r source || [ -n "$source" ]; do
    case "$source" in
        *.asl) ;;
        *) continue ;;
    esac
    source_path="${SRC_DIR}/${source}"
    stem="${source##*/}"
    stem="${stem%.*}"
    aml="${OUT_DIR}/ia64-fw-${stem}.aml"
    inc="${OUT_DIR}/ia64-fw-${stem}.inc"
    "$IASL" -p "${OUT_DIR}/ia64-fw-${stem}" -on -oi "$source_path" \
        > "${OUT_DIR}/ia64-fw-${stem}.iasl.log" 2>&1 || {
        command cat "${OUT_DIR}/ia64-fw-${stem}.iasl.log" >&2
        echo "iasl failed for $source (set IASL= to a working binary)" >&2
        exit 2
    }
    # Strip the 36-byte SDT header: the firmware builds and patches its own.
    od -An -v -tx1 -j36 "$aml" | \
        awk '{ for (i = 1; i <= NF; i++) printf "0x%s,", $i; print "" }' \
        > "$inc"
    aml_size=$(( $(wc -c < "$aml") - 36 ))
    guard="$(printf '%s' "$stem" | tr 'a-z-' 'A-Z_')"
    printf '#define FW_%s_AML_SIZE %su\n' "$guard" "$aml_size" \
        >> "$ACPI_SIZES_H"
    ASL_SOURCES="${ASL_SOURCES} ${source_path}"
done < "$MANIFEST"

while IFS= read -r source || [ -n "$source" ]; do
    case "$source" in
        ''|'#'*)
            continue
            ;;
    esac

    source_path="${SRC_DIR}/${source}"
    stem="${source##*/}"
    stem="${stem%.*}"
    object="${OUT_DIR}/ia64-fw-${stem}.o"

    case "$source" in
        *.S)
            # Via $CC so the C preprocessor runs: entry.S includes the shared
            # ABI header.  Dependencies tracked like the C objects.
            object_depfile="${object}.d"
            "$CC" -nostdinc -nostdlib -I"$INCLUDE_DIR" \
                -MMD -MP -MF "$object_depfile" -MT "$OUT_BIN" \
                -c -o "$object" "$source_path"
            set -- "$@" "$object"
            DEPFILES="${DEPFILES} ${object_depfile}"
            ;;
        *.c)
            object_depfile="${object}.d"
            "$CC" -O2 -fno-builtin -ffreestanding -nostdinc -nostdlib \
                -G 0 -mno-sdata -fno-stack-protector -fno-common \
                -fno-optimize-sibling-calls -fno-pic \
                -I"$INCLUDE_DIR" -I"$OUT_DIR" \
                -Wall -Wextra -Wno-unused-parameter \
                -MMD -MP -MF "$object_depfile" -MT "$OUT_BIN" \
                -c -o "$object" "$source_path"
            set -- "$@" "$object"
            DEPFILES="${DEPFILES} ${object_depfile}"
            ;;
        *.asl)
            # Compiled in the first pass above.
            ;;
        *.lds)
            LINKER_SCRIPT="$source_path"
            ;;
        *)
            echo "unsupported firmware manifest entry: $source" >&2
            exit 2
            ;;
    esac
done < "$MANIFEST"

if [ -z "$LINKER_SCRIPT" ]; then
    echo "firmware manifest does not name a linker script" >&2
    exit 2
fi

"$LD" -nostdlib -static -T "$LINKER_SCRIPT" -Map="$FW_MAP" \
    -o "$FW_ELF" "$@" "$LIBGCC"
"$OBJCOPY" -O binary "$FW_ELF" "$OUT_BIN"
"$SIZE" -A "$FW_ELF" > "$FW_SECTIONS"

{
    for dependency in $DEPFILES; do
        command cat "$dependency"
    done
    echo "$OUT_BIN: $MANIFEST $LINKER_SCRIPT $SRC_DIR/build_firmware.sh" \
        "$ASL_SOURCES"
} > "$DEPFILE"
