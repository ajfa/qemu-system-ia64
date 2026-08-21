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
LIBGCC="$("$CC" -print-libgcc-file-name)"

set --
LINKER_SCRIPT=
DEPFILES=

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
                -I"$INCLUDE_DIR" \
                -Wall -Wextra -Wno-unused-parameter \
                -MMD -MP -MF "$object_depfile" -MT "$OUT_BIN" \
                -c -o "$object" "$source_path"
            set -- "$@" "$object"
            DEPFILES="${DEPFILES} ${object_depfile}"
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
    echo "$OUT_BIN: $MANIFEST $LINKER_SCRIPT $SRC_DIR/build_firmware.sh"
} > "$DEPFILE"
