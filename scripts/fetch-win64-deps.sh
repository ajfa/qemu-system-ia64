#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fetch the pinned MSYS2 MinGW64 libraries used by the Linux-to-Windows build.

set -eu

error()
{
    printf 'fetch-win64-deps: %s\n' "$*" >&2
    exit 1
}

for command_name in awk cat curl dirname mkdir mv rm sha256sum tar; do
    command -v "$command_name" >/dev/null 2>&1 ||
        error "required command not found: $command_name"
done

SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -P "$SCRIPT_DIR/.." && pwd)
DEPS_DIR=${1:-"$SOURCE_DIR/build-win64-deps"}
REPOSITORY=${MSYS2_MINGW64_REPOSITORY:-https://repo.msys2.org/mingw/mingw64}

mkdir -p "$DEPS_DIR"
DEPS_DIR=$(CDPATH= cd -P "$DEPS_DIR" && pwd)
PACKAGE_DIR="$DEPS_DIR/packages"
mkdir -p "$PACKAGE_DIR"

PACKAGES=$(command cat <<'EOF'
5991afbcfeb2f8b838ab80b2270d713a727199ca392715677a7c1931a0d9ecef mingw-w64-x86_64-SDL2-2.32.10-1-any.pkg.tar.zst
be68d7f260633284b910c588c6d82ee304a81c8817a686d2cd9df83f872c27af mingw-w64-x86_64-gettext-runtime-1.0-1-any.pkg.tar.zst
5aa850934d0216f5b7237bd54c3ec660ebfc3a42fd992bc7abbd611bd9cc7663 mingw-w64-x86_64-glib2-2.88.3-1-any.pkg.tar.zst
a016df13c67a0438a0b94267f2911c68fd4d7216b4d45fbac7a66af41fe78f44 mingw-w64-x86_64-libffi-3.7.1-1-any.pkg.tar.zst
21e334d0911f25de75d3e18e0697648bcecfa9658256d600cad0827d719c2f35 mingw-w64-x86_64-libiconv-1.19-1-any.pkg.tar.zst
f695f6084c516374a483c167407d424acc41b33b4bd22133558e87239f9db058 mingw-w64-x86_64-libslirp-4.9.3-1-any.pkg.tar.zst
7c9e3cd47af02a096c0c1810d1021f63c5fb1d22dbec91fa019d8b37eda00d98 mingw-w64-x86_64-pcre2-10.47-1-any.pkg.tar.zst
435715dd1ca4c55873cf3c38d644615196bc2d238e3366f8ff81cc0811260eb2 mingw-w64-x86_64-pixman-0.46.4-3-any.pkg.tar.zst
9e75842a070ba648e986e12424e1c92c9d7d77200e85f6a34eeb600819f2e694 mingw-w64-x86_64-zlib-1.3.2-2-any.pkg.tar.zst
EOF
)

MANIFEST_HASH=$(printf '%s\n' "$PACKAGES" | sha256sum | awk '{print $1}')
SYSROOT="$DEPS_DIR/sysroot-$MANIFEST_HASH"
REQUIRED_FILES="
mingw64/bin/SDL2.dll
mingw64/bin/libglib-2.0-0.dll
mingw64/bin/libpixman-1-0.dll
mingw64/bin/libslirp-0.dll
mingw64/lib/pkgconfig/glib-2.0.pc
mingw64/lib/pkgconfig/pixman-1.pc
mingw64/lib/pkgconfig/sdl2.pc
mingw64/lib/pkgconfig/slirp.pc
"

verify_file()
{
    expected_hash=$1
    file=$2
    actual_hash=$(sha256sum "$file" | awk '{print $1}')
    test "$actual_hash" = "$expected_hash"
}

verify_sysroot()
{
    root=$1

    test -f "$root/.qemu-win64-deps" &&
        test "$(command cat "$root/.qemu-win64-deps")" = "$MANIFEST_HASH" ||
        return 1

    for required_file in $REQUIRED_FILES; do
        test -f "$root/$required_file" || return 1
    done
}

if verify_sysroot "$SYSROOT"; then
    printf '%s\n' "$SYSROOT"
    exit 0
fi

if test -e "$SYSROOT"; then
    error "existing sysroot is incomplete or invalid: $SYSROOT"
fi

STAGING="$SYSROOT.tmp.$$"
DOWNLOAD_TEMPORARY=
test ! -e "$STAGING" || error "temporary path already exists: $STAGING"
mkdir -p "$STAGING"

cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    if test -n "${DOWNLOAD_TEMPORARY:-}" &&
            test -f "$DOWNLOAD_TEMPORARY"; then
        rm -f "$DOWNLOAD_TEMPORARY"
    fi
    if test -n "${STAGING:-}" && test -d "$STAGING"; then
        rm -rf "$STAGING"
    fi
    exit "$status"
}
trap cleanup 0 1 2 3 15

while read -r expected_hash filename; do
    destination="$PACKAGE_DIR/$filename"

    if test -f "$destination" &&
            verify_file "$expected_hash" "$destination"; then
        printf 'Using %s\n' "$filename" >&2
    else
        temporary="$destination.tmp.$$"
        DOWNLOAD_TEMPORARY=$temporary
        test ! -e "$temporary" ||
            error "temporary download already exists: $temporary"
        printf 'Downloading %s\n' "$filename" >&2
        curl --fail --location --retry 3 --silent --show-error \
            --output "$temporary" "$REPOSITORY/$filename"
        verify_file "$expected_hash" "$temporary" ||
            error "SHA-256 mismatch for $filename"
        mv "$temporary" "$destination"
        DOWNLOAD_TEMPORARY=
    fi

    tar --zstd --extract --file "$destination" --directory "$STAGING"
done <<EOF
$PACKAGES
EOF

for required_file in $REQUIRED_FILES; do
    test -f "$STAGING/$required_file" ||
        error "package set did not provide $required_file"
done

printf '%s\n' "$MANIFEST_HASH" > "$STAGING/.qemu-win64-deps"
mv "$STAGING" "$SYSROOT"
STAGING=
printf '%s\n' "$SYSROOT"
