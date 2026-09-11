#!/bin/sh
# Build the V9990 R#22 (SDA/SDB) test ROMs.
#
# Needs sjasmplus: https://github.com/z00m128/sjasmplus
# Override the assembler with e.g.  SJASMPLUS=/path/to/sjasmplus ./build.sh

set -e
cd "$(dirname "$0")"

SJASMPLUS="${SJASMPLUS:-sjasmplus}"

for src in v9990_r22_[0-9]_*.asm; do
    rom="${src%.asm}.rom"
    "$SJASMPLUS" --nologo --raw="$rom" "$src"
    printf '%-32s %s bytes\n' "$rom" "$(wc -c < "$rom" | tr -d ' ')"
done
