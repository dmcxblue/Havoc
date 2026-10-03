#!/usr/bin/env bash
# fixcase.sh — resolve #include case mismatches (mimikatz is written on Windows,
# a case-insensitive FS; Linux is case-sensitive). Creates symlinks in a
# casefix/ dir (added first to the include path) mapping wrong-case names to
# the real files. Idempotent.
set -uo pipefail

MIK="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$MIK/BOF/casefix"
mkdir -p "$FIX"

INCDIRS=("$MIK/inc" "$MIK/modules" "$MIK/mimikatz/modules")

# 1. collect every quoted include across the tree
grep -rhoE '#\s*include\s+"[^"]+"' "$MIK/inc" "$MIK/modules" "$MIK/mimikatz" 2>/dev/null \
  | sed -E 's/.*include\s+"([^"]+)"/\1/' \
  | sort -u > /tmp/miki_includes.txt

fixed=0
while IFS= read -r inc; do
    [ -z "$inc" ] && continue
    # try to resolve case-sensitively against any include dir
    found=""
    for d in "${INCDIRS[@]}"; do
        if [ -e "$d/$inc" ]; then found="$d/$inc"; break; fi
    done
    [ -n "$found" ] && continue   # already resolves fine

    # case-insensitive search for the basename across all include dirs
    base="$(basename "$inc")"
    real=""
    for d in "${INCDIRS[@]}"; do
        r="$(find "$d" -maxdepth 4 -iname "$base" -print -quit 2>/dev/null)"
        if [ -n "$r" ]; then real="$r"; break; fi
    done
    [ -z "$real" ] && continue     # genuinely missing header (report later)

    # symlink: casefix/<wrong-case-path> -> real
    dest="$FIX/$inc"
    mkdir -p "$(dirname "$dest")"
    if [ ! -e "$dest" ]; then
        rel="$(python3 - "$dest" "$real" <<'PY'
import os,sys
d=os.path.abspath(sys.argv[1]); r=os.path.abspath(sys.argv[2])
print(os.path.relpath(r, os.path.dirname(d)))
PY
)"
        ln -s "$rel" "$dest"
        fixed=$((fixed+1))
        echo "  [fix] $inc -> $(basename "$real")"
    fi
done < /tmp/miki_includes.txt

echo "== casefix: $fixed symlink(s) created in $FIX =="
