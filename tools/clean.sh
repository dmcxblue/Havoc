#!/usr/bin/env bash
#
# clean.sh - Havoc repository cleanup utility
#
# Removes non-essential / generated artifacts: build output, compiled binaries,
# generated implants, runtime databases, TLS certs/keys, downloaded loot, and
# editor/OS cruft.
#
# SAFETY MODEL
#   * Dry-run by default: nothing is deleted unless you pass --force (or -f).
#   * Never deletes files that git tracks. Every candidate is checked with
#     `git ls-files --error-unmatch` and skipped if it is under version control.
#     This protects the committed loaders (payloads/*.bin), source, and profiles.
#   * Root-owned artifacts (e.g. a `havoc` binary built as root) are removed with
#     sudo, and the script warns instead of failing when sudo is unavailable.
#
# USAGE
#   tools/clean.sh                 # dry run, ALL categories (shows what would go)
#   tools/clean.sh --force         # actually delete ALL categories
#   tools/clean.sh --build --data  # only those categories (dry run)
#   tools/clean.sh --build -f      # delete only build artifacts
#
# CATEGORIES
#   --build     client/Build, client/build, teamserver/bin, CMake output
#   --binaries  compiled havoc / teamserver server binaries
#   --implants  generated demon payloads (compiled, NOT the committed *.bin)
#   --data      runtime databases (data/*.db)
#   --certs     TLS material (data/server.cert, data/server.key, stray *.key/*.cert)
#   --loot      downloaded loot (data/loot/*)
#   --python    __pycache__, *.pyc, *.pyo
#   --cruft     .DS_Store, Thumbs.db, *.swp, *.swo, *~, .idea
#   --toolchain data/*-w64-mingw32-cross (downloaded MinGW/MUSL cross compilers)
#   --all       every category above (default when none specified)
#
set -uo pipefail

# --- locate repo root ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || { echo "cannot cd to repo root"; exit 1; }

# --- flags --------------------------------------------------------------------
FORCE=0
declare -A WANT
ANY_CATEGORY=0

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

for arg in "$@"; do
    case "$arg" in
        -f|--force|--yes) FORCE=1 ;;
        -h|--help)        usage ;;
        --all)            WANT[all]=1; ANY_CATEGORY=1 ;;
        --build|--binaries|--implants|--data|--certs|--loot|--python|--cruft|--toolchain)
                          WANT[${arg#--}]=1; ANY_CATEGORY=1 ;;
        *) echo "unknown option: $arg"; echo "run with --help"; exit 1 ;;
    esac
done

# default to everything if no category was named
if [ "$ANY_CATEGORY" -eq 0 ]; then WANT[all]=1; fi
want() { [ -n "${WANT[all]:-}" ] || [ -n "${WANT[$1]:-}" ]; }

HAVE_GIT=0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 && HAVE_GIT=1

# --- counters -----------------------------------------------------------------
TOTAL_ITEMS=0
TOTAL_BYTES=0

human() {  # bytes -> human readable
    local b=$1
    if   [ "$b" -ge 1073741824 ]; then printf '%.1fG' "$(echo "$b/1073741824" | bc -l)"
    elif [ "$b" -ge 1048576 ];    then printf '%.1fM' "$(echo "$b/1048576" | bc -l)"
    elif [ "$b" -ge 1024 ];       then printf '%.1fK' "$(echo "$b/1024" | bc -l)"
    else printf '%dB' "$b"; fi
}

is_tracked() {  # 0 = tracked by git (must NOT delete)
    [ "$HAVE_GIT" -eq 1 ] || return 1
    git ls-files --error-unmatch "$1" >/dev/null 2>&1
}

size_of() { du -sb "$1" 2>/dev/null | cut -f1 || echo 0; }

# remove one path (file or dir). honors dry-run, git protection, root ownership.
remove_path() {
    local p="$1"
    [ -e "$p" ] || [ -L "$p" ] || return 0

    if is_tracked "$p"; then
        printf '   \033[33mskip (tracked)\033[0m %s\n' "$p"
        return 0
    fi

    local sz; sz=$(size_of "$p")
    TOTAL_ITEMS=$((TOTAL_ITEMS + 1))
    TOTAL_BYTES=$((TOTAL_BYTES + sz))

    if [ "$FORCE" -eq 0 ]; then
        printf '   would remove  %-8s %s\n' "$(human "$sz")" "$p"
        return 0
    fi

    if rm -rf -- "$p" 2>/dev/null; then
        printf '   \033[32mremoved\033[0m       %-8s %s\n' "$(human "$sz")" "$p"
    elif command -v sudo >/dev/null 2>&1 && sudo rm -rf -- "$p" 2>/dev/null; then
        printf '   \033[32mremoved (sudo)\033[0m %s\n' "$p"
    else
        printf '   \033[31mFAILED\033[0m (permission?) %s\n' "$p"
    fi
}

# find + remove by pattern, protecting tracked files
remove_glob() {  # $1 = find expr type, rest handled by caller via find
    while IFS= read -r -d '' p; do remove_path "$p"; done
}

section() { printf '\n\033[1m[%s]\033[0m\n' "$1"; }

# --- categories ---------------------------------------------------------------

if want build; then
    section "build artifacts"
    remove_path "client/Build"
    remove_path "client/build"
    remove_path "client/cmake-build-debug"
    remove_path "client/Havoc"          # client GUI binary
    remove_path "teamserver/bin"
    remove_path "teamserver/.idea"
    # stray CMake output anywhere outside tracked tree
    find . -type d \( -name CMakeFiles -o -name "*_autogen" -o -name cmake-build-debug \) \
        -not -path './.git/*' -print0 2>/dev/null | remove_glob
fi

if want binaries; then
    section "compiled binaries"
    remove_path "havoc"                 # teamserver binary (often root-owned)
    remove_path "teamserver/teamserver"
    remove_path "teamserver/havoc"
fi

if want implants; then
    section "generated implants (compiled payloads; committed *.bin are protected)"
    # Compiled demon output that lands in the build/output tree. The committed
    # loaders payloads/DllLdr.x64.bin and payloads/Shellcode.*.bin are tracked,
    # so is_tracked() will skip them automatically.
    find payloads data -type f \
        \( -name "*.exe" -o -name "*.dll" -o -name "*.o" -o -name "*.obj" \
           -o -name "demon.*.bin" -o -name "*.svc.exe" \) \
        -not -path './.git/*' -print0 2>/dev/null | remove_glob
fi

if want data; then
    section "runtime databases"
    find data -maxdepth 1 -type f -name "*.db" -print0 2>/dev/null | remove_glob
    remove_path "client/Data/database.db"
fi

if want certs; then
    section "TLS certificates and keys"
    remove_path "data/server.cert"
    remove_path "data/server.key"
    # any stray, UNTRACKED key/cert material in the tree (loot handled separately)
    find . -type f \( -name "*.key" -o -name "*.cert" -o -name "*.pem" \) \
        -not -path './.git/*' -not -path './data/loot/*' -print0 2>/dev/null | remove_glob
fi

if want loot; then
    section "downloaded loot"
    if [ -d data/loot ]; then
        find data/loot -mindepth 1 -maxdepth 1 -print0 2>/dev/null | remove_glob
    fi
fi

if want toolchain; then
    section "downloaded cross-compiler toolchains"
    find data -maxdepth 1 -type d -name "*-w64-mingw32-cross" -print0 2>/dev/null | remove_glob
fi

if want python; then
    section "python bytecode"
    find . -type d -name __pycache__ -not -path './.git/*' -print0 2>/dev/null | remove_glob
    find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -not -path './.git/*' -print0 2>/dev/null | remove_glob
fi

if want cruft; then
    section "editor / OS cruft"
    find . -type f \( -name ".DS_Store" -o -name "Thumbs.db" -o -name "*.swp" \
        -o -name "*.swo" -o -name "*~" \) -not -path './.git/*' -print0 2>/dev/null | remove_glob
    find . -type d -name ".idea" -not -path './.git/*' -print0 2>/dev/null | remove_glob
fi

# --- summary ------------------------------------------------------------------
echo
if [ "$FORCE" -eq 0 ]; then
    printf '\033[1mDRY RUN\033[0m — %d item(s), %s would be freed. Re-run with --force to delete.\n' \
        "$TOTAL_ITEMS" "$(human "$TOTAL_BYTES")"
else
    printf '\033[1mDone\033[0m — %d item(s), ~%s freed.\n' "$TOTAL_ITEMS" "$(human "$TOTAL_BYTES")"
fi
