#!/usr/bin/env bash
#
# Fail the build if a banned unbounded string function appears in src/.
# Plan 7.2: these are the functions that cannot be used safely without
# out-of-band length knowledge, and that knowledge is exactly what gets lost
# during maintenance.
#
# Allowing a specific line requires an explicit marker:
#     strcpy(dst, src);  /* ps-allow-banned: <reason> */
#
set -uo pipefail

cd "$(dirname "$0")/.."

SRC_DIR=src
STATUS=0

# Word-boundary matched so that e.g. "ps_strlcpy" is not a false positive.
BANNED=(
    strcpy strcat sprintf vsprintf gets
    strncpy strncat            # truncate without NUL-terminating; use snprintf
    alloca                     # unbounded stack growth from request data
    atoi atol atoll            # no error reporting at all
    tmpnam mktemp              # racy temporary files
)

if [ ! -d "$SRC_DIR" ]; then
    echo "no $SRC_DIR directory; nothing to check"
    exit 0
fi

for fn in "${BANNED[@]}"; do
    # -n line numbers, -w whole word, -r recursive, restricted to C sources.
    hits=$(grep -rnw --include='*.c' --include='*.h' "$fn" "$SRC_DIR" 2>/dev/null \
           | grep -v 'ps-allow-banned' || true)
    if [ -n "$hits" ]; then
        echo "BANNED: $fn"
        echo "$hits" | sed 's/^/    /'
        STATUS=1
    fi
done

if [ "$STATUS" -eq 0 ]; then
    echo "check-banned: clean (${#BANNED[@]} patterns, no violations)"
else
    echo
    echo "Use a bounded alternative:"
    echo "  strcpy/strcat/sprintf -> snprintf, with the return value checked"
    echo "  strncpy/strncat       -> snprintf, or memcpy with an explicit NUL"
    echo "  atoi/atol             -> strtol, checking errno and endptr"
    echo "  alloca                -> a fixed buffer, or malloc with a free path"
    echo
    echo "If a use is genuinely correct, mark it:  /* ps-allow-banned: reason */"
fi

exit "$STATUS"
