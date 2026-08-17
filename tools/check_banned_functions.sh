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

# audit_log is append-only by construction (plan 6.10): no UPDATE or DELETE
# against it exists anywhere except the maintenance retention sweep. Rather
# than pattern-match SQL text (the sweep builds its statement from a
# runtime table-name argument, not a literal "DELETE FROM audit_log"
# string, so a text grep for that phrase wouldn't even see it), this
# restricts which files may reference the table by name at all: only the
# module that writes/reads it and the module that sweeps it.
AUDIT_LOG_ALLOWED_FILES="src/store/audit_store.c src/store/audit_store.h src/platform/maintenance.c"
audit_hits=$(grep -rnw --include='*.c' --include='*.h' 'audit_log' "$SRC_DIR" 2>/dev/null || true)
if [ -n "$audit_hits" ]; then
    bad_audit_hits=$(echo "$audit_hits" | while IFS=: read -r file _; do
        allowed=0
        for f in $AUDIT_LOG_ALLOWED_FILES; do
            [ "$file" = "$f" ] && allowed=1 && break
        done
        [ "$allowed" -eq 0 ] && echo "$file"
    done)
    if [ -n "$bad_audit_hits" ]; then
        echo "BANNED: audit_log referenced outside $AUDIT_LOG_ALLOWED_FILES"
        echo "$audit_hits" | sed 's/^/    /'
        STATUS=1
    fi
fi

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
