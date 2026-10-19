#!/bin/sh
# Verify every file under testvectors/ against the SHA-256 manifest in
# docs/SPEC.md ("Test vector manifest"). Run by CI, and meant to be run
# locally before pushing a change to a vector file.
#
# Fails when a file's digest does not match its row, when a file has no row
# at all, or when a row names a file that is not present.

set -eu

cd "$(dirname "$0")/.."
spec="docs/SPEC.md"

if command -v sha256sum >/dev/null 2>&1; then
    hash() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    hash() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    echo "error: no sha256 tool on PATH (need sha256sum or shasum)" >&2
    exit 1
fi

if [ ! -f "$spec" ]; then
    echo "error: $spec not found" >&2
    exit 1
fi

# Rows of the manifest table, which lives under the "## Test vector manifest"
# heading. A row is: | `file` | `64 hex digits` |
manifest_names() {
    awk '/^## Test vector manifest/{f=1;next} f&&/^## /{f=0} f' "$spec" \
        | sed -n 's/^| *`\([^`]*\)` *| *`[0-9a-f]\{64\}` *|.*/\1/p'
}

manifest_hash() {
    awk '/^## Test vector manifest/{f=1;next} f&&/^## /{f=0} f' "$spec" \
        | sed -n "s/^| *\`$1\` *| *\`\([0-9a-f]\{64\}\)\` *|.*/\1/p" \
        | head -n 1
}

fail=0

for path in testvectors/*; do
    [ -f "$path" ] || continue
    name=$(basename "$path")
    actual=$(hash "$path")
    expected=$(manifest_hash "$name")
    if [ -z "$expected" ]; then
        echo "MISSING  $name has no row in the manifest in $spec"
        fail=1
    elif [ "$expected" != "$actual" ]; then
        echo "MISMATCH $name"
        echo "  manifest: $expected"
        echo "  actual:   $actual"
        fail=1
    else
        echo "OK       $name"
    fi
done

for name in $(manifest_names); do
    if [ ! -f "testvectors/$name" ]; then
        echo "STALE    manifest lists $name but testvectors/$name does not exist"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "test-vector manifest check failed" >&2
fi

exit $fail
