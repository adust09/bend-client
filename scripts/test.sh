#!/bin/sh
set -eu

export BEND_NO_TELEMETRY=1
BEND=${BEND:-bend}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for file in "$ROOT"/src/*.bend; do
  "$BEND" "$file" --check-only >/dev/null
done

uv run --no-dev --directory "$ROOT/.vendor/leanSpec" \
  python "$ROOT/tests/proof_selection_vectors.py" --check

"$BEND" "$ROOT/tests/conformance.bend" >"$TMP/conformance.actual"
diff -u "$ROOT/tests/conformance.expected" "$TMP/conformance.actual"

"$BEND" "$ROOT/tests/proof_selection.bend" -o "$TMP/proof_selection"
"$TMP/proof_selection" >"$TMP/proof_selection.actual"
diff -u "$ROOT/tests/proof_selection.expected" "$TMP/proof_selection.actual"
echo "all Bend conformance tests passed"
