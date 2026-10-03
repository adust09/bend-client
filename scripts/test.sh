#!/bin/sh
set -eu

export BEND_NO_TELEMETRY=1
BEND=${BEND:-bend}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

for file in "$ROOT"/src/*.bend; do
  "$BEND" "$file" --check-only >/dev/null
done

"$BEND" "$ROOT/tests/conformance.bend" >"$TMP"
diff -u "$ROOT/tests/conformance.expected" "$TMP"
echo "all Bend conformance tests passed"
