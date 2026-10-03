#!/bin/sh
set -eu

export BEND_NO_TELEMETRY=1
BEND=${BEND:-bend}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for file in "$ROOT"/src/*.bend "$ROOT"/src/merkle/*.bend; do
  "$BEND" "$file" --check-only >/dev/null
done

for suite in conformance merkle; do
  "$BEND" "$ROOT/tests/$suite.bend" >"$TMP/$suite.out"
  diff -u "$ROOT/tests/$suite.expected" "$TMP/$suite.out"
  echo "bend $suite tests passed"
done
