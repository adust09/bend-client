#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SPEC="$ROOT/.vendor/leanSpec"

if [ ! -x "$SPEC/.venv/bin/python" ]; then
  "$ROOT/scripts/bootstrap.sh" >/dev/null
fi

exec uv run --directory "$SPEC" python -m lean_spec "$@"
