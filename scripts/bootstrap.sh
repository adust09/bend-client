#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SPEC="$ROOT/.vendor/leanSpec"
PIN="0b7d33ecbc9ee2435759c92de4da4d08d7faf1c8"
URL="https://github.com/leanEthereum/leanSpec.git"

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 127; }
command -v uv >/dev/null 2>&1 || { echo "uv is required" >&2; exit 127; }

if [ ! -d "$SPEC/.git" ]; then
  mkdir -p "$ROOT/.vendor"
  git clone --filter=blob:none "$URL" "$SPEC"
fi

if [ -n "$(git -C "$SPEC" status --short)" ]; then
  echo "refusing to use a modified leanSpec sidecar at $SPEC" >&2
  exit 1
fi

current=$(git -C "$SPEC" rev-parse HEAD)
if [ "$current" != "$PIN" ]; then
  git -C "$SPEC" fetch origin "$PIN"
  git -C "$SPEC" checkout --detach "$PIN"
fi

uv sync --directory "$SPEC" --no-dev
printf '%s\n' "$PIN"
