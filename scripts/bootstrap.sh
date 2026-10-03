#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SPEC="$ROOT/.vendor/leanSpec"
SPEC_PIN="0b7d33ecbc9ee2435759c92de4da4d08d7faf1c8"
SPEC_URL="https://github.com/leanEthereum/leanSpec.git"
MERKLE="$ROOT/deps/bend-merkle-tree"
MERKLE_PIN="53d47b46c28803e8e6ccc67e5faabb0254534dbc"
MERKLE_URL="https://github.com/adust09/bend-merkle-tree.git"

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 127; }
command -v uv >/dev/null 2>&1 || { echo "uv is required" >&2; exit 127; }

checkout_pin() {
  name=$1
  path=$2
  url=$3
  pin=$4

  if [ ! -d "$path/.git" ]; then
    mkdir -p "$ROOT/.vendor"
    git clone --filter=blob:none "$url" "$path"
  fi

  if [ -n "$(git -C "$path" status --short)" ]; then
    echo "refusing to use a modified $name checkout at $path" >&2
    exit 1
  fi

  current=$(git -C "$path" rev-parse HEAD)
  if [ "$current" != "$pin" ]; then
    git -C "$path" fetch origin "$pin"
    git -C "$path" checkout --detach "$pin"
  fi
}

checkout_pin "leanSpec sidecar" "$SPEC" "$SPEC_URL" "$SPEC_PIN"
checkout_pin "Merkle library" "$MERKLE" "$MERKLE_URL" "$MERKLE_PIN"
uv sync --directory "$SPEC" --no-dev
printf 'leanSpec=%s\nbend-merkle-tree=%s\n' "$SPEC_PIN" "$MERKLE_PIN"
