#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    /bin/kill -TERM "-$PID" 2>/dev/null || true
    sleep 0.5
    /bin/kill -KILL "-$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

now=$(date +%s)
port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
udp_port=$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
cat >"$TMP/genesis.yaml" <<EOF
GENESIS_TIME: $((now - 4))
GENESIS_VALIDATORS:
  - attestation_public_key: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    proposal_public_key: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
EOF

setsid "$ROOT/bend-client" -- \
  --genesis "$TMP/genesis.yaml" \
  --listen "/ip4/127.0.0.1/udp/$udp_port/quic-v1" \
  --api-port "$port" \
  --no-color >"$TMP/node.log" 2>&1 &
PID=$!

attempt=0
while [ "$attempt" -lt 60 ]; do
  if body=$(curl --silent --fail "http://127.0.0.1:$port/lean/v0/health"); then
    [ "$body" = '{"status":"healthy","service":"lean-rpc-api"}' ] || {
      echo "unexpected health response: $body" >&2
      exit 1
    }
    curl --silent --fail "http://127.0.0.1:$port/metrics" | grep -q '^# HELP'
    uv run --directory "$ROOT/.vendor/leanSpec" apitest \
      "http://127.0.0.1:$port" -q -k 'health or metrics'
    echo "end-to-end node and leanSpec API conformance passed"
    exit 0
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    cat "$TMP/node.log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 0.5
done

cat "$TMP/node.log" >&2
echo "node API did not become ready" >&2
exit 1
