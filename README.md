# bend-client

A Bend 2 client entry point for the Lean Ethereum **Lstar** consensus protocol.
It pins leanSpec commit `0b7d33ecbc9ee2435759c92de4da4d08d7faf1c8` and exposes the complete node surface from that revision: state transition, 3SF-mini fork choice, XMSS, QUIC/libp2p, gossipsub, synchronization, validator duties, storage, metrics, and the `/lean/v0` API.

The repository also contains Bend-native consensus primitives under `src/`: SHA-256, SSZ merkleization, Lstar containers, genesis, slot processing, header checks, and state-root validation. The network/runtime layer executes the pinned leanSpec sidecar because Bend 2 does not yet ship QUIC/TLS, SQLite, YAML, or XMSS libraries. The Bend executable remains the public entry point and passes arguments unchanged.

## Prerequisites

- Bend `2.0.34`
- `git`
- `uv`
- Clang 14 or newer

Install Bend:

```sh
curl -fsSL https://bend-lang.com/install.sh | sh
export PATH="$HOME/.bend/bin:$PATH"
```

## Build and run

```sh
./scripts/bootstrap.sh
bend main.bend -o bend-client
./bend-client -- --genesis ./config.yaml
```

Options after `--` are leanSpec node options. Inspect them with:

```sh
./bend-client -- --help
```

Common options include repeated `--bootnode`, `--listen`, `--checkpoint-sync-url`, `--validator-keys`, `--node-id`, `--is-aggregator`, and `--api-port`.

A genesis file uses this shape:

```yaml
GENESIS_TIME: 1766620797
GENESIS_VALIDATORS:
  - attestation_public_key: "0x<52-byte-hex>"
    proposal_public_key: "0x<52-byte-hex>"
```

## Verify

```sh
./scripts/test.sh
bend main.bend -o bend-client
./tests/e2e.sh
```

The conformance test compares Bend results with leanSpec-generated golden roots for SHA-256, SSZ, bitlists, genesis, and an Lstar block transition. The end-to-end test starts the compiled client and probes `/lean/v0/health` and `/metrics`.

For external API conformance testing:

```sh
cd .vendor/leanSpec
uv run apitest http://127.0.0.1:5052
```

See [docs/architecture.md](docs/architecture.md) for trust boundaries and protocol coverage.
