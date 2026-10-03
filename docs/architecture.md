---
title: Architecture
author: bend-client contributors
last_updated: 2026-10-03
tags:
  - bend
  - lean-ethereum
  - consensus-client
---

# Architecture

## Version boundary

`VERSION` and `scripts/bootstrap.sh` pin leanSpec commit `0b7d33ecbc9ee2435759c92de4da4d08d7faf1c8`. The client does not follow a moving branch at runtime.

## Bend-native layer

- `src/bytes.bend`: byte/hex and endian operations.
- `src/sha256.bend`: FIPS 180-4 SHA-256.
- `src/merkle/`: hash-generic 32-byte chunk packing, perfect-tree merkleization, bounded trees, and the SHA-256 adapter.
- `src/ssz.bend`: Lstar SSZ roots built on the reusable Merkle tree library.
- `src/types.bend`: Lstar containers and their SSZ roots.
- `src/transition.bend`: slot processing, block-header validation, history updates, and post-state-root validation.

Every Bend source passes `bend --check-only`. Golden values come from the pinned `eth-ssz-specs` and leanSpec implementations.

## Runtime sidecar

`main.bend` forwards the node argument vector to `scripts/run-node.sh`. The script starts the pinned leanSpec runtime with no protocol translation. This supplies components absent from Bend 2's standard library:

- QUIC/TLS and libp2p stream negotiation;
- gossipsub 1.2 and request/response protocols;
- XMSS signing, proof aggregation, and verification;
- YAML genesis and validator-key loading;
- SQLite persistence, checkpoint/head/backfill sync;
- validator duties, Prometheus metrics, and `/lean/v0` HTTP APIs.

The sidecar checkout is isolated under ignored `.vendor/leanSpec`. Bootstrap refuses to replace a modified checkout and verifies the exact commit before dependency synchronization.

## Verification boundary

`scripts/test.sh` checks every Bend module and compares deterministic consensus roots. `tests/e2e.sh` starts the compiled public entry point and validates live health and metrics endpoints. leanSpec's own `apitest` command can exercise the full HTTP conformance suite.
