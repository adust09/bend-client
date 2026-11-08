---
title: Architecture
author: bend-client contributors
last_updated: 2026-11-08
tags:
  - bend
  - lean-ethereum
  - consensus-client
---

# Architecture

## Version boundary

`VERSION` and `scripts/bootstrap.sh` pin leanSpec commit `0b7d33ecbc9ee2435759c92de4da4d08d7faf1c8` and bend-merkle-tree commit `53d47b46c28803e8e6ccc67e5faabb0254534dbc`. The client does not follow moving dependency branches.

## Bend-native layer

- `deps/bend-merkle-tree`: pinned hash-generic chunk packing, merkleization, bounded trees, and SHA-256 adapter.
- `deps/bend-ssz`: pinned SHA-256-bound SSZ serialization layer (chunk encodings, bitlist packing and roots) over the merkle library.
- `src/types.bend`: Lstar containers, their SSZ roots, and the transition result type.
- `src/justification.bend`: 3SF-mini attestation filters, vote tallies, and the justification/finalization cascade, including the square/pronic justifiability rule.
- `src/transition.bend`: slot processing, block-header validation, history updates, and the wiring that folds attestations before the post-state-root check.

Every Bend source passes `bend --check-only`. Golden values come from the pinned `eth-ssz-specs` and leanSpec implementations.

## Runtime sidecar

`main.bend` forwards the node argument vector to `scripts/run-node.sh`. The script starts the pinned leanSpec runtime with no protocol translation. This supplies components absent from Bend 2's standard library:

- QUIC/TLS and libp2p stream negotiation;
- gossipsub 1.2 and request/response protocols;
- XMSS signing, proof aggregation, and verification;
- YAML genesis and validator-key loading;
- SQLite persistence, checkpoint/head/backfill sync;
- validator duties, Prometheus metrics, and `/lean/v0` HTTP APIs.

The sidecar checkout is isolated under ignored `.vendor/leanSpec`; the merkle-tree and bend-ssz libraries live under ignored `deps/` (non-hidden) because Bend import paths cannot traverse hidden directory names, with bend-ssz pinning its own merkle-tree checkout. Bootstrap refuses to replace modified checkouts and verifies every exact commit before dependency synchronization.

## Verification boundary

`scripts/test.sh` checks every Bend module and compares deterministic consensus roots; `tests/vectors.py` regenerates them with the pinned leanSpec. `tests/e2e.sh` starts the compiled public entry point and validates live health and metrics endpoints. leanSpec's own `apitest` command can exercise the full HTTP conformance suite.
