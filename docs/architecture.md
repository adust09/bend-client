---
title: Architecture
author: bend-client contributors
last_updated: 2026-11-12
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
- `src/proof_selection.bend`: greedy proof coverage selection over the existing `fork_choice.bend` proof type; no signing, aggregation, or verification.

Every Bend source passes `bend --check-only`. Golden values come from the pinned `eth-ssz-specs` and leanSpec implementations.

## Proof coverage selection

`select_proofs_for_coverage(priority, fallback)` takes two `List<&2, F.Proof>` pools. `Nil{}` represents either an absent or empty Python pool. Each `F.Pf{who, blob}` retains the original participant bitlist and opaque proof bytes.

The caller must supply SSZ-valid values: at most 4096 participant bits, at most 524288 payload bytes, and byte values in `0..255`. As with the fork-choice store, the host owns decoding and cryptographic verification. The selector rejects proofs with no set participant bits, including in an otherwise redundant fallback pool, with `Rejected{"EMPTY_AGGREGATION_BITS"}`.

For each pool, priority first, the selector repeatedly chooses the proof adding the most uncovered validators. Ties go to the lexicographically largest complete `SingleMessageAggregate` SSZ encoding: both little-endian offsets, the participant bitlist with its termination bit, then the payload. Coverage carries across pools. Duplicate proofs never add a second selection. The result is `Selected{proofs, covered}`, with proofs in greedy selection order and unique validator indices in ascending order.

`tests/proof_selection_vectors.py` obtains expected selections and encoding fingerprints directly from the pinned leanSpec. It generates the Bend inputs and golden output, including empty pools, invalid empty proofs, overlaps, duplicates, permutations, offset and bitlist boundaries, and seeded cases. `make test` checks that the committed fixtures still match leanSpec, then compiles and runs the proof-selection suite as a native Bend executable against them. The cases include 4096 participant bits and 524288-byte payloads differing only at their last byte. Native builds avoid Bend 2.0.34's direct-runner memory fault when constructing a 512 KiB list, reproducible even without the selector. To regenerate after an intentional reference change:

```sh
uv run --no-dev --directory .vendor/leanSpec python ../../tests/proof_selection_vectors.py --write
```

This is a standalone pure computation, not a runtime replacement. `main.bend` does not invoke it.

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
