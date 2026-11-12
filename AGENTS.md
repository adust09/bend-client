# AGENTS.md

## Overview

Bend 2 client entry point for the Lean Ethereum Lstar consensus protocol. The Bend code holds only the public entry point plus pure consensus primitives under `src/`; all protocol/runtime behavior (QUIC/libp2p, gossipsub, XMSS, SQLite, YAML, metrics, `/lean/v0` API) comes from a pinned leanSpec Python sidecar because Bend 2 ships none of those libraries. `VERSION` records the pinned Bend version (`2.0.34`) and fork (`Lstar`).

## Prerequisites

- Bend `2.0.34` (`bend` on PATH), `git`, `uv`, Clang 14+. Other Bend versions are untested.

## Commands

Run `make bootstrap` before anything else — both dependency checkouts are git-ignored and absent on a fresh clone.

- `make check` — `bend <file> --check-only` typecheck of `main.bend`, `src/*.bend`, `tests/*.bend`
- `make test` — check plus golden conformance diff (see Testing)
- `make build` — compile `main.bend` to the `bend-client` executable
- `make e2e` — build, then `tests/e2e.sh` (starts the client, probes `/lean/v0/health` and `/metrics`)
- `make clean` — removes compiled artifacts (`bend-client`, `.c/.js/.mjs/.gpu`)
- Override the Bend binary with `make BEND=<path>`; scripts set `BEND_NO_TELEMETRY=1`.

These commands are declared in the `Makefile` and were inspected, not executed, when this file was written.

## Pinned dependencies — vendor code, not workspace code

- `.vendor/leanSpec`: leanSpec at the exact commit pinned by `SPEC_PIN` in `scripts/bootstrap.sh`; synced with `uv` (`uv sync --no-dev`).
- `deps/bend-merkle-tree`: audited Merkle-tree library at the commit pinned by `MERKLE_PIN`; `src/ssz.bend` imports it via relative paths (`../deps/bend-merkle-tree/src/merkle/*.bend`).
- Both checkouts are detached at exact pins by `scripts/bootstrap.sh`, which refuses to proceed if a checkout has modifications. Never edit files inside them. To change versions, edit `SPEC_PIN` / `MERKLE_PIN` explicitly; do not follow moving branches.
- `deps/bend-merkle-tree` must stay at a non-hidden path: Bend import paths cannot traverse hidden directory names, so it cannot move under `.vendor/`.

## Implementation boundary policy

Library boundaries are decided by trust, not by availability: a trusted reference
implementation (pinned leanSpec sidecar, published libraries) stays the single
executive source, and in-tree re-implementations exist only where differential
golden checking can fully verify them. Bend hosts pure, deterministic computation
such as the 3SF state transition and fork-choice/store state machines; port those
only with sequence-based golden vectors from the pinned leanSpec and keep event
sourcing (transport, clock, persistence) host-side. Do not port the executive
role of crypto (XMSS signing and key state) without proof-grade assurance.

## Architecture

- `main.bend` is an entry point only: it forwards the argument vector (minus program name) to `scripts/run-node.sh`, which execs the sidecar (`uv run --directory .vendor/leanSpec python -m lean_spec`). No protocol translation layer exists — pass node options through unchanged. Options after `--` on the compiled binary are leanSpec node options.
- Bend layering chain (imports are relative with aliases, e.g. `import ../src/types.bend as T`): `src/bytes.bend` → `src/sha256.bend` → (merkle library) → `src/ssz.bend` → `src/types.bend` → `src/transition.bend` (slot processing, header validation, post-state-root validation).
- Golden test values originate from the pinned leanSpec / eth-ssz-specs implementations.

## Testing

- `scripts/test.sh` runs each `src/*.bend` with `--check-only`, then pipes `tests/conformance.bend` output and diffs it against `tests/conformance.expected`. When adding or changing consensus outputs, regenerate the golden file from values cross-checked against the pinned spec implementations — not from whatever the Bend code currently produces.
- `tests/e2e.sh` requires a built `bend-client` (it runs after `make build`).
- Full HTTP conformance suite lives in the sidecar: `uv run apitest http://127.0.0.1:5052` from `.vendor/leanSpec`.

## Conventions

- Shell scripts are POSIX `sh` with `set -eu`; match that for new scripts.
- `docs/*.md` carry YAML frontmatter (`title`, `last_updated`, `tags`), as in `docs/architecture.md`.
