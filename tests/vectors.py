"""Generate 3SF-mini conformance vectors with the pinned leanSpec.

The script builds the same genesis, blocks, and attestations that
tests/conformance.bend replays in Bend, and prints `key=value` lines that
mirror the labels printed there. Run it from the repository root:

    uv run --directory .vendor/leanSpec python ../../tests/vectors.py

Every value the Bend conformance suite prints must come from this pinned
implementation, not from the Bend code's own output. Parent and checkpoint
roots are taken after slot processing, because it caches the state root
into the latest header before the block is applied.
"""

import sys

from ssz import Uint64, hash_tree_root

from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.ssz_types import Bytes52, Bytes32
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.containers.participation import AggregationBits
from lean_spec.spec.forks.lstar.errors import SpecRejectionError
from lean_spec.spec.forks.lstar.spec import LstarSpec

# Mirrors tests/conformance.bend three_vals: attestation keys 11/12/13,
# proposal keys 22/23/24, one byte repeated across all 52 bytes.
ATT_KEYS = (11, 12, 13)
PROP_KEYS = (22, 23, 24)
GENESIS_TIME = 1000

ZERO = Bytes32(b"\x00" * 32)


def validators() -> Validators:
    entries = []
    for i in range(3):
        entries.append(
            Validator(
                attestation_public_key=Bytes52(bytes([ATT_KEYS[i]] * 52)),
                proposal_public_key=Bytes52(bytes([PROP_KEYS[i]] * 52)),
                index=ValidatorIndex(i),
            )
        )
    return Validators(data=entries)


def attestation(bits, data_slot: int, cps) -> AggregatedAttestation:
    """cps maps slot -> cached block root, mirroring historical_block_hashes."""
    head_slot = data_slot - 1
    source_slot = data_slot - 2
    return AggregatedAttestation(
        aggregation_bits=bits,
        data=AttestationData(
            slot=Slot(data_slot),
            head=Checkpoint(root=cps[head_slot], slot=Slot(head_slot)),
            target=Checkpoint(root=cps[head_slot], slot=Slot(head_slot)),
            source=Checkpoint(root=cps[source_slot], slot=Slot(source_slot)),
        ),
    )


def build(state, slot: int, body) -> tuple[Block, object, dict[int, bytes]]:
    """Build a block whose state root commits to the real post-state."""
    spec = LstarSpec()
    advanced = spec.process_slots(state, Slot(slot))
    parent = hash_tree_root(advanced.latest_block_header)
    block = Block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(slot % len(state.validators)),
        parent_root=parent,
        state_root=ZERO,
        body=BlockBody(attestations=AggregatedAttestations(data=body)),
    )
    pre = spec.process_block_header(advanced, block)
    post = spec.process_attestations(pre, block.body.attestations.data)
    block = block.model_copy(update={"state_root": hash_tree_root(post)})
    final = spec.state_transition(state, block)
    assert int(final.slot) == slot
    return block, post, {slot: parent}


def outcome(label: str, thunk) -> None:
    try:
        value, post, _ = thunk()
        print(f"{label}={hash_tree_root(post).hex()}")
        assert int(post.slot) == value.slot
    except SpecRejectionError as err:
        print(f"{label}={err.reason.value}")


def parent_of(spec, state, slot: int) -> bytes:
    """Root of the cached block header at `slot`, i.e. block slot+1's parent."""
    advanced = spec.process_slots(state, Slot(slot + 1))
    return hash_tree_root(advanced.latest_block_header)


def main() -> int:
    spec = LstarSpec()
    genesis = spec.generate_genesis(Uint64(GENESIS_TIME), validators())

    # Blocks are chained one after another: each block is applied to the
    # post-state of the previous one. A slot's chain root (the value recorded
    # in historical_block_hashes) is the cached tip header root of the state
    # the block was applied to, taken after slot processing.
    root0 = parent_of(spec, genesis, 0)
    _, s1, _ = build(genesis, 1, [])
    print(f"att-block1={hash_tree_root(s1).hex()}")

    root1 = parent_of(spec, s1, 1)
    block2, s2, _ = build(
        s1, 2,
        [attestation(AggregationBits.from_indices([0, 1]), 2,
                     cps={0: root0, 1: root1})],
    )
    print(f"att-justify={hash_tree_root(s2).hex()}")

    root2 = parent_of(spec, s2, 2)
    block3, s3, _ = build(
        s2, 3,
        [attestation(AggregationBits.from_indices([0, 1, 2]), 3,
                     cps={0: root0, 1: root1, 2: root2})],
    )
    print(f"att-finalize={hash_tree_root(s3).hex()}")

    root3 = parent_of(spec, s3, 3)
    block4, s4, _ = build(
        s3, 4,
        [attestation(AggregationBits.from_indices([0, 1, 2]), 4,
                     cps={0: root0, 1: root1, 2: root2, 3: root3})],
    )
    print(f"att-finalize2={hash_tree_root(s4).hex()}")

    # Rejections against the block-1 state: a bit outside the registry, an
    # aggregate with no set bits, and too many distinct attestation data.
    cps2 = {0: root0, 1: root1}
    range_bits = AggregationBits.from_indices([0, 4])
    outcome("att-index-range", lambda: build(
        s1, 2, [attestation(range_bits, 2, cps2)],
    ))
    outcome("att-bits-empty", lambda: build(
        s1, 2, [attestation(AggregationBits(data=[]), 2, cps2)],
    ))
    cps_many = {s: p for s, p in [(0, root0), (1, root1)] + [(k, root1) for k in range(2, 12)]}
    many = [
        attestation(AggregationBits.from_indices([0]), 2 + k, cps_many)
        for k in range(9)
    ]
    outcome("att-too-many", lambda: build(
        s1, 2, many,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
