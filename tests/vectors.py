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
from lean_spec.spec.ssz_types import Bytes52, Bytes32, ByteList512KiB
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Interval,
    MultiMessageAggregate,
    SignedBlock,
    SingleMessageAggregate,
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


def fc_block(state, slot: int, parent_root, atts) -> tuple[Block, object]:
    """Seal a block whose state root commits to the real post-state."""
    spec = LstarSpec()
    block = Block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(slot % len(state.validators)),
        parent_root=parent_root,
        state_root=ZERO,
        body=BlockBody(attestations=AggregatedAttestations(data=list(atts))),
    )
    advanced = spec.process_slots(state, Slot(slot))
    pre = spec.process_block_header(advanced, block)
    post = spec.process_attestations(pre, block.body.attestations.data)
    block = block.model_copy(update={"state_root": hash_tree_root(post)})
    final = spec.state_transition(state, block)
    return block, final


def fc_signed(block) -> SignedBlock:
    """Wrap a block; the proof stays opaque because verification is bypassed."""
    return SignedBlock.model_construct(
        block=block,
        proof=MultiMessageAggregate(proof=ByteList512KiB(data=bytes(8))),
    )


def fc_proof(indices) -> SingleMessageAggregate:
    """An opaque aggregate proof naming its participants."""
    return SingleMessageAggregate(
        participants=AggregationBits.from_indices(indices),
        proof=ByteList512KiB(data=bytes(8)),
    )


def fork_choice(spec) -> None:
    """Print fork-choice golden values, mirroring tests/conformance.bend.

    Signature verification is an upstream gate, so the block proof is bypassed
    and vote pools are seeded directly; participants bitfields still drive
    weights, exactly as in the Bend port.
    """
    LstarSpec.verify_signatures = lambda self, signed_block, validators: True

    genesis = spec.generate_genesis(Uint64(GENESIS_TIME), validators())
    anchor = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=ZERO,
        state_root=hash_tree_root(genesis),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    anchor_root = hash_tree_root(anchor)
    print(f"fc-anchor={anchor_root.hex()}")

    store = spec.create_store(genesis, anchor, None)

    def cp(root, slot: int) -> Checkpoint:
        return Checkpoint(root=root, slot=Slot(slot))

    def att(data_slot: int, head_root, target_root, source_root, source_slot: int) -> AttestationData:
        return AttestationData(
            slot=Slot(data_slot),
            head=cp(head_root, data_slot - 1),
            target=cp(target_root, data_slot - 1),
            source=cp(source_root, source_slot),
        )

    b1, s1 = fc_block(genesis, 1, anchor_root, [])
    store = spec.on_block(store, fc_signed(b1))
    print(f"fc-on-block1={store.head.hex()}")

    b1_root = hash_tree_root(b1)
    data2 = att(2, b1_root, b1_root, anchor_root, 0)
    b2a, _ = fc_block(s1, 2, b1_root, [
        AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([0, 1]), data=data2,
        ),
    ])
    b2b, _ = fc_block(s1, 2, b1_root, [
        AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([0]), data=data2,
        ),
    ])
    b2a_root = hash_tree_root(b2a)
    b2b_root = hash_tree_root(b2b)

    # A slot-2 import needs store time to have reached interval 5.
    store = store.model_copy(update={"time": Interval(5)})
    store = spec.on_block(store, fc_signed(b2a))
    print(f"fc-on-block2={store.head.hex()}")
    store = spec.on_block(store, fc_signed(b2b))
    print(f"fc-tie-break={store.head.hex()}")

    # A vote on b2b pulls the head off the import-order tie-break.
    data_v = att(3, b2b_root, b2b_root, anchor_root, 0)
    data_u = att(3, b2a_root, b2a_root, anchor_root, 0)
    head_store = store.model_copy(update={
        "latest_known_aggregated_payloads": {data_v: {fc_proof([0, 1, 2])}},
    })
    head_store = spec.update_head(head_store)
    print(f"fc-head-votes={head_store.head.hex()}")

    # The safe target only descends through children clearing the 2/3 threshold.
    safe_store = store.model_copy(update={
        "latest_new_aggregated_payloads": {data_u: {fc_proof([0, 1])}},
    })
    safe_store = spec.update_safe_target(safe_store)
    print(f"fc-safe-target={safe_store.safe_target.hex()}")

    # Acceptance promotes pending proofs into the counted pool, then re-picks.
    accept_store = store.model_copy(update={
        "latest_known_aggregated_payloads": {},
        "latest_new_aggregated_payloads": {data_u: {fc_proof([1, 2])}, data_v: {fc_proof([0])}},
    })
    accept_store = spec.accept_new_attestations(accept_store)
    print(f"fc-accept={accept_store.head.hex()}")

    def check(label: str, data: AttestationData) -> None:
        try:
            spec.validate_attestation(store, data)
            print(f"{label}=CLEAN")
        except SpecRejectionError as err:
            print(f"{label}={err.reason.value}")

    anchor_cp = cp(anchor_root, 0)
    b1_cp = cp(b1_root, 1)
    b2a_cp = cp(b2a_root, 2)
    b2b_cp = cp(b2b_root, 2)

    check("fc-att-clean", AttestationData(slot=Slot(0), head=anchor_cp, target=anchor_cp, source=anchor_cp))
    check("fc-att-unknown-source", AttestationData(slot=Slot(0), head=b2a_cp, target=b2a_cp, source=cp(ZERO, 0)))
    check("fc-att-source-after-target", AttestationData(slot=Slot(0), head=anchor_cp, target=anchor_cp, source=b1_cp))
    check("fc-att-head-older", AttestationData(slot=Slot(0), head=anchor_cp, target=b1_cp, source=anchor_cp))
    check("fc-att-target-not-ancestor", AttestationData(slot=Slot(0), head=b2b_cp, target=b2a_cp, source=anchor_cp))
    check("fc-att-before-head", AttestationData(slot=Slot(0), head=b2a_cp, target=b1_cp, source=anchor_cp))
    check("fc-att-too-far", AttestationData(slot=Slot(5), head=anchor_cp, target=anchor_cp, source=anchor_cp))


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
    fork_choice(spec)
    return 0


if __name__ == "__main__":
    sys.exit(main())
