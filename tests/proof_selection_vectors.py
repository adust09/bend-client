"""Generate coverage-selection fixtures from the pinned leanSpec, never from Bend."""

import argparse
import hashlib
import itertools
import random
from dataclasses import dataclass
from pathlib import Path

from ssz import Boolean

from lean_spec.spec.forks.lstar.aggregation import select_proofs_for_coverage
from lean_spec.spec.forks.lstar.containers import AggregationBits, SingleMessageAggregate
from lean_spec.spec.forks.lstar.errors import SpecRejectionError
from lean_spec.spec.ssz_types import ByteList512KiB

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Proof:
    width: int
    indices: tuple[int, ...]
    payload: bytes

    def reference(self) -> SingleMessageAggregate:
        return SingleMessageAggregate(
            participants=AggregationBits(
                data=[Boolean(index in self.indices) for index in range(self.width)]
            ),
            proof=ByteList512KiB(data=self.payload),
        )


@dataclass(frozen=True)
class Case:
    label: str
    priority: tuple[int, ...] | None
    fallback: tuple[int, ...] | None = None


def catalogue() -> list[Proof]:
    masks = [
        Proof(4, tuple(i for i in range(4) if mask & (1 << i)), bytes([mask]))
        for mask in range(16)
    ]
    ties = [
        Proof(4, (0, 1), blob)
        for blob in (b"", b"\x00", b"\x01", b"\x01\x00", b"\xff", b"\x01\xff")
    ]
    boundaries = [
        Proof(width, (0,), b"\x00")
        for width in (1, 7, 8, 9, 15, 16, 17, 31, 32, 1975, 1976, 4023, 4024, 4096)
    ]
    edges = [
        Proof(0, (), b""),
        Proof(8, (), b"\xff"),
        Proof(4096, (0, 7, 8, 4095), b"\xff\x00"),
        Proof(4096, (4095,), b"\x01"),
        Proof(9, (7, 8), b"\x00\xff"),
        Proof(1, (0,), b"\xff"),
    ]
    rng = random.Random(0xC0A3)
    random_proofs = [
        Proof(
            width,
            tuple(i for i in range(width) if rng.randrange(4) == 0),
            rng.randbytes(rng.randrange(9)),
        )
        for width in (4, 8, 9, 16, 17, 32) * 4
    ]
    return masks + ties + boundaries + edges + random_proofs


def named_cases() -> list[Case]:
    return [
        Case("should_select_nothing_when_both_pools_are_none", None),
        Case("should_select_nothing_when_both_pools_are_empty", (), ()),
        Case("should_use_fallback_when_priority_is_none", None, (3, 12)),
        Case("should_use_fallback_when_priority_is_empty", (), (3, 12)),
        Case("should_reject_when_a_proof_has_no_participants", (0, 36, 37)),
        Case("should_reject_when_an_empty_proof_accompanies_valid_proofs", (3, 0)),
        Case("should_reject_when_fallback_is_invalid_despite_full_priority_coverage", (15,), (0,)),
        Case("should_reject_when_only_fallback_has_an_empty_bitlist", None, (36,)),
        Case("should_prefer_priority_when_fallback_covers_more", (1,), (15,)),
        Case("should_skip_fallback_when_priority_covers_everyone", (15,), (3, 12)),
        Case("should_skip_redundant_proofs_when_priority_is_exhausted", (3,), (1, 2, 3)),
        Case("should_add_uncovered_fallback_validators_when_pools_overlap", (3,), (6, 12)),
        Case("should_recompute_scores_when_coverage_grows", (7, 11, 12)),
        Case("should_choose_largest_encoding_when_scores_tie", (3, 5, 6, 9, 10, 12)),
        Case("should_compare_payload_bytes_when_participants_match", (16, 17, 18, 19, 20, 21)),
        Case("should_choose_longer_payload_when_one_is_a_prefix", (18, 19)),
        Case("should_compare_later_payload_bytes_when_prefixes_match", (19, 21)),
        Case("should_preserve_bitlist_length_when_coverage_is_identical", (22, 23)),
        Case("should_compare_offsets_before_payload_when_widths_differ", (24, 41)),
        Case("should_compare_little_endian_offsets_when_the_low_byte_wraps", (31, 32)),
        Case("should_compare_offset_high_bytes_when_low_bytes_match", (23, 35)),
        Case("should_compare_offsets_when_the_second_page_wraps", (33, 34)),
        Case("should_deduplicate_selection_when_a_pool_repeats_proofs", (3, 3, 12, 12)),
        Case("should_deduplicate_selection_when_proofs_span_both_pools", (3, 3), (3, 12, 12)),
        Case("should_preserve_priority_order_when_fallback_has_larger_encoding", (17,), (20, 12)),
        Case("should_cover_highest_validator_when_bitlist_is_at_capacity", (39,), (38,)),
        Case("should_union_different_widths_when_fallback_adds_low_indices", (39,), (3, 40)),
        Case("should_select_in_greedy_order_when_three_picks_are_needed", (1, 2, 4)),
    ]


def cases(proof_count: int) -> list[Case]:
    exhaustive = [
        Case(f"should_match_reference_when_three_bit_masks_are_{a}_{b}", (a,), (b,))
        for a, b in itertools.product(range(8), repeat=2)
    ]
    permutations = [
        Case(f"should_ignore_input_order_when_permutation_is_{i}", order, tuple(reversed(order)))
        for i, order in enumerate(itertools.permutations((3, 5, 9, 12)))
    ]
    rng = random.Random(0xB3AD)
    randomized = [
        Case(
            f"should_match_reference_when_seeded_case_is_{i}",
            tuple(rng.randrange(proof_count) for _ in range(rng.randrange(9))),
            tuple(rng.randrange(proof_count) for _ in range(rng.randrange(9))),
        )
        for i in range(96)
    ]
    return named_cases() + exhaustive + permutations + randomized


BEND_HEADER = """# Generated by tests/proof_selection_vectors.py from pinned leanSpec inputs.
import Base
import ../deps/bend-merkle-tree/src/bytes.bend as B
import ../src/fork_choice.bend as F

type Case is Data:
  Vector{label: String, priority: List<&2, F.Proof>, fallback: List<&2, F.Proof>}

def contains(indices: List<&2, Nat>, +index: Nat) -> Bool:
  match indices:
    case Nil{}:
      False{}
    case Con{head, tail}:
      Bool.or(Nat.is_eq(head, index), contains(tail, index))

def bits(width: Nat, +indices: List<&2, Nat>, +index: Nat) -> List<&2, Bool>:
  match width:
    case 0n:
      Nil{}
    case 1n+rest:
      contains(indices, index) <> bits(rest, indices, Nat.add(index, 1n))

def proof(width: Nat, indices: List<&2, Nat>, payload: List<&2, U32>) -> F.Proof:
  F.Pf{bits(width, indices, 0n), payload}
"""


def bend_list(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


def pool_expression(pool: tuple[int, ...] | None) -> str:
    return bend_list([f"p{index}()" for index in pool or ()])


def emit_groups(name: str, type_name: str, expressions: list[str]) -> str:
    # Small groups keep native code generation below Bend 2.0.34's arity limit.
    chunks = [expressions[start : start + 8] for start in range(0, len(expressions), 8)]
    definitions = [
        f"\ndef {name}_{i}() -> List<&2, {type_name}>:\n  [\n    "
        + ",\n    ".join(chunk)
        + "\n  ]\n"
        for i, chunk in enumerate(chunks)
    ]
    combined = "Nil{}"
    for i in reversed(range(len(chunks))):
        combined = f"List.append(&2, {type_name}, {name}_{i}(), {combined})"
    return "".join(definitions) + f"\ndef {name}() -> List<&2, {type_name}>:\n  {combined}\n"


def payload_expression(payload: bytes) -> str:
    if len(payload) <= 16:
        return bend_list([str(byte) for byte in payload])
    runs = [(byte, len(list(group))) for byte, group in itertools.groupby(payload)]
    expression = "Nil{}"
    for byte, length in reversed(runs):
        expression = f"B.Bytes.append(B.Bytes.rep({length}n, {byte}), {expression})"
    return expression


def bend_source(proofs: list[Proof], vectors: list[Case]) -> str:
    definitions = [
        f"\ndef p{i}() -> F.Proof:\n"
        f"  proof({proof.width}n, "
        f"{bend_list([str(index) + 'n' for index in proof.indices])}, "
        f"{payload_expression(proof.payload)})\n"
        for i, proof in enumerate(proofs)
    ]
    encodings = emit_groups("proofs", "F.Proof", [f"p{i}()" for i in range(len(proofs))])
    inputs = [
        f'Vector{{"{case.label}", {pool_expression(case.priority)}, '
        f"{pool_expression(case.fallback)}}}"
        for case in vectors
    ]
    return BEND_HEADER + "".join(definitions) + encodings + emit_groups("cases", "Case", inputs)


def fingerprint(proof: SingleMessageAggregate) -> str:
    return hashlib.sha256(proof.encode_bytes()).hexdigest()


def golden(proofs: list[Proof], vectors: list[Case]) -> str:
    reference = [proof.reference() for proof in proofs]
    lines = [f"encoding-{i}={fingerprint(proof)}" for i, proof in enumerate(reference)]
    for case in vectors:
        priority = None if case.priority is None else {reference[i] for i in case.priority}
        fallback = None if case.fallback is None else {reference[i] for i in case.fallback}
        try:
            selected, covered = select_proofs_for_coverage(priority, fallback)
        except SpecRejectionError as error:
            lines.append(f"{case.label}=REJECT:{error.reason.value}")
            continue
        choices = ",".join(fingerprint(proof) for proof in selected)
        indices = ",".join(str(int(index)) for index in sorted(covered))
        lines.append(f"{case.label}={choices}|{indices}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the committed fixtures")
    mode.add_argument("--check", action="store_true", help="check fixtures against pinned leanSpec")
    args = parser.parse_args()
    basic = catalogue()
    low, high = len(basic), len(basic) + 1
    proofs = basic + [
        Proof(4096, (0, 4095), bytes(524288)),
        Proof(4096, (0, 4095), bytes(524287) + b"\x01"),
    ]
    vectors = cases(len(basic)) + [
        Case("should_compare_the_last_byte_when_payloads_are_at_capacity", (low, high)),
        Case("should_ignore_input_order_when_payloads_are_at_capacity", (high, low)),
        Case("should_preserve_priority_when_payloads_are_at_capacity", (low,), (high,)),
    ]
    artifacts = {
        ROOT / "proof_selection_cases.bend": bend_source(proofs, vectors),
        ROOT / "proof_selection.expected": golden(proofs, vectors),
    }
    for path, content in artifacts.items():
        if args.write:
            path.write_text(content)
        elif not path.exists() or path.read_text() != content:
            raise SystemExit(f"stale fixture: {path.name}; regenerate with --write")
    print(f"verified {len(proofs)} encodings and {len(vectors)} coverage selections against leanSpec")


if __name__ == "__main__":
    main()
