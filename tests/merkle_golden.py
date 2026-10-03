#!/usr/bin/env python3
"""Regenerate tests/merkle.expected from reference implementations.

SHA-256 based roots come from the `ssz` package leanSpec depends on
(``ssz.trees.merkleize`` / ``ssz.chunks.zero_tree_root``) over ``hashlib.sha256``.
The ``mix-`` lines replicate the toy pair hash used by tests/merkle.bend, so the
hash-generic tree code is pinned independently of any hash implementation.
Point SSZ_PYTHON at the interpreter of a leanSpec checkout (it installs the same
``ssz`` version the client interoperates with); it falls back to any interpreter
that can import ``ssz``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from hashlib import sha256

SSZ_PYTHON = os.environ.get("SSZ_PYTHON", sys.executable)

# (key, leaf count, capacity) for every merkleize expectation; capacity None
# means the unbounded tree shape.
MERKLEIZE_CASES: list[tuple[str, int, int | None]] = [
    ("mz-empty", 0, None),
    ("mz-1", 1, None),
    ("mz-2", 2, None),
    ("mz-3", 3, None),
    ("mz-5", 5, None),
    ("mz-8", 8, None),
    ("mzl-3-8", 3, 8),
    ("mzl-5-1024", 5, 1024),
    ("mzl-0-1024", 0, 1024),
    ("mzl-1-1", 1, 1),
    ("mzl-2-2", 2, 2),
    ("mzl-8-8", 8, 8),
]

ZERO_DEPTHS = (0, 1, 2, 3, 6, 10, 12)


def chunk(index: int) -> bytes:
    """The chunk literal used by tests/merkle.bend: (i*j + 1) mod 256."""
    return bytes(((index * j + 1) % 256) for j in range(32))


def reference_roots() -> dict[str, str]:
    """Every SHA-256 expectation, computed by the reference `ssz` package."""
    script = f"""
import sys
from hashlib import sha256
from ssz.trees import merkleize
from ssz.chunks import zero_tree_root

Z = bytes(32)
def c(i): return bytes(((i * j + 1) % 256) for j in range(32))
cs = [c(i) for i in range(8)]
cases = {MERKLEIZE_CASES!r}
depths = {ZERO_DEPTHS!r}

out = [("pair-zero", sha256(Z + Z).hexdigest())]
for depth in depths:
    out.append((f"zero-{{depth}}", zero_tree_root(1 << depth).hex()))
for key, count, limit in cases:
    root = merkleize(cs[:count]) if limit is None else merkleize(cs[:count], limit=limit)
    out.append((key, root.hex()))
out.append(("mixlen-5", sha256(cs[0] + (5).to_bytes(32, "little")).hexdigest()))
out.append(("mixlen-0", sha256(Z + bytes(32)).hexdigest()))
print("\\n".join(f"{{key}}={{value}}" for key, value in out))
"""
    done = subprocess.run(
        [SSZ_PYTHON, "-c", script], capture_output=True, text=True, check=True
    )
    roots = {}
    for line in done.stdout.splitlines():
        key, _, value = line.partition("=")
        roots[key] = value
    return roots


def mix_hash(left: bytes, right: bytes) -> bytes:
    """The toy hash in tests/merkle.bend: (a + 2b + 1) mod 256 per byte."""
    return bytes((a + 2 * b + 1) & 0xFF for a, b in zip(left, right))


def next_pow2(value: int) -> int:
    return 1 if value <= 1 else 1 << (value - 1).bit_length()


def mix_zero_tree(depth: int) -> bytes:
    node = bytes(32)
    for _ in range(depth):
        node = mix_hash(node, node)
    return node


def mix_merkleize(leaves: list[bytes]) -> bytes:
    if not leaves:
        return bytes(32)
    level = list(leaves) + [bytes(32)] * (next_pow2(len(leaves)) - len(leaves))
    while len(level) > 1:
        level = [mix_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def mix_merkleize_limit(leaves: list[bytes], limit: int) -> bytes:
    if not leaves:
        return mix_zero_tree((limit - 1).bit_length())
    data_depth = (next_pow2(len(leaves)) - 1).bit_length()
    node = mix_merkleize(leaves)
    for depth in range(data_depth, (next_pow2(limit) - 1).bit_length()):
        node = mix_hash(node, mix_zero_tree(depth))
    return node


def packed(data: bytes) -> str:
    if not data:
        return ""
    return ",".join(
        data[i : i + 32].ljust(32, b"\0").hex() for i in range(0, len(data), 32)
    )


def main() -> None:
    ref = reference_roots()
    order = ["pair-zero"] + [f"zero-{d}" for d in ZERO_DEPTHS]
    order += [key for key, _, _ in MERKLEIZE_CASES]
    order += ["checked-valid", "checked-overflow", "mixlen-5", "mixlen-0"]
    ref["checked-valid"] = "True"
    ref["checked-overflow"] = "True"
    lines = [f"{key}={ref[key]}" for key in order]

    lines += [
        "pow2-0=1",
        "pow2-1=1",
        "pow2-5=8",
        "pow2-1024=1024",
        "pow2-2^40=1099511627776",
        "depth-1=0",
        "depth-1024=10",
        "depth-2^40=40",
        "chunk-count-0=0",
        "chunk-count-32=1",
        "chunk-count-33=2",
        "chunk-count-100=4",
        "u64le-1000=" + (1000).to_bytes(8, "little").ljust(32, b"\0").hex(),
        "pack-4=" + packed(bytes(range(4))),
        "pack-100=" + packed(bytes(range(100))),
        "bytes-abc=" + sha256(b"abc").hexdigest(),
        "bytes-empty=" + sha256(b"").hexdigest(),
        "bytes-64=" + sha256(bytes(range(64))).hexdigest(),
        "mix-zero-1=" + mix_zero_tree(1).hex(),
        "mix-zero-3=" + mix_zero_tree(3).hex(),
        "mix-mz-3=" + mix_merkleize([chunk(i) for i in range(3)]).hex(),
        "mix-mzl-3-8=" + mix_merkleize_limit([chunk(i) for i in range(3)], 8).hex(),
        "mix-mzl-2-4=" + mix_merkleize_limit([chunk(i) for i in range(2)], 4).hex(),
        "eq-self=True",
        "eq-diff=False",
        "is-zero=True",
        "is-zero-false=False",
        "hex-roundtrip=True",
        "hex-short=True",
    ]

    print("\n".join(lines))


if __name__ == "__main__":
    main()
