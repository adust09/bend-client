import Base
import ./bytes.bend as B
import ../deps/bend-merkle-tree/src/merkle/chunk.bend as C
import ../deps/bend-merkle-tree/src/merkle/tree.bend as M
import ../deps/bend-merkle-tree/src/merkle/sha256.bend as H

# SSZ hash_tree_root for the Lstar containers, on top of the pinned standalone
# bend-merkle-tree library. Tree shapes and the SHA-256 pair hash both come from
# there, so this module only states the SSZ-level rules: which subtrees a
# container has, how lengths are mixed in, and how short byte vectors are packed.

def zero32() -> List<&2, U32>:
  C.Chunk.zero()

def hash2(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  H.sha256_pair(a, b)

def zero_tree(depth: Nat) -> List<&2, U32>:
  M.tree.zero_tree(~H.sha256_pair, depth)

def u64_chunk(n: Nat) -> List<&2, U32>:
  B.Bytes.append(B.Bytes.u64_le(n), B.Bytes.zeros(24n))

def bool_chunk(bit: Bool) -> List<&2, U32>:
  match bit:
    case False{}:
      zero32()
    case True{}:
      B.Bytes.append({[1] : List<&2, U32>}, B.Bytes.zeros(31n))

def mix_len(root: List<&2, U32>, n: Nat) -> List<&2, U32>:
  hash2(root, u64_chunk(n))

def merkle(+xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  M.tree.merkleize(~H.sha256_pair, xs)

def merkle_limit(+xs: List<&2, List<&2, U32>>, limit: Nat) -> List<&2, U32>:
  M.tree.merkleize_limit(~H.sha256_pair, xs, limit)

def list_root(+xs: List<&2, List<&2, U32>>, limit: Nat) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  mix_len(merkle_limit(xs, limit), n)

def bytes52_root(+b: List<&2, U32>) -> List<&2, U32>:
  hash2(B.Bytes.take(b, 32n), B.Bytes.append(B.Bytes.drop(b, 32n), B.Bytes.zeros(12n)))

def chunk1(a: List<&2, U32>) -> List<&2, U32>:
  a

def chunk2(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  hash2(a, b)

def chunk4(a: List<&2, U32>, b: List<&2, U32>, c: List<&2, U32>, d: List<&2, U32>)
  -> List<&2, U32>:
  hash2(hash2(a, b), hash2(c, d))

def repeat_byte(n: Nat, b: U32) -> List<&2, U32>:
  B.Bytes.rep(n, b)
