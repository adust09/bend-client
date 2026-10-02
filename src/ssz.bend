import Base
import ./bytes.bend as B
import ./sha256.bend as H

# SSZ hash_tree_root using SHA-256, matching eth-ssz-specs 0.1 / leanSpec.

def zero32() -> List<&2, U32>:
  B.Bytes.zero32()

def hash2(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  H.sha256(B.Bytes.append(a, b))

def zero_tree(depth: Nat) -> List<&2, U32>:
  match depth:
    case 0n:
      zero32()
    case 1n+p:
      +z = zero_tree(p)
      hash2(z, z)

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

def head_chunk(xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      zero32()
    case Con{h, t}:
      h

def pair_all(xs: List<&2, List<&2, U32>>, phase: Nat, pending: List<&2, U32>) -> List<&2, List<&2, U32>>:
  match xs:
    case Nil{}:
      match phase:
        case 0n:
          Nil{}
        case _:
          hash2(pending, zero32()) <> Nil{}
    case Con{h, t}:
      match phase:
        case 0n:
          pair_all(t, 1n, h)
        case _:
          hash2(pending, h) <> pair_all(t, 0n, zero32())

def merkle_pow2(fuel: Nat, n: Nat, xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match fuel:
    case 0n:
      head_chunk(xs)
    case 1n+p:
      match n:
        case 0n:
          zero32()
        case 1n:
          head_chunk(xs)
        case _:
          merkle_pow2(p, Nat.div(n, 2n), pair_all(xs, 0n, zero32()))

def pad_zeros(need: Nat, xs: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match need:
    case 0n:
      xs
    case 1n+p:
      pad_zeros(p, List.append(&2, List<&2, U32>, xs, zero32() <> Nil{}))

def next_pow2(fuel: Nat, phase: Nat, +n: Nat, +p: Nat, le: Bool) -> Nat:
  match fuel:
    case 0n:
      p
    case 1n+f:
      match phase:
        case 0n:
          next_pow2(f, 1n, n, p, Nat.is_le(n, p))
        case _:
          match le:
            case True{}:
              p
            case False{}:
              next_pow2(f, 0n, n, Nat.mul(p, 2n), False{})

def pow2(n: Nat) -> Nat:
  next_pow2(64n, 0n, n, 1n, False{})

def merkle(+xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  +w = pow2(n)
  merkle_pow2(40n, w, pad_zeros(Nat.sub(w, n), xs))

def lift(steps: Nat, depth: Nat, node: List<&2, U32>) -> List<&2, U32>:
  match steps:
    case 0n:
      node
    case 1n+p:
      +depth2 = depth
      lift(p, Nat.add(depth2, 1n), hash2(node, zero_tree(depth2)))

def log2_pow2(fuel: Nat, n: Nat, d: Nat) -> Nat:
  match fuel:
    case 0n:
      d
    case 1n+p:
      match n:
        case 0n:
          d
        case 1n:
          d
        case _:
          log2_pow2(p, Nat.div(n, 2n), Nat.add(d, 1n))

def depth_of(width: Nat) -> Nat:
  log2_pow2(40n, width, 0n)

def merkle_limit_n(+n: Nat, xs: List<&2, List<&2, U32>>, limit: Nat, empty: Bool) -> List<&2, U32>:
  match empty:
    case True{}:
      zero_tree(depth_of(pow2(limit)))
    case False{}:
      +dw = pow2(n)
      +lw = pow2(limit)
      node = merkle_pow2(40n, dw, pad_zeros(Nat.sub(dw, n), xs))
      lift(Nat.sub(depth_of(lw), depth_of(dw)), depth_of(dw), node)

def merkle_limit(+xs: List<&2, List<&2, U32>>, limit: Nat) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  merkle_limit_n(n, xs, limit, Nat.is_eq(n, 0n))

def list_root(+xs: List<&2, List<&2, U32>>, limit: Nat) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  mix_len(merkle_limit(xs, limit), n)

def bytes52_root(+b: List<&2, U32>) -> List<&2, U32>:
  hash2(B.Bytes.take(b, 32n), B.Bytes.append(B.Bytes.drop(b, 32n), B.Bytes.zeros(12n)))

def chunk1(a: List<&2, U32>) -> List<&2, U32>:
  a

def chunk2(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  hash2(a, b)

def chunk4(a: List<&2, U32>, b: List<&2, U32>, c: List<&2, U32>, d: List<&2, U32>) -> List<&2, U32>:
  hash2(hash2(a, b), hash2(c, d))

def repeat_byte(n: Nat, b: U32) -> List<&2, U32>:
  B.Bytes.rep(n, b)
