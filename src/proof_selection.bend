import Base
import ../deps/bend-merkle-tree/src/bytes.bend as B
import ../deps/bend-ssz/src/ssz.bend as S
import ./fork_choice.bend as F
import ./justification.bend as J

# Inputs use the same host-validated SSZ bounds as F.Proof. Payloads stay opaque.
# Nil represents both an absent pool and an empty pool in the Python reference.
type Selection is Data:
  Selected{proofs: List<&2, F.Proof>, covered: List<&2, Nat>}
  Rejected{reason: String}

type Candidate is Data:
  Cached{proof: F.Proof, encoding: List<&2, U32>}

type Best is Data:
  NoBest{}
  Pick{candidate: Candidate, gain: Nat}

type Progress is Data:
  Acc{reversed: List<&2, F.Proof>, covered: List<&2, Bool>}

# SingleMessageAggregate has two variable-size fields: offsets, bitlist, payload.
# The bitlist's termination bit belongs in its wire encoding, not its SSZ root.
def proof_encoding(proof: F.Proof) -> List<&2, U32>:
  match proof:
    case F.Pf{who, blob}:
      +bits = S.pack_bits(List.append(&2, Bool, who, True{} <> Nil{}))
      +offset = Nat.add(8n, List.length(&2, U32, bits))
      +header = B.Bytes.append(B.Bytes.u32_le(8), B.Bytes.u32_le(U32.from_nat(offset)))
      B.Bytes.append(header, B.Bytes.append(bits, blob))

# Carry the preceding byte comparison to short-circuit without mutual recursion.
def encoding_gt(a: List<&2, U32>, b: List<&2, U32>, order: Cmp) -> Bool:
  match a b order:
    case _ _ GT{}:
      True{}
    case _ _ LT{}:
      False{}
    case Nil{} _ EQ{}:
      False{}
    case Con{_, _} Nil{} EQ{}:
      True{}
    case Con{ah, at} Con{bh, bt} EQ{}:
      encoding_gt(at, bt, U32.cmp(ah, bh))

def uncovered(who: List<&2, Bool>, covered: List<&2, Bool>) -> List<&2, Bool>:
  match who covered:
    case Nil{} _:
      Nil{}
    case Con{head, tail} Nil{}:
      head <> tail
    case Con{head, tail} Con{seen, rest}:
      Bool.and(head, Bool.not(seen)) <> uncovered(tail, rest)

def cover(who: List<&2, Bool>, covered: List<&2, Bool>) -> List<&2, Bool>:
  match who covered:
    case Nil{} _:
      covered
    case Con{head, tail} Nil{}:
      head <> tail
    case Con{head, tail} Con{seen, rest}:
      Bool.or(head, seen) <> cover(tail, rest)

def prepare(proofs: List<&2, F.Proof>) -> List<&2, Candidate>:
  match proofs:
    case Nil{}:
      Nil{}
    case Con{+proof, tail}:
      Cached{proof, proof_encoding(proof)} <> prepare(tail)

def candidate_encoding(candidate: Candidate) -> List<&2, U32>:
  match candidate:
    case Cached{_, encoding}:
      encoding

def candidate_gain(candidate: Candidate, covered: List<&2, Bool>) -> Nat:
  match candidate:
    case Cached{proof, _}:
      J.count_true(uncovered(F.proof_who(proof), covered))

def prefer(best: Best, +candidate: Candidate, +gain: Nat) -> Best:
  match best:
    case NoBest{}:
      Pick{candidate, gain}
    case Pick{+previous, +previous_gain}:
      +more = Nat.is_gt(gain, previous_gain)
      +equal = Nat.is_eq(gain, previous_gain)
      +larger = encoding_gt(candidate_encoding(candidate), candidate_encoding(previous), EQ{})
      +wins = Bool.or(more, Bool.and(equal, larger))
      Bool.pick(Best, wins, Pick{candidate, gain}, Pick{previous, previous_gain})

def consider(gain: Nat, candidate: Candidate, best: Best) -> Best:
  match gain:
    case 0n:
      best
    case 1n+rest:
      prefer(best, candidate, 1n+rest)

def find_best(candidates: List<&2, Candidate>, +covered: List<&2, Bool>, best: Best) -> Best:
  match candidates:
    case Nil{}:
      best
    case Con{+candidate, tail}:
      +gain = candidate_gain(candidate, covered)
      find_best(tail, covered, consider(gain, candidate, best))

# Each pick adds a validator, so it and all duplicates score zero thereafter.
# Keeping those entries is equivalent to removing them; pool length bounds picks.
def select_pool_go(fuel: Nat, best: Best, +candidates: List<&2, Candidate>, covered: List<&2, Bool>, reversed: List<&2, F.Proof>) -> Progress:
  match fuel:
    case 0n:
      Acc{reversed, covered}
    case 1n+rest:
      match best:
        case NoBest{}:
          Acc{reversed, covered}
        case Pick{Cached{+proof, _}, _}:
          +next = cover(F.proof_who(proof), covered)
          +pick = find_best(candidates, next, NoBest{})
          select_pool_go(rest, pick, candidates, next, proof <> reversed)

def select_pool(proofs: List<&2, F.Proof>, progress: Progress) -> Progress:
  match progress:
    case Acc{reversed, +covered}:
      +candidates = prepare(proofs)
      +fuel = List.length(&2, Candidate, candidates)
      +best = find_best(candidates, covered, NoBest{})
      select_pool_go(fuel, best, candidates, covered, reversed)

def finish(progress: Progress) -> Selection:
  match progress:
    case Acc{reversed, covered}:
      Selected{List.reverse(&2, F.Proof, reversed), J.voter_indices(covered)}

def pool_valid(proofs: List<&2, F.Proof>) -> Bool:
  match proofs:
    case Nil{}:
      True{}
    case Con{proof, tail}:
      +nonempty = Nat.is_gt(J.count_true(F.proof_who(proof)), 0n)
      Bool.and(nonempty, pool_valid(tail))

def select_valid(valid: Bool, priority: List<&2, F.Proof>, fallback: List<&2, F.Proof>) -> Selection:
  match valid:
    case False{}:
      Rejected{"EMPTY_AGGREGATION_BITS"}
    case True{}:
      +first = select_pool(priority, Acc{Nil{}, Nil{}})
      finish(select_pool(fallback, first))

def select_proofs_for_coverage(+priority: List<&2, F.Proof>, +fallback: List<&2, F.Proof>) -> Selection:
  +valid = Bool.and(pool_valid(priority), pool_valid(fallback))
  select_valid(valid, priority, fallback)
