import Base
import ../src/bytes.bend as B
import ../src/sha256.bend as H
import ../src/ssz.bend as S
import ../src/types.bend as T
import ../src/justification.bend as J
import ../src/transition.bend as R

def ascii(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{x}, t}:
      x <> ascii(t)

def one_val() -> List<&2, T.Validator>:
  T.Val{B.Bytes.rep(52n, 17), B.Bytes.rep(52n, 17), 0n} <> Nil{}

def must_bytes(m: Maybe<&2, List<&2, U32>>) -> List<&2, U32>:
  match m:
    case None{}:
      Nil{}
    case Some{b}:
      b

def parent_root() -> List<&2, U32>:
  must_bytes(B.Bytes.from_hex("2187b393993699e19d3af1724f6437cdd207d09fa545955c16ca92ac43528691"))

def post_root() -> List<&2, U32>:
  must_bytes(B.Bytes.from_hex("5581a5db6e3b962aa4573080c64448efc9fbfda02beeab333a7019f82319fdd6"))

def outcome_root(o: T.Outcome) -> String:
  match o:
    case T.Ok{state}:
      B.Bytes.hex(T.state_root(state))
    case T.Reject{reason}:
      reason

# --- 3SF-mini attestation scenario (mirrors tests/vectors.py) ---------------

def three_vals() -> List<&2, T.Validator>:
  T.Val{B.Bytes.rep(52n, 11), B.Bytes.rep(52n, 22), 0n}
    <> T.Val{B.Bytes.rep(52n, 12), B.Bytes.rep(52n, 23), 1n}
    <> T.Val{B.Bytes.rep(52n, 13), B.Bytes.rep(52n, 24), 2n} <> Nil{}

def advance(res: T.Outcome, s: T.State) -> T.State:
  match res:
    case T.Ok{state}:
      state
    case T.Reject{reason}:
      s

def advance_to(+s: T.State, +target: Nat) -> T.State:
  +res = R.process_slots(s, target)
  advance(res, s)

def hdr_state(o: T.Outcome, advanced: T.State) -> T.State:
  match o:
    case T.Ok{state}:
      state
    case T.Reject{reason}:
      advanced

def post_ok(o: T.Outcome, fallback: T.State) -> T.State:
  match o:
    case T.Ok{state}:
      state
    case T.Reject{reason}:
      fallback

# Mirror the Python harness: compute the attestations' post-state first, then
# commit its root into the block before running the real transition.
def step(+s: T.State, +b: T.Block) -> T.Outcome:
  +target = T.block_slot(b)
  +advanced = advance_to(s, target)
  +hdr = R.header_ok(advanced, b)
  +applied = hdr_state(hdr, advanced)
  +post = J.process_attestations(applied, T.block_body(b))
  +post_state = post_ok(post, advanced)
  +root = T.state_root(post_state)
  +sealed : T.Block = T.Blk{T.block_slot(b), T.block_proposer(b), T.block_parent(b), root, T.block_body(b)}
  R.transition(s, sealed)



def chain_b1(+g: T.State) -> T.Outcome:
  +p0 = T.header_root(T.header_of(advance_to(g, 1n)))
  step(g, T.Blk{1n, 1n, p0, T.zero(), Nil{}})

def chain_b2(+g: T.State, +o: T.Outcome) -> T.Outcome:
  match o:
    case T.Ok{s1}:
      +p0 = T.header_root(T.header_of(advance_to(g, 1n)))
      +p1 = T.header_root(T.header_of(advance_to(s1, 2n)))
      +target : T.Checkpoint = T.Cp{p1, 1n}
      +source : T.Checkpoint = T.Cp{p0, 0n}
      +body : List<&2, T.AggAtt> = T.Agg{True{} <> True{} <> Nil{}, T.Ad{2n, target, target, source}} <> Nil{}
      step(s1, T.Blk{2n, 2n, p1, T.zero(), body})
    case T.Reject{reason}:
      T.Reject{reason}

def chain_b3(+s1: T.State, +s2: T.State, +o: T.Outcome) -> T.Outcome:
  match o:
    case T.Ok{_}:
      +p2 = T.header_root(T.header_of(advance_to(s1, 2n)))
      +p3 = T.header_root(T.header_of(advance_to(s2, 3n)))
      +target : T.Checkpoint = T.Cp{p3, 2n}
      +source : T.Checkpoint = T.Cp{p2, 1n}
      +body : List<&2, T.AggAtt> = T.Agg{True{} <> True{} <> True{} <> Nil{}, T.Ad{3n, target, target, source}} <> Nil{}
      step(s2, T.Blk{3n, 0n, p3, T.zero(), body})
    case T.Reject{reason}:
      T.Reject{reason}

def chain_b4(+s2: T.State, +s3: T.State, +o: T.Outcome) -> T.Outcome:
  match o:
    case T.Ok{_}:
      +p3 = T.header_root(T.header_of(advance_to(s2, 3n)))
      +p4 = T.header_root(T.header_of(advance_to(s3, 4n)))
      +target : T.Checkpoint = T.Cp{p4, 3n}
      +source : T.Checkpoint = T.Cp{p3, 2n}
      +body : List<&2, T.AggAtt> = T.Agg{True{} <> True{} <> True{} <> Nil{}, T.Ad{4n, target, target, source}} <> Nil{}
      step(s3, T.Blk{4n, 1n, p4, T.zero(), body})
    case T.Reject{reason}:
      T.Reject{reason}

def reject_base(+g: T.State, +bits: List<&2, Bool>, +o: T.Outcome) -> T.Outcome:
  match o:
    case T.Ok{s1}:
      +p0 = T.header_root(T.header_of(advance_to(g, 1n)))
      +p1 = T.header_root(T.header_of(advance_to(s1, 2n)))
      +target : T.Checkpoint = T.Cp{p1, 1n}
      +source : T.Checkpoint = T.Cp{p0, 0n}
      +body : List<&2, T.AggAtt> = T.Agg{bits, T.Ad{2n, target, target, source}} <> Nil{}
      step(s1, T.Blk{2n, 2n, p1, T.zero(), body})
    case T.Reject{reason}:
      T.Reject{reason}

def many_atts(fuel: Nat, +k: Nat, +p0: List<&2, U32>, +p1: List<&2, U32>) -> List<&2, T.AggAtt>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+m:
      +target : T.Checkpoint = T.Cp{p1, 1n}
      +source : T.Checkpoint = T.Cp{p0, 0n}
      +one : List<&2, T.AggAtt> = T.Agg{True{} <> Nil{}, T.Ad{k, target, target, source}} <> Nil{}
      +rest = many_atts(m, Nat.add(k, 1n), p0, p1)
      List.append(&2, T.AggAtt, one, rest)

def reject_many(+g: T.State, +o: T.Outcome) -> T.Outcome:
  match o:
    case T.Ok{s1}:
      +p0 = T.header_root(T.header_of(advance_to(g, 1n)))
      +p1 = T.header_root(T.header_of(advance_to(s1, 2n)))
      step(s1, T.Blk{2n, 2n, p1, T.zero(), many_atts(9n, 2n, p0, p1)})
    case T.Reject{reason}:
      T.Reject{reason}

def chain_state(o: T.Outcome, fallback: T.State) -> T.State:
  match o:
    case T.Ok{state}:
      state
    case T.Reject{reason}:
      fallback

def main() -> IO(Unit):
  +g : T.State = T.genesis(1000n, one_val())
  +b : T.Block = T.Blk{1n, 0n, parent_root(), post_root(), Nil{}}
  +wrong_parent : T.Block = T.Blk{1n, 0n, T.zero(), post_root(), Nil{}}
  +wrong_proposer : T.Block = T.Blk{1n, 1n, parent_root(), post_root(), Nil{}}
  +same_slot : T.Block = T.Blk{0n, 0n, T.zero(), T.zero(), Nil{}}
  +bad_bits : List<&2, Bool> = True{} <> False{} <> False{} <> False{} <> True{} <> Nil{}
  +g3 : T.State = T.genesis(1000n, three_vals())
  +o1 = chain_b1(g3)
  +s1 = chain_state(o1, g3)
  +d1 = reject_base(g3, bad_bits, o1)
  +d2 = reject_base(g3, Nil{}, o1)
  +d3 = reject_many(g3, o1)
  +o2 = chain_b2(g3, o1)
  +s2 = chain_state(o2, s1)
  +o3 = chain_b3(s1, s2, o2)
  +s3 = chain_state(o3, s2)
  +o4 = chain_b4(s2, s3, o3)
  do IO<Unit>:
    IO.print("sha-empty=" ++ H.sha256_hex(Nil{}))
    IO.print("sha-abc=" ++ H.sha256_hex(ascii("abc")))
    IO.print("ssz-u64-1000=" ++ B.Bytes.hex(S.u64_chunk(1000n)))
    IO.print("ssz-zero-depth10=" ++ B.Bytes.hex(S.zero_tree(10n)))
    IO.print("ssz-bytes52=" ++ B.Bytes.hex(S.bytes52_root(B.Bytes.rep(52n, 17))))
    IO.print("genesis=" ++ B.Bytes.hex(T.state_root(g)))
    IO.print("bitlist-empty=" ++ B.Bytes.hex(T.jslots_root(Nil{})))
    IO.print("bitlist-one=" ++ B.Bytes.hex(T.jslots_root(True{} <> Nil{})))
    IO.print("transition=" ++ outcome_root(R.transition(g, b)))
    IO.print("reject-parent=" ++ outcome_root(R.transition(g, wrong_parent)))
    IO.print("reject-proposer=" ++ outcome_root(R.transition(g, wrong_proposer)))
    IO.print("reject-not-future=" ++ outcome_root(R.transition(g, same_slot)))
    IO.print("att-block1=" ++ outcome_root(o1))
    IO.print("att-index-range=" ++ outcome_root(d1))
    IO.print("att-bits-empty=" ++ outcome_root(d2))
    IO.print("att-too-many=" ++ outcome_root(d3))
    IO.print("att-justify=" ++ outcome_root(o2))
    IO.print("att-finalize=" ++ outcome_root(o3))
    IO.print("att-finalize2=" ++ outcome_root(o4))
