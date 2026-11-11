import Base
import ../deps/bend-merkle-tree/src/bytes.bend as B
import ../deps/bend-merkle-tree/src/sha256.bend as H
import ../deps/bend-ssz/src/ssz.bend as S
import ../src/types.bend as T
import ../src/justification.bend as J
import ../src/transition.bend as R
import ../src/fork_choice.bend as F

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

# Mirror tests/vectors.py: heads and sources advance with the data slot, and
# the first aggregate anchors on the genesis root.
def att_source_pick(first: Bool, p0: List<&2, U32>, p1: List<&2, U32>) -> List<&2, U32>:
  match first:
    case True{}:
      +genesis = p0
      genesis
    case False{}:
      +later = p1
      later

def att_source_root(+k: Nat, p0: List<&2, U32>, p1: List<&2, U32>) -> List<&2, U32>:
  att_source_pick(Nat.is_eq(Nat.sub(k, 2n), 0n), p0, p1)

def many_atts(fuel: Nat, +k: Nat, +p0: List<&2, U32>, +p1: List<&2, U32>) -> List<&2, T.AggAtt>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+m:
      +head : T.Checkpoint = T.Cp{p1, Nat.sub(k, 1n)}
      +sroot = att_source_root(k, p0, p1)
      +source : T.Checkpoint = T.Cp{sroot, Nat.sub(k, 2n)}
      +one : List<&2, T.AggAtt> = T.Agg{True{} <> Nil{}, T.Ad{k, head, head, source}} <> Nil{}
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

# --- fork-choice scenario (mirrors tests/vectors.py) -------------------------

def fc_empty_body() -> List<&2, T.AggAtt>:
  Nil{}

def fc_seal_from(+post: T.State, +b: T.Block) -> T.Block:
  +root = T.state_root(post)
  T.Blk{T.block_slot(b), T.block_proposer(b), T.block_parent(b), root, T.block_body(b)}

def fc_who3() -> List<&2, Bool>:
  True{} <> True{} <> True{} <> Nil{}

def fc_who2() -> List<&2, Bool>:
  True{} <> True{} <> Nil{}

def fc_who12() -> List<&2, Bool>:
  False{} <> True{} <> True{} <> Nil{}

def fc_who0() -> List<&2, Bool>:
  True{} <> Nil{}

def fc_proofs_one(+p: F.Proof) -> List<&2, F.Proof>:
  p <> Nil{}

def fc_entry(+d: T.AttData, who: List<&2, Bool>) -> F.VoteEntry:
  +blob : List<&2, U32> = Nil{}
  +proof : F.Proof = F.Pf{who, blob}
  +proofs = fc_proofs_one(proof)
  F.Ve{d, proofs}

def fc_pool_add(+xs: List<&2, F.VoteEntry>, +e: F.VoteEntry) -> List<&2, F.VoteEntry>:
  e <> xs

def fc_store_time(+store: F.FcStore, +t: Nat) -> F.FcStore:
  match store:
    case F.Fc{_, +head, +safe_at, +justified, +finalized, +blocks, +states, +known, +pending}:
      F.Fc{t, head, safe_at, justified, finalized, blocks, states, known, pending}

def fc_set_pools(+store: F.FcStore, +known: List<&2, F.VoteEntry>,
  +pending: List<&2, F.VoteEntry>) -> F.FcStore:
  match store:
    case F.Fc{+time, +head, +safe_at, +justified, +finalized, +blocks, +states, _, _}:
      F.Fc{time, head, safe_at, justified, finalized, blocks, states, known, pending}

def fc_head_hex(+store: F.FcStore) -> String:
  match store:
    case F.Fc{_, +head, _, _, _, _, _, _, _}:
      B.Bytes.hex(head)

def fc_safe_hex(+store: F.FcStore) -> String:
  match store:
    case F.Fc{_, _, +safe_at, _, _, _, _, _, _}:
      B.Bytes.hex(safe_at)

def fc_pick_went(step: F.FcStep, +fallback: F.FcStore) -> F.FcStore:
  match step:
    case F.Went{store}:
      store
    case F.Stop{_}:
      +same : F.FcStore = fallback
      same

def fc_checked_str(c: F.Checked) -> String:
  match c:
    case F.Clean{}:
      "CLEAN"
    case F.Dirty{reason}:
      reason

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
  +anchor : T.Block = T.Blk{0n, 0n, T.zero(), T.state_root(g3), fc_empty_body()}
  +fc_anchorroot = T.block_root(anchor)
  +b1_u : T.Block = T.Blk{1n, 1n, fc_anchorroot, T.zero(), fc_empty_body()}
  +o1_fc = step(g3, b1_u)
  +s1_fc = chain_state(o1_fc, g3)
  +b1s = fc_seal_from(s1_fc, b1_u)
  +b1root = T.block_root(b1s)
  +cp1 : T.Checkpoint = T.Cp{b1root, 1n}
  +cp0 : T.Checkpoint = T.Cp{fc_anchorroot, 0n}
  +att2 : T.AttData = T.Ad{2n, cp1, cp1, cp0}
  +bits2 : List<&2, Bool> = True{} <> True{} <> Nil{}
  +body2a : List<&2, T.AggAtt> = T.Agg{bits2, att2} <> Nil{}
  +b2a_u : T.Block = T.Blk{2n, 2n, b1root, T.zero(), body2a}
  +o2a = step(s1_fc, b2a_u)
  +s2a = chain_state(o2a, s1_fc)
  +b2a = fc_seal_from(s2a, b2a_u)
  +b2aroot = T.block_root(b2a)
  +bits2b : List<&2, Bool> = True{} <> Nil{}
  +body2b : List<&2, T.AggAtt> = T.Agg{bits2b, att2} <> Nil{}
  +b2b_u : T.Block = T.Blk{2n, 2n, b1root, T.zero(), body2b}
  +o2b = step(s1_fc, b2b_u)
  +s2b = chain_state(o2b, s1_fc)
  +b2b = fc_seal_from(s2b, b2b_u)
  +b2broot = T.block_root(b2b)
  +store0 = F.fc_anchor(g3, anchor)
  +st1 = F.fc_on_block(store0, b1s)
  +store1 = fc_pick_went(st1, store0)
  +store1t = fc_store_time(store1, 5n)
  +st2a = F.fc_on_block(store1t, b2a)
  +store2 = fc_pick_went(st2a, store1t)
  +st2b = F.fc_on_block(store2, b2b)
  +store3 = fc_pick_went(st2b, store2)
  +dataV : T.AttData = T.Ad{3n, T.Cp{b2broot, 2n}, T.Cp{b2broot, 2n}, cp0}
  +dataU : T.AttData = T.Ad{3n, T.Cp{b2aroot, 2n}, T.Cp{b2aroot, 2n}, cp0}
  +poolV = fc_pool_add(Nil{}, fc_entry(dataV, fc_who3()))
  +store_v = fc_set_pools(store3, poolV, Nil{})
  +st_u = F.fc_update_head(store_v)
  +poolU = fc_pool_add(Nil{}, fc_entry(dataU, fc_who2()))
  +store_p = fc_set_pools(store3, Nil{}, poolU)
  +st_s = F.fc_safe_target(store_p)
  +pend2 = fc_pool_add(fc_pool_add(Nil{}, fc_entry(dataU, fc_who12())), fc_entry(dataV, fc_who0()))
  +store_c = fc_set_pools(store3, Nil{}, pend2)
  +st_c = F.fc_accept(store_c)
  +cpAnc : T.Checkpoint = T.Cp{fc_anchorroot, 0n}
  +attC : T.AttData = T.Ad{0n, cpAnc, cpAnc, cpAnc}
  +attUNK : T.AttData = T.Ad{0n, T.Cp{b2aroot, 2n}, T.Cp{b2aroot, 2n}, T.Cp{T.zero(), 0n}}
  +attSAT : T.AttData = T.Ad{0n, cpAnc, cpAnc, T.Cp{b1root, 1n}}
  +attHO : T.AttData = T.Ad{0n, cpAnc, T.Cp{b1root, 1n}, cpAnc}
  +attTNA : T.AttData = T.Ad{0n, T.Cp{b2broot, 2n}, T.Cp{b2aroot, 2n}, cpAnc}
  +attBH : T.AttData = T.Ad{0n, T.Cp{b2aroot, 2n}, T.Cp{b1root, 1n}, cpAnc}
  +attFAR : T.AttData = T.Ad{5n, cpAnc, cpAnc, cpAnc}
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
    IO.print("fc-anchor=" ++ B.Bytes.hex(fc_anchorroot))
    IO.print("fc-on-block1=" ++ fc_head_hex(store1))
    IO.print("fc-on-block2=" ++ fc_head_hex(store2))
    IO.print("fc-tie-break=" ++ fc_head_hex(store3))
    IO.print("fc-head-votes=" ++ fc_head_hex(st_u))
    IO.print("fc-safe-target=" ++ fc_safe_hex(st_s))
    IO.print("fc-accept=" ++ fc_head_hex(st_c))
    IO.print("fc-att-clean=" ++ fc_checked_str(F.fc_validate(store3, attC)))
    IO.print("fc-att-unknown-source=" ++ fc_checked_str(F.fc_validate(store3, attUNK)))
    IO.print("fc-att-source-after-target=" ++ fc_checked_str(F.fc_validate(store3, attSAT)))
    IO.print("fc-att-head-older=" ++ fc_checked_str(F.fc_validate(store3, attHO)))
    IO.print("fc-att-target-not-ancestor=" ++ fc_checked_str(F.fc_validate(store3, attTNA)))
    IO.print("fc-att-before-head=" ++ fc_checked_str(F.fc_validate(store3, attBH)))
    IO.print("fc-att-too-far=" ++ fc_checked_str(F.fc_validate(store3, attFAR)))
