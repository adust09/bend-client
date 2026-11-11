import Base
import ../deps/bend-merkle-tree/src/bytes.bend as B
import ./types.bend as T
import ./justification.bend as J
import ./transition.bend as R

# Fork-choice store and the pure state machine around it, ported 1:1 from the
# pinned leanSpec fork_choice.py. Event sourcing (gossip arrival, clock ticks,
# persistence) stays host-side; signature and aggregate-proof verification is an
# upstream gate, so every input here is already verified. Proofs travel as
# opaque payloads; only their participant bitsets feed fork choice.

# A fork-choice proof: participants plus an opaque XMSS payload.
type Proof is Data:
  Pf{who: List<&2, Bool>, blob: List<&2, U32>}

# One vote (attestation data) with the proofs that cover it.
type VoteEntry is Data:
  Ve{data: T.AttData, proofs: List<&2, Proof>}

# A known block under its ssz root.
type BlockAt is Data:
  BlkAt{root: List<&2, U32>, block: T.Block}

# A post-state under the block root that produced it.
type StateAt is Data:
  StiAt{root: List<&2, U32>, state: T.State}

# The fork-choice store: the node's local view of the chain.
type FcStore is Data:
  Fc{time: Nat,
     head: List<&2, U32>,
     safe_at: List<&2, U32>,
     justified: T.Checkpoint,
     finalized: T.Checkpoint,
     blocks: List<&2, BlockAt>,
     states: List<&2, StateAt>,
     known: List<&2, VoteEntry>,
     pending: List<&2, VoteEntry>}

# The result of the pure attestation validation gates.
type Checked is Data:
  Clean{}
  Dirty{reason: String}

# --- map primitives over assoc lists keyed by roots -------------------------

def block_hit_pick(hit: Bool, b: T.Block, tail: Maybe<&2, T.Block>) -> Maybe<&2, T.Block>:
  match hit:
    case True{}:
      Some{b}
    case False{}:
      tail

def block_get(blocks: List<&2, BlockAt>, +root: List<&2, U32>) -> Maybe<&2, T.Block>:
  match blocks:
    case Nil{}:
      None{}
    case Con{BlkAt{r, b}, t}:
      +hit = T.bytes_eq(r, root)
      +tail = block_get(t, root)
      block_hit_pick(hit, b, tail)

def block_known(found: Maybe<&2, T.Block>) -> Bool:
  match found:
    case None{}:
      False{}
    case Some{_}:
      True{}

def block_has(blocks: List<&2, BlockAt>, root: List<&2, U32>) -> Bool:
  +found = block_get(blocks, root)
  block_known(found)

def del_pick(+hit: Bool, +one: List<&2, BlockAt>, +rest: List<&2, BlockAt>, +kept: List<&2, BlockAt>) -> List<&2, BlockAt>:
  match hit:
    case True{}:
      +dropped : List<&2, BlockAt> = rest
      dropped
    case False{}:
      +in2 : List<&2, BlockAt> = kept
      in2

def block_del(blocks: List<&2, BlockAt>, +root: List<&2, U32>) -> List<&2, BlockAt>:
  match blocks:
    case Nil{}:
      Nil{}
    case Con{BlkAt{+r, +b}, t}:
      +hit = T.bytes_eq(r, root)
      +one : List<&2, BlockAt> = {[BlkAt{r, b}] : List<&2, BlockAt>}
      +rest : List<&2, BlockAt> = block_del(t, root)
      +kept : List<&2, BlockAt> = List.append(&2, BlockAt, one, rest)
      del_pick(hit, one, rest, kept)

def block_put(blocks: List<&2, BlockAt>, +root: List<&2, U32>, +b: T.Block) -> List<&2, BlockAt>:
  +rest : List<&2, BlockAt> = block_del(blocks, root)
  +one : List<&2, BlockAt> = {[BlkAt{root, b}] : List<&2, BlockAt>}
  List.append(&2, BlockAt, one, rest)

def state_hit_pick(hit: Bool, s: T.State, tail: Maybe<&2, T.State>) -> Maybe<&2, T.State>:
  match hit:
    case True{}:
      Some{s}
    case False{}:
      tail

def state_get(states: List<&2, StateAt>, +root: List<&2, U32>) -> Maybe<&2, T.State>:
  match states:
    case Nil{}:
      None{}
    case Con{StiAt{r, s}, t}:
      +hit = T.bytes_eq(r, root)
      +tail = state_get(t, root)
      state_hit_pick(hit, s, tail)

def sdel_pick(+hit: Bool, +one: List<&2, StateAt>, +rest: List<&2, StateAt>, +kept: List<&2, StateAt>) -> List<&2, StateAt>:
  match hit:
    case True{}:
      +dropped : List<&2, StateAt> = rest
      dropped
    case False{}:
      +in2 : List<&2, StateAt> = kept
      in2

def state_del(states: List<&2, StateAt>, +root: List<&2, U32>) -> List<&2, StateAt>:
  match states:
    case Nil{}:
      Nil{}
    case Con{StiAt{+r, +s}, t}:
      +hit = T.bytes_eq(r, root)
      +one : List<&2, StateAt> = {[StiAt{r, s}] : List<&2, StateAt>}
      +rest : List<&2, StateAt> = state_del(t, root)
      +kept : List<&2, StateAt> = List.append(&2, StateAt, one, rest)
      sdel_pick(hit, one, rest, kept)

def state_put(states: List<&2, StateAt>, +root: List<&2, U32>, +s: T.State) -> List<&2, StateAt>:
  +rest : List<&2, StateAt> = state_del(states, root)
  +one : List<&2, StateAt> = {[StiAt{root, s}] : List<&2, StateAt>}
  List.append(&2, StateAt, one, rest)

# --- ancestor climb ---------------------------------------------------------

def anc_above_slot(b: T.Block, anc: T.Checkpoint) -> Bool:
  match b:
    case T.Blk{slot, _, _, _, _}:
      Nat.is_gt(slot, T.cp_slot(anc))

def anc_above_parent(b: T.Block) -> List<&2, U32>:
  match b:
    case T.Blk{_, _, parent, _, _}:
      parent

# Phase-dispatched ancestor climb (single self-recursive def, no mutual pairs).
def ancestor_eq_root(current: List<&2, U32>, anc: T.Checkpoint) -> Bool:
  match anc:
    case T.Cp{r, _}:
      T.bytes_eq(current, r)

def fc_block_slot(b: T.Block) -> Nat:
  match b:
    case T.Blk{slot, _, _, _, _}:
      slot


def fc_slot_zero(m: Maybe<&2, Nat>) -> Nat:
  match m:
    case None{}:
      0n
    case Some{v}:
      v


def fc_slot_here_m(found: Maybe<&2, T.Block>) -> Maybe<&2, Nat>:
  match found:
    case None{}:
      None{}
    case Some{blk}:
      Some{fc_block_slot(blk)}

def anc_climb(fuel: Nat, found: Maybe<&2, T.Block>, +blocks: List<&2, BlockAt>, +anc: T.Checkpoint, current: List<&2, U32>) -> Bool:
  match fuel:
    case 1n+ +p:
      match found:
        case None{}:
          False{}
        case Some{+blk}:
          +here = fc_block_slot(blk)
          +slot = T.cp_slot(anc)
          +eq = Nat.is_eq(here, slot)
          +on = ancestor_eq_root(current, anc)
          +gt = Nat.is_gt(here, slot)
          +parent = anc_above_parent(blk)
          +next_m = block_get(blocks, parent)
          +past = anc_climb(p, next_m, blocks, anc, parent)
          +gt_out : Bool = Bool.pick(Bool, gt, past, False{})
          Bool.pick(Bool, eq, on, gt_out)
    case _:
      False{}

def block_slot_m(found: Maybe<&2, T.Block>) -> Maybe<&2, Nat>:
  match found:
    case None{}:
      None{}
    case Some{blk}:
      Some{fc_block_slot(blk)}

def checkpoint_is_ancestor(+blocks: List<&2, BlockAt>, +anc: T.Checkpoint, +descendant: List<&2, U32>) -> Bool:
  +found = block_get(blocks, descendant)
  +slot_m = block_slot_m(found)
  +fuel = Nat.add(fc_slot_zero(slot_m), 2n)
  anc_climb(fuel, found, blocks, anc, descendant)

def reason_unknown_source() -> String:
  "UNKNOWN_SOURCE_BLOCK"

def reason_unknown_target() -> String:
  "UNKNOWN_TARGET_BLOCK"

def reason_unknown_head() -> String:
  "UNKNOWN_HEAD_BLOCK"

def reason_source_after_target() -> String:
  "SOURCE_AFTER_TARGET"

def reason_head_older_than_target() -> String:
  "HEAD_OLDER_THAN_TARGET"

def reason_source_slot_mismatch() -> String:
  "SOURCE_SLOT_MISMATCH"

def reason_target_slot_mismatch() -> String:
  "TARGET_SLOT_MISMATCH"

def reason_head_slot_mismatch() -> String:
  "HEAD_SLOT_MISMATCH"

def reason_source_not_ancestor() -> String:
  "SOURCE_NOT_ANCESTOR_OF_TARGET"

def reason_target_not_ancestor() -> String:
  "TARGET_NOT_ANCESTOR_OF_HEAD"

def reason_head_not_descendant() -> String:
  "HEAD_NOT_DESCENDANT_OF_FINALIZED"

def reason_att_slot_before_head() -> String:
  "ATTESTATION_SLOT_BEFORE_HEAD"

def reason_att_too_far_in_future() -> String:
  "ATTESTATION_TOO_FAR_IN_FUTURE"

def fc_slot_zero_v(v: Nat) -> Nat:
  v

# --- vote pools -------------------------------------------------------------

def fc_same_bit(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      Bool.not(b)

def fc_bit_eq(a: List<&2, Bool>, b: List<&2, Bool>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{ah, at} Con{bh, bt}:
      +h = fc_same_bit(ah, bh)
      +r = fc_bit_eq(at, bt)
      Bool.and(h, r)
    case _ _:
      False{}

def match_proof_eq(a: Proof, b: Proof) -> Bool:
  match a:
    case Pf{who, blob}:
      match b:
        case Pf{b_who, b_blob}:
          +same = fc_bit_eq(who, b_who)
          +same2 = T.bytes_eq(blob, b_blob)
          Bool.and(same, same2)

def ve_hit_pick(hit: Bool, entry: VoteEntry, tail: Maybe<&2, VoteEntry>) -> Maybe<&2, VoteEntry>:
  match hit:
    case True{}:
      Some{entry}
    case False{}:
      tail

def ve_get(entries: List<&2, VoteEntry>, +vote: T.AttData) -> Maybe<&2, VoteEntry>:
  match entries:
    case Nil{}:
      None{}
    case Con{Ve{+d, proofs}, t}:
      +hit = J.att_data_eq(d, vote)
      +entry : VoteEntry = Ve{d, proofs}
      ve_hit_pick(hit, entry, ve_get(t, vote))

# put-if-absent semantics: existing entries keep their proofs.
def ve_drop_pick(hit: Bool, dropped: List<&2, VoteEntry>, kept: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match hit:
    case True{}:
      dropped
    case False{}:
      kept

def ve_del(entries: List<&2, VoteEntry>, +vote: T.AttData) -> List<&2, VoteEntry>:
  match entries:
    case Nil{}:
      Nil{}
    case Con{Ve{+d, +proofs}, t}:
      +hit = J.att_data_eq(d, vote)
      +one : VoteEntry = Ve{d, proofs}
      +keep = {[one] : List<&2, VoteEntry>}
      +rest = ve_del(t, vote)
      +kept = List.append(&2, VoteEntry, keep, rest)
      ve_drop_pick(hit, rest, kept)

def ve_put_go(+entries: List<&2, VoteEntry>, found: Maybe<&2, VoteEntry>, +entry: VoteEntry) -> List<&2, VoteEntry>:
  match found:
    case Some{_}:
      +same : List<&2, VoteEntry> = entries
      same
    case None{}:
      +one : List<&2, VoteEntry> = {[entry] : List<&2, VoteEntry>}
      List.append(&2, VoteEntry, one, entries)

def ve_put(+entries: List<&2, VoteEntry>, +entry: VoteEntry) -> List<&2, VoteEntry>:
  match entry:
    case Ve{d, proofs}:
      ve_put_go(entries, ve_get(entries, d), entry)

def fc_true(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      +not_b = Bool.not(b)
      not_b

def fc_bool_eq(a: List<&2, Bool>, b: List<&2, Bool>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{ah, at} Con{bh, bt}:
      +h = fc_true(ah, bh)
      +r = fc_bool_eq(at, bt)
      Bool.and(h, r)
    case _ _:
      False{}

def proof_same(p: Proof, candidate: Proof) -> Bool:
  match p:
    case Pf{who, blob}:
      match candidate:
        case Pf{c_who, c_blob}:
          +who_same = fc_bool_eq(who, c_who)
          +blob_same = T.bytes_eq(blob, c_blob)
          Bool.and(who_same, blob_same)

def proof_has(+proofs: List<&2, Proof>, +candidate: Proof) -> Bool:
  match proofs:
    case Nil{}:
      False{}
    case Con{p, t}:
      +hit = proof_same(p, candidate)
      +rest = proof_has(t, candidate)
      Bool.or(hit, rest)

def ve_has_go(proofs: List<&2, Proof>, +candidate: Proof) -> Bool:
  match proofs:
    case Nil{}:
      False{}
    case Con{p, t}:
      +hit = proof_same(p, candidate)
      +rest = proof_has(t, candidate)
      Bool.or(hit, rest)

def proof_add(known: List<&2, Proof>, p: Proof, hit: Bool) -> List<&2, Proof>:
  match hit:
    case True{}:
      +same : List<&2, Proof> = known
      same
    case False{}:
      +one : List<&2, Proof> = {[p] : List<&2, Proof>}
      List.append(&2, Proof, one, known)

def union_into(incoming: List<&2, Proof>, known: List<&2, Proof>) -> List<&2, Proof>:
  match incoming:
    case Nil{}:
      +same : List<&2, Proof> = known
      same
    case Con{+p, +t}:
      +hit = proof_has(known, p)
      +added = proof_add(t, p, hit)
      union_into(t, added)
def pool_union_proofs(found: Maybe<&2, VoteEntry>, +d: T.AttData, +proofs: List<&2, Proof>,
  entries: List<&2, VoteEntry>) -> UnionOut:
  match found:
    case None{}:
      +empty : List<&2, Proof> = Nil{}
      +out : List<&2, VoteEntry> = ve_put(entries, Ve{d, proofs})
      +merged : List<&2, Proof> = proofs
      Uo{out, merged}
    case Some{Ve{d2, known_proofs}}:
      +out : List<&2, VoteEntry> = ve_del(entries, d)
      +one = union_into(known_proofs, proofs)
      +two = union_into(proofs, one)
      +merged = two
      +out2 : List<&2, VoteEntry> = ve_put(out, Ve{d, merged})
      Uo{out2, merged}

type UnionOut is Data:
  Uo{entries: List<&2, VoteEntry>, proofs: List<&2, Proof>}

# Proof identity: participants bitset plus opaque payload must both match.
# --- pool union for accept (pending merges into known) ----------------------

# Union two proof lists with dedup (proof identity by who+blob).


# --- leaf helpers -----------------------------------------------------------

# a <= b for Nats, as a pick chain (Base has no is_le helper with Nats here).
def fc_le(+a: Nat, +b: Nat) -> Bool:
  +eq = Nat.is_eq(a, b)
  +lt = Nat.is_lt(a, b)
  Bool.or(eq, lt)

def fc_parent_of(b: T.Block) -> List<&2, U32>:
  match b:
    case T.Blk{_, _, parent, _, _}:
      parent

# --- target walks (pure; bounded by fuel) -----------------------------------

# Walk back at most `fuel` steps while the block outruns `lower`.
def fc_walk(fuel: Nat, found: Maybe<&2, T.Block>, +blocks: List<&2, BlockAt>,
  +lower: Nat, current: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 1n+ +p:
      match found:
        case None{}:
          +hold : List<&2, U32> = current
          hold
        case Some{+blk}:
          +here = fc_block_slot(blk)
          +past = Nat.is_gt(here, lower)
          +parent = fc_parent_of(blk)
          +walked = fc_walk(p, block_get(blocks, parent), blocks, lower, parent)
          +hold : List<&2, U32> = current
          Bool.pick(List<&2, U32>, past, walked, hold)
    case _:
      +hold : List<&2, U32> = current
      hold

# Walk back while the block is above the finalized slot but not justifiable.
def fc_just_walk(fuel: Nat, found: Maybe<&2, T.Block>, +blocks: List<&2, BlockAt>,
  +fin: Nat, current: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 1n+ +p:
      match found:
        case None{}:
          +hold : List<&2, U32> = current
          hold
        case Some{+blk}:
          +here = fc_block_slot(blk)
          +at_or_below = fc_le(here, fin)
          +just = J.justifiable_after(here, fin)
          +stop = Bool.or(at_or_below, just)
          +parent = fc_parent_of(blk)
          +walked = fc_just_walk(p, block_get(blocks, parent), blocks, fin, parent)
          +hold : List<&2, U32> = current
          Bool.pick(List<&2, U32>, stop, hold, walked)
    case _:
      +hold : List<&2, U32> = current
      hold

# --- duties: target and attestation data ------------------------------------

def fc_target(+store: FcStore) -> T.Checkpoint:
  match store:
    case Fc{time, +head, +safe_at, justified, +finalized, +blocks, states, known, pending}:
      +safe_found = block_get(blocks, safe_at)
      +safe_slot : Nat = fc_slot_zero(fc_slot_here_m(safe_found))
      +fin_slot = T.cp_slot(finalized)
      +lower = Nat.max(safe_slot, fin_slot)
      +head_found = block_get(blocks, head)
      +back3 = fc_walk(3n, head_found, blocks, lower, head)
      +back3_found = block_get(blocks, back3)
      +target_root = fc_just_walk(262146n, back3_found, blocks, fin_slot, back3)
      +tgt_found = block_get(blocks, target_root)
      +tgt_slot : Nat = fc_slot_zero(block_slot_m(tgt_found))
      T.Cp{target_root, tgt_slot}

# The vote's source is the head chain's own justified checkpoint; a placeholder
# zero root is replaced with the head itself.
def fc_cp_clone(c: T.Checkpoint) -> T.Checkpoint:
  match c:
    case T.Cp{r, s}:
      T.Cp{r, s}

def fc_source(head_root: List<&2, U32>, st_m: Maybe<&2, T.State>) -> T.Checkpoint:
  match st_m:
    case None{}:
      T.Cp{head_root, 0n}
    case Some{st}:
      match st:
        case T.St{time, slot, header, +justified, finalized, hist, jslots, validators, jroots, jvotes}:
          +just_cp : T.Checkpoint = T.Cp{head_root, T.cp_slot(justified)}
          +zero = T.is_zero(T.cp_root(justified))
          Bool.pick(T.Checkpoint, zero, just_cp, justified)

def fc_att_data(+store: FcStore, +slot: Nat) -> T.AttData:
  match store:
    case Fc{time, +head, safe_at, justified, finalized, blocks, states, known, pending}:
      +head_found = block_get(blocks, head)
      +head_slot : Nat = fc_slot_zero(fc_slot_here_m(head_found))
      +head_cp : T.Checkpoint = T.Cp{head, head_slot}
      +target = fc_target(store)
      +src_state = state_get(states, head)
      +source = fc_source(head, src_state)
      T.Ad{slot, head_cp, target, source}

# --- anchor -----------------------------------------------------------------

# create_store: the anchor block and state start fork choice, justified and
# finalized by definition.
def fc_anchor(+state: T.State, +block: T.Block) -> FcStore:
  +root = T.block_root(block)
  +slot = T.slot_of(state)
  +time = Nat.mul(slot, 5n)
  +blocks : List<&2, BlockAt> = {[BlkAt{root, block}] : List<&2, BlockAt>}
  +states : List<&2, StateAt> = {[StiAt{root, state}] : List<&2, StateAt>}
  +just_cp : T.Checkpoint = T.Cp{root, slot}
  +fin_cp : T.Checkpoint = T.Cp{root, slot}
  +out : FcStore = Fc{time, root, root, just_cp, fin_cp, blocks, states, Nil{}, Nil{}}
  out

# --- LMD view: extract + sort + weights (pending compile; next unit) --------
