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

def union_into(incoming: List<&2, Proof>, +known: List<&2, Proof>) -> List<&2, Proof>:
  match incoming:
    case Nil{}:
      +same : List<&2, Proof> = known
      same
    case Con{+p, +t}:
      +hit = proof_has(known, p)
      +added = proof_add(known, p, hit)
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
          +zero = T.is_zero(T.cp_raw(justified))
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

# Fork choice past the store checkpoint. Computed branches are their own defs
# so a match never scrutinizes a local. Signature checks stay upstream.

type FcStep is Data:
  Went{store: FcStore}
  Stop{reason: String}

type VoteSel is Data:
  Vs{validator: Nat, data: T.AttData}

type WeightAt is Data:
  Wt{root: List<&2, U32>, n: Nat}

type KidsAt is Data:
  Kd{parent: List<&2, U32>, kids: List<&2, List<&2, U32>>}

type Best is Data:
  NoBest{}
  Has{root: List<&2, U32>, w: Nat}

def reason_unknown_parent() -> String:
  "UNKNOWN_PARENT_BLOCK"

def reason_slot_gap() -> String:
  "BLOCK_SLOT_GAP_TOO_LARGE"

def reason_block_future() -> String:
  "BLOCK_TOO_FAR_IN_FUTURE"

def reason_dup_att() -> String:
  "DUPLICATE_ATTESTATION_DATA"

def fc_att_slot(d: T.AttData) -> Nat:
  match d:
    case T.Ad{slot, _, _, _}:
      slot

def att_head_root(d: T.AttData) -> List<&2, U32>:
  match d:
    case T.Ad{_, head, _, _}:
      T.cp_raw(head)

def att_head_slot(d: T.AttData) -> Nat:
  match d:
    case T.Ad{_, head, _, _}:
      T.cp_slot(head)

def state_justified(s: T.State) -> T.Checkpoint:
  match s:
    case T.St{_, _, _, justified, _, _, _, _, _, _}:
      justified

def state_finalized(s: T.State) -> T.Checkpoint:
  match s:
    case T.St{_, _, _, _, finalized, _, _, _, _, _}:
      finalized

def slot_mismatch(found: Maybe<&2, T.Block>, slot: Nat) -> Bool:
  match found:
    case None{}:
      True{}
    case Some{blk}:
      Bool.not(Nat.is_eq(fc_block_slot(blk), slot))

def slot_gap_too_big(bslot: Nat, pslot: Nat) -> Bool:
  +gap = Nat.sub(bslot, pslot)
  Nat.is_gt(gap, 262144n)

def block_too_far(time: Nat, bslot: Nat) -> Bool:
  +now = Nat.div(time, 5n)
  +limit = Nat.add(now, 1n)
  Nat.is_gt(bslot, limit)

def root_gt_eq(eq: Bool, rest: Bool) -> Bool:
  match eq:
    case True{}:
      rest
    case False{}:
      False{}

def root_gt_arm(gt: Bool, eq: Bool, rest: Bool) -> Bool:
  match gt:
    case True{}:
      True{}
    case False{}:
      root_gt_eq(eq, rest)

def fc_root_gt(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      False{}
    case Con{ah, at} Con{bh, bt}:
      +an = U32.to_nat(ah)
      +bn = U32.to_nat(bh)
      +gt = Nat.is_gt(an, bn)
      +eq = Nat.is_eq(an, bn)
      +rest = fc_root_gt(at, bt)
      root_gt_arm(gt, eq, rest)
    case _ _:
      False{}

def fc_vote_prec(a: VoteEntry, b: VoteEntry) -> Bool:
  match a:
    case Ve{+da, _}:
      match b:
        case Ve{+db, _}:
          +as = fc_att_slot(da)
          +bs = fc_att_slot(db)
          +gt = Nat.is_gt(as, bs)
          +eq = Nat.is_eq(as, bs)
          +ar = T.att_root(da)
          +br = T.att_root(db)
          +rg = fc_root_gt(ar, br)
          +tie = Bool.and(eq, rg)
          Bool.or(gt, tie)

def fv_ins_nil(done: Bool, entry: VoteEntry) -> List<&2, VoteEntry>:
  match done:
    case True{}:
      Nil{}
    case False{}:
      entry <> Nil{}

def fv_ins_cons(insert_here: Bool, entry: VoteEntry, j: VoteEntry, rest: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match insert_here:
    case True{}:
      entry <> (j <> rest)
    case False{}:
      j <> rest

def fv_ins(xs: List<&2, VoteEntry>, +entry: VoteEntry, +done: Bool) -> List<&2, VoteEntry>:
  match xs:
    case Nil{}:
      fv_ins_nil(done, entry)
    case Con{+j, ht}:
      +pre = fc_vote_prec(entry, j)
      +fresh = Bool.not(done)
      +insert_here = Bool.and(fresh, pre)
      +next_done = Bool.or(done, pre)
      +rest = fv_ins(ht, entry, next_done)
      fv_ins_cons(insert_here, entry, j, rest)

def fv_sort_go(xs: List<&2, VoteEntry>, acc: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match xs:
    case Nil{}:
      acc
    case Con{h, t}:
      +acc2 = fv_ins(acc, h, False{})
      fv_sort_go(t, acc2)

def fv_sort(xs: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  fv_sort_go(xs, Nil{})

def proof_who(p: Proof) -> List<&2, Bool>:
  match p:
    case Pf{who, _}:
      who

def fv_known(seen: List<&2, VoteSel>, +v: Nat) -> Bool:
  match seen:
    case Nil{}:
      False{}
    case Con{Vs{v2, _}, t}:
      +hit = Nat.is_eq(v2, v)
      +rest = fv_known(t, v)
      Bool.or(hit, rest)

def fv_keep(known: Bool, seen: List<&2, VoteSel>, v: Nat, d: T.AttData) -> List<&2, VoteSel>:
  match known:
    case True{}:
      seen
    case False{}:
      Vs{v, d} <> seen

def fv_idxs(idxs: List<&2, Nat>, +seen: List<&2, VoteSel>, +d: T.AttData) -> List<&2, VoteSel>:
  match idxs:
    case Nil{}:
      seen
    case Con{+v, t}:
      +known = fv_known(seen, v)
      +next = fv_keep(known, seen, v, d)
      fv_idxs(t, next, d)

def fv_proofs(proofs: List<&2, Proof>, +seen: List<&2, VoteSel>, +d: T.AttData) -> List<&2, VoteSel>:
  match proofs:
    case Nil{}:
      seen
    case Con{p, t}:
      +who = proof_who(p)
      +idxs = J.voter_indices(who)
      +next = fv_idxs(idxs, seen, d)
      fv_proofs(t, next, d)

def fv_stale(d: T.AttData, fin_slot: Nat) -> Bool:
  fc_le(att_head_slot(d), fin_slot)

def fv_if_fresh(stale: Bool, seen: List<&2, VoteSel>, d: T.AttData, proofs: List<&2, Proof>) -> List<&2, VoteSel>:
  match stale:
    case True{}:
      seen
    case False{}:
      fv_proofs(proofs, seen, d)

def fv_entries(entries: List<&2, VoteEntry>, +fin_slot: Nat, seen: List<&2, VoteSel>) -> List<&2, VoteSel>:
  match entries:
    case Nil{}:
      seen
    case Con{Ve{+d, proofs}, t}:
      +stale = fv_stale(d, fin_slot)
      +next = fv_if_fresh(stale, seen, d, proofs)
      fv_entries(t, fin_slot, next)

def fv_view(pool: List<&2, VoteEntry>, fin_slot: Nat) -> List<&2, VoteSel>:
  +sorted = fv_sort(pool)
  fv_entries(sorted, fin_slot, Nil{})

def gate_future(bad: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_att_too_far_in_future()}
    case False{}:
      Clean{}

def gate_before(bad: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_att_slot_before_head()}
    case False{}:
      gate_future(b12)

def gate_fin(bad: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_head_not_descendant()}
    case False{}:
      gate_before(b11, b12)

def gate_tgt_anc(bad: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_target_not_ancestor()}
    case False{}:
      gate_fin(b10, b11, b12)

def gate_src_anc(bad: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_source_not_ancestor()}
    case False{}:
      gate_tgt_anc(b9, b10, b11, b12)

def gate_head_slot(bad: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_head_slot_mismatch()}
    case False{}:
      gate_src_anc(b8, b9, b10, b11, b12)

def gate_tgt_slot(bad: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_target_slot_mismatch()}
    case False{}:
      gate_head_slot(b7, b8, b9, b10, b11, b12)

def gate_src_slot(bad: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_source_slot_mismatch()}
    case False{}:
      gate_tgt_slot(b6, b7, b8, b9, b10, b11, b12)

def gate_order_ht(bad: Bool, b5: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_head_older_than_target()}
    case False{}:
      gate_src_slot(b5, b6, b7, b8, b9, b10, b11, b12)

def gate_order_st(bad: Bool, b4: Bool, b5: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_source_after_target()}
    case False{}:
      gate_order_ht(b4, b5, b6, b7, b8, b9, b10, b11, b12)

def gate_head(bad: Bool, b3: Bool, b4: Bool, b5: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_unknown_head()}
    case False{}:
      gate_order_st(b3, b4, b5, b6, b7, b8, b9, b10, b11, b12)

def gate_tgt(bad: Bool, b2: Bool, b3: Bool, b4: Bool, b5: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match bad:
    case True{}:
      Dirty{reason_unknown_target()}
    case False{}:
      gate_head(b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12)

def gate_src(b0: Bool, b1: Bool, b2: Bool, b3: Bool, b4: Bool, b5: Bool, b6: Bool, b7: Bool, b8: Bool, b9: Bool, b10: Bool, b11: Bool, b12: Bool) -> Checked:
  match b0:
    case True{}:
      Dirty{reason_unknown_source()}
    case False{}:
      gate_tgt(b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12)

def fc_validate_at(time: Nat, +blocks: List<&2, BlockAt>, fin: T.Checkpoint, d: T.AttData) -> Checked:
  match d:
    case T.Ad{+slot, +head, +target, +source}:
      +src_r = T.cp_raw(source)
      +tgt_r = T.cp_raw(target)
      +head_r = T.cp_raw(head)
      +src_s = T.cp_slot(source)
      +tgt_s = T.cp_slot(target)
      +head_s = T.cp_slot(head)
      +src_b = block_get(blocks, src_r)
      +tgt_b = block_get(blocks, tgt_r)
      +head_b = block_get(blocks, head_r)
      +b0 = Bool.not(block_known(src_b))
      +b1 = Bool.not(block_known(tgt_b))
      +b2 = Bool.not(block_known(head_b))
      +b3 = Nat.is_gt(src_s, tgt_s)
      +b4 = Nat.is_gt(tgt_s, head_s)
      +b5 = slot_mismatch(src_b, src_s)
      +b6 = slot_mismatch(tgt_b, tgt_s)
      +b7 = slot_mismatch(head_b, head_s)
      +b8 = Bool.not(checkpoint_is_ancestor(blocks, source, tgt_r))
      +b9 = Bool.not(checkpoint_is_ancestor(blocks, target, head_r))
      +b10 = Bool.not(checkpoint_is_ancestor(blocks, fin, head_r))
      +max_s = Nat.div(Nat.add(time, 1n), 5n)
      +b11 = Nat.is_gt(head_s, slot)
      +b12 = Nat.is_gt(slot, max_s)
      gate_src(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12)

def fc_validate(store: FcStore, d: T.AttData) -> Checked:
  match store:
    case Fc{time, _, _, _, finalized, blocks, _, _, _}:
      fc_validate_at(time, blocks, finalized, d)

def wt_nil(done: Bool, root: List<&2, U32>) -> List<&2, WeightAt>:
  match done:
    case True{}:
      Nil{}
    case False{}:
      Wt{root, 1n} <> Nil{}

def wt_cons_hit(hit: Bool, r: List<&2, U32>, n: Nat, rest: List<&2, WeightAt>) -> List<&2, WeightAt>:
  match hit:
    case True{}:
      +n2 = Nat.add(n, 1n)
      Wt{r, n2} <> rest
    case False{}:
      Wt{r, n} <> rest

def wt_cons(done: Bool, hit: Bool, r: List<&2, U32>, n: Nat, rest: List<&2, WeightAt>) -> List<&2, WeightAt>:
  match done:
    case True{}:
      Wt{r, n} <> rest
    case False{}:
      wt_cons_hit(hit, r, n, rest)

def wt_inc(ws: List<&2, WeightAt>, +root: List<&2, U32>, +done: Bool) -> List<&2, WeightAt>:
  match ws:
    case Nil{}:
      wt_nil(done, root)
    case Con{Wt{+hr, hn}, ht}:
      +h = T.bytes_eq(hr, root)
      +next_done = Bool.or(done, h)
      +rest = wt_inc(ht, root, next_done)
      wt_cons(done, h, hr, hn, rest)

def wt_pick(hit: Bool, n: Nat, rest: Nat) -> Nat:
  match hit:
    case True{}:
      n
    case False{}:
      rest

def wt_get(ws: List<&2, WeightAt>, +root: List<&2, U32>) -> Nat:
  match ws:
    case Nil{}:
      0n
    case Con{Wt{r, n}, t}:
      +hit = T.bytes_eq(r, root)
      +rest = wt_get(t, root)
      wt_pick(hit, n, rest)

def credit_one(fuel: Nat, phase: Nat, stop: Bool, found: Maybe<&2, T.Block>, +blocks: List<&2, BlockAt>, +start: Nat, current: List<&2, U32>, +nxt_root: List<&2, U32>, +nxt_found: Maybe<&2, T.Block>, weights: List<&2, WeightAt>) -> List<&2, WeightAt>:
  match fuel:
    case 0n:
      weights
    case 1n+ +p:
      match phase:
        case 0n:
          match found:
            case None{}:
              weights
            case Some{+blk}:
              +here = fc_block_slot(blk)
              +nst = fc_le(here, start)
              +parent = fc_parent_of(blk)
              +nf = block_get(blocks, parent)
              credit_one(p, 1n, nst, nf, blocks, start, current, parent, nf, weights)
        case _:
          match stop:
            case True{}:
              weights
            case False{}:
              +bumped = wt_inc(weights, current, False{})
              credit_one(p, 0n, False{}, nxt_found, blocks, start, nxt_root, nxt_root, nxt_found, bumped)

def credit_votes(votes: List<&2, VoteSel>, +blocks: List<&2, BlockAt>, +start: Nat, weights: List<&2, WeightAt>) -> List<&2, WeightAt>:
  match votes:
    case Nil{}:
      weights
    case Con{Vs{_, d}, t}:
      +head = att_head_root(d)
      +found = block_get(blocks, head)
      +slot = fc_slot_zero(fc_slot_here_m(found))
      +found2 = block_get(blocks, head)
      +fuel = Nat.add(Nat.mul(slot, 2n), 8n)
      +empty_r : List<&2, U32> = Nil{}
      +none : Maybe<&2, T.Block> = None{}
      +next = credit_one(fuel, 0n, False{}, found2, blocks, start, head, empty_r, none, weights)
      credit_votes(t, blocks, start, next)

def fc_weights(store: FcStore) -> List<&2, WeightAt>:
  match store:
    case Fc{_, _, _, _, finalized, blocks, _, known, _}:
      +fin_slot = T.cp_slot(finalized)
      +votes = fv_view(known, fin_slot)
      credit_votes(votes, blocks, fin_slot, Nil{})

def kids_nil(done: Bool, parent: List<&2, U32>, child: List<&2, U32>) -> List<&2, KidsAt>:
  match done:
    case True{}:
      Nil{}
    case False{}:
      Kd{parent, child <> Nil{}} <> Nil{}

def kids_cons_hit(hit: Bool, here: List<&2, U32>, kids: List<&2, List<&2, U32>>, child: List<&2, U32>, rest: List<&2, KidsAt>) -> List<&2, KidsAt>:
  match hit:
    case True{}:
      Kd{here, child <> kids} <> rest
    case False{}:
      Kd{here, kids} <> rest

def kids_cons(done: Bool, hit: Bool, here: List<&2, U32>, kids: List<&2, List<&2, U32>>, child: List<&2, U32>, rest: List<&2, KidsAt>) -> List<&2, KidsAt>:
  match done:
    case True{}:
      Kd{here, kids} <> rest
    case False{}:
      kids_cons_hit(hit, here, kids, child, rest)

def kids_add(buckets: List<&2, KidsAt>, +parent: List<&2, U32>, +child: List<&2, U32>, +done: Bool) -> List<&2, KidsAt>:
  match buckets:
    case Nil{}:
      kids_nil(done, parent, child)
    case Con{Kd{+hp, hk}, ht}:
      +h = T.bytes_eq(hp, parent)
      +next_done = Bool.or(done, h)
      +rest = kids_add(ht, parent, child, next_done)
      kids_cons(done, h, hp, hk, child, rest)

def kids_pick(hit: Bool, kids: List<&2, List<&2, U32>>, rest: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match hit:
    case True{}:
      kids
    case False{}:
      rest

def kids_get(buckets: List<&2, KidsAt>, +parent: List<&2, U32>) -> List<&2, List<&2, U32>>:
  match buckets:
    case Nil{}:
      Nil{}
    case Con{Kd{p, kids}, t}:
      +hit = T.bytes_eq(p, parent)
      +rest = kids_get(t, parent)
      kids_pick(hit, kids, rest)

def build_keep(no_min: Bool, ge: Bool) -> Bool:
  match no_min:
    case True{}:
      True{}
    case False{}:
      ge

def build_add(keep: Bool, buckets: List<&2, KidsAt>, parent: List<&2, U32>, child: List<&2, U32>) -> List<&2, KidsAt>:
  match keep:
    case False{}:
      buckets
    case True{}:
      kids_add(buckets, parent, child, False{})

def build_kids(blocks: List<&2, BlockAt>, +weights: List<&2, WeightAt>, +no_min: Bool, +min_score: Nat, buckets: List<&2, KidsAt>) -> List<&2, KidsAt>:
  match blocks:
    case Nil{}:
      buckets
    case Con{BlkAt{+root, block}, t}:
      +parent = fc_parent_of(block)
      +w = wt_get(weights, root)
      +ge = Nat.is_ge(w, min_score)
      +keep = build_keep(no_min, ge)
      +next = build_add(keep, buckets, parent, root)
      build_kids(t, weights, no_min, min_score, next)

def better(+cw: Nat, +bw: Nat, child: List<&2, U32>, best: List<&2, U32>) -> Bool:
  +gt = Nat.is_gt(cw, bw)
  +eq = Nat.is_eq(cw, bw)
  +rg = fc_root_gt(child, best)
  +tie = Bool.and(eq, rg)
  Bool.or(gt, tie)

def best_take(win: Bool, child: List<&2, U32>, cw: Nat, best: List<&2, U32>, bw: Nat) -> Best:
  match win:
    case True{}:
      Has{child, cw}
    case False{}:
      Has{best, bw}

def best_step(acc: Best, +child: List<&2, U32>, +cw: Nat) -> Best:
  match acc:
    case NoBest{}:
      Has{child, cw}
    case Has{+b, +bw}:
      +win = better(cw, bw, child, b)
      best_take(win, child, cw, b, bw)

def ghost_best(kids: List<&2, List<&2, U32>>, +weights: List<&2, WeightAt>, acc: Best) -> Best:
  match kids:
    case Nil{}:
      acc
    case Con{+k, t}:
      +w = wt_get(weights, k)
      +next = best_step(acc, k, w)
      ghost_best(t, weights, next)

def ghost_walk(fuel: Nat, phase: Nat, best: Best, +current: List<&2, U32>, +buckets: List<&2, KidsAt>, +weights: List<&2, WeightAt>) -> List<&2, U32>:
  match fuel:
    case 0n:
      current
    case 1n+ +p:
      match phase:
        case 0n:
          +kids = kids_get(buckets, current)
          +nb = ghost_best(kids, weights, NoBest{})
          ghost_walk(p, 1n, nb, current, buckets, weights)
        case _:
          match best:
            case NoBest{}:
              current
            case Has{root, _}:
              ghost_walk(p, 0n, NoBest{}, root, buckets, weights)

def ghost_from(found: Maybe<&2, T.Block>, start: List<&2, U32>, old: List<&2, U32>, +blocks: List<&2, BlockAt>, votes: List<&2, VoteSel>, no_min: Bool, min_score: Nat) -> List<&2, U32>:
  match found:
    case None{}:
      old
    case Some{blk}:
      +slot = fc_block_slot(blk)
      +weights = credit_votes(votes, blocks, slot, Nil{})
      +kids = build_kids(blocks, weights, no_min, min_score, Nil{})
      +n = List.length(&2, BlockAt, blocks)
      +fuel = Nat.add(Nat.mul(n, 2n), 2n)
      ghost_walk(fuel, 0n, NoBest{}, start, kids, weights)

def fin_hold(go: Bool, walked: List<&2, U32>, current: List<&2, U32>) -> List<&2, U32>:
  match go:
    case True{}:
      walked
    case False{}:
      current

def fin_walk(fuel: Nat, found: Maybe<&2, T.Block>, +blocks: List<&2, BlockAt>, +target: Nat, current: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      current
    case 1n+ +p:
      match found:
        case None{}:
          current
        case Some{+blk}:
          +here = fc_block_slot(blk)
          +above = Nat.is_gt(here, target)
          +parent = fc_parent_of(blk)
          +parent_m = block_get(blocks, parent)
          +known = block_known(parent_m)
          +go = Bool.and(above, known)
          +walked = fin_walk(p, parent_m, blocks, target, parent)
          fin_hold(go, walked, current)

def fin_pick(ok: Bool, root: List<&2, U32>, slot: Nat, fallback: T.Checkpoint) -> T.Checkpoint:
  match ok:
    case True{}:
      T.Cp{root, slot}
    case False{}:
      fallback

def fin_landed(found: Maybe<&2, T.Block>, root: List<&2, U32>, +target: Nat, fallback: T.Checkpoint) -> T.Checkpoint:
  match found:
    case None{}:
      fallback
    case Some{blk}:
      +here = fc_block_slot(blk)
      +ok = Nat.is_eq(here, target)
      fin_pick(ok, root, target, fallback)

def fin_from(st: Maybe<&2, T.State>, +blocks: List<&2, BlockAt>, +head: List<&2, U32>, fallback: T.Checkpoint) -> T.Checkpoint:
  match st:
    case None{}:
      fallback
    case Some{state}:
      +target = T.cp_slot(state_finalized(state))
      +found = block_get(blocks, head)
      +slot = fc_slot_zero(fc_slot_here_m(found))
      +found2 = block_get(blocks, head)
      +fuel = Nat.add(slot, 2n)
      +landed = fin_walk(fuel, found2, blocks, target, head)
      +landed_m = block_get(blocks, landed)
      fin_landed(landed_m, landed, target, fallback)

def adv_pick(take: Bool, cand: T.Checkpoint, cur: T.Checkpoint) -> T.Checkpoint:
  match take:
    case True{}:
      cand
    case False{}:
      cur

def fc_advance(+cur: T.Checkpoint, +cand: T.Checkpoint) -> T.Checkpoint:
  +cs = T.cp_slot(cur)
  +ks = T.cp_slot(cand)
  +take = Nat.is_gt(ks, cs)
  adv_pick(take, cand, cur)

def fc_update_head(store: FcStore) -> FcStore:
  match store:
    case Fc{time, head, safe_at, +justified, +finalized, +blocks, +states, +known, pending}:
      +fin_slot = T.cp_slot(finalized)
      +votes = fv_view(known, fin_slot)
      +start = T.cp_raw(justified)
      +found = block_get(blocks, start)
      +new_head = ghost_from(found, start, head, blocks, votes, True{}, 0n)
      +st = state_get(states, new_head)
      +fin2 = fin_from(st, blocks, new_head, finalized)
      Fc{time, new_head, safe_at, justified, fin2, blocks, states, known, pending}

def uo_entries(u: UnionOut) -> List<&2, VoteEntry>:
  match u:
    case Uo{entries, _}:
      entries

def accept_merge(pending: List<&2, VoteEntry>, +known: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match pending:
    case Nil{}:
      known
    case Con{Ve{+d, proofs}, t}:
      +found = ve_get(known, d)
      +uo = pool_union_proofs(found, d, proofs, known)
      +next = uo_entries(uo)
      accept_merge(t, next)

def fc_accept(store: FcStore) -> FcStore:
  match store:
    case Fc{time, head, safe_at, justified, finalized, blocks, states, known, pending}:
      +merged = accept_merge(pending, known)
      +next : FcStore = Fc{time, head, safe_at, justified, finalized, blocks, states, merged, Nil{}}
      fc_update_head(next)

def safe_score(found: Maybe<&2, T.State>) -> Nat:
  match found:
    case None{}:
      0n
    case Some{st}:
      +n = T.val_count(st)
      Nat.div(Nat.add(Nat.mul(n, 2n), 2n), 3n)

def fc_safe_target(store: FcStore) -> FcStore:
  match store:
    case Fc{time, +head, _, +justified, +finalized, +blocks, +states, known, +pending}:
      +fin_slot = T.cp_slot(finalized)
      +votes = fv_view(pending, fin_slot)
      +start = T.cp_raw(justified)
      +found = block_get(blocks, start)
      +st = state_get(states, head)
      +score = safe_score(st)
      +safe = ghost_from(found, start, head, blocks, votes, False{}, score)
      Fc{time, head, safe, justified, finalized, blocks, states, known, pending}

def vote_lives(blocks: List<&2, BlockAt>, +fin: T.Checkpoint, d: T.AttData) -> Bool:
  match d:
    case T.Ad{_, +head, _, _}:
      +hs = T.cp_slot(head)
      +fs = T.cp_slot(fin)
      +above = Nat.is_gt(hs, fs)
      +anc = checkpoint_is_ancestor(blocks, fin, T.cp_raw(head))
      Bool.and(above, anc)

def prune_keep(live: Bool, acc: List<&2, VoteEntry>, entry: VoteEntry) -> List<&2, VoteEntry>:
  match live:
    case True{}:
      entry <> acc
    case False{}:
      acc

def prune_pool(entries: List<&2, VoteEntry>, +blocks: List<&2, BlockAt>, +fin: T.Checkpoint, acc: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match entries:
    case Nil{}:
      acc
    case Con{Ve{+d, proofs}, t}:
      +live = vote_lives(blocks, fin, d)
      +entry : VoteEntry = Ve{d, proofs}
      +next = prune_keep(live, acc, entry)
      prune_pool(t, blocks, fin, next)

def fc_prune(store: FcStore) -> FcStore:
  match store:
    case Fc{time, head, safe_at, justified, +finalized, +blocks, states, known, pending}:
      +k2 = prune_pool(known, blocks, finalized, Nil{})
      +p2 = prune_pool(pending, blocks, finalized, Nil{})
      Fc{time, head, safe_at, justified, finalized, blocks, states, k2, p2}

def seen_add(seen: List<&2, List<&2, U32>>, root: List<&2, U32>) -> List<&2, List<&2, U32>>:
  root <> seen

def root_seen(seen: List<&2, List<&2, U32>>, +root: List<&2, U32>) -> Bool:
  match seen:
    case Nil{}:
      False{}
    case Con{h, t}:
      +hit = T.bytes_eq(h, root)
      +rest = root_seen(t, root)
      Bool.or(hit, rest)

def body_dups(body: List<&2, T.AggAtt>, +seen: List<&2, List<&2, U32>>) -> Bool:
  match body:
    case Nil{}:
      False{}
    case Con{T.Agg{_, d}, t}:
      +root = T.att_root(d)
      +hit = root_seen(seen, root)
      +next = seen_add(seen, root)
      +rest = body_dups(t, next)
      Bool.or(hit, rest)

def seed_body(body: List<&2, T.AggAtt>, known: List<&2, VoteEntry>) -> List<&2, VoteEntry>:
  match body:
    case Nil{}:
      known
    case Con{T.Agg{_, d}, t}:
      +entry : VoteEntry = Ve{d, Nil{}}
      +next = ve_put(known, entry)
      seed_body(t, next)

def ob_prune_if(advanced: Bool, store: FcStore) -> FcStore:
  match advanced:
    case True{}:
      fc_prune(store)
    case False{}:
      store

def ob_headed(+headed: FcStore, prev: Nat) -> FcStep:
  match headed:
    case Fc{_, _, _, _, finalized, _, _, _, _}:
      +now = T.cp_slot(finalized)
      +advanced = Nat.is_gt(now, prev)
      +done = ob_prune_if(advanced, headed)
      Went{done}

def ob_finish(store: FcStore, prev: Nat) -> FcStep:
  +headed = fc_update_head(store)
  ob_headed(headed, prev)

def ob_import(store: FcStore, +block: T.Block, +post: T.State, prev: Nat) -> FcStep:
  match store:
    case Fc{time, head, safe_at, justified, finalized, blocks, states, known, pending}:
      +root = T.block_root(block)
      +body = T.block_body(block)
      +known2 = seed_body(body, known)
      +just2 = fc_advance(justified, state_justified(post))
      +blocks2 = block_put(blocks, root, block)
      +states2 = state_put(states, root, post)
      +next : FcStore = Fc{time, head, safe_at, just2, finalized, blocks2, states2, known2, pending}
      ob_finish(next, prev)

def ob_outcome(out: T.Outcome, store: FcStore, block: T.Block, prev: Nat) -> FcStep:
  match out:
    case T.Reject{reason}:
      Stop{reason}
    case T.Ok{state}:
      ob_import(store, block, state, prev)

def ob_apply(store: FcStore, +block: T.Block, state: T.State, prev: Nat) -> FcStep:
  +out = R.transition(state, block)
  ob_outcome(out, store, block, prev)

def ob_dups_b(dup: Bool, store: FcStore, block: T.Block, state: T.State, prev: Nat) -> FcStep:
  match dup:
    case True{}:
      Stop{reason_dup_att()}
    case False{}:
      ob_apply(store, block, state, prev)

def ob_dups(store: FcStore, +block: T.Block, state: T.State, prev: Nat) -> FcStep:
  +body = T.block_body(block)
  +dup = body_dups(body, Nil{})
  ob_dups_b(dup, store, block, state, prev)

def ob_future_b(far: Bool, store: FcStore, block: T.Block, state: T.State, prev: Nat) -> FcStep:
  match far:
    case True{}:
      Stop{reason_block_future()}
    case False{}:
      ob_dups(store, block, state, prev)

def ob_future(+store: FcStore, +block: T.Block, state: T.State, prev: Nat) -> FcStep:
  match store:
    case Fc{time, _, _, _, _, _, _, _, _}:
      +bslot = T.block_slot(block)
      +far = block_too_far(time, bslot)
      ob_future_b(far, store, block, state, prev)

def ob_gap_b(big: Bool, store: FcStore, block: T.Block, state: T.State, prev: Nat) -> FcStep:
  match big:
    case True{}:
      Stop{reason_slot_gap()}
    case False{}:
      ob_future(store, block, state, prev)

def ob_gap(store: FcStore, +block: T.Block, +state: T.State, prev: Nat) -> FcStep:
  +bslot = T.block_slot(block)
  +pslot = T.slot_of(state)
  +big = slot_gap_too_big(bslot, pslot)
  ob_gap_b(big, store, block, state, prev)

def ob_parent_m(st: Maybe<&2, T.State>, store: FcStore, block: T.Block, prev: Nat) -> FcStep:
  match st:
    case None{}:
      Stop{reason_unknown_parent()}
    case Some{state}:
      ob_gap(store, block, state, prev)

def ob_parent(+store: FcStore, +block: T.Block) -> FcStep:
  match store:
    case Fc{_, _, _, _, finalized, _, states, _, _}:
      +parent = T.block_parent(block)
      +st = state_get(states, parent)
      +prev = T.cp_slot(finalized)
      ob_parent_m(st, store, block, prev)

def ob_have(have: Bool, store: FcStore, block: T.Block) -> FcStep:
  match have:
    case True{}:
      Went{store}
    case False{}:
      ob_parent(store, block)

def fc_on_block(+store: FcStore, +block: T.Block) -> FcStep:
  match store:
    case Fc{_, _, _, _, _, blocks, _, _, _}:
      +root = T.block_root(block)
      +have = block_has(blocks, root)
      ob_have(have, store, block)
