import Base
import ./types.bend as T

# 3SF-mini justification and finalization
#
# Vote accounting ported from the pinned leanSpec process_attestations:
# the state carries one vote tally per tracked root, and a target is justified
# once two thirds of the validators back it. Attestation filters (source
# justified, target unjustified, on-chain roots, ordering, justifiable
# distance) and the finalization cascade must match the upstream spec.
# ============================================================================

def reason_empty() -> String:
  "EMPTY_VALIDATOR_REGISTRY"

def reason_too_many() -> String:
  "TOO_MANY_ATTESTATION_DATA"

def reason_bits() -> String:
  "EMPTY_AGGREGATION_BITS"

def reason_index() -> String:
  "VALIDATOR_INDEX_OUT_OF_RANGE"

def reason_votes_len() -> String:
  "JUSTIFICATION_VOTES_LENGTH_MISMATCH"

def reason_zero_root() -> String:
  "ZERO_HASH_JUSTIFICATION_ROOT"

# One tracked vote tally: a block root and one vote flag per validator.
type Jury is Data:
  Ju{root: List<&2, U32>, votes: List<&2, Bool>}

# Per-attestation fold state: tallies plus the moving checkpoints.
type Trial is Data:
  Tr{juries: List<&2, Jury>, jslots: List<&2, Bool>, justified: T.Checkpoint, fin: T.Checkpoint}

type Attempt is Data:
  Abad{reason: String}
  Agood{trial: Trial}

# A historical root lookup: index in historical_block_hashes, root at that slot.
type ChainRef is Data:
  Cr{root: List<&2, U32>, at: Nat}

# --- chain root lookup ------------------------------------------------------

def ref_default(+m: Maybe<&2, Nat>) -> Nat:
  match m:
    case None{}:
      0n
    case Some{at}:
      at

def ref_hit(hit: Bool, +at: Nat, +tail: Maybe<&2, Nat>) -> Maybe<&2, Nat>:
  match hit:
    case True{}:
      Some{at}
    case False{}:
      tail

def ref_slot_go(+refs: List<&2, ChainRef>, +root: List<&2, U32>) -> Maybe<&2, Nat>:
  match refs:
    case Nil{}:
      None{}
    case Con{Cr{r, at}, t}:
      +hit = T.bytes_eq(r, root)
      +tail = ref_slot_go(t, root)
      ref_hit(hit, at, tail)

def chain_root(+m: Maybe<&2, List<&2, U32>>) -> List<&2, U32>:
  match m:
    case None{}:
      T.zero()
    case Some{r}:
      r

def chain_at(+hist: List<&2, List<&2, U32>>, +i: Nat) -> List<&2, U32>:
  +rooted = List.get(&2, List<&2, U32>, hist, i)
  chain_root(rooted)

def chain_hit(zero: Bool, matched: Bool) -> Bool:
  match zero:
    case True{}:
      False{}
    case False{}:
      matched

def cp_chain(+hist: List<&2, List<&2, U32>>, +root: List<&2, U32>, +at: Nat) -> Bool:
  +rooted = chain_at(hist, at)
  chain_hit(T.is_zero(root), T.bytes_eq(root, rooted))

def cp_on_chain(hist: List<&2, List<&2, U32>>, c: T.Checkpoint) -> Bool:
  match c:
    case T.Cp{r, s}:
      cp_chain(hist, r, s)

def refs_over(over: Bool, +ahead: List<&2, ChainRef>, +rest: List<&2, ChainRef>) -> List<&2, ChainRef>:
  match over:
    case True{}:
      ahead
    case False{}:
      rest

def refs_go(fuel: Nat, hist: List<&2, List<&2, U32>>, +i: Nat, +boundary: Nat, over: Bool) -> List<&2, ChainRef>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+p:
      match hist:
        case Nil{}:
          Nil{}
        case Con{h, t}:
          +i2 = Nat.add(i, 1n)
          +over2 = Nat.is_gt(i2, boundary)
          +rest = refs_go(p, t, i2, boundary, over2)
          +item : List<&2, ChainRef> = {[Cr{h, i}] : List<&2, ChainRef>}
          +ahead = List.append(&2, ChainRef, item, rest)
          refs_over(over, ahead, rest)

def chain_refs(+hist: List<&2, List<&2, U32>>, +finalized: Nat) -> List<&2, ChainRef>:
  +count = List.length(&2, List<&2, U32>, hist)
  +fuel = Nat.add(count, 1n)
  +over = Nat.is_gt(0n, finalized)
  refs_go(fuel, hist, 0n, finalized, over)

# --- integer square root and 3SF justifiability -----------------------------

# Bisection; 64 steps cover any 32-bit input.
def isqrt_go(fuel: Nat, +lo: Nat, +hi: Nat, +n: Nat) -> Nat:
  match fuel:
    case 0n:
      lo
    case 1n+p:
      +live = Nat.is_lt(lo, hi)
      +mid = Nat.add(lo, Nat.div(Nat.add(Nat.sub(hi, lo), 1n), 2n))
      +msq = Nat.mul(mid, mid)
      +down = Bool.and(live, Nat.is_le(msq, n))
      +next = Nat.sub(mid, 1n)
      +lo_out = Bool.pick(Nat, down, mid, lo)
      +hi_out = Bool.pick(Nat, down, hi, Bool.pick(Nat, live, next, hi))
      isqrt_go(p, lo_out, hi_out, n)

def isqrt_top(empty: Bool, zero: Nat) -> Nat:
  match empty:
    case True{}:
      0n
    case False{}:
      zero

def isqrt(+n: Nat) -> Nat:
  +zero = isqrt_go(64n, 0n, n, n)
  isqrt_top(Nat.is_eq(n, 0n), zero)

# A slot is justifiable when its distance from the finalized slot is at most
# the immediate window of five, a perfect square, or a pronic number.
def justifiable_far(near: Bool, far: Bool) -> Bool:
  match near:
    case True{}:
      True{}
    case False{}:
      far

def justifiable_near(near: Bool, +delta: Nat) -> Bool:
  +d1 = Nat.add(Nat.mul(delta, 4n), 1n)
  +r = isqrt(d1)
  +root_sq = Nat.mul(isqrt(delta), isqrt(delta))
  +disc_sq = Nat.mul(r, r)
  +pronic = Bool.and(Nat.is_eq(disc_sq, d1), Nat.is_eq(Nat.mod(r, 2n), 1n))
  +far = Bool.or(Nat.is_eq(root_sq, delta), pronic)
  justifiable_far(near, far)

def justifiable_go(c: Cmp, +s: Nat, +f: Nat) -> Bool:
  match c:
    case LT{}:
      False{}
    case _:
      +d = Nat.sub(s, f)
      +near = Nat.is_le(d, 5n)
      justifiable_near(near, d)

def justifiable_after(+s: Nat, +f: Nat) -> Bool:
  +c = Nat.cmp(s, f)
  justifiable_go(c, s, f)

# A source finalizes when no justifiable slot sits between it and the target.
def none_pick(+hit: Bool, +cont: Bool) -> Bool:
  match hit:
    case True{}:
      False{}
    case False{}:
      cont

def none_span(+spanned: Bool, +cont: Bool) -> Bool:
  match spanned:
    case True{}:
      cont
    case False{}:
      True{}

def none_justifiable_between(fuel: Nat, +lo: Nat, +hi: Nat, +f: Nat) -> Bool:
  match fuel:
    case 0n:
      True{}
    case 1n+p:
      +hit = justifiable_after(lo, f)
      +next = none_justifiable_between(p, Nat.add(lo, 1n), hi, f)
      +open_res = none_pick(hit, next)
      none_span(Nat.is_lt(lo, hi), open_res)

def finalize_over(+over: Bool, +open_res: Bool) -> Bool:
  match over:
    case True{}:
      open_res
    case False{}:
      False{}

def finalize_source(+s: T.Checkpoint, +t: T.Checkpoint, +f: Nat) -> Bool:
  +sslot = T.cp_slot(s)
  +tslot = T.cp_slot(t)
  +span = Nat.sub(tslot, sslot)
  +fuel = Nat.min(span, 262145n)
  +over = Nat.is_gt(sslot, f)
  +open_res = none_justifiable_between(fuel, Nat.add(sslot, 1n), tslot, f)
  finalize_over(over, open_res)

# --- tally bookkeeping ------------------------------------------------------

def jury_pick(+hit: Bool, +votes: List<&2, Bool>, +tail: Maybe<&2, List<&2, Bool>>) -> Maybe<&2, List<&2, Bool>>:
  match hit:
    case True{}:
      Some{votes}
    case False{}:
      tail

def jury_get(+juries: List<&2, Jury>, +root: List<&2, U32>) -> Maybe<&2, List<&2, Bool>>:
  match juries:
    case Nil{}:
      None{}
    case Con{Ju{r, votes}, t}:
      +hit = T.bytes_eq(r, root)
      +tail = jury_get(t, root)
      jury_pick(hit, votes, tail)

def jury_del_pick(+hit: Bool, +keep: Jury, +tail: List<&2, Jury>) -> List<&2, Jury>:
  match hit:
    case True{}:
      tail
    case False{}:
      +item : List<&2, Jury> = {[keep] : List<&2, Jury>}
      +kept = List.append(&2, Jury, item, tail)
      kept

def jury_del(+juries: List<&2, Jury>, +root: List<&2, U32>) -> List<&2, Jury>:
  match juries:
    case Nil{}:
      Nil{}
    case Con{Ju{r, votes}, t}:
      +hit = T.bytes_eq(r, root)
      +tail = jury_del(t, root)
      jury_del_pick(hit, Ju{r, votes}, tail)

def jury_put(+juries: List<&2, Jury>, +root: List<&2, U32>, +votes: List<&2, Bool>) -> List<&2, Jury>:
  +one : List<&2, Jury> = {[Ju{root, votes}] : List<&2, Jury>}
  +cleared = jury_del(juries, root)
  List.append(&2, Jury, cleared, one)

# Drop tallies for roots off the chain or at or before the new finalized slot.
def jury_over(+over: Bool, +kept: List<&2, Jury>, +rest: List<&2, Jury>) -> List<&2, Jury>:
  match over:
    case True{}:
      kept
    case False{}:
      rest

def prune_at_of(ju: Jury, refs: List<&2, ChainRef>) -> Nat:
  match ju:
    case Ju{r, _}:
      +at = ref_default(ref_slot_go(refs, r))
      at

def prune_keep(ju: Jury, +rest: List<&2, Jury>) -> List<&2, Jury>:
  match ju:
    case Ju{r, votes}:
      +item : List<&2, Jury> = List.replicate(Jury, 1n, Ju{r, votes})
      List.append(&2, Jury, item, rest)

def prune_seg(+ju: Jury, +refs: List<&2, ChainRef>, +boundary: Nat, +rest: List<&2, Jury>) -> List<&2, Jury>:
  +at = prune_at_of(ju, refs)
  +kept = prune_keep(ju, rest)
  jury_over(Nat.is_gt(at, boundary), kept, rest)

def jury_prune(juries: List<&2, Jury>, +refs: List<&2, ChainRef>, +boundary: Nat) -> List<&2, Jury>:
  match juries:
    case Nil{}:
      Nil{}
    case Con{ju, +t}:
      +rest = jury_prune(t, refs, boundary)
      +kept = prune_seg(ju, refs, boundary, rest)
      kept

# Strict lexicographic order on roots; tally roots are unique, so the
# stability of equal keys never matters.
def root_pick(+eq: Bool, +lt: Bool, +deeper: Bool) -> Bool:
  match eq:
    case True{}:
      deeper
    case False{}:
      lt

def root_lt_nil(+b: List<&2, U32>) -> Bool:
  match b:
    case Nil{}:
      False{}
    case Con{_, _}:
      True{}

def root_lt(+a: List<&2, U32>, +b: List<&2, U32>) -> Bool:
  match a:
    case Nil{}:
      root_lt_nil(b)
    case Con{head_a, tail_a}:
      match b:
        case Nil{}:
          False{}
        case Con{head_b, tail_b}:
          +deeper = root_lt(tail_a, tail_b)
          root_pick(U32.is_eq(head_a, head_b), U32.is_lt(head_a, head_b), deeper)

def jury_lt(+x: Jury, +y: Jury) -> Bool:
  match x:
    case Ju{rx, _}:
      match y:
        case Ju{ry, _}:
          root_lt(rx, ry)

def jury_insert(+x: Jury, +xs: List<&2, Jury>) -> List<&2, Jury>:
  match xs:
    case Nil{}:
      List.replicate(Jury, 1n, x)
    case Con{j, t}:
      +ago = jury_lt(x, j)
      +one_x : List<&2, Jury> = List.replicate(Jury, 1n, x)
      +one_j = List.replicate(Jury, 1n, j)
      +pair = List.append(&2, Jury, one_x, one_j)
      +ahead = List.append(&2, Jury, pair, t)
      +kept = List.append(&2, Jury, one_j, jury_insert(x, t))
      jury_over(ago, ahead, kept)

def jury_sort(+xs: List<&2, Jury>, +acc: List<&2, Jury>) -> List<&2, Jury>:
  match xs:
    case Nil{}:
      acc
    case Con{head, t}:
      +one = jury_insert(head, acc)
      jury_sort(t, one)

def jury_roots(+xs: List<&2, Jury>) -> List<&2, List<&2, U32>>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{Ju{r, _}, t}:
      r <> jury_roots(t)

def jury_votess(+xs: List<&2, Jury>) -> List<&2, List<&2, Bool>>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{Ju{_, votes}, t}:
      votes <> jury_votess(t)

# --- vote helpers -----------------------------------------------------------

def bit_default(+m: Maybe<&2, Bool>) -> Bool:
  match m:
    case None{}:
      False{}
    case Some{b}:
      b

def bit_bool(+bits: List<&2, Bool>, +i: Nat) -> Bool:
  +got = List.get(&2, Bool, bits, i)
  bit_default(got)

# Slots at or before the finalized boundary are justified by definition.
def is_slot_go(c: Cmp, +jslots: List<&2, Bool>, +finalized: Nat, +target: Nat) -> Bool:
  match c:
    case GT{}:
      +index = Nat.sub(Nat.sub(target, finalized), 1n)
      bit_bool(jslots, index)
    case _:
      True{}

def is_slot_justified(+jslots: List<&2, Bool>, +finalized: Nat, +target: Nat) -> Bool:
  +c = Nat.cmp(target, finalized)
  is_slot_go(c, jslots, finalized, target)

# Set-bit positions of an aggregation bitlist, bounded by the registry limit.
def voter_acc(+b: Bool, +i: Nat, +acc: List<&2, Nat>) -> List<&2, Nat>:
  match b:
    case True{}:
      +one : List<&2, Nat> = {[i] : List<&2, Nat>}
      +with_set = List.append(&2, Nat, one, acc)
      with_set
    case False{}:
      acc

def voter_go(+bits: List<&2, Bool>, +i: Nat, +acc: List<&2, Nat>) -> List<&2, Nat>:
  match bits:
    case Nil{}:
      List.reverse(&2, Nat, acc)
    case Con{b, t}:
      +i2 = Nat.add(i, 1n)
      +acc2 = voter_acc(b, i, acc)
      voter_go(t, i2, acc2)

def voter_indices(+bits: List<&2, Bool>) -> List<&2, Nat>:
  voter_go(bits, 0n, Nil{})

def voters_in_range(+idxs: List<&2, Nat>, +nvals: Nat) -> Bool:
  match idxs:
    case Nil{}:
      True{}
    case Con{h, t}:
      +lt = Nat.is_lt(h, nvals)
      +rest = voters_in_range(t, nvals)
      +ok = Bool.and(lt, rest)
      ok

def mark_votes(idxs: List<&2, Nat>, votes: List<&2, Bool>) -> List<&2, Bool>:
  match idxs:
    case Nil{}:
      +same = votes
      same
    case Con{h, t}:
      +marked = List.set(&2, Bool, votes, h, True{})
      mark_votes(t, marked)

def count_pick(+b: Bool, +n: Nat, +c: Nat) -> Nat:
  match b:
    case True{}:
      n
    case False{}:
      c

def count_true(+bits: List<&2, Bool>) -> Nat:
  match bits:
    case Nil{}:
      0n
    case Con{b, t}:
      +c = count_true(t)
      +n = Nat.add(c, 1n)
      count_pick(b, n, c)

# The state stores one flat vote list segmented by tracked root; split it back.
def unpack_juries(+roots: List<&2, List<&2, U32>>, +votes: List<&2, Bool>, +n: Nat) -> List<&2, Jury>:
  match roots:
    case Nil{}:
      Nil{}
    case Con{r, t}:
      +head = List.take(&2, Bool, votes, n)
      +tail = List.drop(&2, Bool, votes, n)
      +rest = unpack_juries(t, tail, n)
      +item = {[Ju{r, head}] : List<&2, Jury>}
      List.append(&2, Jury, item, rest)

def zero_root(+zero: Bool, +rest: Bool) -> Bool:
  match zero:
    case True{}:
      True{}
    case False{}:
      rest

def any_zero_root(+xs: List<&2, List<&2, U32>>) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{r, t}:
      +rest = any_zero_root(t)
      zero_root(T.is_zero(r), rest)

# --- distinct attestation data cap ------------------------------------------

def cp_eq(+a: T.Checkpoint, +b: T.Checkpoint) -> Bool:
  match a:
    case T.Cp{ra, sa}:
      match b:
        case T.Cp{rb, sb}:
          +same = T.bytes_eq(ra, rb)
          +slots = Nat.is_eq(sa, sb)
          Bool.and(same, slots)

def att_data_eq(+a: T.AttData, +b: T.AttData) -> Bool:
  match a:
    case T.Ad{slot, head, target, source}:
      match b:
        case T.Ad{slot2, head2, target2, source2}:
          +same = Nat.is_eq(slot, slot2)
          +heads = cp_eq(head, head2)
          +targets = cp_eq(target, target2)
          +sources = cp_eq(source, source2)
          Bool.and(same, Bool.and(heads, Bool.and(targets, sources)))

def data_hit(+hit: Bool, +rest: Bool) -> Bool:
  match hit:
    case True{}:
      True{}
    case False{}:
      rest

def any_data_eq(+seen: List<&2, T.AttData>, +d: T.AttData) -> Bool:
  match seen:
    case Nil{}:
      False{}
    case Con{h, t}:
      +hit = att_data_eq(h, d)
      +rest = any_data_eq(t, d)
      data_hit(hit, rest)

def distinct_dupe_seen(dupe: Bool, +added: List<&2, T.AttData>, +seen: List<&2, T.AttData>) -> List<&2, T.AttData>:
  match dupe:
    case True{}:
      +same = seen
      same
    case False{}:
      +grown = added
      grown

def distinct_dupe_count(dupe: Bool, +count: Nat) -> Nat:
  match dupe:
    case True{}:
      +same = count
      same
    case False{}:
      +grown = Nat.add(count, 1n)
      grown

def distinct_next_seen(over: Bool, dupe: Bool, +added: List<&2, T.AttData>, +seen: List<&2, T.AttData>) -> List<&2, T.AttData>:
  match over:
    case True{}:
      +same = seen
      same
    case False{}:
      +same2 = distinct_dupe_seen(dupe, added, seen)
      same2

def distinct_next_count(over: Bool, dupe: Bool, +count: Nat) -> Nat:
  match over:
    case True{}:
      +same = count
      same
    case False{}:
      +same2 = distinct_dupe_count(dupe, count)
      same2

def distinct_add(d: T.AttData, +seen: List<&2, T.AttData>) -> List<&2, T.AttData>:
  +added = List.append(&2, T.AttData, {[d] : List<&2, T.AttData>}, seen)
  added

def distinct_go(atts: List<&2, T.AggAtt>, +seen: List<&2, T.AttData>, +count: Nat) -> Bool:
  match atts:
    case Nil{}:
      +verdict = Nat.is_gt(count, 8n)
      verdict
    case Con{T.Agg{_, d}, t}:
      +dd = d
      +dupe = any_data_eq(seen, dd)
      +over = Nat.is_gt(count, 8n)
      +added = distinct_add(dd, seen)
      +seen2 = distinct_next_seen(over, dupe, added, seen)
      +count2 = distinct_next_count(over, dupe, count)
      +next = distinct_go(t, seen2, count2)
      next

def att_over_cap(+atts: List<&2, T.AggAtt>) -> Bool:
  distinct_go(atts, Nil{}, 0n)

# --- per-attestation processing (filters, votes, justification) -------------

def attach_latest(+greater: Bool, +target: T.Checkpoint, +justified: T.Checkpoint) -> T.Checkpoint:
  match greater:
    case True{}:
      target
    case False{}:
      justified

def attach_tail(+refs: List<&2, ChainRef>, +juries: List<&2, Jury>, +window: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +source: T.Checkpoint, +done: Bool) -> Attempt:
  match done:
    case True{}:
      +sslot = T.cp_slot(source)
      +fin_slot = T.cp_slot(fin)
      +pruned = jury_prune(juries, refs, sslot)
      +rebased = List.drop(&2, Bool, window, Nat.sub(sslot, fin_slot))
      +settled : Trial = Tr{pruned, rebased, justified, source}
      Agood{settled}
    case False{}:
      +idle : Trial = Tr{juries, window, justified, fin}
      Agood{idle}

def attach_final(+refs: List<&2, ChainRef>, +juries: List<&2, Jury>, +window: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint) -> Attempt:
  +done = finalize_source(source, target, T.cp_slot(fin))
  attach_tail(refs, juries, window, justified, fin, source, done)

def attach_justify(+refs: List<&2, ChainRef>, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint) -> Attempt:
  +window = List.set(&2, Bool, jslots, Nat.sub(Nat.sub(T.cp_slot(target), T.cp_slot(fin)), 1n), True{})
  +greater = Nat.is_gt(T.cp_slot(target), T.cp_slot(justified))
  +latest = attach_latest(greater, target, justified)
  attach_final(refs, juries, window, latest, fin, target, source)

def tally_default(+m: Maybe<&2, List<&2, Bool>>, +fresh: List<&2, Bool>) -> List<&2, Bool>:
  match m:
    case None{}:
      fresh
    case Some{votes}:
      votes

def attach_hit(+hit: Bool, +refs: List<&2, ChainRef>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint, +cleared: List<&2, Jury>, +kept: Attempt) -> Attempt:
  match hit:
    case True{}:
      +next = attach_justify(refs, cleared, jslots, justified, fin, target, source)
      next
    case False{}:
      kept

def attach_tally(+refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint, +voters: List<&2, Nat>) -> Attempt:
  +troot = T.cp_raw(target)
  +fresh : List<&2, Bool> = List.replicate(Bool, n, False{})
  +votes = tally_default(jury_get(juries, troot), fresh)
  +marked = mark_votes(voters, votes)
  +hit = Nat.is_ge(Nat.mul(count_true(marked), 3n), Nat.mul(n, 2n))
  +cleared = jury_del(juries, troot)
  +kept : Attempt = Agood{Tr{jury_put(juries, troot, marked), jslots, justified, fin}}
  attach_hit(hit, refs, jslots, justified, fin, target, source, cleared, kept)

def attach_valid(+valid: Bool, +refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint, +voters: List<&2, Nat>) -> Attempt:
  match valid:
    case True{}:
      +tally = attach_tally(refs, n, juries, jslots, justified, fin, target, source, voters)
      tally
    case False{}:
      Abad{reason_index()}

def attach_some(+refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint, +voters: List<&2, Nat>, +some: Bool) -> Attempt:
  match some:
    case False{}:
      +empty : Attempt = Abad{reason_bits()}
      empty
    case True{}:
      +valid = voters_in_range(voters, n)
      attach_valid(valid, refs, n, juries, jslots, justified, fin, target, source, voters)

def attach_open(+refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +bits: List<&2, Bool>, +target: T.Checkpoint, +source: T.Checkpoint, +near: Bool) -> Attempt:
  match near:
    case True{}:
      +voters = voter_indices(bits)
      +some = Bool.not(List.is_empty(&2, Nat, voters))
      attach_some(refs, n, juries, jslots, justified, fin, target, source, voters, some)
    case False{}:
      +idle : Trial = Tr{juries, jslots, justified, fin}
      Agood{idle}

def attach_pass(+refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +bits: List<&2, Bool>, +target: T.Checkpoint, +source: T.Checkpoint, +ordered: Bool) -> Attempt:
  +near = Bool.and(ordered, justifiable_after(T.cp_slot(target), T.cp_slot(fin)))
  attach_open(refs, n, juries, jslots, justified, fin, bits, target, source, near)

def attach_move(+refs: List<&2, ChainRef>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +bits: List<&2, Bool>, +target: T.Checkpoint, +source: T.Checkpoint, +on_chain: Bool) -> Attempt:
  +sslot = T.cp_slot(source)
  +tslot = T.cp_slot(target)
  +ordered = Bool.and(on_chain, Nat.is_gt(tslot, sslot))
  attach_pass(refs, n, juries, jslots, justified, fin, bits, target, source, ordered)

def attach_chain(+refs: List<&2, ChainRef>, +hist: List<&2, List<&2, U32>>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +bits: List<&2, Bool>, +head: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint) -> Attempt:
  +src_ok = cp_on_chain(hist, source)
  +tgt_ok = cp_on_chain(hist, target)
  +head_ok = cp_on_chain(hist, head)
  +on_chain = Bool.and(src_ok, Bool.and(tgt_ok, head_ok))
  attach_move(refs, n, juries, jslots, justified, fin, bits, target, source, on_chain)

# An attestation outside the filters leaves the trial unchanged.
def attach_gate(+go: Bool, +tr: Trial, +refs: List<&2, ChainRef>, +hist: List<&2, List<&2, U32>>, +n: Nat, +juries: List<&2, Jury>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +fin: T.Checkpoint, +bits: List<&2, Bool>, +head: T.Checkpoint, +target: T.Checkpoint, +source: T.Checkpoint) -> Attempt:
  match go:
    case True{}:
      +next = attach_chain(refs, hist, n, juries, jslots, justified, fin, bits, head, target, source)
      next
    case False{}:
      +idle : Trial = Tr{juries, jslots, justified, fin}
      Agood{idle}

def attach_one(+tr: Trial, +refs: List<&2, ChainRef>, +hist: List<&2, List<&2, U32>>, +n: Nat, +a: T.AggAtt) -> Attempt:
  match tr a:
    case Tr{juries, jslots, justified, +fin} T.Agg{bits, T.Ad{_, head, +target, +source}}:
      +fs = T.cp_slot(fin)
      +src = T.cp_slot(source)
      +tgt = T.cp_slot(target)
      +open_src = is_slot_justified(jslots, fs, src)
      +done_tgt = is_slot_justified(jslots, fs, tgt)
      +go = Bool.and(open_src, Bool.not(done_tgt))
      attach_gate(go, tr, refs, hist, n, juries, jslots, justified, fin, bits, head, target, source)

# The empty-bits and indexing rejections fire only after the vote filters pass,
# matching the upstream check placement.

def patch_votes(+s: T.State, +jroots: List<&2, List<&2, U32>>, +jvotes: List<&2, Bool>, +jslots: List<&2, Bool>, +justified: T.Checkpoint, +finalized: T.Checkpoint) -> T.State:
  match s:
    case T.St{time, slot, header, _, _, hist, _, validators, _, _}:
      T.St{time, slot, header, justified, finalized, hist, jslots, validators, jroots, jvotes}

def att_done(+s: T.State, +r: Attempt) -> T.Outcome:
  match r:
    case Abad{reason}:
      T.Reject{reason}
    case Agood{Tr{juries, jslots2, justified2, fin2}}:
      +sorted = jury_sort(juries, Nil{})
      +roots = jury_roots(sorted)
      +votess = jury_votess(sorted)
      +flattened = List.concat(&2, Bool, votess)
      +next = patch_votes(s, roots, flattened, jslots2, justified2, fin2)
      T.Ok{next}

def atts_fold(atts: List<&2, T.AggAtt>, +r: Attempt, +tr: Trial, +refs: List<&2, ChainRef>, +hist: List<&2, List<&2, U32>>, +n: Nat) -> Attempt:
  match atts:
    case Nil{}:
      match r:
        case Abad{reason}:
          +bad : Attempt = Abad{reason}
          bad
        case Agood{tr2}:
          +done : Attempt = Agood{tr2}
          done
    case Con{a, +t}:
      match r:
        case Abad{reason}:
          +idle : Attempt = Abad{reason}
          atts_fold(t, idle, tr, refs, hist, n)
        case Agood{tr2}:
          +one = attach_one(tr2, refs, hist, n, a)
          atts_fold(t, one, tr2, refs, hist, n)

def att_fold(+s: T.State, +body: List<&2, T.AggAtt>, +n: Nat, +jroots: List<&2, List<&2, U32>>, +jvotes: List<&2, Bool>) -> T.Outcome:
  match s:
    case T.St{_, _, _, justified, finalized, hist, jslots, _, _, _}:
      +refs = chain_refs(hist, T.cp_slot(finalized))
      +jstart = unpack_juries(jroots, jvotes, n)
      +tr0 : Trial = Tr{jstart, jslots, justified, finalized}
      +start : Attempt = Agood{tr0}
      +r = atts_fold(body, start, tr0, refs, hist, n)
      att_done(s, r)

def att_zero(+zero: Bool, +s: T.State, +body: List<&2, T.AggAtt>, +n: Nat, +jroots: List<&2, List<&2, U32>>, +jvotes: List<&2, Bool>) -> T.Outcome:
  match zero:
    case True{}:
      T.Reject{reason_zero_root()}
    case False{}:
      +next = att_fold(s, body, n, jroots, jvotes)
      next

def att_layout(+ok: Bool, +s: T.State, +body: List<&2, T.AggAtt>, +n: Nat, +jroots: List<&2, List<&2, U32>>, +jvotes: List<&2, Bool>) -> T.Outcome:
  match ok:
    case True{}:
      +zero = any_zero_root(jroots)
      att_zero(zero, s, body, n, jroots, jvotes)
    case False{}:
      T.Reject{reason_votes_len()}

def att_registry(+empty: Bool, +s: T.State, +body: List<&2, T.AggAtt>, +n: Nat, +jroots: List<&2, List<&2, U32>>, +jvotes: List<&2, Bool>) -> T.Outcome:
  match empty:
    case True{}:
      T.Reject{reason_empty()}
    case False{}:
      +nroot = List.length(&2, List<&2, U32>, jroots)
      +nvotes = List.length(&2, Bool, jvotes)
      +width = Nat.mul(n, nroot)
      +ok = Nat.is_eq(nvotes, width)
      att_layout(ok, s, body, n, jroots, jvotes)

def att_voters_check(+s: T.State, +body: List<&2, T.AggAtt>, +n: Nat) -> T.Outcome:
  match s:
    case T.St{_, _, _, _, _, _, _, _, jroots, jvotes}:
      +empty = Nat.is_eq(n, 0n)
      att_registry(empty, s, body, n, jroots, jvotes)

def att_cap(+over: Bool, +s: T.State, +body: List<&2, T.AggAtt>, +n: Nat) -> T.Outcome:
  match over:
    case True{}:
      T.Reject{reason_too_many()}
    case False{}:
      +next = att_voters_check(s, body, n)
      next

def process_attestations(+s: T.State, +body: List<&2, T.AggAtt>) -> T.Outcome:
  +n = T.val_count(s)
  +over = att_over_cap(body)
  att_cap(over, s, body, n)

