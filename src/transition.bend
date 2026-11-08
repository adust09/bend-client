import Base
import ./types.bend as T
import ./justification.bend as J

# Lstar state transition. Signature verification is an upstream gate in leanSpec.
# The 3SF-mini justification rules below are ported 1:1 from the pinned leanSpec
# (state_transition.py, slot.py, containers/state.py) at the same commit.

def reason_not_future() -> String:
  "BLOCK_SLOT_NOT_IN_FUTURE"

def reason_mismatch() -> String:
  "BLOCK_SLOT_MISMATCH"

def reason_old() -> String:
  "BLOCK_OLDER_THAN_LATEST_HEADER"

def reason_proposer() -> String:
  "WRONG_PROPOSER"

def reason_parent() -> String:
  "PARENT_ROOT_MISMATCH"

def reason_state() -> String:
  "STATE_ROOT_MISMATCH"

def reason_empty() -> String:
  "EMPTY_VALIDATOR_REGISTRY"

def fill_and_advance(s: T.State, root: List<&2, U32>) -> T.State:
  match s:
    case T.St{time, slot, T.Hd{hs, hp, parent, _, body}, justified, finalized, hist, jslots, validators, jroots, jvotes}:
      T.St{time, Nat.add(slot, 1n), T.Hd{hs, hp, parent, root, body}, justified, finalized, hist, jslots, validators, jroots, jvotes}

def advance_only(s: T.State) -> T.State:
  match s:
    case T.St{time, slot, header, justified, finalized, hist, jslots, validators, jroots, jvotes}:
      T.St{time, Nat.add(slot, 1n), header, justified, finalized, hist, jslots, validators, jroots, jvotes}

def cache_step(s: T.State, blank: Bool) -> T.State:
  match blank:
    case True{}:
      +s2 = s
      fill_and_advance(s2, T.state_root(s2))
    case False{}:
      advance_only(s)

def slots_go(fuel: Nat, phase: Nat, progressed: Bool, +s: T.State, +target: Nat, cmp: Cmp, blank: Bool) -> T.Outcome:
  match fuel:
    case 0n:
      T.Reject{reason_not_future()}
    case 1n+p:
      match phase:
        case 0n:
          slots_go(p, 1n, progressed, s, target, Nat.cmp(T.slot_of(s), target), blank)
        case 1n:
          match progressed cmp:
            case _ LT{}:
              slots_go(p, 2n, progressed, s, target, cmp, T.header_blank(s))
            case True{} EQ{}:
              T.Ok{s}
            case False{} EQ{}:
              T.Reject{reason_not_future()}
            case _ GT{}:
              T.Reject{reason_not_future()}
        case _:
          slots_go(p, 0n, True{}, cache_step(s, blank), target, EQ{}, False{})

def process_slots(s: T.State, target: Nat) -> T.Outcome:
  slots_go(8192n, 0n, False{}, s, target, EQ{}, False{})

def apply_cp(c: T.Checkpoint, parent: List<&2, U32>, genesis_parent: Bool) -> T.Checkpoint:
  match genesis_parent:
    case True{}:
      T.Cp{parent, 0n}
    case False{}:
      c

# Capacity extension for the justified-slot bitfield, mirroring
# JustifiedSlots.extend_to_slot: one False bit per slot up to the target.
def extend_bits(+bits: List<&2, Bool>, +boundary: Nat, +target: Nat) -> List<&2, Bool>:
  +c = Nat.cmp(target, boundary)
  +gt = Cmp.is_gt(c)
  +n = List.length(&2, Bool, bits)
  +gap = Nat.cmp(Nat.sub(target, boundary), n)
  +gt2 = Cmp.is_gt(gap)
  +cap = Nat.sub(target, boundary)
  +pad : List<&2, Bool> = List.replicate(Bool, Nat.sub(cap, n), False{})
  +grown = List.append(&2, Bool, bits, pad)
  +res = Bool.pick(List<&2, Bool>, gt2, grown, bits)
  Bool.pick(List<&2, Bool>, gt, res, bits)

def append_zero_roots(n: Nat, xs: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match n:
    case 0n:
      xs
    case 1n+p:
      append_zero_roots(p, List.append(&2, List<&2, U32>, xs, T.zero() <> Nil{}))

def apply_header(s: T.State, b: T.Block, +parent: List<&2, U32>, +genesis_parent: Bool) -> T.State:
  match s b:
    case T.St{time, slot, T.Hd{hslot, _, _, _, _}, justified, finalized, hist, jslots, validators, jroots, jvotes} T.Blk{+bs, bp, bparent, _, body}:
      +fin = apply_cp(finalized, parent, genesis_parent)
      +last_slot = Nat.sub(bs, 1n)
      +window = extend_bits(jslots, T.cp_slot(fin), last_slot)
      +history = List.append(&2, List<&2, U32>, hist, parent <> Nil{})
      +skipped = Nat.sub(Nat.sub(bs, hslot), 1n)
      +filled = append_zero_roots(skipped, history)
      T.St{
        time,
        slot,
        T.Hd{bs, bp, bparent, T.zero(), T.body_root(body)},
        apply_cp(justified, parent, genesis_parent),
        fin,
        filled,
        window,
        validators,
        jroots,
        jvotes
      }

def header_go(fuel: Nat, phase: Nat, +s: T.State, +b: T.Block,
  +parent: List<&2, U32>, +st_slot: Nat, +bslot: Nat, +hslot: Nat,
  +proposer_i: Nat, +nvals: Nat, +bparent: List<&2, U32>, check: Bool) -> T.Outcome:
  match fuel:
    case 0n:
      T.Reject{reason_mismatch()}
    case 1n+p:
      match phase:
        case 0n:
          header_go(p, 1n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(nvals, 0n))
        case 1n:
          match check:
            case True{}:
              T.Reject{reason_empty()}
            case False{}:
              header_go(p, 2n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(bslot, st_slot))
        case 2n:
          match check:
            case False{}:
              T.Reject{reason_mismatch()}
            case True{}:
              header_go(p, 3n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_gt(bslot, hslot))
        case 3n:
          match check:
            case False{}:
              T.Reject{reason_old()}
            case True{}:
              header_go(p, 4n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(proposer_i, Nat.mod(bslot, nvals)))
        case 4n:
          match check:
            case False{}:
              T.Reject{reason_proposer()}
            case True{}:
              header_go(p, 5n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, T.bytes_eq(bparent, parent))
        case _:
          match check:
            case False{}:
              T.Reject{reason_parent()}
            case True{}:
              T.Ok{apply_header(s, b, parent, Nat.is_eq(hslot, 0n))}

def header_ok(s: T.State, b: T.Block) -> T.Outcome:
  +s2 = s
  +b2 = b
  +parent = T.header_root(T.header_of(s2))
  header_go(
    8n,
    0n,
    s2,
    b2,
    parent,
    T.slot_of(s2),
    T.block_slot(b2),
    T.header_slot(s2),
    T.block_proposer(b2),
    T.val_count(s2),
    T.block_parent(b2),
    False{}
  )

def finish_eq(post: T.State, same: Bool) -> T.Outcome:
  match same:
    case True{}:
      T.Ok{post}
    case False{}:
      T.Reject{reason_state()}

def finish(b: T.Block, post: T.State) -> T.Outcome:
  +post2 = post
  finish_eq(post2, T.bytes_eq(T.block_state(b), T.state_root(post2)))

# ============================================================================
# Wire the fold into the transition: the block state root is committed after
# the body's attestations are applied.
def after_atts(+o: T.Outcome, +b: T.Block) -> T.Outcome:
  match o:
    case T.Reject{reason}:
      T.Reject{reason}
    case T.Ok{state}:
      finish(b, state)

def after_header(+o: T.Outcome, +b: T.Block) -> T.Outcome:
  match o:
    case T.Reject{reason}:
      T.Reject{reason}
    case T.Ok{state}:
      +body = T.block_body(b)
      +next = after_atts(J.process_attestations(state, body), b)
      next

def after_slots(o: T.Outcome, +b: T.Block) -> T.Outcome:
  match o:
    case T.Reject{reason}:
      T.Reject{reason}
    case T.Ok{state}:
      after_header(header_ok(state, b), b)

def transition(+s: T.State, +b: T.Block) -> T.Outcome:
  after_slots(process_slots(s, T.block_slot(b)), b)
