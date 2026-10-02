import Base
import ./types.bend as T

# Lstar state transition. Signature verification is an upstream gate in leanSpec.

type Outcome is Data:
  Ok{state: T.State}
  Reject{reason: String}

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

def slots_go(fuel: Nat, phase: Nat, progressed: Bool, +s: T.State, +target: Nat, cmp: Cmp, blank: Bool) -> Outcome:
  match fuel:
    case 0n:
      Reject{reason_not_future()}
    case 1n+p:
      match phase:
        case 0n:
          slots_go(p, 1n, progressed, s, target, Nat.cmp(T.slot_of(s), target), blank)
        case 1n:
          match progressed cmp:
            case _ LT{}:
              slots_go(p, 2n, progressed, s, target, cmp, T.header_blank(s))
            case True{} EQ{}:
              Ok{s}
            case False{} EQ{}:
              Reject{reason_not_future()}
            case _ GT{}:
              Reject{reason_not_future()}
        case _:
          slots_go(p, 0n, True{}, cache_step(s, blank), target, EQ{}, False{})

def process_slots(s: T.State, target: Nat) -> Outcome:
  slots_go(8192n, 0n, False{}, s, target, EQ{}, False{})

def apply_cp(c: T.Checkpoint, parent: List<&2, U32>, genesis_parent: Bool) -> T.Checkpoint:
  match genesis_parent:
    case True{}:
      T.Cp{parent, 0n}
    case False{}:
      c

def append_zero_roots(n: Nat, xs: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match n:
    case 0n:
      xs
    case 1n+p:
      append_zero_roots(p, List.append(&2, List<&2, U32>, xs, T.zero() <> Nil{}))

def apply_header(s: T.State, b: T.Block, +parent: List<&2, U32>, +genesis_parent: Bool) -> T.State:
  match s b:
    case T.St{time, slot, T.Hd{hslot, _, _, _, _}, justified, finalized, hist, jslots, validators, jroots, jvotes} T.Blk{+bs, bp, bparent, _, body}:
      history = List.append(&2, List<&2, U32>, hist, parent <> Nil{})
      skipped = Nat.sub(Nat.sub(bs, hslot), 1n)
      T.St{
        time,
        slot,
        T.Hd{bs, bp, bparent, T.zero(), T.body_root(body)},
        apply_cp(justified, parent, genesis_parent),
        apply_cp(finalized, parent, genesis_parent),
        append_zero_roots(skipped, history),
        jslots,
        validators,
        jroots,
        jvotes
      }

def header_go(fuel: Nat, phase: Nat, +s: T.State, +b: T.Block,
  +parent: List<&2, U32>, +st_slot: Nat, +bslot: Nat, +hslot: Nat,
  +proposer_i: Nat, +nvals: Nat, +bparent: List<&2, U32>, check: Bool) -> Outcome:
  match fuel:
    case 0n:
      Reject{reason_mismatch()}
    case 1n+p:
      match phase:
        case 0n:
          header_go(p, 1n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(nvals, 0n))
        case 1n:
          match check:
            case True{}:
              Reject{reason_empty()}
            case False{}:
              header_go(p, 2n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(bslot, st_slot))
        case 2n:
          match check:
            case False{}:
              Reject{reason_mismatch()}
            case True{}:
              header_go(p, 3n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_gt(bslot, hslot))
        case 3n:
          match check:
            case False{}:
              Reject{reason_old()}
            case True{}:
              header_go(p, 4n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, Nat.is_eq(proposer_i, Nat.mod(bslot, nvals)))
        case 4n:
          match check:
            case False{}:
              Reject{reason_proposer()}
            case True{}:
              header_go(p, 5n, s, b, parent, st_slot, bslot, hslot, proposer_i, nvals, bparent, T.bytes_eq(bparent, parent))
        case _:
          match check:
            case False{}:
              Reject{reason_parent()}
            case True{}:
              Ok{apply_header(s, b, parent, Nat.is_eq(hslot, 0n))}

def header_ok(s: T.State, b: T.Block) -> Outcome:
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

def finish_eq(post: T.State, same: Bool) -> Outcome:
  match same:
    case True{}:
      Ok{post}
    case False{}:
      Reject{reason_state()}

def finish(b: T.Block, post: T.State) -> Outcome:
  +post2 = post
  finish_eq(post2, T.bytes_eq(T.block_state(b), T.state_root(post2)))

def after_header(o: Outcome, b: T.Block) -> Outcome:
  match o:
    case Reject{reason}:
      Reject{reason}
    case Ok{state}:
      finish(b, state)

def after_slots(o: Outcome, +b: T.Block) -> Outcome:
  match o:
    case Reject{reason}:
      Reject{reason}
    case Ok{state}:
      after_header(header_ok(state, b), b)

def transition(s: T.State, b: T.Block) -> Outcome:
  +b2 = b
  after_slots(process_slots(s, T.block_slot(b2)), b2)
