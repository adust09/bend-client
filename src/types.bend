import Base
import ./bytes.bend as B
import ./ssz.bend as S

# Lstar consensus values. Roots are 32-byte lists. Public keys are 52-byte lists.

type Checkpoint is Data:
  Cp{root: List<&2, U32>, slot: Nat}

type Header is Data:
  Hd{slot: Nat, proposer: Nat, parent: List<&2, U32>, state_root: List<&2, U32>, body_root: List<&2, U32>}

type Validator is Data:
  Val{attestation: List<&2, U32>, proposal: List<&2, U32>, index: Nat}

type AttData is Data:
  Ad{slot: Nat, head: Checkpoint, target: Checkpoint, source: Checkpoint}

type AggAtt is Data:
  Agg{bits: List<&2, Bool>, data: AttData}

type Block is Data:
  Blk{slot: Nat, proposer: Nat, parent: List<&2, U32>, state_root: List<&2, U32>, body: List<&2, AggAtt>}

type State is Data:
  St{
    time: Nat,
    slot: Nat,
    header: Header,
    justified: Checkpoint,
    finalized: Checkpoint,
    hist: List<&2, List<&2, U32>>,
    jslots: List<&2, Bool>,
    validators: List<&2, Validator>,
    jroots: List<&2, List<&2, U32>>,
    jvotes: List<&2, Bool>
  }

def zero() -> List<&2, U32>:
  S.zero32()

def is_zero(b: List<&2, U32>) -> Bool:
  String.eq(B.Bytes.hex(b), "0000000000000000000000000000000000000000000000000000000000000000")

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  B.Bytes.eq(a, b)

def cp_root(c: Checkpoint) -> List<&2, U32>:
  match c:
    case Cp{root, slot}:
      S.chunk2(root, S.u64_chunk(slot))

def header_root(h: Header) -> List<&2, U32>:
  match h:
    case Hd{slot, proposer, parent, state_root, body_root}:
      S.merkle([S.u64_chunk(slot), S.u64_chunk(proposer), parent, state_root, body_root])

def val_root(v: Validator) -> List<&2, U32>:
  match v:
    case Val{attestation, proposal, index}:
      S.merkle([S.bytes52_root(attestation), S.bytes52_root(proposal), S.u64_chunk(index)])

def val_roots(vs: List<&2, Validator>) -> List<&2, List<&2, U32>>:
  match vs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      val_root(h) <> val_roots(t)

def vals_root(vs: List<&2, Validator>) -> List<&2, U32>:
  S.list_root(val_roots(vs), 4096n)

def att_root(a: AttData) -> List<&2, U32>:
  match a:
    case Ad{slot, head, target, source}:
      S.merkle([S.u64_chunk(slot), cp_root(head), cp_root(target), cp_root(source)])

def maybe_bit(m: Maybe<&2, Bool>) -> U32:
  match m:
    case None{}:
      0
    case Some{False{}}:
      0
    case Some{True{}}:
      1

def bit_at(+bits: List<&2, Bool>, i: Nat) -> U32:
  maybe_bit(List.get(&2, Bool, bits, i))

def packed_byte(+bits: List<&2, Bool>) -> U32:
  (bit_at(bits, 0n)
    + U32.shln(bit_at(bits, 1n), 1n)
    + U32.shln(bit_at(bits, 2n), 2n)
    + U32.shln(bit_at(bits, 3n), 3n)
    + U32.shln(bit_at(bits, 4n), 4n)
    + U32.shln(bit_at(bits, 5n), 5n)
    + U32.shln(bit_at(bits, 6n), 6n)
    + U32.shln(bit_at(bits, 7n), 7n) : U32)

def pack_bits_go(fuel: Nat, +bits: List<&2, Bool>, empty: Bool) -> List<&2, U32>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+p:
      match empty:
        case True{}:
          Nil{}
        case False{}:
          +rest = List.drop(&2, Bool, bits, 8n)
          packed_byte(bits) <> pack_bits_go(p, rest, List.is_empty(&2, Bool, rest))

def pack_bits(+bits: List<&2, Bool>) -> List<&2, U32>:
  pack_bits_go(32769n, bits, List.is_empty(&2, Bool, bits))

def pad_chunk(+bytes: List<&2, U32>) -> List<&2, U32>:
  B.Bytes.append(bytes, B.Bytes.zeros(Nat.sub(32n, B.Bytes.len(bytes))))

def byte_chunks_go(fuel: Nat, +bytes: List<&2, U32>, empty: Bool) -> List<&2, List<&2, U32>>:
  match fuel:
    case 0n:
      Nil{}
    case 1n+p:
      match empty:
        case True{}:
          Nil{}
        case False{}:
          +rest = B.Bytes.drop(bytes, 32n)
          pad_chunk(B.Bytes.take(bytes, 32n)) <> byte_chunks_go(p, rest, List.is_empty(&2, U32, rest))

def byte_chunks(+bytes: List<&2, U32>) -> List<&2, List<&2, U32>>:
  byte_chunks_go(32769n, bytes, List.is_empty(&2, U32, bytes))

def bit_chunk_limit(limit_bits: Nat) -> Nat:
  Nat.add(Nat.div(Nat.sub(limit_bits, 1n), 256n), 1n)

def bitlist_root(+bits: List<&2, Bool>, limit_bits: Nat) -> List<&2, U32>:
  +n = List.length(&2, Bool, bits)
  S.mix_len(S.merkle_limit(byte_chunks(pack_bits(bits)), bit_chunk_limit(limit_bits)), n)

def agg_root(a: AggAtt) -> List<&2, U32>:
  match a:
    case Agg{bits, data}:
      S.chunk2(bitlist_root(bits, 4096n), att_root(data))

def agg_roots(xs: List<&2, AggAtt>) -> List<&2, List<&2, U32>>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      agg_root(h) <> agg_roots(t)

def body_root(body: List<&2, AggAtt>) -> List<&2, U32>:
  S.list_root(agg_roots(body), 4096n)

def empty_body() -> List<&2, U32>:
  body_root(Nil{})

def hist_root(xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  S.list_root(xs, 262144n)

def jslots_root(bits: List<&2, Bool>) -> List<&2, U32>:
  bitlist_root(bits, 262144n)

def jvotes_root(bits: List<&2, Bool>) -> List<&2, U32>:
  bitlist_root(bits, 1073741824n)

def state_root(s: State) -> List<&2, U32>:
  match s:
    case St{time, slot, header, justified, finalized, hist, jslots, validators, jroots, jvotes}:
      S.merkle([
        S.u64_chunk(time),
        S.u64_chunk(slot),
        header_root(header),
        cp_root(justified),
        cp_root(finalized),
        hist_root(hist),
        jslots_root(jslots),
        vals_root(validators),
        hist_root(jroots),
        jvotes_root(jvotes)
      ])

def genesis_header() -> Header:
  Hd{0n, 0n, zero(), zero(), empty_body()}

def genesis_cp() -> Checkpoint:
  Cp{zero(), 0n}

def genesis(time: Nat, validators: List<&2, Validator>) -> State:
  St{time, 0n, genesis_header(), genesis_cp(), genesis_cp(), Nil{}, Nil{}, validators, Nil{}, Nil{}}

def slot_of(s: State) -> Nat:
  match s:
    case St{_, slot, _, _, _, _, _, _, _, _}:
      slot

def header_of(s: State) -> Header:
  match s:
    case St{_, _, header, _, _, _, _, _, _, _}:
      header

def header_slot(s: State) -> Nat:
  match s:
    case St{_, _, Hd{slot, _, _, _, _}, _, _, _, _, _, _, _}:
      slot

def header_blank(s: State) -> Bool:
  match s:
    case St{_, _, Hd{_, _, _, state_root, _}, _, _, _, _, _, _, _}:
      is_zero(state_root)

def header_is_genesis(s: State) -> Bool:
  match s:
    case St{_, _, Hd{slot, _, _, _, _}, _, _, _, _, _, _, _}:
      Nat.is_eq(slot, 0n)

def val_count(s: State) -> Nat:
  match s:
    case St{_, _, _, _, _, _, _, validators, _, _}:
      List.length(&2, Validator, validators)

def block_slot(b: Block) -> Nat:
  match b:
    case Blk{slot, _, _, _, _}:
      slot

def block_proposer(b: Block) -> Nat:
  match b:
    case Blk{_, proposer, _, _, _}:
      proposer

def block_parent(b: Block) -> List<&2, U32>:
  match b:
    case Blk{_, _, parent, _, _}:
      parent

def block_state(b: Block) -> List<&2, U32>:
  match b:
    case Blk{_, _, _, state_root, _}:
      state_root

def block_root(b: Block) -> List<&2, U32>:
  match b:
    case Blk{slot, proposer, parent, state_root, body}:
      S.merkle([S.u64_chunk(slot), S.u64_chunk(proposer), parent, state_root, body_root(body)])
