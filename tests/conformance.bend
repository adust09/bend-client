import Base
import ../src/bytes.bend as B
import ../src/sha256.bend as H
import ../src/ssz.bend as S
import ../src/types.bend as T
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

def outcome_root(o: R.Outcome) -> String:
  match o:
    case R.Ok{state}:
      B.Bytes.hex(T.state_root(state))
    case R.Reject{reason}:
      reason

def main() -> IO(Unit):
  do IO<Unit>:
    +g : T.State = T.genesis(1000n, one_val())
    b : T.Block = T.Blk{1n, 0n, parent_root(), post_root(), Nil{}}
    wrong_parent : T.Block = T.Blk{1n, 0n, T.zero(), post_root(), Nil{}}
    wrong_proposer : T.Block = T.Blk{1n, 1n, parent_root(), post_root(), Nil{}}
    same_slot : T.Block = T.Blk{0n, 0n, T.zero(), T.zero(), Nil{}}
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
