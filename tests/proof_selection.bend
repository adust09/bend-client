import Base
import ../deps/bend-merkle-tree/src/sha256.bend as H
import ../src/fork_choice.bend as F
import ../src/proof_selection.bend as P
import ./proof_selection_cases.bend as V

def comma_tail(tail: String) -> String:
  match tail:
    case SNil{}:
      ""
    case SCon{head, rest}:
      "," ++ SCon{head, rest}

def proof_ids(proofs: List<&2, F.Proof>) -> String:
  match proofs:
    case Nil{}:
      ""
    case Con{proof, tail}:
      H.sha256_hex(P.proof_encoding(proof)) ++ comma_tail(proof_ids(tail))

def indices_text(indices: List<&2, Nat>) -> String:
  match indices:
    case Nil{}:
      ""
    case Con{index, tail}:
      Nat.show(index) ++ comma_tail(indices_text(tail))

def selection_text(result: P.Selection) -> String:
  match result:
    case P.Selected{proofs, covered}:
      proof_ids(proofs) ++ "|" ++ indices_text(covered)
    case P.Rejected{reason}:
      "REJECT:" ++ reason

def run_cases(cases: List<&2, V.Case>) -> IO(Unit):
  match cases:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{V.Vector{label, priority, fallback}, tail}:
      do IO<Unit>:
        IO.print(label ++ "=" ++ selection_text(P.select_proofs_for_coverage(priority, fallback)))
        run_cases(tail)

def run_encodings(proofs: List<&2, F.Proof>, index: Nat) -> IO(Unit):
  match proofs:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{proof, tail}:
      +i = index
      do IO<Unit>:
        IO.print("encoding-" ++ Nat.show(i) ++ "=" ++ H.sha256_hex(P.proof_encoding(proof)))
        run_encodings(tail, Nat.add(i, 1n))

def main() -> IO(Unit):
  do IO<Unit>:
    run_encodings(V.proofs(), 0n)
    run_cases(V.cases())
