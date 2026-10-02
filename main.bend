import Base

# Bend is the client entry point. The protocol sidecar is pinned to the exact
# leanSpec revision named in scripts/bootstrap.sh; pure consensus primitives
# live in src/ and are checked independently by scripts/test.sh.

def finish_process(status: U32, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit, Unit{})
    case False{}:
      IO.die(Unit, status, "leanSpec node exited with an error")

def report_done(value: U32 & (String & String)) -> IO(Unit):
  (+status, (stdout, stderr)) = value
  do IO<Unit>:
    IO.print(stdout)
    IO.print_err(stderr)
    finish_process(status, U32.is_eq(status, 0))

def report(result: Result<&1, &1, U32 & String, U32 & (String & String)>) -> IO(Unit):
  match result:
    case Fail{error}:
      (code, message) = error
      IO.die(Unit, code, "failed to start leanSpec sidecar: " ++ message)
    case Done{value}:
      report_done(value)

def main() -> IO(Unit):
  do IO<Unit>:
    argv : List<String> <- IO.args()
    result : Result<&1, &1, U32 & String, U32 & (String & String)> <- Process.run(
      "./scripts/run-node.sh",
      List.tail(&1, String, argv),
      "",
      4294967295,
      4294967295
    )
    report(result)
