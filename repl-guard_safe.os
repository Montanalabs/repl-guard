#! REPL guard — untrusted an expression can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires evalRepl — the repl guard sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant evalRepl

type ReplOp = ArithR | DefR | CallR
type Decision = EvalExpr(ReplOp) | RejectRepl

let raw = fetch<web>  # UNTRUSTED an expression — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { evalRepl(d) }  # act on the trusted decision only
