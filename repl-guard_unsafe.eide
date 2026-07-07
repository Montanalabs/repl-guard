#! VULNERABLE repl-guard — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant evalRepl

let raw = fetch<web>
privileged { evalRepl(raw) }  # tainted -> tool: REJECTED
