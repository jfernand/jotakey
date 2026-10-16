import Jotakey

/-! Axiom audit: `just lean` fails if any theorem depends on `sorryAx`, on
`Lean.ofReduceBool` (native_decide) or on any axiom beyond Lean's standard three
(`propext`, `Quot.sound`, `Classical.choice`). -/
open Jotakey
-- Syntax: `#print axioms t` lists every axiom the proof of `t` depends on, directly or through
-- the lemmas it uses. `scripts/axiom-audit.sh` runs this file and checks the output.
#print axioms Cbor.decodeHead_encodeHead
#print axioms Cbor.encodeHead_of_decodeHead
#print axioms Cbor.decodeHead_shrinks
#print axioms CtapHid.run_isolated
#print axioms CtapHid.step_wf
#print axioms CtapHid.run_wf
#print axioms CtapHid.reassemble_fragment
#print axioms Authenticator.signature_needs_touch
#print axioms Authenticator.no_double_sign
#print axioms Authenticator.trace_counters_increasing
#print axioms Authenticator.reset_needs_touch
#print axioms Authenticator.reset_needs_window
#print axioms Authenticator.faulted_never_signs
#print axioms Credential.unwrap_wrap
#print axioms Credential.unwrap_sound
#print axioms Credential.rp_binding
