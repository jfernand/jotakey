-- (c) Javier Fernandez @ JotaSoft 2026
import Jotakey

/-! Axiom audit: `just lean` fails if any theorem depends on `sorryAx`, on
`Lean.ofReduceBool` (native_decide) or on any axiom beyond Lean's standard three
(`propext`, `Quot.sound`, `Classical.choice`). -/
open Jotakey
-- Syntax: `#print axioms t` lists every axiom the proof of `t` depends on, directly or through
-- the lemmas it uses. `scripts/axiom-audit.sh` runs this file and checks the output.
#print axioms Cbor.decodeHead_inverts_encodeHead
#print axioms Cbor.decodeHead_accepts_only_canonical
#print axioms Cbor.decodeHead_consumes_input
#print axioms CtapHid.receivePackets_ignores_other_channels
#print axioms CtapHid.receivePacket_preserves_well_formed
#print axioms CtapHid.receivePackets_preserves_well_formed
#print axioms CtapHid.fragmented_message_is_reassembled
#print axioms Authenticator.processRequest_never_signs_with_presence
#print axioms Authenticator.request_signs_only_silently
#print axioms Authenticator.signature_requires_confirmed_touch
#print axioms Authenticator.one_touch_signs_at_most_once
#print axioms Authenticator.trace_signature_counters_increase
#print axioms Authenticator.epoch_change_requires_confirmed_touch
#print axioms Authenticator.epoch_change_requires_reset_in_window
#print axioms Authenticator.faulted_stays_faulted_and_never_signs
#print axioms Credential.unwrap_recovers_nonce
#print axioms Credential.unwrap_accepts_only_wrapped_ids
#print axioms Credential.credential_bound_to_relying_party
#print axioms ClientPin.comparison_needs_a_counted_retry
#print axioms ClientPin.wrong_pins_between_successes_le_eight
#print axioms ClientPin.wrong_pins_in_a_row_le_three
#print axioms ClientPin.blocked_until_reset
