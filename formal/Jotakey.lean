-- (c) Javier Fernandez @ JotaSoft 2026
-- The root of the `Jotakey` library: importing this file builds every model and every proof.
--
-- Suggested reading order (each file introduces the Lean syntax it uses the first time it
-- appears, so later files build on earlier ones):
--
--   1. `Jotakey/Cbor/Heads.lean`   numbers ↔ bytes, CBOR heads; most basic tactics
--   2. `Jotakey/Cbor/Cbor.lean`    the strict validator; mutual recursion, `termination_by`
--   3. `Jotakey/CtapHid.lean`      CTAPHID reassembly; inductive types, recursive proofs
--   4. `Jotakey/Authenticator.lean` the user-presence/counter state machine; structures, traces
--   5. `Jotakey/Credential.lean`   credential IDs; `variable`, assumptions as hypotheses
--   6. `Main.lean`, `AxiomAudit.lean` the executable spec and the axiom check
--
-- Three kinds of comments appear throughout:
--   `--` ...            a line comment, ignored by Lean (like `//` in Rust)
--   `/-- ... -/`        a doc comment for the declaration right below it (like `///`)
--   `/-! ... -/`        a module or section doc comment (like `//!`)
-- Block comments nest in Lean, so a doc comment never contains a bare `/-`.
import Jotakey.Cbor.Heads
import Jotakey.Cbor.Cbor
import Jotakey.CtapHid
import Jotakey.Authenticator
import Jotakey.Credential
