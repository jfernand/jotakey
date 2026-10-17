-- (c) Javier Fernandez @ JotaSoft 2026
/-!
# Credential IDs

Formal model of `crates/jotakey-core/src/credential.rs`.

A credential ID is `[formatVersion] ++ nonce ++ tag`, with `tag = mac key relyingParty nonce`.
The MAC is a *parameter* of the model (any function), not an axiom. Each theorem states
exactly what it assumes about it:

* `unwrap_recovers_nonce`: wrapping then unwrapping returns the nonce (only assumes the MAC
  output has the right length).
* `unwrap_accepts_only_wrapped_ids`: if unwrap accepts an ID, that ID is *exactly* what `wrap`
  mints for the recovered nonce at that relying party (no assumption). Nothing else is
  accepted.
* `credential_bound_to_relying_party`: an ID minted for one relying party is rejected at any
  other, **assuming** the MAC does not collide across relying parties for the same key and
  nonce.

That last assumption is the cryptographic part. For HMAC-SHA256 truncated to 128 bits it
holds except with probability about 2⁻¹²⁸ per attempt. Lean cannot prove that; it is a
property of SHA-256 that the cryptographic literature argues for. The proof shows that the
*construction* adds no weakness of its own on top of the MAC.

Relying parties are represented by their `rpIdHash` bytes, keys and nonces by their bytes.

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in the earlier files (see `Jotakey.lean` for the
reading order).
-/

namespace Jotakey.Credential

/-- Format version byte. -/
def formatVersion : Nat := 1
/-- Nonce length in bytes. -/
def nonceLength : Nat := 32
/-- Tag length in bytes (truncated HMAC). -/
def tagLength : Nat := 16

-- Syntax: `variable (mac : …)` declares a parameter shared by everything below. Each
-- definition or theorem that mentions `mac` silently gets it as an extra first argument, so
-- `wrap` really is `wrap mac key relyingParty nonce`, as the theorems write it. Nothing is
-- assumed about `mac`: the theorems hold for *every* function of this type, HMAC-SHA256
-- included. Its arguments are the key, the relying party and the nonce; it returns the tag.
variable (mac : List Nat → List Nat → List Nat → List Nat)

/-- `credential::wrap`. -/
def wrap (key relyingParty nonce : List Nat) : List Nat :=
  formatVersion :: (nonce ++ mac key relyingParty nonce)

/-- `credential::unwrap`: check length and version, recompute the tag, compare. -/
def unwrap (key relyingParty credentialId : List Nat) : Option (List Nat) :=
  match credentialId with
  | versionByte :: rest =>
    if credentialId.length = 1 + nonceLength + tagLength ∧ versionByte = formatVersion then
      let nonce := rest.take nonceLength
      let tag := rest.drop nonceLength
      if mac key relyingParty nonce = tag then some nonce else none
    else none
  | [] => none

/-- Well-formed MAC output: always `tagLength` bytes. -/
def MacOutputsTagLength : Prop :=
  ∀ key relyingParty nonce, (mac key relyingParty nonce).length = tagLength
-- Syntax: `MacOutputsTagLength` is a *definition of a statement*, not a proof of one. A
-- theorem that needs it takes a hypothesis `(hTagLength : MacOutputsTagLength mac)`: the
-- caller must supply the proof. That is how an assumption is made explicit in Lean, without
-- adding an axiom.

/-- **Proves:** unwrapping a freshly wrapped ID, at the same key and relying party, returns
the nonce it was minted with. Assumes only that the MAC always outputs `tagLength` bytes and
the nonce is `nonceLength` bytes, both of which the Rust types guarantee (`[u8; 16]`,
`[u8; 32]`).

**How:** compute. The ID has length `1 + 32 + 16`, so the length check passes, and its first
byte is `formatVersion`. Splitting the rest at 32 gives back `nonce` (`hTake`) and the tag
(`hDrop`), so the recomputed MAC equals the stored tag and `unwrap` returns `some nonce`. The
final `omega` settles the leftover length arithmetic. -/
theorem unwrap_recovers_nonce (hTagLength : MacOutputsTagLength mac)
    (key relyingParty nonce : List Nat) (hNonceLength : nonce.length = nonceLength) :
    unwrap mac key relyingParty (wrap mac key relyingParty nonce) = some nonce := by
  simp only [wrap, unwrap, List.length_cons, List.length_append, hNonceLength,
    hTagLength key relyingParty nonce]
  have hTake : (nonce ++ mac key relyingParty nonce).take nonceLength = nonce := by
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
  have hDrop :
      (nonce ++ mac key relyingParty nonce).drop nonceLength = mac key relyingParty nonce := by
    rw [← hNonceLength, List.drop_left]
  simp [hTake, hDrop]
  omega

/-- **Soundness.** Anything `unwrap` accepts is precisely the ID `wrap` would mint for the
returned nonce. There are no alternative encodings and no "almost right" IDs.

**Proves:** if `unwrap mac key relyingParty credentialId = some nonce`, then
`credentialId = wrap mac key relyingParty nonce` and the nonce is 32 bytes. No assumption
about the MAC.

**How:** an empty ID is rejected, so `credentialId = versionByte :: rest`. Follow `unwrap`'s
two `if`s with `split at h`; both rejecting branches contradict `h`. In the accepting branch:
`nonce = rest.take 32`, `versionByte = formatVersion` and the tag check gave
`mac key relyingParty nonce = rest.drop 32`. Then
`wrap … nonce = formatVersion :: (rest.take 32 ++ rest.drop 32) = versionByte :: rest`
(`List.take_append_drop`). The length check, `1 + rest.length = 49`, gives the nonce
length. -/
theorem unwrap_accepts_only_wrapped_ids (key relyingParty credentialId nonce : List Nat)
    (h : unwrap mac key relyingParty credentialId = some nonce) :
    credentialId = wrap mac key relyingParty nonce ∧ nonce.length = nonceLength := by
  match credentialId, h with
  | versionByte :: rest, h =>
    simp only [unwrap] at h
    split at h
    · rename_i hChecks
      split at h
      · rename_i hTagMatches
        simp only [Option.some.injEq] at h
        subst h
        obtain ⟨hIdLength, hVersion⟩ := hChecks
        simp only [List.length_cons] at hIdLength
        refine ⟨?_, ?_⟩
        · simp only [wrap, hVersion, hTagMatches, List.take_append_drop]
        · simp [nonceLength, tagLength] at hIdLength ⊢; omega
      · simp at h
    · simp at h

/-- **RP binding (invariant 3).** Under the assumption that tags for one key and nonce
differ between relying parties, an ID minted for one relying party never unwraps at another.

**Proves:** if the MAC never gives the same tag for two different relying parties (same key
and nonce), then `unwrap` at `otherParty ≠ relyingParty` rejects an ID that `wrap` minted at
`relyingParty`. A credential created for one site is useless at another.

The hypothesis `hNoCrossSiteCollision` is an idealisation. Stated for *all* inputs it is
false for any real 16-byte MAC (there are more relying parties than tags, so collisions
exist). What the cryptography provides is that nobody can *find* such a collision, except
with probability about 2⁻¹²⁸ per attempt. The theorem shows that this collision is the
*only* way an ID can be moved between sites: the format, parsing and comparison add no other
way.

**How:** by contradiction. Suppose `unwrap` at `otherParty` accepted, returning `recovered`.
By `unwrap_accepts_only_wrapped_ids`, the ID is also `wrap` at `otherParty` for `recovered`:
`nonce ++ mac key relyingParty nonce = recovered ++ mac key otherParty recovered`. Both nonces
are 32 bytes long, so `List.append_inj` splits this equation into `nonce = recovered` and
`mac key relyingParty nonce = mac key otherParty nonce`, which `hNoCrossSiteCollision` says
can't happen because the relying parties differ. -/
theorem credential_bound_to_relying_party
    (hNoCrossSiteCollision : ∀ key party party' nonce,
      party ≠ party' → mac key party nonce ≠ mac key party' nonce)
    (key relyingParty otherParty nonce : List Nat) (hNonceLength : nonce.length = nonceLength)
    (hDifferentParty : relyingParty ≠ otherParty) :
    unwrap mac key otherParty (wrap mac key relyingParty nonce) = none := by
  cases hUnwrap : unwrap mac key otherParty (wrap mac key relyingParty nonce) with
  | none => rfl
  | some recovered =>
    exfalso
    obtain ⟨hSameId, hRecoveredLength⟩ :=
      unwrap_accepts_only_wrapped_ids mac key otherParty _ recovered hUnwrap
    simp only [wrap, List.cons.injEq, true_and] at hSameId
    -- equal lengths of nonces force equal nonces and equal tags
    have hSameLength : recovered.length = nonce.length := by
      have := congrArg List.length hSameId
      -- Syntax: `congrArg f h` turns `h : a = b` into `f a = f b` (here: equal lists have
      -- equal lengths).
      simp only [List.length_append] at this
      omega
    have ⟨hSameNonce, hSameTag⟩ := List.append_inj hSameId hSameLength.symm
    -- Syntax: `have ⟨h1, h2⟩ := e` is `obtain` in `have` form; `.symm` flips an equation.
    subst hSameNonce
    exact hNoCrossSiteCollision key relyingParty otherParty nonce hDifferentParty hSameTag

end Jotakey.Credential
