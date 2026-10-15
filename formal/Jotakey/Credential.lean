/-!
# Credential IDs

Formal model of `crates/jotakey-core/src/credential.rs`.

A credential ID is `[version] ++ nonce ++ tag`, with `tag = mac key rp nonce`. The MAC is a
*parameter* of the model (any function), not an axiom. Each theorem states exactly what it
assumes about it:

* `unwrap_wrap`: wrapping then unwrapping returns the nonce (no assumption).
* `unwrap_sound`: if unwrap accepts an ID, that ID is *exactly* what `wrap` mints for the
  recovered nonce at that RP (no assumption). Nothing else is accepted.
* `rp_binding`: an ID minted for `rp` is rejected at `rp' ≠ rp`, **assuming** the MAC does
  not collide across relying parties for the same key and nonce.

That last assumption is the cryptographic part. For HMAC-SHA256 truncated to 128 bits it
holds except with probability about 2⁻¹²⁸ per attempt. Lean cannot prove that; it is a
property of SHA-256 that the cryptographic literature argues for. The proof shows that the
*construction* adds no weakness of its own on top of the MAC.
-/

namespace Jotakey.Credential

/-- Format version byte. -/
def version : Nat := 1
/-- Nonce length. -/
def nonceLen : Nat := 32
/-- Tag length (truncated HMAC). -/
def tagLen : Nat := 16

variable (mac : List Nat → List Nat → List Nat → List Nat)

/-- `credential::wrap`. -/
def wrap (key rp nonce : List Nat) : List Nat :=
  version :: (nonce ++ mac key rp nonce)

/-- `credential::unwrap`: check length and version, recompute the tag, compare. -/
def unwrap (key rp id : List Nat) : Option (List Nat) :=
  match id with
  | v :: rest =>
    if id.length = 1 + nonceLen + tagLen ∧ v = version then
      let nonce := rest.take nonceLen
      let tag := rest.drop nonceLen
      if mac key rp nonce = tag then some nonce else none
    else none
  | [] => none

/-- Well-formed MAC output: always `tagLen` bytes. -/
def MacLen : Prop := ∀ k r n, (mac k r n).length = tagLen

theorem unwrap_wrap (hlen : MacLen mac) (key rp nonce : List Nat) (hn : nonce.length = nonceLen) :
    unwrap mac key rp (wrap mac key rp nonce) = some nonce := by
  simp only [wrap, unwrap, List.length_cons, List.length_append, hn, hlen key rp nonce]
  have ht : (nonce ++ mac key rp nonce).take nonceLen = nonce := by
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
  have hd : (nonce ++ mac key rp nonce).drop nonceLen = mac key rp nonce := by
    rw [← hn, List.drop_left]
  simp [ht, hd]
  omega

/-- **Soundness.** Anything `unwrap` accepts is precisely the ID `wrap` would mint for the
returned nonce. There are no alternative encodings and no "almost right" IDs. -/
theorem unwrap_sound (key rp id nonce : List Nat) (h : unwrap mac key rp id = some nonce) :
    id = wrap mac key rp nonce ∧ nonce.length = nonceLen := by
  match id, h with
  | v :: rest, h =>
    simp only [unwrap] at h
    split at h
    · rename_i hc
      split at h
      · rename_i htag
        simp only [Option.some.injEq] at h
        subst h
        obtain ⟨hl, hv⟩ := hc
        simp only [List.length_cons] at hl
        refine ⟨?_, ?_⟩
        · simp only [wrap, hv, htag, List.take_append_drop]
        · simp [nonceLen, tagLen] at hl ⊢; omega
      · simp at h
    · simp at h

/-- **RP binding (invariant 3).** Under the assumption that tags for one key and nonce
differ between relying parties, an ID minted for `rp` never unwraps at another RP. -/
theorem rp_binding
    (hcr : ∀ k r r' n, r ≠ r' → mac k r n ≠ mac k r' n)
    (key rp rp' nonce : List Nat) (hn : nonce.length = nonceLen) (hne : rp ≠ rp') :
    unwrap mac key rp' (wrap mac key rp nonce) = none := by
  cases h : unwrap mac key rp' (wrap mac key rp nonce) with
  | none => rfl
  | some n =>
    exfalso
    obtain ⟨hid, hnl⟩ := unwrap_sound mac key rp' _ n h
    simp only [wrap, List.cons.injEq, true_and] at hid
    -- equal lengths of nonces force equal nonces and equal tags
    have hn' : n.length = nonce.length := by
      have := congrArg List.length hid
      simp only [List.length_append] at this
      omega
    have ⟨h1, h2⟩ := List.append_inj hid hn'.symm
    subst h1
    exact hcr key rp rp' nonce hne h2

end Jotakey.Credential
