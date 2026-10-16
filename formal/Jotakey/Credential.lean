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

Each theorem's doc comment says what it **proves** and **how**. *Syntax* comments
introduce notation not already explained in the earlier files (see `Jotakey.lean` for the
reading order).
-/

namespace Jotakey.Credential

/-- Format version byte. -/
def version : Nat := 1
/-- Nonce length. -/
def nonceLen : Nat := 32
/-- Tag length (truncated HMAC). -/
def tagLen : Nat := 16

-- Syntax: `variable (mac : …)` declares a parameter shared by everything below. Each
-- definition or theorem that mentions `mac` silently gets it as an extra first argument, so
-- `wrap` really is `wrap mac key rp nonce`, as the theorems write it. Nothing is assumed about
-- `mac`: the theorems hold for *every* function of this type, HMAC-SHA256 included.
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
-- Syntax: `MacLen` is a *definition of a statement*, not a proof of one. A theorem that needs
-- it takes a hypothesis `(hlen : MacLen mac)`: the caller must supply the proof. That is how
-- an assumption is made explicit in Lean, without adding an axiom.

/-- **Proves:** unwrapping a freshly wrapped ID, at the same key and RP, returns the nonce it
was minted with. Assumes only that the MAC always outputs `tagLen` bytes and the nonce is
`nonceLen` bytes, both of which the Rust types guarantee (`[u8; 16]`, `[u8; 32]`).

**How:** compute. The ID has length `1 + 32 + 16`, so the length check passes, and its first
byte is `version`. Splitting the rest at 32 gives back `nonce` (`ht`) and the tag (`hd`), so
the recomputed MAC equals the stored tag and `unwrap` returns `some nonce`. The final
`omega` settles the leftover length arithmetic. -/
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
returned nonce. There are no alternative encodings and no "almost right" IDs.

**Proves:** if `unwrap mac key rp id = some nonce`, then `id = wrap mac key rp nonce` and the
nonce is 32 bytes. No assumption about the MAC.

**How:** an empty `id` is rejected, so `id = v :: rest`. Follow `unwrap`'s two `if`s with
`split at h`; both rejecting branches contradict `h`. In the accepting branch:
`nonce = rest.take 32`, `v = version` and the tag check gave `mac key rp nonce = rest.drop 32`.
Then `wrap … nonce = version :: (rest.take 32 ++ rest.drop 32) = v :: rest = id`
(`List.take_append_drop`). The length check, `1 + rest.length = 49`, gives the nonce length. -/
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
differ between relying parties, an ID minted for `rp` never unwraps at another RP.

**Proves:** if the MAC never gives the same tag for two different RPs (same key and nonce),
then `unwrap` at `rp' ≠ rp` rejects an ID that `wrap` minted at `rp`. A credential created
for one site is useless at another.

The hypothesis `hcr` is an idealisation. Stated for *all* inputs it is false for any real
16-byte MAC (there are more RPs than tags, so collisions exist). What the cryptography
provides is that nobody can *find* such a collision, except with probability about 2⁻¹²⁸ per
attempt. The theorem shows that this collision is the *only* way an ID can be moved
between sites: the format, parsing and comparison add no other way.

**How:** by contradiction. Suppose `unwrap` at `rp'` accepted, returning `n`. By
`unwrap_sound`, the ID is also `wrap` at `rp'` for `n`:
`nonce ++ mac key rp nonce = n ++ mac key rp' n`. Both nonces are 32 bytes long, so
`List.append_inj` splits this equation into `nonce = n` and
`mac key rp nonce = mac key rp' nonce`, which `hcr` says can't happen because `rp ≠ rp'`. -/
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
      -- Syntax: `congrArg f h` turns `h : a = b` into `f a = f b` (here: equal lists have
      -- equal lengths).
      simp only [List.length_append] at this
      omega
    have ⟨h1, h2⟩ := List.append_inj hid hn'.symm
    -- Syntax: `have ⟨h1, h2⟩ := e` is `obtain` in `have` form; `hn'.symm` flips the equation.
    subst h1
    exact hcr key rp rp' nonce hne h2

end Jotakey.Credential
