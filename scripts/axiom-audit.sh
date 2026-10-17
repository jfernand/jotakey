#!/usr/bin/env bash
# (c) Javier Fernandez @ JotaSoft 2026
# Axiom audit for the Lean proofs (AGENTS.md §4). Fails if:
#  - formal/AxiomAudit.lean does not elaborate cleanly,
#  - any `#print axioms` line produced no report (so nothing can pass silently),
#  - any theorem depends on an axiom outside Lean's standard three.
set -euo pipefail
cd "$(dirname "$0")/../formal"

out=$(lake env lean AxiomAudit.lean 2>&1) || { printf '%s\n' "$out"; echo "axiom audit: lean failed" >&2; exit 1; }

if grep -q 'error' <<<"$out"; then
    printf '%s\n' "$out"; echo "axiom audit: errors reported" >&2; exit 1
fi

expected=$(grep -c '^#print axioms' AxiomAudit.lean)
reported=$(grep -c -E "depends on axioms|does not depend on any axioms" <<<"$out" || true)
if [ "$expected" -eq 0 ] || [ "$reported" -ne "$expected" ]; then
    printf '%s\n' "$out"
    echo "axiom audit: expected $expected reports, got $reported" >&2; exit 1
fi

bad=$(sed -n 's/.*depends on axioms: \[\(.*\)\]/\1/p' <<<"$out" | tr ',' '\n' | tr -d ' ' \
      | grep -v -x -E 'propext|Quot.sound|Classical.choice' || true)
if [ -n "$bad" ]; then
    echo "axiom audit: forbidden axioms:" >&2; printf '%s\n' "$bad" | sort -u >&2; exit 1
fi

echo "axiom audit: $reported theorems, only propext / Quot.sound / Classical.choice"
