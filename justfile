# Jotakey task runner. See AGENTS.md §5.

default: test

test:
    cargo test -p jotakey-core
    cargo clippy -p jotakey-core --all-targets -- -D warnings

miri:
    cargo +nightly miri test -p jotakey-core --lib

fuzz target time="300":
    cd fuzz && cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}

fuzz-all time="120":
    for t in cbor_decode ctap_dispatch ctaphid_stack ble_stream credential_unwrap; do \
        (cd fuzz && cargo +nightly fuzz run $t -- -max_total_time={{time}}) || exit 1; \
    done

mutants:
    cargo mutants -p jotakey-core

lean:
    cd formal && lake build
    ! grep -rn --include=*.lean -E '\bsorry\b|^\s*axiom |native_decide' formal/Jotakey formal/Main.lean
    scripts/axiom-audit.sh

diff:
    cd formal && lake build jotakey-spec
    JOTAKEY_SPEC=formal/.lake/build/bin/jotakey-spec cargo test -p jotakey-core --test differential -- --nocapture

fw:
    cd crates/jotakey-fw && cargo build --release

flash:
    cd crates/jotakey-fw && cargo run --release

testfw:
    cd crates/jotakey-testfw && cargo test

bridge port="/dev/ttyACM0":
    cargo run -p jotakey-bridge --release -- {{port}}

host-tests:
    cargo test -p jotakey-host-tests -- --ignored --test-threads=1

doc:
    typst compile docs/jotakey.typ docs/jotakey.pdf

deny:
    cargo deny check
