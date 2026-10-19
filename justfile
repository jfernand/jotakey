# Jotakey task runner. See AGENTS.md §5.

default: test

test:
    cargo test -p jotakey-core
    cargo clippy -p jotakey-core --all-targets -- -D warnings

miri:
    cargo +nightly miri test -p jotakey-core --lib

# Seeds (fuzz/seeds, tracked) are read next to the working corpus (fuzz/corpus, untracked).
fuzz target time="300":
    cd fuzz && mkdir -p corpus/{{target}} && cargo +nightly fuzz run {{target}} corpus/{{target}} $(test -d seeds/{{target}} && echo seeds/{{target}}) -- -max_total_time={{time}}

fuzz-all time="120":
    for t in cbor_decode ctap_dispatch ctaphid_stack ble_stream serial_deframe credential_unwrap pin_protocol client_pin; do \
        {{just_executable()}} fuzz $t {{time}} || exit 1; \
    done

mutants:
    cargo mutants -p jotakey-core

lean:
    cd formal && lake build
    ! grep -rn --include=*.lean -E '\bsorry\b|^\s*axiom |native_decide' formal/Jotakey formal/Main.lean
    scripts/axiom-audit.sh

diff:
    cd formal && lake build jotakey-spec
    cargo test -p jotakey-core --test differential -- --nocapture

fw:
    cd crates/jotakey-fw && cargo build --release

flash:
    cd crates/jotakey-fw && cargo run --release

testfw:
    cd crates/jotakey-testfw && cargo test

bridge port="/dev/ttyACM0":
    cargo run -p jotakey-bridge --release -- {{port}}

# Browse the FIDO keys attached to this computer (read-only). `just explore --dump` prints them.
explore *args:
    cargo run -p jotakey-explorer --release -- {{args}}

host-tests:
    cargo test -p jotakey-host-tests -- --ignored --test-threads=1

doc:
    typst compile --font-path docs/fonts --ignore-system-fonts docs/jotakey.typ docs/jotakey.pdf

# Print version: plain white pages, no black cover band.
doc-print:
    typst compile --font-path docs/fonts --ignore-system-fonts --input print=true docs/jotakey.typ docs/jotakey-print.pdf

deny:
    cargo deny check
