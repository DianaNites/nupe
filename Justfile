export MIRIFLAGS := "\
-Zmiri-strict-provenance \
-Zmiri-symbolic-alignment-check \
"

@_default:

@miri *args='':
    cargo +nightly miri nextest run {{args}}

@test *args='':
    cargo +nightly nextest run {{args}}

@clippy:
    cargo clippy --all-targets
