export MIRIFLAGS := "\
-Zmiri-strict-provenance \
-Zmiri-symbolic-alignment-check \
"

@_default:

@miri:
    cargo +nightly miri test

@clippy:
    cargo clippy --all-targets
