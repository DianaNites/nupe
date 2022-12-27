export MIRIFLAGS := "\
-Zmiri-strict-provenance \
-Zmiri-symbolic-alignment-check \
"

@_default:

@miri *args='':
    cargo +nightly miri test {{args}}

@clippy:
    cargo clippy --all-targets
