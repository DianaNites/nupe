export MIRIFLAGS := "\
-Zmiri-strict-provenance \
-Zmiri-symbolic-alignment-check \
-Zmiri-isolation-error=warn-nobacktrace \
"

@_default:
    {{just_executable()}} --list

# Run tests with miri nextest
@miri *args='':
    cargo +nightly miri nextest run {{args}}

# Run tests with nextest
@test *args='':
    cargo +nightly nextest run {{args}}

# Run clippy on all targets
@clippy:
    cargo clippy --all-targets
