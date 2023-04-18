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

@doc *args='':
    cargo +nightly doc --no-deps {{args}}

# Run the Kani model tests
@kani:
    if ! RUSTC_WRAPPER= cargo kani --tests; then \
        echo; \
        echo RUSTC_WRAPPER= cargo kani --tests --enable-unstable --concrete-playback=print; \
        echo; \
        RUSTC_WRAPPER= cargo kani \
            --tests \
            --enable-unstable \
            --visualize \
    ;fi
