miri_base := "\
-Zmiri-strict-provenance \
-Zmiri-symbolic-alignment-check \
"

miri_isolation := miri_base + " -Zmiri-isolation-error=warn-nobacktrace"

export MIRIFLAGS := miri_base + miri_isolation

@_default:
    {{just_executable()}} --list

# Run tests with miri nextest
@miri *args='':
    cargo +nightly miri nextest run {{args}}

# Run miri without isolation, for bolero tests
@miri-no-isolation *args='':
    MIRIFLAGS="{{miri_base}} -Zmiri-disable-isolation" \
    cargo +nightly miri nextest run {{args}}

# Run tests with nextest
@test *args='':
    cargo +nightly nextest run {{args}}

# Run clippy on all targets
@clippy:
    cargo clippy --all-targets

@doc *args='':
    cargo +nightly doc --no-deps {{args}}

kani_flags := "\
RUSTC_WRAPPER= cargo kani --tests --enable-unstable \
"

# Run the Kani model tests
@kani *args='':
    # {{kani_flags}} {{args}}
    RUSTC_WRAPPER= cargo bolero test --engine=kani {{args}}

# Visualize failing Kani model tests
@kani_v *args='':
    # {{kani_flags}} {{args}} --concrete-playback=print
    {{kani_flags}} --visualize --harness={{args}}

# Run bolero fuzz tests
@fuzz *args='':
    cargo bolero test {{args}}

# Run bolero for AFL fuzz tests
@fuzz-afl *args='':
    AFL_SKIP_CPUFREQ= cargo bolero test --sanitizer=NONE --engine=afl  {{args}}
