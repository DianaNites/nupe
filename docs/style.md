# Nupe Code Style Guide

Describes code style and conventions used while developing this library

## Formatting

`cargo fmt`

## Naming

Structures, fields, and operations described in the [PE Reference][pe_ref]
are named to Rust naming conventions, and additionally may be renamed
to improve clarity and overall coherence, and in this case the naming
used in the [PE Reference][pe_ref] should be documented as an alias
and use `doc(alias)`

### Raw Layer

<!-- TODO: Discuss this -->

Types in the `Raw` layer should be prefixed `Raw`, e.g. `RawDOS`
for the raw DOS header.

## Unsafe

## Safety Comments

Unsafe operations should have a `// Safety` comment explaining why they're safe

### Safety Comments Example

This is an example structure, and not a hard rule.

None of the explanations are required.

```rust
// Safety: Short Explanation
// Long Explanation
// - Condition 1
//   - Sub-condition
//   - Specific Explanation
//   - Specific Explanation that is pretending to be very, very, very,
//     very long
// - Condition 2
// - Condition 3
```

## Safety Documentation

Unsafe functions and methods should have a `# Safety` section explaining
what pre-conditions they rely on.

## Documentation

Documentation should be provided for all public items and fields,
as well as private ones where possible.

Documentation describing things from the [PE Reference][pe_ref]
should link their source, if any.

Documentation describing things from the [PE Reference][pe_ref]
should document the name used in reference, if different from the Rust name,
see [Naming][naming].

In documentation, `"must"` refers to something the [PE Reference][pe_ref]
requires, but which is known to, in the wild, work if violated.
These requirements should be upheld unless you know what you're doing.

### Lists

Lists in documentation should not end in periods.

[pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
[naming]: #naming
