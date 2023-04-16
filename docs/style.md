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

## Unsafe

Unsafe operations should have a `// Safety` comment explaining why they're safe

### Example

```rust
// Safety:
// - Condition 1
// - Condition 2
// - Condition 3
```

[pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
