# Nupe Design

This document describes design decisions in Nupe

## Code Layout / Organization

Our design uses roughly 3 "layers" for describing the [PE Format][pe_ref],
each building on the last.

### Raw Layer

The `Raw` layer is the lowest, it contains the raw types
described in the [PE Reference][pe_ref].

All such types, and their fields, should be public, to allow the most advanced
usage.

Methods to "parse" these structures from memory, returning a reference
to the typed data, should be provided.

Methods to write these structures to memory should be provided.

Always take a pointer *and* size, and *always* ensure all accesses
to any memory is within bounds.

### Advanced Layer

The `Advanced` layer is a few steps above the `Raw` layer in ergonomics,
it provides things useful for complicated and advanced API usage,
possibly using unsafe.

### Easy Layer

The `Easy` layer is the highest layer, and should be completely safe.

Using the public APIs from the `Raw` and `Advanced` layers,
it should describe a safe interface to working with [PE Format][pe_ref] files.

As the highest and safest layer, it will also be the least flexible,
potentially being unsuitable for advanced usage and requirements.

Composable Helpers for operations `Advanced` and `Raw` end-users may want to do
should be provided where possible and it makes sense.

## Error Handling

## Unsafe

### Pointers

Code should be careful to maintain pointers and their proper provenance
throughout operations on them.

See issue [#256 Storing an object as &Header, but reading the data past the end of the header][unsafe_256]
from the Unsafe Code Guidelines for details.

This also helps code pass miri for the same reason, see miri [issue #134][miri_134]

In short, all raw pointers should *stay* raw pointers and
be *derived* from other raw pointers. ***Not*** references to a specific type.

[pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
[unsafe_256]: https://github.com/rust-lang/unsafe-code-guidelines/issues/256
[miri_134]: https://github.com/rust-lang/unsafe-code-guidelines/issues/134
