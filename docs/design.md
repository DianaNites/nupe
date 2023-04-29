# Nupe Design

This document describes design decisions in Nupe

## Goals / Pipedreams

- `no_std` from the ground up
- Simple safety invariants in unsafe code
- Extensive safe API
- Seamlessly work with (mutable) in memory data, or owned data
- Miri runs on the entire codebase
- Should be as fast and small as possible, favoring fast
- Should be usable entirely without allocating, though may require `alloc` to be linked.

## Code Layout / Organization

Our design uses roughly 3 conceptual "layers" for describing the
[PE Format][pe_ref], each building on the last.

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

This layer may be unsafe, and takes the most care to use correctly,
with the most manual work and knowledge of the PE format required.

As the lowest layer, this is the most flexible, you should be able to use
the tools here to accomplish essentially anything, in any way you want.

The only requirement at this layer is that each individual object must be
contiguous in memory.

### Advanced Layer

The `Advanced` layer is a few steps above the `Raw` layer in ergonomics,
it provides things useful for complicated and advanced API usage,
possibly using unsafe.

This layer should require less or even know specific knowledge of the PE format,
but will still require special care to work with.

This layer should primarily be safe, but logic errors and invalid
PE images may result if documentation is not followed.

### Easy Layer

The `Easy` layer is the highest layer, and should be completely safe.

Using the public APIs from the `Raw` and `Advanced` layers,
it should describe a safe interface to working with [PE Format][pe_ref] files.

This layer should ideally have no unsafe code, and require the least
knowledge and care.

As a result, this layer will be the least flexible, requiring data to be
in specific formats or laid out in certain ways.

This layer is likely to internally do things that users of the other two
layers would also want to do, and as such functions and methods should be provided
to generalize this functionality for them when and where possible and sensible.

## Error Handling

Each level should have its own error? Each module? type? function?

<https://mmapped.blog/posts/12-rust-error-handling.html>

## Unsafe

### Pointers

Code should be careful to maintain pointers and their proper provenance
throughout operations on them.

All pointers should be accompanied by a size in bytes that they are valid for,
and all operations must ensure they are within bounds.

See issue [#256 Storing an object as &Header, but reading the data past the end of the header][unsafe_256]
from the Unsafe Code Guidelines for details.

This also helps code pass miri for the same reason, see miri [issue #134][miri_134]

In short, all raw pointers should *stay* raw pointers and
be *derived* from other raw pointers. ***Not*** references to a specific type.

[pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
[unsafe_256]: https://github.com/rust-lang/unsafe-code-guidelines/issues/256
[miri_134]: https://github.com/rust-lang/unsafe-code-guidelines/issues/134
