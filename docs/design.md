# Nupe Design

This document describes design decisions in Nupe

## Code Layout / Organization

Our design uses roughly 3 "layers" for describing the [PE Format][pe_ref],
each building on the last.

### Raw Layer

The `Raw` layer is the lowest, it contains the raw types
described in the [PE Reference][pe_ref]

### Advanced Layer

The `Advanced` layer is a few steps above the `Raw` layer in ergonomics,
it provides things useful for complicated and advanced API usage,
possibly using unsafe.

### Easy Layer

The `Easy` layer is the highest layer, and should be completely safe.

Using the public APIs from the `Raw` and `Advanced` layers,
it should describe a safe interface fo working with [PE Format][pe_ref] files.

As the highest and safest layer, it will also be the least flexible,
potentially being unsuitable for advanced usage and requirements.

Composable Helpers for operations `Advanced` and `Raw` end-users may want to do
should be provided where possible and it makes sense.

[pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
