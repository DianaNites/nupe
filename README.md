# NuPe

A `no_std` library for handling PE files

## Design goals / Features

- `no_std`
- std support
- Support modification
  - At least enough to append sections.
  - Support through Pe type controlling rights, can give it a.. writer
  - Shit
  - CpioRead and CpioWrite?
  - Separate types, take references to write?
  - diff updates?
- Safe API
- Provide raw types for advanced users

### Use cases

- Given a pointer to a image (partially??) loaded in memory
  - Read the header
  - Find the location of other sections in memory

- Given a (mutable) byte slice to a (partial??) image
  - Read the header
  - Add sections
  - Remove sections
  - Re-order sections
  - Remove gaps
  - Shrink/Expand sections
  - Modify the header as appropriate

- Given any parsed structure, be able to perfectly recreate it? bit for bit?
  - Should we have the ability to parse/create invalid structures?
    - Certainly not through the standard API, but its fine if a "raw" API allows it?
  - DO need the ability to at least perfectly read it? Don't drop "irrelevant" data?
    - But want an easy path that doesn't overwhelm common/normal use-cases?
