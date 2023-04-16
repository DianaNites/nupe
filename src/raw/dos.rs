//! Raw DOS Header data structures
//!
//! The Microsoft DOS Header, in the context of PE files,
//! is a legacy stub they insist on still adding for DOS compatibility.
//! Conventionally this stub program does nothing more than print it cannot
//! run in DOS.
//!
//! The DOS Stub contains one field of interest, the offset to the start
//! of the actual PE headers.
