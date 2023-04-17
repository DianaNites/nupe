//! Higher level wrappers around the [Rich Header][RawRich],
//! see there for more details.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    internal::debug::DosHelper,
    raw::rich::{RawRich, RawRichArray, RawRichEntry},
    OwnedOrRef,
    VecOrSlice,
};

// pub type RichHdrArg<'data> = VecOrSlice<'data, u8>;
pub type RichHdrArg<'data> = OwnedOrRef<'data, RawRich>;

pub type RichEntryArg<'data> = VecOrSlice<'data, RawRichEntry>;

#[derive(Clone)]
pub struct Rich<'data> {
    /// Optional Rich Header
    ///
    /// # Invariants
    ///
    /// - When [`OwnedOrRef::Owned`], [`RawRich::key`] must be `0`
    header: RichHdrArg<'data>,

    /// Optional Rich Header entries
    entries: Option<RichEntryArg<'data>>,
}

/// Public Serialization API
impl<'data> Rich<'data> {
    pub const fn new(header: RichHdrArg<'data>, entries: Option<RichEntryArg<'data>>) -> Self {
        Self { header, entries }
    }
}

/// Public Deserialization API
impl<'data> Rich<'data> {
    /// Get a [`Rich`] from a pointer to the [DOS stub][Dos]
    ///
    /// `size` *should* be *at least* [`RawDos::pe_offset`][RawDos] to be able
    /// to fully parse the header.
    ///
    /// Higher values may lead to incorrect results.
    ///
    /// `count` must be the number of elements in the
    /// [Rich Header Array][RawRichEntry]
    ///
    /// # Errors
    ///
    /// - [`Error::MissingRich`] If the rich header is missing
    /// - See [`RawRich::from_ptr`][RawRich]
    ///
    /// # Safety
    ///
    /// - `data` must be valid for `size` bytes
    ///
    /// [RawDos]: crate::raw::dos::RawDos
    /// [Dos]: crate::dos::Dos
    pub unsafe fn from_ptr(stub_ptr: *const u8, stub_size: usize) -> Result<Self> {
        Self::from_ptr_internal(stub_ptr, stub_size)
    }
}

/// Public Data API
impl<'data> Rich<'data> {
    //
}

/// Internal API
impl<'data> Rich<'data> {
    /// See [`Rich::from_ptr`]
    unsafe fn from_ptr_internal(stub_ptr: *const u8, stub_size: usize) -> Result<Self> {
        // Safety: Caller
        let (rich, rich_offset) =
            RawRich::find_rich(stub_ptr, stub_size)?.ok_or(Error::MissingRich)?;

        // Safety: Caller
        // Note that, as this is in memory, fields will need to be XORed.
        let (_, array_header_offset) = RawRichArray::find_array(stub_ptr, stub_size, rich.key)?
            .ok_or(Error::MissingRichArray)?;

        let entry_offset = array_header_offset + size_of::<RawRichArray>();
        let array_size = rich_offset - entry_offset;

        // Safety:
        // - `entry_offset` is guaranteed to be valid via `find_array`
        // - If `array_size` is not a multiple of 8, it gets rounded down.
        let entries = from_raw_parts(
            stub_ptr.add(entry_offset) as *const RawRichEntry,
            array_size / size_of::<RawRichEntry>(),
        );

        let entries = Some(VecOrSlice::Slice(entries));

        Ok(Self {
            header: OwnedOrRef::Ref(rich),
            entries,
        })
    }
}

impl<'data> fmt::Debug for Rich<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Rich");
        s.field("header", &self.header);

        // FIXME: hides Vec vs Slice
        s.field("entries", &debug::RichHelper::new(self.entries.as_ref()));
        s.finish()
    }
}

mod debug {
    //! [`fmt::Debug`] helper types
    use core::fmt;

    use crate::{internal::VecOrSlice, raw::rich::RawRichEntry};

    pub struct RichHelper(usize);

    impl RichHelper {
        pub fn new(data: Option<&VecOrSlice<'_, RawRichEntry>>) -> Self {
            Self(data.map(|d| d.len()).unwrap_or(0))
        }
    }

    impl fmt::Debug for RichHelper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, r#"Rich Array (entries {})"#, self.0)
        }
    }
}

#[cfg(test)]
mod r_tests {
    use super::*;
    use crate::{dos::Dos, raw::dos::RawDos};
    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[test]
    fn rich() -> Result<()> {
        unsafe {
            let data = RUSTUP_IMAGE.as_ptr();
            let size = RUSTUP_IMAGE.len();

            // Safety: slice is trivially valid
            let dos = Dos::from_ptr(data, size)?;
            let stub = dos.dos_stub();

            // Safety: slice is trivially valid
            let rich = Rich::from_ptr(stub.as_ptr(), stub.len())?;
            dbg!(&rich);

            // panic!();
            Ok(())
        }
    }
}
