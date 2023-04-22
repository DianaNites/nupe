//! Higher level wrappers around the [Rich Header][RawRich],
//! see there for more details.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::{
    dos::Dos,
    error::{Error, Result},
    raw::rich::{calculate_key, RawRich, RawRichArray, RawRichEntry},
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

    /// Rich Header entries
    entries: RichEntryArg<'data>,
    // /// Offset in the
    // entry_offset: u32,
}

/// Public Serialization API
impl<'data> Rich<'data> {
    pub const fn new(header: RichHdrArg<'data>, entries: RichEntryArg<'data>) -> Self {
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
    /// Higher values may lead to confusion with data in the stub.
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
    /// Get the XOR key used for the entries in memory
    #[inline]
    pub const fn key(&self) -> u32 {
        self.header.as_ref().key
    }

    #[inline]
    pub fn entries(&self) -> &[RawRichEntry] {
        &self.entries
    }

    /// Return whether the checksum, calculated over `dos` and `stub`,
    /// matches the one in the rich header.
    pub fn validate_checksum(&self, dos: &Dos, stub: &[u8]) -> bool {
        calculate_key(dos.raw_dos(), stub, self.key()) == self.key()
    }
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
        let array_size = rich_offset.saturating_sub(entry_offset);

        // TODO: Error if array_size not % 8?

        // Safety:
        // - `entry_offset` is guaranteed to be valid via `find_array`
        // - If `array_size` is not a multiple of `RawRichEntry`, it gets rounded down.
        let entries = from_raw_parts(
            stub_ptr.add(entry_offset) as *const RawRichEntry,
            array_size / size_of::<RawRichEntry>(),
        );

        let entries = VecOrSlice::Slice(entries);

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
        s.field(
            "entries",
            &debug::RichHelper::new(&self.entries, self.header.key),
        );

        s.finish()
    }
}

mod debug {
    //! [`fmt::Debug`] helper types
    use core::fmt;

    use crate::{internal::VecOrSlice, raw::rich::RawRichEntry};

    pub struct RichHelper<'a>(&'a VecOrSlice<'a, RawRichEntry>, u32);

    impl<'a> RichHelper<'a> {}

    impl<'a> RichHelper<'a> {
        pub const fn new(data: &'a VecOrSlice<'_, RawRichEntry>, key: u32) -> Self {
            Self(data, key)
        }
    }

    impl<'a> fmt::Debug for RichHelper<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list()
                .entries(self.0.iter().map(|f| f.debug_with_key(self.1)))
                .finish()
        }
    }
}

#[cfg(test)]
mod r_tests {
    use super::*;
    use crate::{dos::Dos, internal::test_util::*, raw::rich::RICH_MAGIC};

    /// Test, fuzz, and model [`Rich::from_ptr`]
    #[test]
    // #[ignore]
    #[cfg_attr(kani, kani::proof)]
    fn rich_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let rich = unsafe { Rich::from_ptr(ptr, len) };

            match rich {
                // Ensure the `Ok(Some)` branch is hit
                Ok(r) => {
                    kani::cover!(true, "Ok");
                    let r = r.header;

                    assert_eq!(r.magic, RICH_MAGIC, "Incorrect `Ok` Rich magic");

                    // Should only be `Ok(Some)` if `len` is enough
                    assert!(len >= size_of::<RawRich>(), "Invalid `Ok` len");
                }

                // Ensure `MissingRich` error happens
                Err(Error::MissingRich) => {
                    kani::cover!(true, "MissingRich");
                }

                // Ensure no other errors happen
                Err(_) => {
                    kani::cover!(false, "Unexpected Error");
                    // unreachable!();
                }
            };
        });
    }

    #[test]
    fn rich() -> Result<()> {
        let data = RUSTUP_IMAGE.as_ptr();
        let size = RUSTUP_IMAGE.len();

        // Safety: slice is trivially valid
        let dos = unsafe { Dos::from_ptr(data, size)? };
        let stub = dos.stub();

        // Safety: slice is trivially valid
        let rich = unsafe { Rich::from_ptr(stub.as_ptr(), stub.len())? };
        dbg!(&rich);

        let key = rich.key();
        let entry = rich.entries()[0];
        let (product_id, build_id) = entry.id_with_key(key);

        assert_eq!(build_id, 30795, "");
        assert_eq!(product_id, 259, "");
        assert_eq!(entry.count ^ key, 9, "");

        assert!(
            rich.validate_checksum(&dos, stub),
            "Rich header checksum mismatch"
        );

        // panic!();
        Ok(())
    }
}
