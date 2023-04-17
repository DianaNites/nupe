//! Higher level wrappers around the [DOS Header][RawDos],
//! see there for more details.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    internal::debug::DosHelper,
    raw::{
        dos::RawDos,
        rich::{RawRich, RawRichArray, RawRichEntry},
    },
    OwnedOrRef,
    VecOrSlice,
};

pub type DosArg<'data> = OwnedOrRef<'data, RawDos>;

pub type DosStubArg<'data> = VecOrSlice<'data, u8>;

// pub type RichHdrArg<'data> = VecOrSlice<'data, u8>;
pub type RichHdrArg<'data> = OwnedOrRef<'data, RawRich>;

pub type RichEntryArg<'data> = VecOrSlice<'data, RawRichEntry>;

#[derive(Clone)]
pub struct Dos<'data> {
    /// DOS header
    dos: DosArg<'data>,

    /// DOS stub code
    dos_stub: DosStubArg<'data>,

    /// Optional DOS Rich Header
    rich_header: Option<RichHdrArg<'data>>,

    /// Optional DOS Rich Header entries
    rich_entries: Option<RichEntryArg<'data>>,
}

/// Public Serialization API
impl<'data> Dos<'data> {
    #[inline]
    pub const fn new(
        dos: DosArg<'data>,
        dos_stub: DosStubArg<'data>,
        rich_header: Option<RichHdrArg<'data>>,
        rich_entries: Option<RichEntryArg<'data>>,
    ) -> Self {
        Self {
            dos,
            dos_stub,
            rich_header,
            rich_entries,
        }
    }
}

/// Public Deserialization API
impl<'data> Dos<'data> {
    /// Get a [`Dos`] from a pointer to a DOS Header
    ///
    /// `size` *should* be *at least* [`RawDos::pe_offset`] to be able to
    /// fully parse DOS structures.
    ///
    /// Higher values will lead to slower, but still memory safe, code.
    ///
    /// # Errors
    ///
    /// - [`Error::TooMuchData`] If
    /// - [`Error::MissingDOS`] If the DOS header is missing
    /// - See [`RawDos::from_ptr`]
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size)
    }
}

/// Public Data API
impl<'data> Dos<'data> {
    /// Reference to the DOS stub code
    ///
    /// The DOS stub code is determined to be everything between
    /// the end of the DOS header, and the start of either the
    /// [Rich Header][rich] or the PE header, if the former does not exist.
    ///
    /// [rich]: RawRich
    #[inline]
    pub fn dos_stub(&self) -> &[u8] {
        &self.dos_stub
    }

    /// Absolute offset in the file to the PE header
    ///
    /// "must" be aligned to 8 bytes
    ///
    /// Note that this value is untrusted input, and can be anything.
    /// This should be handled appropriately when using it to find the PE header
    #[inline]
    pub const fn pe_offset(&self) -> u32 {
        self.dos.as_ref().pe_offset
    }

    /// Reference to the DOS Rich header, if it exists.
    ///
    /// The Rich header is an undocumented Microsoft linker specific
    /// data structure located somewhere before the PE header.
    #[cfg(no)]
    #[inline]
    pub fn rich_header(&self) -> Option<&RawRich> {
        self.rich_header.as_ref().map(|f| f.as_ref())
    }

    // pub fn
}

/// Internal API
impl<'data> Dos<'data> {
    /// See [`Dos::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, input_size: usize) -> Result<Self> {
        let dos = RawDos::from_ptr(data, input_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingDOS,
            _ => e,
        })?;

        // Pointer to the DOS stub code, and size of the code before the PE header
        // The Rich header may be hidden somewhere in here
        let stub_ptr = data.add(size_of::<RawDos>());
        let stub_size: usize = dos
            .pe_offset
            .saturating_sub(size_of::<RawDos>() as u32)
            .try_into()
            .map_err(|_| Error::TooMuchData)?;

        // Ensure that `input_size` is enough for the DOS stub
        input_size
            .checked_sub(stub_size)
            .ok_or(Error::NotEnoughData)?;

        let mut rich_ptr = stub_ptr;
        let mut rich_size = 0;
        let mut rich_entries = None;

        // Rich header is optional
        if let Ok(Some((rich, rich_offset))) = RawRich::find_rich(stub_ptr, stub_size) {
            // Safety: `find_rich`
            rich_ptr = stub_ptr.add(rich_offset);
            rich_size = stub_size - rich_offset;

            // Invalid Rich Header Array is not a `from_ptr` error/problem.
            if let Ok(Some((array, array_offset))) =
                RawRichArray::find_array(stub_ptr, stub_size, rich.key)
            {
                let entry_offset = array_offset + size_of::<RawRichArray>();
                let array_size = rich_offset - entry_offset;

                // Safety:
                // - `entry_offset` is guaranteed to be valid via `find_array
                // - If `array_size` is not a multiple of 8, it gets rounded down.
                let rich = from_raw_parts(
                    stub_ptr.add(entry_offset) as *const RawRichEntry,
                    array_size / size_of::<RawRichEntry>(),
                );

                rich_size = stub_size - array_offset;
                rich_entries = Some(VecOrSlice::Slice(rich));
            }
        };

        // Safety:
        // - We ensure `stub_size` can never exceed `input_size`
        // - `RawRich` ensures `rich_size` can never exceed `stub_size`.
        let stub = from_raw_parts(stub_ptr, stub_size - rich_size);
        // let rich = from_raw_parts(rich_ptr, rich_size);
        let rich_header = if rich_size >= size_of::<RawRich>() {
            Some(OwnedOrRef::Ref(&*(rich_ptr as *const RawRich)))
        } else {
            None
        };

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            dos_stub: VecOrSlice::Slice(stub),
            // rich_header: Some(VecOrSlice::Slice(rich)),
            rich_header,
            rich_entries,
        })
    }
}

impl<'data> fmt::Debug for Dos<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Dos");
        s.field("dos", &self.dos);

        s.field("dos_stub", &DosHelper::new(&self.dos_stub));
        // s.field(
        //     "rich_header",
        //     &debug::DosRichHelper::new(self.rich_header.as_ref()),
        // );
        s.field("rich_header", &self.rich_header);

        // FIXME: hides Vec vs Slice
        s.field(
            "rich_entries",
            &debug::DosRichHelper2::new(self.rich_entries.as_ref()),
        );
        s.finish()
    }
}

pub mod debug {
    //! [`fmt::Debug`] helper types
    use core::fmt;

    use crate::{internal::VecOrSlice, raw::rich::RawRichEntry};

    pub struct DosRichHelper(usize);

    impl DosRichHelper {
        pub fn new(data: Option<&VecOrSlice<'_, u8>>) -> Self {
            Self(data.map(|d| d.len()).unwrap_or(0))
        }
    }

    impl fmt::Debug for DosRichHelper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, r#"Rich Header (len {})"#, self.0)
        }
    }

    pub struct DosRichHelper2(usize);

    impl DosRichHelper2 {
        pub fn new(data: Option<&VecOrSlice<'_, RawRichEntry>>) -> Self {
            Self(data.map(|d| d.len()).unwrap_or(0))
        }
    }

    impl fmt::Debug for DosRichHelper2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, r#"Rich Array (entries {})"#, self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[test]
    fn dos() -> Result<()> {
        unsafe {
            let data = RUSTUP_IMAGE.as_ptr();
            let size = RUSTUP_IMAGE[..272].len();
            let size = RUSTUP_IMAGE.len();

            let dos = Dos::from_ptr(data, size);
            dbg!(&dos);

            panic!();
            Ok(())
        }
    }
}
