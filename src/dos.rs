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

#[derive(Clone)]
pub struct Dos<'data> {
    /// DOS header
    dos: DosArg<'data>,

    /// DOS stub code
    dos_stub: DosStubArg<'data>,
}

/// Public Serialization API
impl<'data> Dos<'data> {
    #[inline]
    pub const fn new(dos: DosArg<'data>, dos_stub: DosStubArg<'data>) -> Self {
        Self { dos, dos_stub }
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
    /// - [`Error::TooMuchData`] If the [PE Offset][pe_off] does not fit in
    ///   [`usize`]. This will only happen on 16-bit platforms
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`Dos`]
    /// - [`Error::MissingDOS`] If the DOS header is missing
    /// - See [`RawDos::from_ptr`]
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size)
    }
}

/// Public Data API
impl<'data> Dos<'data> {
    /// Reference to the DOS stub
    ///
    /// The "DOS stub" is everything after the [DOS header][RawDos] but before
    /// the [PE header][RawPe].
    ///
    /// [RawPe]: crate::raw::pe::RawPe
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

    /// Reference to the [Raw DOS header][RawDos]
    #[inline]
    pub const fn raw_dos(&self) -> &RawDos {
        self.dos.as_ref()
    }
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

        // Safety:
        // - We ensure `stub_size` can never exceed `input_size`
        // - `RawRich` ensures `rich_size` can never exceed `stub_size`.
        let stub = from_raw_parts(stub_ptr, stub_size);

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            dos_stub: VecOrSlice::Slice(stub),
        })
    }
}

impl<'data> fmt::Debug for Dos<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Dos");
        s.field("dos", &self.dos);

        s.field("dos_stub", &DosHelper::new(&self.dos_stub));

        s.finish()
    }
}

pub mod debug {
    //! [`fmt::Debug`] helper types
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rich::Rich;

    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[test]
    fn dos() -> Result<()> {
        unsafe {
            let data = RUSTUP_IMAGE.as_ptr();
            let size = RUSTUP_IMAGE[..272].len();
            let size = RUSTUP_IMAGE.len();

            let dos = Dos::from_ptr(data, size);
            dbg!(&dos);

            // panic!();
            Ok(())
        }
    }
}
