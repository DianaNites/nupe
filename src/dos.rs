//! Higher level wrappers around the [DOS Header][RawDos],
//! see there for more details.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    raw::dos::RawDos,
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
    stub: DosStubArg<'data>,
}

/// Public Serialization API
impl<'data> Dos<'data> {
    #[inline]
    pub const fn new(dos: DosArg<'data>, stub: DosStubArg<'data>) -> Self {
        Self { dos, stub }
    }
}

/// Public Deserialization API
impl<'data> Dos<'data> {
    /// Get a [`Dos`] from a pointer to the [DOS Header][`RawDos`]
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the DOS magic is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::TooMuchData`] If the size of the DOS stub does not fit in
    ///   [`usize`]
    ///   - Stub size is determined to be everything between the end of
    ///     [header][`RawDos`] and until [`RawDos::pe_offset`]
    /// - [`Error::MissingDOS`] If the DOS header or its stub code is missing
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned
    /// - [`Dos::dos_stub().len()`][`slice::len`] will always be less than
    ///   `size`
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size)
    }
}

/// Public Data API
impl<'data> Dos<'data> {
    /// Reference to the stub code
    ///
    /// The "stub code" is everything after the [DOS header][`RawDos`] but
    /// before the [PE header][RawPe].
    ///
    /// [RawPe]: crate::raw::pe::RawPe
    #[inline]
    pub fn stub(&self) -> &[u8] {
        &self.stub
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
        let dos = RawDos::from_ptr(data, input_size).map_err(|_| Error::MissingDOS)?;

        // Pointer to the DOS stub code, and size of the code before the PE header
        // The Rich header may be hidden somewhere in here
        let stub_size: usize = dos
            .pe_offset
            .saturating_sub(size_of::<RawDos>() as u32)
            .try_into()
            .map_err(|_| Error::TooMuchData)?;

        // Ensure that `input_size` is enough for the DOS stub
        input_size
            .checked_sub(size_of::<RawDos>())
            .ok_or(Error::MissingDOS)?
            .checked_sub(stub_size)
            .ok_or(Error::MissingDOS)?;

        // This operation MUST be done after size is checked, otherwise
        // it is unsound.
        let stub_ptr = data.add(size_of::<RawDos>());

        // Safety:
        // - We ensure `stub_size` can never exceed `input_size`
        let stub = from_raw_parts(stub_ptr, stub_size);

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            stub: VecOrSlice::Slice(stub),
        })
    }
}

impl<'data> fmt::Debug for Dos<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Dos");
        s.field("dos", &self.dos);

        s.field("stub", &debug::DosHelper::new(&self.stub));

        s.finish()
    }
}

pub mod debug {
    //! [`fmt::Debug`] helper types

    use core::fmt;

    use crate::VecOrSlice;

    /// Helper struct for [`fmt::Debug`] to display "DOS code (len N)"
    /// instead of a huge byte array.
    pub struct DosHelper<'data>(usize, &'data VecOrSlice<'data, u8>);

    impl<'data> DosHelper<'data> {
        pub fn new(data: &'data VecOrSlice<'data, u8>) -> Self {
            Self(data.len(), data)
        }
    }

    impl<'data> fmt::Debug for DosHelper<'data> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, r#"DOS code (len {})"#, self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::test_util::RUSTUP_IMAGE;

    #[test]
    fn dos() -> Result<()> {
        unsafe {
            let data = RUSTUP_IMAGE.as_ptr();
            let size = RUSTUP_IMAGE.len();

            let dos = Dos::from_ptr(data, size);
            dbg!(&dos);

            // panic!();
            Ok(())
        }
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::{internal::test_util::kani, raw::dos::DOS_MAGIC};

    /// Test, fuzz, and model [`Dos::from_ptr`]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn dos_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let dos = unsafe { Dos::from_ptr(ptr, len) };

            match dos {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    // This should never fail
                    assert_eq!(d.raw_dos().magic, DOS_MAGIC, "Incorrect `Ok` DOS magic");

                    // Should only be `Ok` if `len` is enough
                    assert!(len >= size_of::<RawDos>(), "Invalid `Ok` len");

                    let stub = d.stub();
                    let expected = (d.pe_offset() as usize).saturating_sub(size_of::<RawDos>());

                    assert_eq!(
                        stub.len(),
                        expected,
                        "mismatch between expected and actual stub size"
                    );
                    assert!((stub.len() < len), "stub was larger than len");
                }

                // Ensure `MissingDOS` error happens
                Err(Error::MissingDOS) => {
                    kani::cover!(true, "MissingDOS");

                    // Should only get this when `len` is too small
                    // or when the dos magic is wrong
                    // or when the stub code is missing
                    let too_small = len < size_of::<RawDos>();
                    let no_magic = !bytes.starts_with(&DOS_MAGIC);

                    // If its not too small, or has no magic
                    if !(too_small || no_magic) {
                        // Then it must have a magic, but a missing stub
                        kani::cover!(true, "MissingDOS - Missing Stub");
                        assert!(!no_magic);

                        let dos = unsafe { RawDos::from_ptr(ptr, len) };
                        let dos = dos.unwrap();

                        let expected = (dos.pe_offset as usize).saturating_sub(size_of::<RawDos>());

                        assert_eq!(dos.magic, DOS_MAGIC);

                        assert!((len - size_of::<RawDos>()) < expected);

                        kani::cover!(true, "Too small for dos stub");
                    }
                }

                // Ensure `TooMuchData` error happens on 16-bit platforms
                #[cfg(target_pointer_width = "4")]
                Err(Error::TooMuchData) => {
                    kani::cover!(true, "TooMuchData (16bit)");
                }

                // Ensure `TooMuchData` error doesn't happen on larger platforms
                #[cfg(not(target_pointer_width = "4"))]
                Err(Error::TooMuchData) => {
                    kani::cover!(false, "TooMuchData (not 16bit)");
                }

                // Ensure no other errors happen
                Err(e) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!("{e:#?}");
                }
            };
        });
    }
}
