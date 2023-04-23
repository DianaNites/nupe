//! This "structure" holds the PE signature and the [COFF Header][RawCoff]
use core::{fmt, mem::size_of};

use crate::{
    error::{Error, Result},
    internal::miri_helper,
    raw::coff::RawCoff,
};

/// PE COFF Magic signature
pub const PE_MAGIC: [u8; 4] = *b"PE\0\0";

/// Microsoft PE Signature and COFF header, assumed to be an executable image.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    /// Constant of value [`PE_MAGIC`] identifying the PE executable
    pub sig: [u8; 4],

    /// COFF file header
    pub coff: RawCoff,
}

/// Public deserialization API
impl RawPe {
    /// Create a new PE signature and COFF header pair
    pub fn new(coff: RawCoff) -> Self {
        Self {
            sig: PE_MAGIC,
            coff,
        }
    }

    /// Get a [`RawPe`] from a pointer to a PE Signature and COFF header
    ///
    /// This function validates that `size` is enough to contain this PE
    /// header, and that the PE signature is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawPe`]
    /// - [`Error::InvalidPeMagic`] If the PE magic value is incorrect
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
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Get a mutable [`RawPe`] from a pointer to the PE signature
    ///
    /// See [`RawPe::from_ptr`] for error information and other details.
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads and writes of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned.
    pub unsafe fn from_ptr_mut<'data>(data: *mut u8, size: usize) -> Result<&'data mut Self> {
        Ok(&mut *(Self::from_ptr_internal(data.cast_const(), size)?).cast_mut())
    }
}

/// Internal base API
impl RawPe {
    /// # Safety
    /// See [`RawPe::from_ptr`]
    pub unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawPe::from_ptr");

        miri_helper!(data, size);

        // Ensure that size is enough
        size.checked_sub(size_of::<RawPe>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawPe` is POD.
        let pe = unsafe { &*(data as *const RawPe) };
        if pe.sig != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }

        Ok(data.cast())
    }
}

impl fmt::Debug for RawPe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RawPe");
        if self.sig == PE_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"PE\0\0""#)
                }
            }
            s.field("sig", &Helper);
        } else {
            s.field("sig", &self.sig);
        }

        s.field("coff", &self.coff).finish()
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::internal::test_util::kani;

    /// Test, fuzz, and model [`RawPe::from_ptr`]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_pe_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawPe::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    assert_eq!(d.sig, PE_MAGIC, "Incorrect `Ok` PE magic");

                    // Should only be `Ok` if `len` is this
                    assert!(len >= size_of::<RawPe>(), "Invalid `Ok` len");
                }

                // Ensure `InvalidPeMagic` error happens
                Err(Error::InvalidPeMagic) => {
                    kani::cover!(true, "InvalidPeMagic");

                    // Should have gotten NotEnoughData if there wasn't enough
                    assert!(len >= size_of::<RawPe>(), "Invalid InvalidPeMagic len");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawPe>());
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
