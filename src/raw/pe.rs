//! This "structure" holds the PE signature and the [COFF Header][RawCoff]
use core::{fmt, mem::size_of};

use crate::{
    error::{Error, Result},
    raw::coff::RawCoff,
};

/// PE COFF Magic signature
pub const PE_MAGIC: &[u8] = b"PE\0\0";

/// Microsoft PE Signature and COFF header, assumed to be an executable image.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    /// Constant of value [`PE_MAGIC`] identifying the PE executable
    pub sig: [u8; 4],

    /// COFF file header
    pub coff: RawCoff,
}

impl RawPe {
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
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawPe::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawPe>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawPe` is POD.
        let pe = unsafe { &*(data as *const RawPe) };
        if pe.sig != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }

        Ok(pe)
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
