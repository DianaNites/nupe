//! Raw Rich Header data structures
//!
//! The Rich Header is an undocumented data structure added to PE files by
//! the Microsoft Visual Studio compiler
//!
//! It appears after the DOS header but before the PE offset,
//! and can be found by searching for the signature [`RICH_MAGIC`] backwards
//! from the PE offset
//!
//! The rich header consists of "encrypted" data of unknown size,
//! followed by [`RICH_MAGIC`], followed by the 32-bit value that should be
//! XORed with the data
//!
//! The start of the data is indicated by

use core::{fmt, mem::size_of, slice::from_raw_parts};

use bstr::{BStr, ByteSlice};

use crate::error::{Error, Result};

/// Undocumented VS-specific rich header signature
pub const RICH_MAGIC: [u8; 4] = *b"Rich";

/// Rich Header array magic signature
pub const ARRAY_MAGIC: [u8; 4] = *b"DanS";

/// Microsoft Rich Header
///
/// The actual rich header *precedes* this structure in memory.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
struct RawRich {
    /// Constant of value [`RICH_MAGIC`] identifying the PE executable
    pub magic: [u8; 4],

    /// XOR key for the data preceding this header
    pub key: u32,
}

/// Public deserialization API
impl RawRich {
    /// Create a new, empty, [`RawRich`].
    ///
    /// Sets the Rich magic and the key to `0`
    pub const fn new() -> Self {
        Self {
            magic: RICH_MAGIC,
            key: 0,
        }
    }

    /// Get a [`RawRich`] from a pointer to the first byte after the
    /// DOS Header [`RawDOS`].
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the rich signature is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawRich`]
    /// - [`Error::InvalidRichMagic`] If the rich magic is incorrect
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Find the Rich Header give a pointer to the first byte after the
    /// DOS Header [`RawDOS`].
    ///
    /// `Size` must be only the length until [`RawDos::pe_offset`]
    ///
    /// # Returns
    ///
    /// - [`Ok(Some)`] If a valid Rich Header was found.
    /// - [`Ok(None)`] If no rich header was found, and no errors occurred.
    /// - [`Err`] See Errors
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawRich`]
    ///
    /// # Safety
    ///
    /// - `data` must be valid for `size` bytes
    /// - `size` must be only until [`RawDos::pe_offset`], not the entire PE
    ///   image.
    pub unsafe fn find_rich<'data>(data: *const u8, size: usize) -> Result<Option<&'data Self>> {
        match Self::find_rich_internal(data, size)? {
            Some(r) => Ok(Some(&*r)),
            None => Ok(None),
        }
    }
}

/// Internal base API
impl RawRich {
    /// See [`RawRich::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawRich::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawRich>())
            .ok_or(Error::NotEnoughData)?;

        // Safety:
        // - We just checked `data` would fit a `RawRich`
        // - Caller guarantees `data` is valid
        let rich = &*(data as *const RawRich);
        if rich.magic != RICH_MAGIC {
            return Err(Error::InvalidRichMagic);
        }

        Ok(data.cast())
    }

    /// See [`RawRich::find_rich`]
    unsafe fn find_rich_internal(data: *const u8, size: usize) -> Result<Option<*const Self>> {
        // Ensure that size is enough
        size.checked_sub(size_of::<RawRich>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Caller
        let b = BStr::new(from_raw_parts(data, size));

        // Safety:
        // - `o` is guaranteed in-bounds by `rfind`
        let o = b.rfind(RICH_MAGIC);
        let o = match o {
            Some(o) => o,
            None => return Ok(None),
        };
        let ptr = data.add(o);

        // Safety:
        // - `ptr` is guaranteed to be valid for `size - o`
        Ok(Some(Self::from_ptr_internal(ptr, size - o)?))
    }
}

impl fmt::Debug for RawRich {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RawRich");
        if self.magic == RICH_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"Rich""#)
                }
            }
            s.field("magic", &Helper);
        } else {
            s.field("magic", &{ self.magic });
        }

        s.field("key", &{ self.key }).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static RUSTUP_IMAGE: &[u8] = include_bytes!("../../tests/data/rustup-init.exe");

    #[test]
    fn rich_header() {
        unsafe {
            let size = 0x1000;
            let y = &RUSTUP_IMAGE[..size];
            let x = RawRich::find_rich(y.as_ptr(), size);
            dbg!(&x);

            panic!();
        }
    }
}
