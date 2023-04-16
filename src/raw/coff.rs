//! The COFF header
//!
//! The Microsoft COFF header is shared between object files and executables
//!
//! In the context of PE executables, most COFF features are unused.
use core::mem::size_of;

use crate::{
    error::{Error, Result},
    CoffFlags,
    MachineType,
};

/// Raw COFF header
///
/// This is common to both executable PE images and object files.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawCoff {
    /// Target machine type
    pub machine: MachineType,

    /// Number of sections
    pub sections: u16,

    /// Timestamp
    pub time: u32,

    /// File offset to COFF symbol table
    ///
    /// According to MS, should be zero for images, as COFF debugging info
    /// is deprecated.
    pub sym_offset: u32,

    /// Number of entries in COFF symbol table
    ///
    /// According to MS, should be zero for images, as COFF debugging info
    /// is deprecated.
    pub sym_len: u32,

    /// Claimed size in bytes of the exec Header.
    ///
    /// Required for executable PE images
    ///
    /// Should be zero for object files, but is not required to be.
    ///
    /// Otherwise known as the "optional" header
    pub exec_header_size: u16,

    /// Object attributes
    pub file_attributes: CoffFlags,
}

/// Public deserialization API
impl RawCoff {
    /// Create a new COFF header
    ///
    /// The deprecated COFF debugging information is set to zero
    pub fn new(
        machine: MachineType,
        sections: u16,
        time: u32,
        optional_size: u16,
        attributes: CoffFlags,
    ) -> Self {
        Self {
            machine,
            sections,
            time,
            sym_offset: 0,
            sym_len: 0,
            exec_header_size: optional_size,
            file_attributes: attributes,
        }
    }

    /// Get a [`RawCoff`] from a pointer to a COFF header
    ///
    /// This function validates that `size` is enough to contain this header
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawCoff`]
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Get a mutable [`RawCoff`] from a pointer to a COFF header
    ///
    /// See [`RawCoff::from_ptr`] for error information and other details.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You MUST ensure NO OTHER references exist when you call this.
    /// - No instance of `&Self` can exist at the moment of this call.
    /// - You must ensure the returned reference does not outlive `data`
    pub unsafe fn from_ptr_mut<'data>(data: *mut u8, size: usize) -> Result<&'data mut Self> {
        Ok(&mut *(Self::from_ptr_internal(data.cast_const(), size)?).cast_mut())
    }
}

/// Internal base API
impl RawCoff {
    /// See [`RawCoff::from_ptr`]
    fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawCoff::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawCoff>())
            .ok_or(Error::NotEnoughData)?;

        Ok(data.cast())
    }
}
