//! The COFF header
//!
//! The Microsoft COFF header is shared between object files and executables
//!
//! In the context of PE executables, most COFF features are unused.
use core::{fmt, mem::size_of};

use bitflags::bitflags;

use crate::error::{Error, Result};

/// Machine type, or target architecture, of the PE file.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachineType(u16);

impl MachineType {
    /// Integer value for this machine type
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl MachineType {
    /// Unknown/Any/All machine type
    pub const UNKNOWN: Self = Self(0);

    /// x64
    pub const AMD64: Self = Self(0x8664);

    /// x86
    pub const I386: Self = Self(0x14C);

    /// EFI Byte Code
    pub const EBC: Self = Self(0xEBC);

    // TODO: Fill out rest of machine types
}

impl fmt::Debug for MachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "MachineType::UNKNOWN"),
            Self::AMD64 => write!(f, "MachineType::AMD64"),
            Self::I386 => write!(f, "MachineType::I386"),
            Self::EBC => write!(f, "MachineType::EBC"),
            _ => f.debug_tuple("MachineType").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for MachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "UNKNOWN"),
            Self::AMD64 => write!(f, "AMD64"),
            Self::I386 => write!(f, "I386"),
            Self::EBC => write!(f, "EBC"),
            _ => f.debug_tuple("MachineType").field(&self.0).finish(),
        }
    }
}

bitflags! {
    /// COFF Header flags
    ///
    /// Otherwise known as "characteristics"
    ///
    /// See [`RawCoff`][`crate::raw::RawCoff`]
    ///
    /// See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics>
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    #[doc(alias = "characteristics")]
    pub struct CoffFlags: u16 {
        /// Indicates file has no base relocations and must be loaded at
        /// its preferred address
        const RELOC_STRIPPED = 0x1;

        /// Indicates this is a valid executable image
        const IMAGE = 0x2;

        /// Deprecated and should not be set
        const COFF_LINE_STRIPPED = 0x4;

        /// Deprecated and should not be set
        const COFF_SYM_STRIPPED = 0x8;

        /// Deprecated and should not be set
        const AGGRESSIVE_WS_TRIM = 0x10;

        /// Indicates application can handle addresses larger than 2 GiB
        const LARGE_ADDRESS_AWARE = 0x20;

        /// Reserved
        const RESERVED = 0x40;

        /// Deprecated and should not be set
        const BYTES_REVERSED_LO = 0x80;

        /// Machine is based on a 32-bit-word architecture.
        const BIT32 = 0x100;

        /// Indicates debug information was stripped
        const DEBUG_STRIPPED = 0x200;

        /// If the image is on removable media, fully load and copy it to swap
        ///
        /// ??? why microsoft?
        const REMOVABLE_SWAP = 0x400;

        /// If the image is on the network media, fully load and copy it to swap
        ///
        /// ??? why microsoft?
        const NET_SWAP = 0x800;

        /// The image is a system file
        const SYSTEM = 0x1000;

        /// The image is a DLL
        const DLL = 0x2000;

        /// Indicates image should only be run on a uniprocessor machine
        ///
        /// ??? why microsoft?
        const UP_SYSTEM = 0x4000;

        /// Deprecated and should not be set
        const BYTES_REVERSED_HI = 0x8000;
    }
}

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
