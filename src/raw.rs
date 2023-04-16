//! Raw PE data structures
//!
//! These are all the raw, C compatible and packed,
//! representations of various PE and COFF data structures.
//!
//! PE Files are laid out as so
//!
//! - [RawDos]
//! - DOS Stub, DOS executable code that conventionally says the program can't
//!   be run in DOS.
//! - Rich Header
//!   - Optional and undocumented structure specific to the Microsoft Visual
//!     Studio compiler
//!   - It can only be found by searching backwards for the signature `Rich`
//! - PE signature and [RawCoff] Header, together in [RawPe]
//! - Executable image Header [RawExec]
//!   - This is required for executable images, but can still exist on objects.
//! - [RawExec32] or [RawExec64]
//!   - Which one is used depends on whether the file is 32 or 64 bit
//!     [`RawExec::magic`]
//! - Variable number of [RawDataDirectory]
//! - Variable number of [RawSectionHeader]
//! - For executables, these tables, identified by [`RawDataDirectory`] entries,
//!   must be placed at the end of the file in this order if they exist.
//!   - Certificate Table
//!   - Debug Table
//!
//! # References
//!
//! The primary documentation reference for this was the [PE Format][pe_ref]
//! from Microsoft
//!
//! [pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
use core::{fmt, mem::size_of};

use crate::{
    error::{Error, Result},
    SectionFlags,
};

pub mod coff;
pub mod dos;
pub mod exec;
pub mod rich;

pub use coff::*;
pub use dos::*;
pub use exec::*;

/// PE COFF Magic signature
pub const PE_MAGIC: &[u8] = b"PE\0\0";

/// Microsoft PE Signature and COFF header, assumed to be an executable image.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    /// Constant of value [PE_MAGIC] identifying the PE executable
    pub sig: [u8; 4],

    /// COFF file header
    pub coff: coff::RawCoff,
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

/// A "data directory", an (address, size) pair used by the windows loader
///
/// There are 16 standard entries, though there can be any number, including
/// less.
///
/// Note that windows is naughty here, and some data directories don't
/// store the same type of data as all the others.
/// The certificate directory, specifically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
pub struct RawDataDirectory {
    /// Virtual address to the data
    ///
    /// Sometimes this is not actually a virtual address.
    pub address: u32,

    /// Size of the data in bytes
    pub size: u32,
}

impl RawDataDirectory {
    pub const fn new(address: u32, size: u32) -> Self {
        Self { address, size }
    }
}

/// Section Header
///
/// The section table starts after the COFF and exec headers, and is
/// [`size_of::<RawSectionHeader>`] * [`RawCoff::sections`] bytes.
///
/// Sections are conventionally numbered starting from 1
///
/// In an image file, the virtual addresses assigned by the linker "must"
/// be assigned in ascending and adjacent order, and they "must" be a multiple
/// of [`RawExec{32|64}::mem_align`][`RawExec64::mem_align`].
///
/// An ideal file upholds this. An in the wild file may not, and yet still run.
/// It must thus also be parsed.
///
/// [`RawCoff::sections`]: coff::RawCoff::sections
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct RawSectionHeader {
    /// Name of the section, as a null-padded UTF-8 string
    ///
    /// If the name is exactly 8 characters, there is no nul byte.
    ///
    /// For exec/image files, section names are limited to 8 bytes.
    ///
    /// For object files, names longer than 8 characters cause this field
    /// to contain a reference to the string table,
    /// represented by a slash `/` and an ASCII digit offset into the string
    /// table.
    ///
    /// Names are truncated in object files upon being emitted to exec files
    pub name: [u8; 8],

    /// Size of the section in memory
    ///
    /// If this is greater than `disk_size`, the section is zero-padded in
    /// memory.
    ///
    /// This is only valid for exec files and should be set to zero for object
    /// files
    pub mem_size: u32,

    /// For exec files, offset of the section in memory, relative to
    /// [`RawExec{32|64}::image_base`][`RawExec64::image_base`].
    ///
    /// For object files, this should be set to zero.
    /// If not, it is an arbitrary value subtracted from all offsets during
    /// relocations.
    pub mem_ptr: u32,

    /// Size of the initialized data of the section on disk
    ///
    /// For exec files, this "must" be a multiple of
    /// [`RawExec{32|64}::disk_align`][`RawExec64::disk_align`].
    ///
    /// If less than [`mem_size`][`RawSectionHeader::mem_size`],
    /// the section is zero-padded on disk.
    ///
    /// If a section contains only uninitialized data, this should be zero.
    ///
    /// Because this is rounded to `disk_align` but `mem_size` is not,
    /// this may be larger than `mem_size`.
    pub disk_size: u32,

    /// Offset to the section on disk
    ///
    /// For exec files this "must" be a multiple of
    /// [`RawExec{32|64}::disk_align`][`RawExec64::disk_align`].
    ///
    /// For object files, this should be aligned to 4 bytes.
    ///
    /// When a section contains only uninitialized data, this should be zero.
    pub disk_offset: u32,

    /// Offset of the relocation entries for the section on disk
    ///
    /// Should be set to zero for exec files or if there are no relocations
    pub reloc_offset: u32,

    /// Offset of the line numbers for the section on disk
    ///
    /// Should be set to zero if there are no line numbers.
    ///
    /// Should be set to zero in exec files
    pub line_offset: u32,

    /// Number of relocation entries at `reloc_offset`
    ///
    /// This should be zero for exec files.
    pub reloc_len: u16,

    /// Number of lines at `line_offset`
    ///
    /// This should be zero for exec files.
    pub lines_len: u16,

    /// Section flags
    pub attributes: SectionFlags,
}

impl RawSectionHeader {
    /// Name of the section as a UTF-8 string, or an error if it was invalid.
    pub fn name(&self) -> Result<&str> {
        core::str::from_utf8(&self.name)
            .map(|s| s.trim_end_matches('\0'))
            .map_err(|_| Error::InvalidUtf8)
    }

    /// A zeroed [`RawSectionHeader`]
    pub fn zeroed() -> Self {
        RawSectionHeader {
            name: Default::default(),
            mem_size: Default::default(),
            mem_ptr: Default::default(),
            disk_size: Default::default(),
            disk_offset: Default::default(),
            reloc_offset: Default::default(),
            line_offset: Default::default(),
            reloc_len: Default::default(),
            lines_len: Default::default(),
            attributes: SectionFlags::empty(),
        }
    }
}

impl fmt::Debug for RawSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("RawSectionHeader");
        if let Ok(s) = self.name() {
            f.field("name(str)", &s);
        } else {
            f.field("name(bytes)", &{ self.name });
        }
        f.field("virtual_size", &{ self.mem_size })
            .field("virtual_address", &{ self.mem_ptr })
            .field("raw_size", &{ self.disk_size })
            .field("raw_ptr", &{ self.disk_offset })
            .field("reloc_ptr", &{ self.reloc_offset })
            .field("line_ptr", &{ self.line_offset })
            .field("num_reloc", &{ self.reloc_len })
            .field("num_lines", &{ self.lines_len })
            .field("characteristics", &{ self.attributes })
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::align_of;

    use coff::RawCoff;
    use dos::RawDos;
    use exec::{RawExec, RawExec64};
    use static_assertions::{assert_eq_size, const_assert_eq};

    use super::*;

    assert_eq_size!(RawCoff, [u8; 20]);
    assert_eq_size!(RawDos, [u8; 64]);
    assert_eq_size!(RawExec, [u8; 24]);
    assert_eq_size!(RawExec64, [u8; 112]);
    assert_eq_size!(RawDataDirectory, [u8; 8]);
    assert_eq_size!(RawSectionHeader, [u8; 40]);
    const_assert_eq!(align_of::<RawCoff>(), 1);
}
