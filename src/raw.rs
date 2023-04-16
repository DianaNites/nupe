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
    CoffFlags,
    ExecFlags,
    MachineType,
    SectionFlags,
    Subsystem,
};

pub mod dos;
pub mod rich;

pub(super) use dos::*;

/// PE COFF Magic signature
pub const PE_MAGIC: &[u8] = b"PE\0\0";

/// PE32 Magic signature
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ Magic signature
pub const PE32_64_MAGIC: u16 = 0x20B;

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

/// Microsoft PE Signature and COFF header, assumed to be an executable image.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    /// Constant of value [PE_MAGIC] identifying the PE executable
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

/// Common subset of the PE Executable header,
/// otherwise known as the "optional" header.
///
/// Parts of this structure differ depending on whether the input is
/// 32 or 64 bit.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec {
    /// Magic identifying PE32 vs PE32+
    pub magic: u16,

    /// Linker major version
    pub linker_major: u8,

    /// Linker minor version
    pub linker_minor: u8,

    /// Virtual Size or sum of all code/text sections
    pub code_size: u32,

    /// Virtual Size or sum of all initialized/data sections
    pub init_size: u32,

    /// Virtual Size or sum of all uninitialized/data sections
    pub uninit_size: u32,

    /// Offset to image entry point, relative to image base.
    pub entry_ptr: u32,

    /// Offset to beginning-of-code section, relative to image base.
    pub code_ptr: u32,
}

impl RawExec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        magic: u16,
        linker_major: u8,
        linker_minor: u8,
        code_size: u32,
        init_size: u32,
        uninit_size: u32,
        entry_offset: u32,
        code_base: u32,
    ) -> Self {
        Self {
            magic,
            linker_major,
            linker_minor,
            code_size,
            init_size,
            uninit_size,
            entry_ptr: entry_offset,
            code_ptr: code_base,
        }
    }
}

impl fmt::Debug for RawExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Helper2<const B: u16>;
        impl fmt::Debug for Helper2<PE32_64_MAGIC> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PE32_64_MAGIC")
            }
        }
        impl fmt::Debug for Helper2<PE32_MAGIC> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PE32_MAGIC")
            }
        }

        let mut s = f.debug_struct("RawPeImageStandard");
        if self.magic == PE32_64_MAGIC {
            s.field("magic", &Helper2::<PE32_64_MAGIC>);
        } else if self.magic == PE32_MAGIC {
            s.field("magic", &Helper2::<PE32_MAGIC>);
        } else {
            struct Helper(u16);
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "(Unknown) {}", &self.0)
                }
            }
            s.field("magic", &Helper(self.magic));
        }

        s.field("linker_major", &{ self.linker_major })
            .field("linker_minor", &{ self.linker_minor })
            .field("code_size", &{ self.code_size })
            .field("init_size", &{ self.init_size })
            .field("uninit_size", &{ self.uninit_size })
            .field("entry_ptr", &{ self.entry_ptr })
            .field("code_ptr", &{ self.code_ptr })
            .finish()
    }
}

/// 32-bit Executable header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec32 {
    /// Standard/common subset
    pub standard: RawExec,

    /// Offset to beginning-of-data section, relative to image base.
    pub data_ptr: u32,

    /// Preferred base address of the image when loaded in memory.
    pub image_base: u32,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub mem_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub disk_align: u32,

    /// Required OS major version
    pub os_major: u16,

    /// Required OS minor version
    pub os_minor: u16,

    /// Image major version
    pub image_major: u16,

    /// Image minor version
    pub image_minor: u16,

    /// Subsystem major version
    pub subsystem_major: u16,

    /// Subsystem minor version
    pub subsystem_minor: u16,

    /// Reserved, 0.
    pub _reserved_win32: u32,

    /// Size in bytes of the image as loaded in memory, aligned to
    /// section_align.
    pub image_size: u32,

    /// Combined size of the DOS stub, PE header, and section headers, aligned
    /// to file_align.
    pub headers_size: u32,

    /// A checksum
    pub checksum: u32,

    /// Subsystem required to run image
    pub subsystem: Subsystem,

    /// Flags for windows
    pub dll_attributes: ExecFlags,

    /// Size of the stack to reserve.
    pub stack_reserve: u32,

    /// Size of the stack to commit. Made available one page at a time until
    /// reserve.
    pub stack_commit: u32,

    /// Size of the heap to reserve.
    pub heap_reserve: u32,

    /// Size of the heap to commit. Made available one page at a time until
    /// reserve.
    pub heap_commit: u32,

    /// Reserved, 0.
    pub _reserved_loader_attributes: u32,

    /// Number of data directories following the header.
    pub data_dirs: u32,
}

impl RawExec32 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        standard: RawExec,
        data_ptr: u32,
        image_ptr: u32,
        mem_align: u32,
        disk_align: u32,
        os_major: u16,
        os_minor: u16,
        image_major: u16,
        image_minor: u16,
        subsystem_major: u16,
        subsystem_minor: u16,
        image_size: u32,
        headers_size: u32,
        subsystem: Subsystem,
        dll_characteristics: ExecFlags,
        stack_reserve: u32,
        stack_commit: u32,
        heap_reserve: u32,
        heap_commit: u32,
        data_dirs: u32,
    ) -> Self {
        Self {
            standard,
            data_ptr,
            image_base: image_ptr,
            mem_align,
            disk_align,
            os_major,
            os_minor,
            image_major,
            image_minor,
            subsystem_major,
            subsystem_minor,
            _reserved_win32: 0,
            image_size,
            headers_size,
            checksum: 0,
            subsystem,
            dll_attributes: dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            _reserved_loader_attributes: 0,
            data_dirs,
        }
    }

    /// Get a [`RawExec32`] from `data`. Checks for the magic.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }

        // Ensure that size is enough
        size.checked_sub(size_of::<RawExec32>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawExec32` is POD.
        let opt = unsafe { &*(data as *const RawExec32) };
        if opt.standard.magic != PE32_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        Ok(opt)
    }

    /// Get a [`RawExec32`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { RawExec32::from_ptr(bytes.as_ptr(), bytes.len()) }
    }
}

/// 64-bit Executable header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec64 {
    /// Standard/common subset
    pub standard: RawExec,

    /// Preferred base address of the image when loaded in memory.
    ///
    /// Windows default for DLLs is `0x10000000`
    ///
    /// Windows default for EXEs is `0x00400000`
    pub image_base: u64,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub mem_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub disk_align: u32,

    /// Required OS major version
    pub os_major: u16,

    /// Required OS minor version
    pub os_minor: u16,

    /// Image major version
    pub image_major: u16,

    /// Image minor version
    pub image_minor: u16,

    /// Subsystem major version
    pub subsystem_major: u16,

    /// Subsystem minor version
    pub subsystem_minor: u16,

    /// Reserved, 0.
    pub _reserved_win32: u32,

    /// Size in bytes of the entire image as loaded in memory
    ///
    /// "must" be aligned to [`mem_align`][`RawExec64::mem_align`].
    pub image_size: u32,

    /// Combined size of the DOS stub, PE header, and section headers
    ///
    /// "must" be aligned to [`disk_align`][`RawExec64::disk_align`].
    pub headers_size: u32,

    /// A checksum
    pub checksum: u32,

    /// Subsystem required to run image
    pub subsystem: Subsystem,

    /// Flags for windows
    pub dll_attributes: ExecFlags,

    /// Size of the stack to reserve.
    pub stack_reserve: u64,

    /// Size of the stack to commit. Made available one page at a time until
    /// reserve.
    pub stack_commit: u64,

    /// Size of the heap to reserve.
    pub heap_reserve: u64,

    /// Size of the heap to commit. Made available one page at a time until
    /// reserve.
    pub heap_commit: u64,

    /// Reserved, 0.
    pub _reserved_loader_attributes: u32,

    /// Number of data directories following the header.
    pub data_dirs: u32,
}

impl RawExec64 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        standard: RawExec,
        image_base: u64,
        section_align: u32,
        file_align: u32,
        os_major: u16,
        os_minor: u16,
        image_major: u16,
        image_minor: u16,
        subsystem_major: u16,
        subsystem_minor: u16,
        image_size: u32,
        headers_size: u32,
        subsystem: Subsystem,
        dll_characteristics: ExecFlags,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        data_dirs: u32,
    ) -> Self {
        Self {
            standard,
            image_base,
            mem_align: section_align,
            disk_align: file_align,
            os_major,
            os_minor,
            image_major,
            image_minor,
            subsystem_major,
            subsystem_minor,
            _reserved_win32: 0,
            image_size,
            headers_size,
            checksum: 0,
            subsystem,
            dll_attributes: dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            _reserved_loader_attributes: 0,
            data_dirs,
        }
    }

    /// Get a [`RawExec64`] from `data`. Checks for the magic.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }

        // Ensure that size is enough
        size.checked_sub(size_of::<RawExec64>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawExec64` is POD.
        let opt = unsafe { &*(data as *const RawExec64) };
        if opt.standard.magic != PE32_64_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        Ok(opt)
    }

    /// Get a [`RawExec64`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { RawExec64::from_ptr(bytes.as_ptr(), bytes.len()) }
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

    use dos::RawDos;
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
