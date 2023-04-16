//! The Executable header
//!
//! Also known as the "Optional" header in [Microsoft PE documentation][pe_ref]
//!
//! The executable header should only exist for PE executables, and
//! follows the [COFF header].
//!
//! The size of this structure differs depending on whether
//! the executable is 32 or 64 bit.
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

/// PE32 Magic signature
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ Magic signature
pub const PE32_64_MAGIC: u16 = 0x20B;

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
