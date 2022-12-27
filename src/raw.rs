//! Raw PE structures
//!
//! PE Files are laid out as so
//!
//! - [RawDos]
//! - DOS Stub
//! - Rich Header?
//! - PE Header [RawPe]
//!     - COFF Header [RawCoff]
//! - Optional Header [RawPeOptStandard]
//! - [RawPe32] or [RawPe32x64]
//! - Variable number of [RawDataDirectory]
//! - Variable number of [RawSectionHeader]
use core::mem::{self, size_of};

use crate::{
    error::{Error, Result},
    CoffAttributes,
    DllCharacteristics,
    MachineType,
    SectionFlags,
    Subsystem,
};

/// DOS Magic signature
pub const DOS_MAGIC: [u8; 2] = *b"MZ";

/// Size of a DOS page
pub const DOS_PAGE: usize = 512;

/// Size of a DOS paragraph
pub const DOS_PARAGRAPH: usize = 16;

/// File cannot possibly be valid if not at least this size.
pub const MIN_SIZE: usize = size_of::<RawCoff>() + size_of::<RawDos>();

/// PE Magic signature
pub const PE_MAGIC: &[u8] = b"PE\0\0";

/// PE32 Magic signature
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ Magic signature
pub const PE32_64_MAGIC: u16 = 0x20B;

/// Raw DOS header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawDos {
    /// [DOS_MAGIC]
    pub magic: [u8; 2],

    /// Number of bytes in the last [DOS_PAGE]
    pub last_bytes: u16,

    /// Number of [DOS_PAGE]s
    pub pages: u16,

    /// Number of entries in the relocations table
    pub relocations: u16,

    /// Number of [DOS_PARAGRAPH] taken up by the header
    pub header_size: u16,

    /// Min number of [DOS_PARAGRAPH]s required by the program
    pub min_alloc: u16,

    /// Max number of [DOS_PARAGRAPH]s requested by the program
    pub max_alloc: u16,

    /// Relocation segment
    pub initial_ss: u16,

    /// Initial stack pointer
    pub initial_sp: u16,

    /// Checksum
    pub checksum: u16,

    /// Initial IP
    pub initial_ip: u16,

    /// Relocatable CS segment address
    pub initial_cs: u16,

    /// Absolute offset to relocation table
    pub relocation_offset: u16,

    /// Overlay management
    pub overlay_num: u16,

    /// Reserved in PE
    pub _reserved: [u16; 4],

    /// Useless
    pub oem_id: u16,

    /// Useless
    pub oem_info: u16,

    /// Reserved in PE
    pub _reserved2: [u8; 20],

    /// Absolute offset to the PE header
    pub pe_offset: u32,
}

impl RawDos {
    /// Create a new, empty, [`RawDos`].
    ///
    /// Sets the magic and pe_offset only.
    pub fn new(pe_offset: u32) -> Self {
        Self {
            magic: DOS_MAGIC,
            pe_offset,
            last_bytes: Default::default(),
            pages: Default::default(),
            relocations: Default::default(),
            header_size: Default::default(),
            min_alloc: Default::default(),
            max_alloc: Default::default(),
            initial_ss: Default::default(),
            initial_sp: Default::default(),
            checksum: Default::default(),
            initial_ip: Default::default(),
            initial_cs: Default::default(),
            relocation_offset: Default::default(),
            overlay_num: Default::default(),
            _reserved: Default::default(),
            oem_id: Default::default(),
            oem_info: Default::default(),
            _reserved2: Default::default(),
        }
    }

    /// Get a [`RawDos`] from `data`. Checks for the DOS magic.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr<'data>(
        data: *const u8,
        size: usize,
    ) -> Result<(&'data Self, (*const u8, usize))> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        if size < size_of::<RawDos>() {
            return Err(Error::NotEnoughData);
        }
        let dos = unsafe { &*(data as *const RawDos) };
        if dos.magic != DOS_MAGIC {
            return Err(Error::InvalidDosMagic);
        }
        let pe_ptr = data.wrapping_add(dos.pe_offset as usize);
        let pe_size = size - dos.pe_offset as usize;
        Ok((dos, (pe_ptr, pe_size)))
    }

    /// Get a [`RawDos`] from `bytes`. Checks for the DOS magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { Ok(RawDos::from_ptr(bytes.as_ptr(), bytes.len())?.0) }
    }

    /// Given the same byte slice given to [`RawDos::from_bytes`],
    /// return the slice of just the PE portion.
    pub fn pe_bytes<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8]> {
        bytes
            .get(self.pe_offset as usize..)
            .ok_or(Error::NotEnoughData)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawCoff {
    pub machine: MachineType,
    pub sections: u16,
    pub time: u32,
    pub sym_offset: u32,
    pub num_sym: u32,
    pub optional_size: u16,
    pub attributes: CoffAttributes,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    pub sig: [u8; 4],
    pub coff: RawCoff,
}

impl RawPe {
    /// Get a [`RawPe`] from `data`. Checks for the PE magic.
    ///
    /// Returns [`RawPe`], opt data, and section data
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    #[allow(clippy::type_complexity)]
    pub unsafe fn from_ptr<'data>(
        data: *const u8,
        size: usize,
    ) -> Result<(&'data Self, (*const u8, usize), (*const u8, usize))> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        if size < size_of::<RawPe>() {
            return Err(Error::NotEnoughData);
        }
        let pe = unsafe { &*(data as *const RawPe) };
        if pe.sig != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        let opt_size = pe.coff.optional_size as usize;
        let opt_ptr = data.wrapping_add(size_of::<RawPe>());

        let section_size = size_of::<RawSectionHeader>() * pe.coff.sections as usize;
        let section_ptr = data.wrapping_add(size_of::<RawPe>() + opt_size);
        Ok((pe, (opt_ptr, opt_size), (section_ptr, section_size)))
    }

    /// Get a [`RawPe`] from `bytes`. Checks for the PE magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { Ok(RawPe::from_ptr(bytes.as_ptr(), bytes.len())?.0) }
    }

    /// Given the same byte slice given to [`RawPe::from_bytes`],
    /// return the slice of just the Optional Header portion.
    pub fn opt_bytes<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8]> {
        let opt_size = self.coff.optional_size as usize;
        bytes
            .get(size_of::<RawPe>()..)
            .ok_or(Error::NotEnoughData)?
            .get(..opt_size)
            .ok_or(Error::NotEnoughData)
    }

    /// Given the same byte slice given to [`RawPe::from_bytes`],
    /// return the slice of just the Sections portion.
    pub fn section_bytes<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8]> {
        let sections_size = size_of::<RawSectionHeader>() * self.coff.sections as usize;
        let opt_size = self.coff.optional_size as usize;
        bytes
            .get(opt_size + size_of::<RawPe>()..)
            .ok_or(Error::NotEnoughData)?
            .get(..sections_size)
            .ok_or(Error::NotEnoughData)
    }

    /// Return a slice of section headers
    pub fn section_slice<'a>(&self, bytes: &'a [u8]) -> Result<&'a [RawSectionHeader]> {
        let data = self.section_bytes(bytes)?;
        Ok(unsafe {
            core::slice::from_raw_parts(
                data.as_ptr() as *const RawSectionHeader,
                self.coff.sections.into(),
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPeOptStandard {
    pub magic: u16,
    pub linker_major: u8,
    pub linker_minor: u8,
    pub code_size: u32,
    pub init_size: u32,
    pub uninit_size: u32,
    pub entry_offset: u32,
    pub code_base: u32,
}

impl RawPeOptStandard {
    /// Get a [`RawPeOptStandard`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        let opt = unsafe {
            &*(bytes
                .get(..size_of::<RawPeOptStandard>())
                .ok_or(Error::NotEnoughData)?
                .as_ptr() as *const RawPeOptStandard)
        };
        if !(opt.magic == PE32_64_MAGIC || opt.magic != PE32_MAGIC) {
            return Err(Error::InvalidPeMagic);
        }
        Ok(opt)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32 {
    pub standard: RawPeOptStandard,
    pub data_base: u32,
    pub image_base: u32,
    pub section_align: u32,
    pub file_align: u32,
    pub os_major: u16,
    pub os_minor: u16,
    pub image_major: u16,
    pub image_minor: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,
    pub _reserved_win32: u32,
    pub image_size: u32,
    pub headers_size: u32,
    pub checksum: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: DllCharacteristics,
    pub stack_reserve: u32,
    pub stack_commit: u32,
    pub heap_reserve: u32,
    pub heap_commit: u32,
    pub _reserved_loader_flags: u32,
    pub data_dirs: u32,
}

impl RawPe32 {
    /// Get a [`RawPe32`] from `data`. Checks for the magic.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        if size < size_of::<RawPe32>() {
            return Err(Error::NotEnoughData);
        }
        let opt = unsafe { &*(data as *const RawPe32) };
        if opt.standard.magic != PE32_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        Ok(opt)
    }

    /// Get a [`RawPe32`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { RawPe32::from_ptr(bytes.as_ptr(), bytes.len()) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32x64 {
    pub standard: RawPeOptStandard,
    pub image_base: u64,
    pub section_align: u32,
    pub file_align: u32,
    pub os_major: u16,
    pub os_minor: u16,
    pub image_major: u16,
    pub image_minor: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,
    pub _reserved_win32: u32,
    pub image_size: u32,
    pub headers_size: u32,
    pub checksum: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: DllCharacteristics,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub _reserved_loader_flags: u32,
    pub data_dirs: u32,
}

impl RawPe32x64 {
    /// Get a [`RawPe32x64`] from `data`. Checks for the magic.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        if size < size_of::<RawPe32x64>() {
            return Err(Error::NotEnoughData);
        }
        let opt = unsafe { &*(data as *const RawPe32x64) };
        if opt.standard.magic != PE32_64_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        Ok(opt)
    }

    /// Get a [`RawPe32x64`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { RawPe32x64::from_ptr(bytes.as_ptr(), bytes.len()) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawDataDirectory {
    pub address: u32,
    pub size: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub reloc_ptr: u32,
    pub line_ptr: u32,
    pub num_reloc: u16,
    pub num_lines: u16,
    pub characteristics: SectionFlags,
}

impl RawSectionHeader {
    pub fn name(&self) -> Result<&str> {
        core::str::from_utf8(&self.name)
            .map(|s| s.trim_end_matches('\0'))
            .map_err(|_| Error::InvalidData)
    }
}

impl core::fmt::Debug for RawSectionHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut f = f.debug_struct("RawSectionHeader");
        if let Ok(s) = self.name() {
            f.field("name(str)", &s);
        } else {
            f.field("name(bytes)", &{ self.name });
        }
        f.field("virtual_size", &{ self.virtual_size })
            .field("virtual_address", &{ self.virtual_address })
            .field("raw_size", &{ self.raw_size })
            .field("raw_ptr", &{ self.raw_ptr })
            .field("reloc_ptr", &{ self.reloc_ptr })
            .field("line_ptr", &{ self.line_ptr })
            .field("num_reloc", &{ self.num_reloc })
            .field("num_lines", &{ self.num_lines })
            .field("characteristics", &{ self.characteristics })
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::align_of;

    use static_assertions::{assert_eq_align, assert_eq_size, const_assert_eq};

    use super::*;

    assert_eq_size!(RawCoff, [u8; 20]);
    assert_eq_size!(RawDos, [u8; 64]);
    assert_eq_size!(RawPeOptStandard, [u8; 24]);
    assert_eq_size!(RawPe32x64, [u8; 112]);
    assert_eq_size!(RawDataDirectory, [u8; 8]);
    assert_eq_size!(RawSectionHeader, [u8; 40]);
    const_assert_eq!(align_of::<RawCoff>(), 1);
}
