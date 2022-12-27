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
use core::{
    fmt,
    mem::{self, size_of},
};

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

/// PE COFF Magic signature
pub const PE_MAGIC: &[u8] = b"PE\0\0";

/// PE32 Magic signature
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ Magic signature
pub const PE32_64_MAGIC: u16 = 0x20B;

/// Raw DOS header
#[derive(Clone, Copy)]
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

    /// Get a [`RawDos`] from `data`, and a new pointer length pair for the PE
    /// portion and the DOS stub.
    ///
    /// Checks for the DOS magic.
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
        size.checked_sub(size_of::<RawDos>())
            .ok_or(Error::NotEnoughData)?;
        let dos = unsafe { &*(data as *const RawDos) };
        dbg!(dos);
        if dos.magic != DOS_MAGIC {
            return Err(Error::InvalidDosMagic);
        }
        // PE headers start at this offset
        let pe_ptr = data.wrapping_add(dos.pe_offset as usize);
        let pe_size = size
            .checked_sub(dos.pe_offset as usize)
            .ok_or(Error::NotEnoughData)?;
        // Dos Stub
        let stub_ptr = data.wrapping_add(size_of::<RawDos>());
        let stub_size = size
            .checked_sub(pe_size)
            .ok_or(Error::NotEnoughData)?
            .checked_sub(size_of::<RawDos>())
            .ok_or(Error::NotEnoughData)?;

        Ok((dos, (pe_ptr, pe_size), (stub_ptr, stub_size)))
    }

    /// Get a [`RawDos`] from `bytes`, and the remaining PE portion of `bytes`.
    ///
    /// Checks for the DOS magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<(&Self, &[u8])> {
        let dos = unsafe { RawDos::from_ptr(bytes.as_ptr(), bytes.len())?.0 };
        Ok((
            dos,
            bytes
                .get(dos.pe_offset as usize..)
                .ok_or(Error::NotEnoughData)?,
        ))
    }
}

impl fmt::Debug for RawDos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RawDos");
        if self.magic == DOS_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"MZ""#)
                }
            }
            s.field("magic", &Helper);
        } else {
            s.field("magic", &{ self.magic });
        }

        s.field("last_bytes", &{ self.last_bytes })
            .field("pages", &{ self.pages })
            .field("relocations", &{ self.relocations })
            .field("header_size", &{ self.header_size })
            .field("min_alloc", &{ self.min_alloc })
            .field("max_alloc", &{ self.max_alloc })
            .field("initial_ss", &{ self.initial_ss })
            .field("initial_sp", &{ self.initial_sp })
            .field("checksum", &{ self.checksum })
            .field("initial_ip", &{ self.initial_ip })
            .field("initial_cs", &{ self.initial_cs })
            .field("relocation_offset", &{ self.relocation_offset })
            .field("overlay_num", &{ self.overlay_num });
        if { self._reserved } == [0; 4] {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "[0u16; 4]")
                }
            }
            s.field("_reserved", &Helper);
        } else {
            s.field("_reserved", &{ self._reserved });
        }

        s.field("oem_id", &{ self.oem_id })
            .field("oem_info", &{ self.oem_info });
        if { self._reserved2 } == [0; 20] {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "[0u8; 20]")
                }
            }
            s.field("_reserved2", &Helper);
        } else {
            s.field("_reserved2", &{ self._reserved2 });
        }
        s.field("pe_offset", &{ self.pe_offset }).finish()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawCoff {
    pub machine: MachineType,

    /// Number of sections
    pub sections: u16,

    /// Timestamp
    pub time: u32,
    pub sym_offset: u32,
    pub num_sym: u32,

    /// Size in bytes of the PE optional header
    pub optional_size: u16,

    pub attributes: CoffAttributes,
}

impl RawCoff {
    /// Create a new COFF header
    ///
    /// The deprecated COFF debugging information is set to zero
    pub fn new(
        machine: MachineType,
        sections: u16,
        time: u32,
        optional_size: u16,
        attributes: CoffAttributes,
    ) -> Self {
        Self {
            machine,
            sections,
            time,
            sym_offset: 0,
            num_sym: 0,
            optional_size,
            attributes,
        }
    }
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
    ) -> Result<(
        &'data Self,
        (*const u8, usize),
        (*const RawSectionHeader, usize),
    )> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        size.checked_sub(size_of::<RawPe>())
            .ok_or(Error::NotEnoughData)?;
        let pe = unsafe { &*(data as *const RawPe) };
        if pe.sig != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }

        let opt_size = pe.coff.optional_size as usize;
        size.checked_sub(
            size_of::<RawPe>()
                .checked_add(opt_size)
                .ok_or(Error::NotEnoughData)?,
        )
        .ok_or(Error::NotEnoughData)?;
        // Optional header appears directly after PE header
        let opt_ptr = data.wrapping_add(size_of::<RawPe>());

        let section_size = size_of::<RawSectionHeader>()
            .checked_mul(pe.coff.sections as usize)
            .ok_or(Error::NotEnoughData)?;
        size.checked_sub(
            size_of::<RawPe>()
                .checked_add(opt_size)
                .ok_or(Error::NotEnoughData)?
                .checked_add(section_size)
                .ok_or(Error::NotEnoughData)?,
        )
        .ok_or(Error::NotEnoughData)?;
        // Section table appears directly after PE and optional header
        let section_ptr = data.wrapping_add(
            size_of::<RawPe>()
                .checked_add(opt_size)
                .ok_or(Error::NotEnoughData)?,
        ) as *const RawSectionHeader;

        Ok((
            pe,
            (opt_ptr, opt_size),
            (section_ptr, pe.coff.sections as usize),
        ))
    }

    /// Get a [`RawPe`] from `bytes`, the optional header, and section
    /// table.
    ///
    /// Checks for the PE magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<(&Self, &[u8], &[RawSectionHeader])> {
        unsafe {
            let (pe, (opt_ptr, opt_size), (section_ptr, section_len)) =
                RawPe::from_ptr(bytes.as_ptr(), bytes.len())?;
            Ok((
                pe,
                core::slice::from_raw_parts(opt_ptr, opt_size),
                core::slice::from_raw_parts(section_ptr, section_len),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPeOptStandard {
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
    pub entry_offset: u32,

    /// Offset to beginning-of-code section, relative to image base.
    pub code_base: u32,
}

impl RawPeOptStandard {
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
            entry_offset,
            code_base,
        }
    }

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

/// 32-bit optional header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32 {
    /// Standard/common subset
    pub standard: RawPeOptStandard,

    /// Offset to beginning-of-data section, relative to image base.
    pub data_base: u32,

    /// Preferred base address of the image when loaded in memory.
    pub image_base: u32,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub section_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub file_align: u32,

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
    pub dll_characteristics: DllCharacteristics,

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
    pub _reserved_loader_flags: u32,

    /// Number of data directories following the header.
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

/// 64-bit optional header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32x64 {
    /// Standard/common subset
    pub standard: RawPeOptStandard,

    /// Preferred base address of the image when loaded in memory.
    pub image_base: u64,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub section_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub file_align: u32,

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
    pub dll_characteristics: DllCharacteristics,

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
    pub _reserved_loader_flags: u32,

    /// Number of data directories following the header.
    pub data_dirs: u32,
}

impl RawPe32x64 {
    pub fn new(
        standard: RawPeOptStandard,
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
        dll_characteristics: DllCharacteristics,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        data_dirs: u32,
    ) -> Self {
        Self {
            standard,
            image_base,
            section_align,
            file_align,
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
            dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            _reserved_loader_flags: 0,
            data_dirs,
        }
    }

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

impl RawDataDirectory {
    pub fn new(address: u32, size: u32) -> Self {
        Self { address, size }
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawSectionHeader {
    /// Name of the section
    pub name: [u8; 8],

    /// Size of the section in memory
    pub virtual_size: u32,

    /// Offset of the section in memory
    pub virtual_address: u32,

    /// Size of the section on disk
    pub raw_size: u32,

    /// Offset of the section on disk
    pub raw_ptr: u32,

    /// Offset of the sections relocations on disk
    pub reloc_ptr: u32,

    /// Offset of the sections line numbers on disk
    pub line_ptr: u32,

    /// Number of relocation entries at `reloc_ptr`
    pub num_reloc: u16,

    /// Number of lines at `line_ptr`
    pub num_lines: u16,

    /// Section flags
    pub characteristics: SectionFlags,
}

impl RawSectionHeader {
    /// Name of the section asa UTF-8 string, or an error if it was invalid.
    pub fn name(&self) -> Result<&str> {
        core::str::from_utf8(&self.name)
            .map(|s| s.trim_end_matches('\0'))
            .map_err(|_| Error::InvalidData)
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
