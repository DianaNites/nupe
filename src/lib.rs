//! PE image handling
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![allow(
    unused_variables,
    unused_imports,
    unused_mut,
    unused_assignments,
    dead_code,
    clippy::let_unit_value,
    clippy::diverging_sub_expression,
    clippy::new_without_default,
    clippy::too_many_arguments,
    unreachable_code
)]
extern crate alloc;

pub mod error;
mod internal;
pub mod raw;
pub mod section;
use alloc::{vec, vec::Vec};
use core::{
    cmp::Ordering,
    fmt,
    marker::PhantomData,
    mem::{self, size_of, MaybeUninit},
    ops::{Deref, DerefMut},
    slice::from_raw_parts,
};

use bitflags::bitflags;
use raw::*;

use crate::error::{Error, Result};
pub use crate::internal::{OwnedOrRef, VecOrSlice};

/// Windows PE Section alignment
const AMD64_SECTION_ALIGN: u32 = 4096;

/// Windows PE Section alignment
const AMD64_FILE_ALIGN: u32 = 512;

/// Default image base to use
const DEFAULT_IMAGE_BASE: u64 = 0x10000000;

/// Machine type, or architecture, of the PE file.
///
/// This is what architectures the file will run on.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachineType(u16);

impl MachineType {
    /// Unknown/Any/All machine type
    pub const UNKNOWN: Self = Self(0);

    /// x64
    pub const AMD64: Self = Self(0x8664);

    /// x86
    pub const I386: Self = Self(0x14C);

    /// EFI Byte Code
    pub const EBC: Self = Self(0xEBC);
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

/// Subsystem, or type, of the PE file.
///
/// This determines a few things, such as the expected signature of the
/// application entry point, expected existence and contents of sections, etc.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Subsystem(u16);

impl Subsystem {
    pub const UNKNOWN: Self = Self(0);
    pub const NATIVE: Self = Self(1);
    pub const WINDOWS_GUI: Self = Self(2);
    pub const WINDOWS_CLI: Self = Self(3);
    pub const OS2_CLI: Self = Self(5);
    pub const POSIX_CLI: Self = Self(7);
    pub const NATIVE_WINDOWS: Self = Self(8);
    pub const WINDOWS_CE_GUI: Self = Self(9);
    pub const EFI_APPLICATION: Self = Self(10);
    pub const EFI_BOOT_DRIVER: Self = Self(11);
    pub const EFI_RUNTIME_DRIVER: Self = Self(12);
    pub const EFI_ROM: Self = Self(13);
    pub const XBOX: Self = Self(14);
    pub const WINDOWS_BOOT: Self = Self(16);
}

impl fmt::Debug for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "Subsystem::UNKNOWN"),
            Self::NATIVE => write!(f, "Subsystem::NATIVE"),
            Self::WINDOWS_GUI => write!(f, "Subsystem::WINDOWS_GUI"),
            Self::WINDOWS_CLI => write!(f, "Subsystem::WINDOWS_CLI"),
            Self::OS2_CLI => write!(f, "Subsystem::OS2_CLI"),
            Self::POSIX_CLI => write!(f, "Subsystem::POSIX_CLI"),
            Self::NATIVE_WINDOWS => write!(f, "Subsystem::NATIVE_WINDOWS"),
            Self::WINDOWS_CE_GUI => write!(f, "Subsystem::WINDOWS_CE_GUI"),
            Self::EFI_APPLICATION => write!(f, "Subsystem::EFI_APPLICATION"),
            Self::EFI_BOOT_DRIVER => write!(f, "Subsystem::EFI_BOOT_DRIVER"),
            Self::EFI_RUNTIME_DRIVER => write!(f, "Subsystem::EFI_RUNTIME_DRIVER"),
            Self::EFI_ROM => write!(f, "Subsystem::EFI_ROM"),
            Self::XBOX => write!(f, "Subsystem::XBOX"),
            Self::WINDOWS_BOOT => write!(f, "Subsystem::WINDOWS_BOOT"),
            _ => f.debug_tuple("Subsystem").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "UNKNOWN"),
            Self::NATIVE => write!(f, "NATIVE"),
            Self::WINDOWS_GUI => write!(f, "WINDOWS_GUI"),
            Self::WINDOWS_CLI => write!(f, "WINDOWS_CLI"),
            Self::OS2_CLI => write!(f, "OS2_CLI"),
            Self::POSIX_CLI => write!(f, "POSIX_CLI"),
            Self::NATIVE_WINDOWS => write!(f, "NATIVE_WINDOWS"),
            Self::WINDOWS_CE_GUI => write!(f, "WINDOWS_CE_GUI"),
            Self::EFI_APPLICATION => write!(f, "EFI_APPLICATION"),
            Self::EFI_BOOT_DRIVER => write!(f, "EFI_BOOT_DRIVER"),
            Self::EFI_RUNTIME_DRIVER => write!(f, "EFI_RUNTIME_DRIVER"),
            Self::EFI_ROM => write!(f, "EFI_ROM"),
            Self::XBOX => write!(f, "XBOX"),
            Self::WINDOWS_BOOT => write!(f, "WINDOWS_BOOT"),
            _ => f.debug_tuple("Subsystem").field(&self.0).finish(),
        }
    }
}

bitflags! {
    #[repr(transparent)]
    pub struct CoffAttributes: u16 {
        const RELOC_STRIPPED = 0x1;
        const IMAGE = 0x2;
        const COFF_LINE_STRIPPED = 0x4;
        const COFF_SYM_STRIPPED = 0x8;
        const AGGRESSIVE_WS_TRIM = 0x10;
        const LARGE_ADDRESS_AWARE = 0x20;
        const RESERVED = 0x40;
        const BYTES_REVERSED_LO = 0x80;
        const BIT32 = 0x100;
        const DEBUG_STRIPPED = 0x200;
        const REMOVABLE_SWAP = 0x400;
        const NET_SWAP = 0x800;
        const SYSTEM = 0x1000;
        const DLL = 0x2000;
        const UP_SYSTEM = 0x4000;
        const BYTES_REVERSED_HI = 0x8000;
    }
}

bitflags! {
    #[repr(transparent)]
    pub struct DllCharacteristics: u16 {
        const EMPTY = 0x0;
        const RESERVED_1 = 0x1;
        const RESERVED_2 = 0x2;
        const RESERVED_3 = 0x4;
        const RESERVED_4 = 0x8;
        const HIGH_ENTROPY_VA = 0x20;
        const DYNAMIC_BASE = 0x40;
        const FORCE_INTEGRITY = 0x80;
        const NX_COMPAT = 0x100;
        const NO_ISOLATION = 0x200;
        const NO_SEH = 0x400;
        const NO_BIND = 0x800;
        const APP_CONTAINER = 0x1000;
        const WDM_DRIVER = 0x2000;
        const GUARD_CF = 0x4000;
        const TERMINAL_SERVER = 0x8000;
    }
}

bitflags! {
    #[repr(transparent)]
    pub struct SectionFlags: u32 {
        const EMPTY = 0x0;
        const RESERVED_1 = 0x1;
        const RESERVED_2 = 0x2;
        const RESERVED_3 = 0x4;
        const NO_PAD = 0x8;
        const RESERVED_4 = 0x10;

        /// Code/executable
        const CODE = 0x20;

        /// Initialized/data
        const INITIALIZED = 0x40;

        /// Uninitialized/bss
        const UNINITIALIZED = 0x80;

        const RESERVED_OTHER = 0x100;
        const INFO = 0x200;
        const RESERVED_6 = 0x400;
        const REMOVE = 0x800;
        const COMDAT = 0x1000;
        const GLOBAL_REL = 0x8000;
        const RESERVED_MEM_PURGE = 0x20000;
        const RESERVED_MEM_16BIT = 0x20000;
        const RESERVED_MEM_LOCKED = 0x40000;
        const RESERVED_MEM_PRELOAD = 0x80000;
        const ALIGN_1 = 0x100000;
        const ALIGN_2 = 0x200000;
        const ALIGN_4 = 0x300000;
        const ALIGN_8 = 0x400000;
        const ALIGN_16 = 0x500000;
        const ALIGN_32 = 0x600000;
        const ALIGN_64 = 0x700000;
        const ALIGN_128 = 0x800000;
        const ALIGN_256 = 0x900000;
        const ALIGN_512 = 0xA00000;
        const ALIGN_1024 = 0xB00000;
        const ALIGN_2048 = 0xC00000;
        const ALIGN_4096 = 0xD00000;
        const ALIGN_8192 = 0xE00000;
        const EXTENDED_RELOC = 0x1000000;
        const DISCARDABLE = 0x2000000;
        const NO_CACHE = 0x4000000;
        const NO_PAGE = 0x8000000;
        const SHARED = 0x10000000;

        /// Memory is executable
        const EXEC = 0x20000000;

        /// Memory is readable
        const READ = 0x40000000;

        /// Memory is writeable
        const WRITE = 0x80000000;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ImageHeader<'data> {
    Raw32(OwnedOrRef<'data, RawPe32>),
    Raw64(OwnedOrRef<'data, RawPe32x64>),
}

#[doc(hidden)]
impl<'data> ImageHeader<'data> {
    /// How many data directories
    fn data_dirs(&self) -> u32 {
        match self {
            ImageHeader::Raw32(h) => h.data_dirs,
            ImageHeader::Raw64(h) => h.data_dirs,
        }
    }

    /// Subsystem
    fn subsystem(&self) -> Subsystem {
        match self {
            ImageHeader::Raw32(h) => h.subsystem,
            ImageHeader::Raw64(h) => h.subsystem,
        }
    }

    /// Entry point address relative to the image base
    fn entry(&self) -> u32 {
        match self {
            ImageHeader::Raw32(h) => h.standard.entry_offset,
            ImageHeader::Raw64(h) => h.standard.entry_offset,
        }
    }

    /// OS (major, minor)
    fn os_version(&self) -> (u16, u16) {
        match self {
            ImageHeader::Raw32(h) => (h.os_major, h.os_minor),
            ImageHeader::Raw64(h) => (h.os_major, h.os_minor),
        }
    }

    /// Image (major, minor)
    fn image_version(&self) -> (u16, u16) {
        match self {
            ImageHeader::Raw32(h) => (h.image_major, h.image_minor),
            ImageHeader::Raw64(h) => (h.image_major, h.image_minor),
        }
    }

    /// Subsystem (major, minor)
    fn subsystem_version(&self) -> (u16, u16) {
        match self {
            ImageHeader::Raw32(h) => (h.subsystem_major, h.subsystem_minor),
            ImageHeader::Raw64(h) => (h.subsystem_major, h.subsystem_minor),
        }
    }

    /// Linker (major, minor)
    fn linker_version(&self) -> (u8, u8) {
        match self {
            ImageHeader::Raw32(h) => (h.standard.linker_major, h.standard.linker_minor),
            ImageHeader::Raw64(h) => (h.standard.linker_major, h.standard.linker_minor),
        }
    }
}

#[doc(hidden)]
impl<'data> ImageHeader<'data> {
    /// Get a [`ImageHeader`] from `data`. Checks for the magic.
    ///
    /// Returns [`ImageHeader`] and data dirs
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    unsafe fn from_ptr(
        data: *const u8,
        size: usize,
    ) -> Result<(Self, (*const RawDataDirectory, usize))> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        size.checked_sub(size_of::<RawPeOptStandard>())
            .ok_or(Error::NotEnoughData)?;
        let opt = unsafe { &*(data as *const RawPeOptStandard) };
        if opt.magic == PE32_64_MAGIC {
            let opt = RawPe32x64::from_ptr(data, size)?;
            let _data_size = size_of::<RawDataDirectory>()
                .checked_mul(opt.data_dirs as usize)
                .ok_or(Error::NotEnoughData)?;
            let data_ptr = data.wrapping_add(size_of::<RawPe32x64>()) as *const RawDataDirectory;
            Ok((
                ImageHeader::Raw64(OwnedOrRef::Ref(opt)),
                (data_ptr, opt.data_dirs as usize),
            ))
        } else if opt.magic == PE32_MAGIC {
            let opt = RawPe32::from_ptr(data, size)?;
            let _data_size = size_of::<RawDataDirectory>()
                .checked_mul(opt.data_dirs as usize)
                .ok_or(Error::NotEnoughData)?;
            let data_ptr = data.wrapping_add(size_of::<RawPe32>()) as *const RawDataDirectory;
            Ok((
                ImageHeader::Raw32(OwnedOrRef::Ref(opt)),
                (data_ptr, opt.data_dirs as usize),
            ))
        } else {
            Err(Error::InvalidPeMagic)
        }
    }

    /// Get a [`ImageHeader`] from `bytes`, and data dirs as slice
    ///
    /// Checks for the magic.
    fn from_bytes(bytes: &'data [u8]) -> Result<(Self, &'data [RawDataDirectory])> {
        // Safety: Slice pointer is trivially valid for its own length.
        let (opt, (data_ptr, data_len)) = unsafe { Self::from_ptr(bytes.as_ptr(), bytes.len())? };
        // Safety: Above guarantees these are valid
        let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };
        Ok((opt, data))
    }

    /// Preferred Base of the image in memory.
    ///
    /// Coerced to u64 even on/for 32bit.
    fn image_base(&self) -> u64 {
        match self {
            ImageHeader::Raw32(h) => h.image_base.into(),
            ImageHeader::Raw64(h) => h.image_base,
        }
    }
}

/// A PE Section
#[derive(Debug)]
pub struct Section<'data> {
    header: OwnedOrRef<'data, RawSectionHeader>,
    base: Option<(*const u8, usize)>,
}

impl<'data> Section<'data> {
    /// Address to the first byte of the section, relative to the image base.
    pub fn virtual_address(&self) -> u32 {
        self.header.virtual_address
    }

    /// Size of the section in memory, zero padded if needed.
    pub fn virtual_size(&self) -> u32 {
        self.header.virtual_size
    }

    /// Offset of the section data on disk
    pub fn file_offset(&self) -> u32 {
        self.header.raw_ptr
    }

    /// Size of the section data on disk
    ///
    /// # WARNING
    ///
    /// Be sure this is what you want. This field is a trap.
    /// You may instead want [`Section::virtual_size`]
    ///
    /// The file_size field is rounded up to a multiple of the file alignment,
    /// but virtual_size is not. That means file_size includes extra padding not
    /// actually part of the section, and that virtual_size is the true size.
    pub fn file_size(&self) -> u32 {
        self.header.raw_size
    }

    /// Name of the section, with nul bytes stripped.
    ///
    /// Empty string is returned if invalid ASCII/UTF-8 somehow makes it here.
    pub fn name(&self) -> &str {
        self.header.name().unwrap_or_default()
    }

    /// Section flags/attributes/characteristics
    pub fn flags(&self) -> SectionFlags {
        self.header.characteristics
    }

    /// Slice of the section data
    ///
    /// Returns [`None`] if not called on a loaded image, or if the section is
    /// outside the loaded image.
    pub fn virtual_data(&self) -> Option<&'data [u8]> {
        if let Some((base, size)) = self.base {
            if size
                .checked_sub(self.virtual_address() as usize)
                .and_then(|s| s.checked_sub(self.virtual_size() as usize))
                .ok_or(Error::NotEnoughData)
                .is_err()
            {
                return None;
            }
            // Safety:
            // - Base is guaranteed valid for size in `from_ptr_internal`
            // - from_ptr_internal does the checking to make sure we're a PE file, without
            //   which we couldnt be here
            // - 'data lifetime means data is still valid
            // - We double check to make sure we're in-bounds above
            Some(unsafe {
                core::slice::from_raw_parts(
                    base.wrapping_add(self.virtual_address() as usize),
                    self.virtual_size() as usize,
                )
            })
        } else {
            None
        }
    }
}

/// A PE file
pub struct Pe<'data> {
    dos: OwnedOrRef<'data, RawDos>,
    dos_stub: VecOrSlice<'data, u8>,
    coff: OwnedOrRef<'data, RawCoff>,
    opt: ImageHeader<'data>,
    data_dirs: VecOrSlice<'data, RawDataDirectory>,
    sections: VecOrSlice<'data, RawSectionHeader>,
    base: Option<(*const u8, usize)>,
    _phantom: PhantomData<&'data u8>,
}

impl<'data> Pe<'data> {
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    unsafe fn from_ptr_internal(data: *const u8, size: usize, loaded: bool) -> Result<Self> {
        let (dos, (pe_ptr, pe_size), (stub_ptr, stub_size)) = RawDos::from_ptr(data, size)?;
        let (pe, (opt_ptr, opt_size), (section_ptr, section_size)) =
            RawPe::from_ptr(pe_ptr, pe_size)?;
        let (header, (data_ptr, data_size)) = ImageHeader::from_ptr(opt_ptr, opt_size)?;
        let data_dirs = unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
        let sections = unsafe { core::slice::from_raw_parts(section_ptr, section_size) };
        let stub = unsafe { core::slice::from_raw_parts(stub_ptr, stub_size) };
        for s in sections {
            if !s.name.is_ascii() {
                return Err(Error::InvalidData);
            }
        }
        let base = if loaded { Some((data, size)) } else { None };

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            dos_stub: VecOrSlice::Slice(stub),
            coff: OwnedOrRef::Ref(&pe.coff),
            opt: header,
            data_dirs: VecOrSlice::Slice(data_dirs),
            sections: VecOrSlice::Slice(sections),
            base,
            _phantom: PhantomData,
        })
    }

    /// # Safety
    ///
    /// - See [`Pe::from_ptr_internal`]
    /// - `data` MUST be a legitimate mutable pointer
    unsafe fn from_ptr_internal_mut(data: *mut u8, size: usize, loaded: bool) -> Result<Self> {
        Self::from_ptr_internal(data as *const u8, size, loaded)
    }
}

impl<'data> Pe<'data> {
    /// Get a [`PeHeader`] from `data`, checking to make sure its valid.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - `data` SHOULD be a valid pointer to a LOADED PE image in memory
    pub unsafe fn from_loaded_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size, true)
    }

    /// Get a [`PeHeader`] from `data`, checking to make sure its valid.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - `data` SHOULD be a valid pointer to a PE image in memory
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size, false)
    }

    pub fn from_bytes(bytes: &'data [u8]) -> Result<Self> {
        // Safety: Slice pointer is trivially valid for its own length.
        unsafe { Self::from_ptr_internal(bytes.as_ptr(), bytes.len(), false) }
    }

    pub fn from_bytes_mut(bytes: &'data mut [u8]) -> Result<Self> {
        // Safety: Slice pointer is trivially valid for its own length.
        unsafe { Self::from_ptr_internal_mut(bytes.as_mut_ptr(), bytes.len(), false) }
    }
}

impl<'data> Pe<'data> {
    /// Get a [`Section`] by `name`. Ignores nul.
    ///
    /// Note that PE section names can only be 8 bytes, total.
    pub fn section(&self, name: &str) -> Option<Section> {
        if name.len() > 8 {
            return None;
        }
        self.sections
            .iter()
            .find(|s| s.name().unwrap() == name)
            .map(|s| Section {
                header: OwnedOrRef::Ref(s),
                base: self.base,
            })
    }

    /// Iterator over [`Section`]s
    pub fn sections(&self) -> impl Iterator<Item = Section> {
        self.sections.iter().map(|s| Section {
            header: OwnedOrRef::Ref(s),
            base: self.base,
        })
    }

    /// Number of sections
    pub fn sections_len(&self) -> usize {
        self.coff.sections.into()
    }

    /// Machine type
    pub fn machine_type(&self) -> MachineType {
        self.coff.machine
    }

    /// COFF Attributes
    pub fn attributes(&self) -> CoffAttributes {
        self.coff.attributes
    }

    /// Subsystem, or type, of the PE file.
    ///
    /// This determines a few things, such as the expected signature of the
    /// application entry point, expected existence and contents of sections,
    /// etc.
    ///
    /// See [Subsystem]
    pub fn subsystem(&self) -> Subsystem {
        self.opt.subsystem()
    }

    /// Entry point address relative to the image base
    pub fn entry(&self) -> u32 {
        self.opt.entry()
    }

    /// The DOS stub code
    pub fn dos_stub(&self) -> &[u8] {
        &self.dos_stub
    }

    /// Low 32-bits of a unix timestamp
    pub fn timestamp(&self) -> u32 {
        self.coff.time
    }

    /// Preferred base address of the image
    pub fn image_base(&self) -> u64 {
        self.opt.image_base()
    }

    /// OS (major, minor)
    pub fn os_version(&self) -> (u16, u16) {
        self.opt.os_version()
    }

    /// Image (major, minor)
    pub fn image_version(&self) -> (u16, u16) {
        self.opt.image_version()
    }

    /// Subsystem (major, minor)
    pub fn subsystem_version(&self) -> (u16, u16) {
        self.opt.subsystem_version()
    }

    /// Linker (major, minor)
    pub fn linker_version(&self) -> (u8, u8) {
        self.opt.linker_version()
    }
}

impl<'data> Pe<'data> {
    /// Raw COFF header for this PE file
    ///
    /// This is only for advanced users.
    pub fn coff(&self) -> &RawCoff {
        &self.coff
    }

    /// Raw COFF header for this PE file
    ///
    /// This is only for advanced users.
    pub fn opt(&self) -> &'data ImageHeader {
        &self.opt
    }

    /// Raw DOS header for this PE file
    ///
    /// This is only for advanced users.
    pub fn dos(&self) -> &RawDos {
        &self.dos
    }
}

impl<'data> fmt::Debug for Pe<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Pe");
        s.field("dos", &self.dos)
            .field("dos_stub", &{
                struct Helper(usize);
                impl fmt::Debug for Helper {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, r#"DOS code (len {})"#, self.0)
                    }
                }
                Helper(self.dos_stub.len())
            })
            .field("coff", &self.coff)
            .field("opt", &self.opt)
            .field("data_dirs", &self.data_dirs)
            .field("sections", &self.sections)
            .field("base", &self.base)
            .field("_phantom", &self._phantom)
            .finish()
    }
}

mod states {
    //! States for [`PeBuilder`]

    #[derive(Debug, Clone, Copy)]
    pub struct Empty;

    #[derive(Debug, Clone, Copy)]
    pub struct Machine;
}

/// Builder for a [`Pe`] file
#[derive(Debug)]
pub struct PeBuilder<'data, State> {
    /// Type state.
    state: PhantomData<State>,

    /// Sections to write to the image.
    sections: VecOrSlice<'data, Section<'data>>,

    /// Data of sections. 1:1 with sections
    sections_data: VecOrSlice<'data, VecOrSlice<'data, u8>>,

    /// Data dirs to write to the image, defaults to zeroed.
    data_dirs: VecOrSlice<'data, RawDataDirectory>,

    /// Machine type. Required.
    machine: MachineType,

    /// Timestamp. Defaults to 0.
    timestamp: u32,

    /// Defaults to [`DEFAULT_IMAGE_BASE`]
    image_base: u64,

    /// Defaults to 4096
    section_align: u64,

    /// Defaults to 512
    file_align: u64,

    /// Defaults to 0
    entry: u32,

    /// DOS Header and stub to use. Defaults to empty, no stub.
    dos: Option<(RawDos, VecOrSlice<'data, u8>)>,

    /// COFF Attributes
    attributes: CoffAttributes,

    /// DLL Attributes
    dll_attributes: DllCharacteristics,

    /// Subsystem
    subsystem: Subsystem,

    /// Stack reserve and commit
    stack: (u64, u64),

    /// Heap reserve and commit
    heap: (u64, u64),

    /// OS version
    os_ver: (u16, u16),

    /// Image version
    image_ver: (u16, u16),

    /// Subsystem version
    subsystem_ver: (u16, u16),

    /// Subsystem version
    linker_ver: (u8, u8),
}

impl<'data> PeBuilder<'data, states::Empty> {
    /// Create a new [`PeBuilder`]
    pub fn new() -> Self {
        Self {
            state: PhantomData,
            sections: VecOrSlice::Vec(Vec::new()),
            sections_data: VecOrSlice::Vec(Vec::new()),
            data_dirs: VecOrSlice::Vec(vec![RawDataDirectory::new(0, 0); 16]),
            machine: MachineType::UNKNOWN,
            timestamp: 0,
            image_base: DEFAULT_IMAGE_BASE,
            section_align: 4096,
            file_align: 512,
            entry: 0,
            dos: None,
            attributes: CoffAttributes::IMAGE | CoffAttributes::LARGE_ADDRESS_AWARE,
            subsystem: Subsystem::UNKNOWN,
            dll_attributes: DllCharacteristics::empty(),
            stack: (0, 0),
            heap: (0, 0),
            os_ver: (0, 0),
            image_ver: (0, 0),
            subsystem_ver: (0, 0),
            linker_ver: (0, 0),
        }
    }

    /// Machine Type. This is required.
    pub fn machine(&mut self, machine: MachineType) -> &mut PeBuilder<'data, states::Machine> {
        self.machine = machine;
        unsafe { &mut *(self as *mut Self as *mut PeBuilder<'data, states::Machine>) }
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Offset from image base to entry point
    ///
    /// Defaults to 0
    pub fn entry(&mut self, entry: u32) -> &mut Self {
        self.entry = entry;
        self
    }

    /// Stack reserve and commit, respectively
    pub fn stack(&mut self, stack: (u64, u64)) -> &mut Self {
        self.stack = stack;
        self
    }

    /// Heap reserve and commit, respectively
    pub fn heap(&mut self, heap: (u64, u64)) -> &mut Self {
        self.heap = heap;
        self
    }

    /// OS (major, minor)
    pub fn os_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.os_ver = ver;
        self
    }

    /// Image (major, minor)
    pub fn image_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.image_ver = ver;
        self
    }

    /// Subsystem (major, minor)
    pub fn subsystem_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.subsystem_ver = ver;
        self
    }

    /// Linker (major, minor)
    pub fn linker_version(&mut self, ver: (u8, u8)) -> &mut Self {
        self.linker_ver = ver;
        self
    }

    /// Stack reserve and commit, respectively
    pub fn subsystem(&mut self, subsystem: Subsystem) -> &mut Self {
        self.subsystem = subsystem;
        self
    }

    /// Attributes for the [`Pe`] file.
    ///
    /// If unset, this defaults to `IMAGE | LARGE_ADDRESS_AWARE`.
    ///
    /// This completely overwrites the attributes.
    pub fn attributes(&mut self, attr: CoffAttributes) -> &mut Self {
        self.attributes = attr;
        self
    }

    /// DOS Header and stub
    ///
    /// If unset, this defaults to an empty header, except for the PE offset,
    /// and no DOS stub.
    ///
    /// This completely overwrites the header and stub.
    pub fn dos(&mut self, dos: RawDos, stub: VecOrSlice<'data, u8>) -> &mut Self {
        self.dos = Some((dos, stub));
        self
    }

    /// Low 32 bits of the unix timestamp for this image.
    pub fn timestamp(&mut self, time: u32) -> &mut Self {
        self.timestamp = time;
        self
    }

    /// Preferred base address of the image
    pub fn image_base(&mut self, image_base: u64) -> &mut Self {
        self.image_base = image_base;
        self
    }

    /// DLL Attributes for the [`Pe`] image.
    pub fn dll_attributes(&mut self, attr: DllCharacteristics) -> &mut Self {
        self.dll_attributes = attr;
        self
    }

    /// Append a section
    pub fn section(&mut self, section: &mut SectionBuilder) -> &mut Self {
        let len = section.data.len().try_into().unwrap();
        let va = self.next_virtual_address();
        let file_offset = section.offset.unwrap_or_else(|| self.next_file_offset());
        let mut header = RawSectionHeader {
            name: section.name,
            virtual_size: { len },
            virtual_address: va,
            raw_size: {
                if len % self.file_align as u32 != 0 {
                    len + (self.file_align as u32 - (len % self.file_align as u32))
                } else {
                    len
                }
            },
            raw_ptr: file_offset,
            reloc_ptr: 0,
            line_ptr: 0,
            num_reloc: 0,
            num_lines: 0,
            characteristics: section.attr,
        };

        match &mut self.sections {
            VecOrSlice::Vec(v) => v.push(Section {
                header: OwnedOrRef::Owned(header),
                base: None,
            }),
            VecOrSlice::Slice(_) => todo!(),
        }

        // FIXME: to_vec
        match &mut self.sections_data {
            VecOrSlice::Vec(v) => v.push(VecOrSlice::Vec(section.data.to_vec())),
            VecOrSlice::Slice(_) => todo!(),
        }

        self
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Calculate the size on disk this file would take
    ///
    /// Ignores file alignment
    #[cfg(no)]
    fn calculate_size(&self) -> usize {
        const DOS_STUB: usize = 0;
        let opt_size = match self.machine {
            MachineType::AMD64 => size_of::<RawPe32x64>(),
            MachineType::I386 => size_of::<RawPe32>(),
            _ => unimplemented!(),
        };
        #[allow(clippy::erasing_op)]
        let data_dirs = size_of::<RawDataDirectory>() * 0;
        #[allow(clippy::erasing_op)]
        let sections = size_of::<RawSectionHeader>() * 0;
        let sections_sum: u32 = self.sections.iter().map(|s| s.header.raw_size).sum();
        let sections_sum = sections_sum as usize;
        size_of::<RawDos>()
            + DOS_STUB
            + size_of::<RawPe>()
            + opt_size
            + data_dirs
            + sections
            + sections_sum
    }

    /// Write the DOS header
    ///
    /// The PE offset is expected to point directly after the DOS header and
    /// stub, aligned up to 8 bytes.
    ///
    /// TODO: May need to support more of the DOS format to be able to perfectly
    /// represent this, because of hidden metadata between the stub and PE.
    ///
    /// By default there is no stub, and the header only contains the offset.
    fn write_dos(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if let Some((dos, stub)) = self.dos.as_ref() {
            // Provided header and stub, PE expected directly after this.
            let bytes = unsafe {
                let ptr = dos as *const RawDos as *const u8;
                from_raw_parts(ptr, size_of::<RawDos>())
            };
            out.extend_from_slice(bytes);
            // Stub
            out.extend_from_slice(stub);
            // Align
            let size = size_of::<RawDos>() + stub.len();
            if size % 8 != 0 {
                let align = size + (8 - (size % 8));
                let align = align - size;
                out.reserve(align);
                for _ in 0..align {
                    out.push(b'\0')
                }
            }
        } else {
            // No stub, PE expected directly after this, 64 is already 8 aligned.
            let dos = RawDos::new(size_of::<RawDos>() as u32);
            let bytes = unsafe {
                let ptr = &dos as *const RawDos as *const u8;
                from_raw_parts(ptr, size_of::<RawDos>())
            };
            out.extend_from_slice(bytes);
        };
        Ok(())
    }

    /// Write the PE header.
    ///
    /// If `plus` is true then expect PE32+ for the optional header.
    fn write_pe(&mut self, out: &mut Vec<u8>, machine: MachineType, plus: bool) -> Result<usize> {
        out.extend_from_slice(PE_MAGIC);

        // We always write the full 16, zeroed, data dirs, and either the 32 or 64-bit
        // header.
        let optional_size = self.data_dirs.len() * size_of::<RawDataDirectory>()
            + if plus {
                size_of::<RawPe32x64>()
            } else {
                size_of::<RawPe32>()
            };

        let coff = OwnedOrRef::Owned(RawCoff::new(
            machine,
            self.sections
                .len()
                .try_into()
                .map_err(|_| Error::InvalidData)?,
            self.timestamp,
            optional_size.try_into().map_err(|_| Error::InvalidData)?,
            self.attributes,
        ));

        let bytes = unsafe {
            let ptr = coff.as_ref() as *const RawCoff as *const u8;
            from_raw_parts(ptr, size_of::<RawCoff>())
        };
        out.extend_from_slice(bytes);
        Ok(optional_size)
    }

    /// Write the optional header, including data dirs.
    fn write_opt(&mut self, out: &mut Vec<u8>, plus: bool) -> Result<()> {
        let mut code_sum = 0;
        let mut init_sum = 0;
        let mut uninit_sum = 0;
        let mut code_base = 0;
        let mut data_base = 0;
        let mut sections_sum: usize = 0;
        // Get section sizes
        for section in self.sections.iter() {
            if section.flags() & SectionFlags::CODE != SectionFlags::empty() {
                code_sum += section.virtual_size();
                code_base = section.virtual_address();
            }

            if section.flags() & SectionFlags::INITIALIZED != SectionFlags::empty() {
                init_sum += section.virtual_size();
                data_base = section.virtual_address();
            }

            if section.flags() & SectionFlags::UNINITIALIZED != SectionFlags::empty() {
                uninit_sum += section.virtual_size()
            }
            match section.flags() {
                SectionFlags::CODE => {
                    // code_sum += section.virtual_size();
                    // code_base = section.virtual_address();
                }
                SectionFlags::INITIALIZED => {
                    // init_sum += section.virtual_size();
                    // data_base = section.virtual_address();
                }
                // SectionFlags::UNINITIALIZED => uninit_sum += section.virtual_size(),
                _ => (),
            }

            let size: usize = section
                .virtual_size()
                .try_into()
                .map_err(|_| Error::InvalidData)?;
            sections_sum += size;
        }

        // Create standard subset
        let opt = RawPeOptStandard::new(
            if plus { PE32_64_MAGIC } else { PE32_MAGIC },
            self.linker_ver.0,
            self.linker_ver.1,
            code_sum,
            init_sum,
            uninit_sum,
            // FIXME: Entry point will be incredibly error prone.
            self.entry,
            code_base,
        );
        let headers_size = (size_of::<RawDos>()
            + size_of::<RawPe>()
            + (size_of::<RawSectionHeader>() * self.sections.len()))
            as u64;
        let headers_size = headers_size + (self.file_align - (headers_size % self.file_align));

        // Image size, calculated as the headers size as a base, plus what its missing
        // Specifically:
        // - Data dirs
        // - Size of all section
        let image_size = headers_size as usize
            + (size_of::<RawDataDirectory>() * self.data_dirs.len())
            + sections_sum;

        let image_size = image_size as u64;
        let image_size = image_size + (self.section_align - (image_size % self.section_align));
        // 568 + (512 - (568 % 512))
        if plus {
            let pe = RawPe32x64::new(
                opt,
                self.image_base,
                self.section_align as u32,
                self.file_align as u32,
                self.os_ver.0,
                self.os_ver.1,
                self.image_ver.0,
                self.image_ver.1,
                self.subsystem_ver.0,
                self.subsystem_ver.1,
                image_size as u32,
                headers_size as u32,
                self.subsystem,
                self.dll_attributes,
                self.stack.0,
                self.stack.1,
                self.heap.0,
                self.heap.1,
                self.data_dirs
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidData)?,
            );
            let bytes = unsafe {
                let ptr = &pe as *const RawPe32x64 as *const u8;
                from_raw_parts(ptr, size_of::<RawPe32x64>())
            };
            out.extend_from_slice(bytes);
        } else {
            #[cfg(no)]
            let pe = RawPe32::new(
                opt,
                self.image_base,
                self.section_align as u32,
                self.file_align as u32,
                0, // os_major,
                0, // os_minor,
                0, // image_major,
                0, // image_minor,
                0, // subsystem_major,
                0, // subsystem_minor,
                image_size as u32,
                headers_size as u32,
                self.subsystem,
                self.dll_attributes,
                self.stack.0,
                self.stack.1,
                self.heap.0,
                self.heap.1,
                self.data_dirs
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidData)?,
            );
            let pe = todo!();
            let bytes = unsafe {
                let ptr = &pe as *const () as *const RawPe32 as *const u8;
                from_raw_parts(ptr, size_of::<RawPe32>())
            };
            out.extend_from_slice(bytes);
        };

        // Data dirs
        let bytes = unsafe {
            let ptr = self.data_dirs.as_ptr() as *const u8;
            from_raw_parts(ptr, size_of::<RawDataDirectory>() * self.data_dirs.len())
        };
        out.extend_from_slice(bytes);

        Ok(())
    }

    /// Truncates `out` and writes [`Pe`] to it
    pub fn write(&mut self, out: &mut Vec<u8>) -> Result<()> {
        /// The way we create and write a PE file is primarily virtually.
        /// This means we pretend we've written a file and fill things in based
        /// on that.
        ///
        /// This should be exactly the same as just writing the file (correctly)
        /// and then reading it.
        ///
        /// The first and most basic things needed are the sections and data
        /// directories.
        ///
        /// Most other structures cant be created without
        /// information from or about these.
        ///
        /// The first structure we can create is [`RawDos`], and this is then
        /// written, followed by the PE COFF magic and COFF header.
        ///
        /// Next is the optional header,
        /// which needs to go through all sections to sum up their sizes before
        /// being written.
        struct _DummyHoverWriteDocs;
        // TODO: Go through sections, assign virtual addresses
        // Now knowing the full scope of sections, assign file offsets
        out.clear();
        let machine = self.machine;
        let plus = match machine {
            MachineType::AMD64 => Ok(true),
            MachineType::I386 => Ok(false),
            _ => Err(Error::InvalidData),
        }?;

        self.write_dos(out)?;
        let expected_opt_size = self.write_pe(out, machine, plus)?;

        let size = out.len();
        self.write_opt(out, plus)?;
        let size = out.len() - size;
        // dbg!(expected_opt_size, size);
        assert_eq!(expected_opt_size, size);

        // Section table
        for s in self.sections.iter() {
            let bytes = unsafe {
                let ptr = s.header.as_ref() as *const RawSectionHeader as *const u8;
                from_raw_parts(ptr, size_of::<RawSectionHeader>() * self.sections.len())
            };
            out.extend_from_slice(bytes);
        }

        // Align to next potential section start
        let size = out.len();
        let align = size + (self.section_align as usize - (size % self.section_align as usize));
        let align = align - size;
        out.reserve(align);
        for _ in 0..align {
            out.push(b'\0')
        }
        // FIXME: Have to be able to write to arbitrary offsets, actually.
        // Need a Seek, Read, Write, and Cursor impl?

        // Section data
        for (s, bytes) in self.sections.iter().zip(self.sections_data.iter()) {
            // Align
            let size = out.len();
            let align = size + (self.section_align as usize - (size % self.section_align as usize));
            let align = align - size;
            out.reserve(align + bytes.len());
            for _ in 0..align {
                out.push(b'\0')
            }
            out.extend_from_slice(bytes);
        }

        #[cfg(no)]
        let pe = Pe {
            dos,
            coff,
            opt,
            data_dirs: self.data_dirs,
            sections: VecOrSlice::Vec(self.sections.iter().map(|s| *s.header).collect()),
            base: None,
            _phantom: PhantomData,
        };

        Ok(())
    }

    /// Assign sections their virtual offsets and file offsets
    fn assign_sections(&mut self) {
        //
    }

    /// Get the next virtual address available for a section, or section align
    /// as a default.
    fn next_virtual_address(&mut self) -> u32 {
        // Highest VA seen, and its size
        let mut max_va = (self.section_align as u32, 0);
        for section in self.sections.iter() {
            let va = max_va.0.max(section.virtual_address());
            let size = section.virtual_size();
            max_va = (va, size);
        }
        let ret = max_va.0 + max_va.1;
        if ret % self.section_align as u32 != 0 {
            ret + (self.section_align as u32 - (ret % self.section_align as u32))
        } else {
            ret
        }
    }

    /// Get the next file offset available for a section, or file align
    /// as a default.
    fn next_file_offset(&mut self) -> u32 {
        // Highest offset seen, and its size
        let mut max_off = (self.file_align as u32, 0);
        for section in self.sections.iter() {
            let off = max_off.0.max(section.file_offset());
            let size = section.file_size();
            max_off = (off, size);
        }

        let ret = max_off.0 + max_off.1;
        if ret % self.file_align as u32 != 0 {
            ret + (self.file_align as u32 - (ret % self.file_align as u32))
        } else {
            ret
        }
    }
}

/// Build a section for a [`Pe`] file.
#[derive(Debug)]
pub struct SectionBuilder<'data> {
    name: [u8; 8],
    data: VecOrSlice<'data, u8>,
    attr: SectionFlags,
    offset: Option<u32>,
}

impl<'data> SectionBuilder<'data> {
    pub fn new() -> Self {
        Self {
            name: [b'\0'; 8],
            data: VecOrSlice::Slice(&[]),
            attr: SectionFlags::empty(),
            offset: None,
        }
    }

    /// Name of the section. Required.
    ///
    /// If `name` is more than 8 bytes, it is truncated.
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name[..name.len().min(8)].copy_from_slice(name.as_bytes());
        self
    }

    /// Name of the section
    ///
    /// # Errors
    ///
    /// - If `name` is more than 8 bytes.
    pub fn try_name(&mut self, name: &str) -> Result<&mut Self> {
        if name.len() > 8 {
            return Err(Error::InvalidData);
        }
        self.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(self)
    }

    /// Data in the section. Required.
    pub fn data(&mut self, data: &'data [u8]) -> &mut Self {
        self.data = VecOrSlice::Slice(data);
        self
    }

    /// Data in the section. Required.
    pub fn data_vec(&mut self, data: Vec<u8>) -> &mut Self {
        // TODO: From/Into impl
        self.data = VecOrSlice::Vec(data);
        self
    }

    /// File offset. Defaults to next available, or file alignment.
    ///
    /// This MUST be a power of 2 between 512 and 64K.
    ///
    /// If not it will silently be rounded up to the next alignment.
    pub fn file_offset(&mut self, offset: u32) -> &mut Self {
        self.offset = Some(offset);
        self
    }

    /// Flags/Attributes for the section
    pub fn attributes(&mut self, attr: SectionFlags) -> &mut Self {
        self.attr = attr;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use anyhow::Result;

    use super::*;

    // EFI Stub kernel
    static _TEST_IMAGE: &[u8] =
        include_bytes!("../../uefi-stub/target/x86_64-unknown-uefi/debug/uefi-stub.efi");
    // static TEST_IMAGE: &[u8] = include_bytes!("/boot/vmlinuz-linux");
    static TEST_IMAGE: &[u8] = include_bytes!("/boot/EFI/Linux/linux.efi");
    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[test]
    fn dev() -> Result<()> {
        // let mut pe = PeHeader::from_bytes(TEST_IMAGE);
        let mut pe = unsafe { Pe::from_ptr(TEST_IMAGE.as_ptr(), TEST_IMAGE.len()) };
        dbg!(&pe);
        let pe = pe?;
        for section in pe.sections() {
            dbg!(section.name());
        }
        let cmdline = pe.section(".cmdline").unwrap();
        dbg!(&cmdline);
        let cmdline = core::str::from_utf8(
            &TEST_IMAGE[cmdline.file_offset() as usize..][..cmdline.file_size() as usize],
        );
        dbg!(&cmdline);

        panic!();

        Ok(())
    }

    /// Test ability to write a copy of rustup-init.exe, from our own parsed
    /// data structures.
    #[test]
    fn write_rustup() -> Result<()> {
        let mut in_pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        dbg!(&in_pe);
        let mut pe = PeBuilder::new();
        let mut pe = pe.machine(MachineType::AMD64);
        pe.subsystem(Subsystem::WINDOWS_CLI)
            .dos(*in_pe.dos(), VecOrSlice::Slice(in_pe.dos_stub()))
            .stack((1048576, 4096))
            .heap((1048576, 4096))
            .entry(in_pe.entry())
            .timestamp(in_pe.timestamp())
            .dll_attributes(
                DllCharacteristics::DYNAMIC_BASE
                    | DllCharacteristics::HIGH_ENTROPY_VA
                    | DllCharacteristics::NX_COMPAT
                    | DllCharacteristics::TERMINAL_SERVER,
            )
            .image_base(in_pe.image_base())
            .os_version(in_pe.os_version())
            .image_version(in_pe.image_version())
            .subsystem_version(in_pe.subsystem_version())
            .linker_version(in_pe.linker_version())
            //
            .section(
                SectionBuilder::new()
                    .name(".text")
                    .data({
                        //
                        let sec = in_pe.section(".text").unwrap();
                        &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size() as usize]
                    })
                    .file_offset(1024)
                    .attributes(SectionFlags::CODE | SectionFlags::EXEC | SectionFlags::READ),
            )
            .section(
                SectionBuilder::new()
                    .name(".rdata")
                    .data({
                        //
                        let sec = in_pe.section(".rdata").unwrap();
                        &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size() as usize]
                    })
                    .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
            );
        // .section(
        //     SectionBuilder::new()
        //         .name(".data")
        //         .data({
        //             //
        //             let sec = in_pe.section(".data").unwrap();
        //             &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size()
        // as usize]         })
        //         .attributes(
        //             SectionFlags::INITIALIZED | SectionFlags::READ |
        // SectionFlags::WRITE,         ),
        // )
        // .section(
        //     SectionBuilder::new()
        //         .name(".pdata")
        //         .data({
        //             //
        //             let sec = in_pe.section(".pdata").unwrap();
        //             &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size()
        // as usize]         })
        //         .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
        // )
        // .section(
        //     SectionBuilder::new()
        //         .name("_RDATA")
        //         .data({
        //             //
        //             let sec = in_pe.section("_RDATA").unwrap();
        //             &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size()
        // as usize]         })
        //         .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
        // )
        // .section(
        //     SectionBuilder::new()
        //         .name(".reloc")
        //         .data({
        //             //
        //             let sec = in_pe.section(".reloc").unwrap();
        //             &RUSTUP_IMAGE[sec.file_offset() as usize..][..sec.virtual_size()
        // as usize]         })
        //         .attributes(
        //             SectionFlags::INITIALIZED | SectionFlags::READ |
        // SectionFlags::DISCARDABLE,         ),
        // );
        let mut out: Vec<u8> = Vec::new();
        pe.write(&mut out)?;
        //
        let out_pe = Pe::from_bytes(&out);
        dbg!(&out_pe);

        panic!();
        Ok(())
    }

    /// Test ability to read rustup-init.exe
    #[test]
    fn read_rustup() -> Result<()> {
        let mut pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        dbg!(&pe);
        assert_eq!(pe.machine_type(), MachineType::AMD64);
        assert_eq!(pe.sections().count(), 6);
        assert_eq!(pe.timestamp(), 1657657359);
        assert_eq!(pe.subsystem(), Subsystem::WINDOWS_CLI);
        assert_eq!(
            pe.attributes(),
            CoffAttributes::IMAGE | CoffAttributes::LARGE_ADDRESS_AWARE
        );
        assert_eq!(pe.image_base(), 5368709120);
        // assert_eq!(pe.section_align(), 4096);
        // assert_eq!(pe.file_align(), 512);
        assert_eq!(pe.os_version(), (6, 0));
        // assert_eq!(pe.image_size(), 10096640);
        // assert_eq!(pe.headers_size(), 1024);
        // assert_eq!(
        //     pe.dll_attributes(),
        //     DllCharacteristics::HIGH_ENTROPY_VA
        //         | DllCharacteristics::DYNAMIC_BASE
        //         | DllCharacteristics::NX_COMPAT
        //         | DllCharacteristics::TERMINAL_SERVER
        // );
        // assert_eq!(pe.stack_reserve(), 1048576);
        // assert_eq!(pe.stack_commit(), 4096);
        // assert_eq!(pe.heap_reserve(), 1048576);
        // assert_eq!(pe.heap_commit(), 4096);
        // assert_eq!(pe.data_dirs(), 16);

        assert_eq!({ pe.coff.machine }, MachineType::AMD64);
        assert_eq!({ pe.coff.sections }, 6);
        assert_eq!({ pe.coff.time }, 1657657359);
        assert_eq!({ pe.coff.sym_offset }, 0);
        assert_eq!({ pe.coff.num_sym }, 0);
        assert_eq!({ pe.coff.optional_size }, 240);
        assert_eq!(
            { pe.coff.attributes },
            CoffAttributes::IMAGE | CoffAttributes::LARGE_ADDRESS_AWARE
        );
        let opt = match pe.opt() {
            ImageHeader::Raw64(o) => *o,
            ImageHeader::Raw32(_) => panic!("Invalid PE Optional Header"),
        };
        assert_eq!({ opt.standard.linker_major }, 14);
        assert_eq!({ opt.standard.linker_minor }, 32);
        assert_eq!({ opt.standard.code_size }, 7170048);
        assert_eq!({ opt.standard.init_size }, 2913792);
        assert_eq!({ opt.standard.uninit_size }, 0);
        assert_eq!({ opt.standard.entry_offset }, 6895788);
        assert_eq!({ opt.standard.code_base }, 4096);
        assert_eq!({ opt.image_base }, 5368709120);
        assert_eq!({ opt.section_align }, 4096);
        assert_eq!({ opt.file_align }, 512);
        assert_eq!({ opt.os_major }, 6);
        assert_eq!({ opt.os_minor }, 0);
        assert_eq!({ opt.image_major }, 0);
        assert_eq!({ opt.image_minor }, 0);
        assert_eq!({ opt.subsystem_major }, 6);
        assert_eq!({ opt.subsystem_minor }, 0);
        assert_eq!({ opt._reserved_win32 }, 0);
        assert_eq!({ opt.image_size }, 10096640);
        assert_eq!({ opt.headers_size }, 1024);
        assert_eq!({ opt.checksum }, 0);
        assert_eq!({ opt.subsystem }, Subsystem::WINDOWS_CLI);
        assert_eq!(
            { opt.dll_characteristics },
            DllCharacteristics::HIGH_ENTROPY_VA
                | DllCharacteristics::DYNAMIC_BASE
                | DllCharacteristics::NX_COMPAT
                | DllCharacteristics::TERMINAL_SERVER
        );
        assert_eq!({ opt.stack_reserve }, 1048576);
        assert_eq!({ opt.stack_commit }, 4096);
        assert_eq!({ opt.stack_reserve }, 1048576);
        assert_eq!({ opt.stack_commit }, 4096);
        assert_eq!({ opt._reserved_loader_flags }, 0);
        assert_eq!({ opt.data_dirs }, 16);

        // panic!();

        Ok(())
    }
}
