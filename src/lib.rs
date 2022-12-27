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
    unreachable_code
)]
extern crate alloc;

pub mod error;
mod internal;
pub mod raw;
mod section;
use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    mem::{self, size_of},
};

use bitflags::bitflags;
use raw::*;

use crate::error::{Error, Result};

/// Machine type, or architecture, of the PE file.
///
/// This is what architectures the file will run on.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachineType(u16);

impl MachineType {
    pub const UNKNOWN: Self = Self(0);
    pub const AMD64: Self = Self(0x8664);
    pub const I386: Self = Self(0x14C);
    pub const EBC: Self = Self(0xEBC);
}

impl core::fmt::Debug for MachineType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "MachineType::UNKNOWN"),
            Self::AMD64 => write!(f, "MachineType::AMD64"),
            Self::I386 => write!(f, "MachineType::I386"),
            Self::EBC => write!(f, "MachineType::EBC"),
            _ => f.debug_tuple("MachineType").field(&self.0).finish(),
        }
    }
}

impl core::fmt::Display for MachineType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl core::fmt::Debug for Subsystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl core::fmt::Display for Subsystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
        const RESERVED_0 = 0x0;
        const RESERVED_1 = 0x1;
        const RESERVED_2 = 0x2;
        const RESERVED_3 = 0x4;
        const NO_PAD = 0x8;
        const RESERVED_4 = 0x10;
        const CODE = 0x20;
        const INITIALIZED = 0x40;
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
        const EXEC = 0x20000000;
        const READ = 0x40000000;
        const WRITE = 0x80000000;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ImageHeader<'data> {
    Raw32(&'data RawPe32),
    Raw64(&'data RawPe32x64),
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
            Ok((ImageHeader::Raw64(opt), (data_ptr, opt.data_dirs as usize)))
        } else if opt.magic == PE32_MAGIC {
            let opt = RawPe32::from_ptr(data, size)?;
            let _data_size = size_of::<RawDataDirectory>()
                .checked_mul(opt.data_dirs as usize)
                .ok_or(Error::NotEnoughData)?;
            let data_ptr = data.wrapping_add(size_of::<RawPe32>()) as *const RawDataDirectory;
            Ok((ImageHeader::Raw32(opt), (data_ptr, opt.data_dirs as usize)))
        } else {
            Err(Error::InvalidPeMagic)
        }
    }

    /// Get a [`ImageHeader`] from `bytes`, and data dirs as slice
    ///
    /// Checks for the magic.
    fn from_bytes(bytes: &'data [u8]) -> Result<(Self, &'data [RawDataDirectory])> {
        let opt = unsafe {
            &*(bytes
                .get(..size_of::<RawPeOptStandard>())
                .ok_or(Error::NotEnoughData)?
                .as_ptr() as *const RawPeOptStandard)
        };
        if opt.magic == PE32_64_MAGIC {
            let opt = RawPe32x64::from_bytes(bytes)?;
            let data_size = size_of::<RawDataDirectory>() * opt.data_dirs as usize;
            let data_bytes = bytes
                .get(size_of::<RawPe32x64>()..)
                .ok_or(Error::NotEnoughData)?
                .get(..data_size)
                .ok_or(Error::NotEnoughData)?;
            Ok((ImageHeader::Raw64(opt), unsafe {
                core::slice::from_raw_parts(
                    data_bytes.as_ptr() as *const RawDataDirectory,
                    opt.data_dirs as usize,
                )
            }))
        } else if opt.magic == PE32_MAGIC {
            let opt = RawPe32::from_bytes(bytes)?;
            let data_size = size_of::<RawDataDirectory>() * opt.data_dirs as usize;
            let data_bytes = bytes
                .get(size_of::<RawPe32>()..)
                .ok_or(Error::NotEnoughData)?
                .get(..data_size)
                .ok_or(Error::NotEnoughData)?;
            Ok((ImageHeader::Raw32(opt), unsafe {
                core::slice::from_raw_parts(
                    data_bytes.as_ptr() as *const RawDataDirectory,
                    opt.data_dirs as usize,
                )
            }))
        } else {
            Err(Error::InvalidPeMagic)
        }
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
    header: &'data RawSectionHeader,
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
    pub fn file_size(&self) -> u32 {
        self.header.raw_size
    }

    /// Name of the section, with nul bytes stripped.
    ///
    /// Empty string is returned if invalid ASCII/UTF-8 somehow makes it here.
    pub fn name(&self) -> &str {
        self.header.name().unwrap_or_default()
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
#[derive(Debug)]
pub struct Pe<'data> {
    dos: &'data RawDos,
    coff: &'data RawCoff,
    opt: ImageHeader<'data>,
    data_dirs: &'data [RawDataDirectory],
    sections: &'data [RawSectionHeader],
    base: Option<(*const u8, usize)>,
    _phantom: PhantomData<&'data u8>,
}

impl<'data> Pe<'data> {
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    unsafe fn from_ptr_internal(data: *const u8, size: usize, loaded: bool) -> Result<Self> {
        let (dos, (pe_ptr, pe_size)) = RawDos::from_ptr(data, size)?;
        let (pe, (opt_ptr, opt_size), (section_ptr, section_size)) =
            RawPe::from_ptr(pe_ptr, pe_size)?;
        let (header, (data_ptr, data_size)) = ImageHeader::from_ptr(opt_ptr, opt_size)?;
        let data_dirs = unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
        let sections = unsafe { core::slice::from_raw_parts(section_ptr, section_size) };
        for s in sections {
            if !s.name.is_ascii() {
                return Err(Error::InvalidData);
            }
        }
        let base = if loaded { Some((data, size)) } else { None };

        Ok(Self {
            dos,
            coff: &pe.coff,
            opt: header,
            data_dirs,
            sections,
            base,
            _phantom: PhantomData,
        })
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
                header: s,
                base: self.base,
            })
    }

    /// Iterator over [`Section`]s
    pub fn sections(&self) -> impl Iterator<Item = Section> {
        self.sections.iter().map(|s| Section {
            header: s,
            base: self.base,
        })
    }

    /// Machine type
    pub fn machine_type(&self) -> MachineType {
        self.coff.machine
    }

    /// Subsystem
    pub fn subsystem(&self) -> Subsystem {
        self.opt.subsystem()
    }
}

impl<'data> Pe<'data> {
    /// Raw COFF header for this PE file
    ///
    /// This is only for advanced users.
    pub fn coff(&self) -> &'data RawCoff {
        self.coff
    }

    /// Raw COFF header for this PE file
    ///
    /// This is only for advanced users.
    pub fn opt(&self) -> &'data ImageHeader {
        &self.opt
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

    /// test ability to read rustup-init.exe
    #[test]
    fn read_rustup() -> Result<()> {
        let mut pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        dbg!(&pe);
        assert_eq!(pe.machine_type(), MachineType::AMD64);
        assert_eq!(pe.sections().count(), 6);
        // assert_eq!(pe.time(), 1657657359);
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
        // assert_eq!(
        //     pe.attributes(),
        //     CoffAttributes::IMAGE | CoffAttributes::LARGE_ADDRESS_AWARE
        // );
        // assert_eq!(pe.image_base(), 5368709120);
        // assert_eq!(pe.section_align(), 4096);
        // assert_eq!(pe.file_align(), 512);
        // assert_eq!(pe.os_ver(), (6, 0));
        // assert_eq!(pe.os(), (6, 0));
        // assert_eq!(pe.image_size(), 10096640);
        // assert_eq!(pe.headers_size(), 1024);
        assert_eq!(pe.subsystem(), Subsystem::WINDOWS_CLI);
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

        panic!();

        Ok(())
    }
}
