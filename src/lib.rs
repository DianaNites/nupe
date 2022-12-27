//! PE image handling
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![allow(
    unused_variables,
    unused_imports,
    unused_mut,
    unused_assignments,
    dead_code,
    clippy::let_unit_value,
    unreachable_code
)]
extern crate alloc;

pub mod error;
mod internal;
pub mod raw;
use alloc::vec::Vec;
use core::mem::{self, size_of};

use bitflags::bitflags;
use raw::*;

use crate::error::{Error, Result};

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
enum ImageHeader {
    Raw32(RawPe32),
    Raw64(RawPe32x64),
}

/// A PE Section
#[derive(Debug)]
pub struct Section {
    header: RawSectionHeader,
}

impl Section {
    pub fn virtual_address(&self) -> u32 {
        self.header.virtual_address
    }

    pub fn virtual_size(&self) -> u32 {
        self.header.virtual_size
    }

    pub fn file_offset(&self) -> u32 {
        self.header.raw_ptr
    }

    pub fn file_size(&self) -> u32 {
        self.header.raw_size
    }

    pub fn name(&self) -> &str {
        // TODO: Validate UTF-8 early on and use unchecked?
        core::str::from_utf8(&self.header.name).unwrap()
    }
}

/// A PE file
#[derive(Debug)]
pub struct PeHeader {
    dos: RawDos,
    coff: RawCoff,
    opt: ImageHeader,
    data_dirs: Vec<RawDataDirectory>,
    sections: Vec<Section>,
}

impl PeHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let dos = RawDos::from_bytes(bytes)?;
        let pe_bytes = bytes
            .get(dos.pe_offset as usize..)
            .ok_or(Error::NotEnoughData)?;
        let pe = RawPe::from_bytes(pe_bytes)?;
        let opt_size = pe.coff.optional_size as usize;
        let opt_bytes = pe_bytes
            .get(size_of::<RawPe>()..)
            .ok_or(Error::NotEnoughData)?
            .get(..opt_size)
            .ok_or(Error::NotEnoughData)?;
        let opt = RawPeOptStandard::from_bytes(opt_bytes)?;
        if opt.magic == PE32_64_MAGIC {
            let header = unsafe {
                &*(opt_bytes
                    .get(..size_of::<RawPe32x64>())
                    .ok_or(Error::NotEnoughData)?
                    .as_ptr() as *const RawPe32x64)
            };
            dbg!(&header);
            let data_size = size_of::<RawDataDirectory>() * header.data_dirs as usize;

            let data = opt_bytes
                .get(size_of::<RawPe32x64>()..)
                .ok_or(Error::NotEnoughData)?
                .get(..data_size)
                .ok_or(Error::NotEnoughData)?;
            let data_dirs = unsafe {
                core::slice::from_raw_parts(
                    data.as_ptr() as *const RawDataDirectory,
                    header.data_dirs as usize,
                )
            };
            let sections_size = size_of::<RawSectionHeader>() * pe.coff.sections as usize;
            let sections_bytes = pe_bytes
                .get(opt_size + size_of::<RawPe>()..)
                .ok_or(Error::NotEnoughData)?
                .get(..sections_size)
                .ok_or(Error::NotEnoughData)?;
            let sections = unsafe {
                core::slice::from_raw_parts(
                    sections_bytes.as_ptr() as *const RawSectionHeader,
                    pe.coff.sections.into(),
                )
            };

            return Ok(Self {
                dos: *dos,
                coff: pe.coff,
                opt: ImageHeader::Raw64(*header),
                data_dirs: Vec::from(data_dirs),
                sections: sections.iter().map(|s| Section { header: *s }).collect(),
            });
        } else if opt.magic == PE32_MAGIC {
            todo!();
        } else {
            return Err(Error::InvalidPeMagic);
        }
        //
        todo!();
    }

    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter()
    }
}

#[cfg(no)]
impl<'bytes> PeHeader<'bytes> {
    /// Create a new [Pe] from a pointer and length to a PE image
    ///
    /// # Safety
    ///
    /// - `data` must be a valid for reads of `size` bytes.
    /// - `data` must be valid for the entire lifetime of `'bytes`.
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        // Data we've read, must always be less than or equal to size.
        let mut read = 0;
        if size <= size_of::<RawDos>() {
            return Err(Error::NotEnoughData);
        }
        read += size_of::<RawDos>();
        let dos = &*(data as *const RawDos);
        if dos.magic != DOS_MAGIC {
            return Err(Error::InvalidDosMagic);
        }
        let pe_offset = dos.pe_offset as usize;
        let dos_size = pe_offset - size_of::<RawDos>();
        read += dos_size;
        if size <= read + size_of::<RawPe>() {
            return Err(Error::NotEnoughData);
        }
        let pe = &*(data.wrapping_add(read) as *const RawPe);
        read += size_of::<RawPe>();
        if pe.sig != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        if size <= read + pe.coff.optional_size as usize {
            return Err(Error::NotEnoughData);
        }
        if size_of::<RawPeOptStandard>() > pe.coff.optional_size as usize {
            return Err(Error::NotEnoughData);
        }
        let opt = &*(data.wrapping_add(read) as *const RawPeOptStandard);
        // Intentionally not "reading" the RawPeOptStandard here
        if opt.magic == PE32_64_MAGIC {
            if size <= read + size_of::<RawPe32x64>() {
                return Err(Error::NotEnoughData);
            }
            let opt = &*(data.wrapping_add(read) as *const RawPe32x64);
            read += size_of::<RawPe32x64>();
            return Ok(Self {
                pe: MaybeMut::Ptr { data, size, read },
                coff: pe.coff,
                opt: ImageHeader::Raw64(*opt),
            });
            //
        } else if opt.magic == PE32_MAGIC {
            if size <= read + size_of::<RawPe32>() {
                return Err(Error::NotEnoughData);
            }
            let opt = &*(data.wrapping_add(read) as *const RawPe32);
            read += size_of::<RawPe32>();
            todo!();
            return Ok(Self {
                pe: MaybeMut::Ptr { data, size, read },
                coff: pe.coff,
                opt: ImageHeader::Raw32(*opt),
            });
        } else {
            return Err(Error::InvalidPeMagic);
        }

        todo!()
    }

    /// Create a new [Pe] from a pointer and length to a PE image
    ///
    /// # Safety
    ///
    /// See [`Pe::from_ptr`]
    pub unsafe fn from_ptr_mut(data: *mut u8, size: usize) -> Result<Self> {
        Self::from_ptr(data, size)
    }

    pub fn from_bytes(bytes: &'bytes [u8]) -> Result<Self> {
        // Safety: Trivially valid
        unsafe { Self::from_ptr(bytes.as_ptr(), bytes.len()) }
    }

    pub fn from_bytes_mut(bytes: &'bytes mut [u8]) -> Result<Self> {
        // Safety: Trivially valid
        unsafe { Self::from_ptr_mut(bytes.as_mut_ptr(), bytes.len()) }
    }

    /// Iterator over the sections in the file
    pub fn sections(&self) -> impl Iterator<Item = Section> {
        #[cfg(no)]
        {
            let sections_bytes = data
                .get(size_of::<RawDataDirectory>() * header.data_dirs as usize..)
                .ok_or(Error::NotEnoughData)?;
            let sections = unsafe {
                core::slice::from_raw_parts(
                    sections_bytes.as_ptr() as *const RawSectionHeader,
                    raw.coff.sections.into(),
                )
            };
        }
        let section_offset = ();
        core::iter::from_fn(|| {
            //
            None
        })
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

    #[test]
    fn dev() -> Result<()> {
        let mut pe = PeHeader::from_bytes(TEST_IMAGE);
        // dbg!(&pe);
        let pe = pe?;
        for section in pe.sections() {
            dbg!(section.name());
        }

        panic!();

        Ok(())
    }
}
