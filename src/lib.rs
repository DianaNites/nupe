//! PE image handling
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
    unused_variables,
    unused_imports,
    dead_code,
    clippy::let_unit_value,
    unreachable_code
)]
pub mod error;

use core::mem::{self, size_of};

use bitflags::bitflags;

use crate::error::{Error, Result};

const DOS_HEADER_SIZE: usize = 64;
const MIN_SIZE: usize = size_of::<RawPe>() + DOS_HEADER_SIZE;
const DOS_MAGIC: &[u8] = b"MZ";
const DOS_PE_OFFSET: usize = 0x3C;
const PE_MAGIC: &[u8] = b"PE\0\0";
const PE32_MAGIC: u16 = 0x10B;
const PE32_64_MAGIC: u16 = 0x20B;

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
    struct CoffAttributes: u16 {
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
    struct DllCharacteristics: u16 {
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

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawCoff {
    machine: MachineType,
    sections: u16,
    time: u32,
    sym_offset: u32,
    num_sym: u32,
    optional_size: u16,
    attributes: CoffAttributes,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe {
    coff: RawCoff,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPeOptStandard {
    magic: u16,
    linker_major: u8,
    linker_minor: u8,
    code_size: u32,
    init_size: u32,
    uninit_size: u32,
    entry_offset: u32,
    code_base: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32 {
    standard: RawPeOptStandard,
    data_base: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawPe32x64 {
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
    _reserved_win32: u32,
    image_size: u32,
    headers_size: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_characteristics: DllCharacteristics,
    stack_reserve: u64,
    stack_commit: u64,
    heap_reserve: u64,
    heap_commit: u64,
    _reserved_loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[derive(Debug)]
pub enum MaybeMut<'data> {
    Data(&'data [u8]),
    Mut(&'data mut [u8]),
}

#[derive(Debug)]
pub struct Pe<'bytes> {
    pe: MaybeMut<'bytes>,
}

impl<'bytes> Pe<'bytes> {
    pub fn from_bytes(bytes: &'bytes [u8]) -> Result<Self> {
        if bytes.len() < MIN_SIZE {
            return Err(Error::NotEnoughData);
        }
        if &bytes[..2] != DOS_MAGIC {
            return Err(Error::InvalidDosMagic);
        }
        let pe_offset =
            u32::from_ne_bytes(bytes[DOS_PE_OFFSET..][..4].try_into().unwrap()) as usize;
        let pe = &bytes[pe_offset..];
        dbg!(pe_offset);
        if &pe[..4] != PE_MAGIC {
            return Err(Error::InvalidPeMagic);
        }
        let pe = &pe[4..];
        let raw = unsafe { &*(pe.as_ptr() as *const RawPe) };
        let opt = raw.coff.optional_size;
        dbg!(&raw);
        let pe = &pe[size_of::<RawPe>()..];
        if pe.len() < opt.into() {
            return Err(Error::NotEnoughData);
        }
        let header = unsafe { &*(pe.as_ptr() as *const RawPeOptStandard) };
        if header.magic == PE32_64_MAGIC {
            let header = unsafe { &*(pe.as_ptr() as *const RawPe32x64) };
            dbg!(&header);
            //
        } else if header.magic == PE32_MAGIC {
        } else {
            return Err(Error::InvalidPeMagic);
        }
        //
        todo!();
        Ok(Self {
            pe: MaybeMut::Data(bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use anyhow::Result;

    use super::*;

    // EFI Stub kernel
    // static TEST_IMAGE: &[u8] = include_bytes!("/boot/vmlinuz-linux");
    static TEST_IMAGE: &[u8] =
        include_bytes!("../../uefi-stub/target/x86_64-unknown-uefi/debug/uefi-stub.efi");

    #[test]
    fn dev() -> Result<()> {
        let pe = Pe::from_bytes(TEST_IMAGE);
        dbg!(&pe);
        let pe = pe?;
        dbg!(&pe);

        panic!();

        Ok(())
    }
}
