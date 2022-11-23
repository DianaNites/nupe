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

use core::mem;

use bitflags::bitflags;

use crate::error::{Error, Result};

const DOS_MAGIC: &[u8] = b"MZ";
const DOS_PE_OFFSET: usize = 0x3C;
const PE_MAGIC: &[u8] = b"PE\0\0";

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

#[derive(Debug)]
pub struct Pe<'bytes> {
    pe: &'bytes RawPe,
}

impl<'bytes> Pe<'bytes> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
        Ok(Self { pe: raw })
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
