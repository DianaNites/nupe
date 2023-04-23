//! `no_std` COFF/PE image handling library
//!
//! # Examples
//!
//! // TODO: Examples
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
    clippy::missing_safety_doc,
    unreachable_code
)]
#![allow(clippy::comparison_chain)]
extern crate alloc;

pub mod builder;
pub mod dos;
pub mod error;
pub mod exec;
mod internal;
mod pe;
pub mod raw;
pub mod rich;

use raw::{RawDataDirectory, RawSectionHeader};

use crate::error::Error;
pub use crate::{
    internal::{DataDirIdent, OwnedOrRef, SectionFlags, VecOrSlice},
    pe::*,
};

/// A PE Section
#[derive(Debug)]
pub struct Section<'data> {
    header: OwnedOrRef<'data, RawSectionHeader>,
    size: u32,
    base: Option<(*const u8, usize)>,
}

impl<'data> Section<'data> {
    fn new(
        header: OwnedOrRef<'data, RawSectionHeader>,
        _file_align: u32,
        base: Option<(*const u8, usize)>,
    ) -> Self {
        Self {
            header,
            size: {
                // let big = header.raw_size.max(header.virtual_size);
                // TODO: Calculate size
                0
            },
            base,
        }
    }

    /// Address to the first byte of the section, relative to the image base.
    pub fn mem_ptr(&self) -> u32 {
        self.header.mem_ptr
    }

    /// Size of the section in memory, zero padded if needed.
    pub fn mem_size(&self) -> u32 {
        self.header.mem_size
    }

    /// Offset of the section data on disk
    pub fn disk_offset(&self) -> u32 {
        self.header.disk_offset
    }

    /// Size of the section data on disk
    ///
    /// # WARNING
    ///
    /// Be sure this is what you want. This field is a trap.
    /// You may instead want `Section::virtual_size`
    ///
    /// The file_size field is rounded up to a multiple of the file alignment,
    /// but virtual_size is not. That means file_size includes extra padding not
    /// actually part of the section, and that virtual_size is the true size.
    pub fn disk_size(&self) -> u32 {
        self.header.disk_size
    }

    /// Actual size of the sections data, without rounding or alignment.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Name of the section, with nul bytes stripped.
    ///
    /// Empty string is returned if invalid ASCII/UTF-8 somehow makes it here.
    pub fn name(&self) -> &str {
        self.header.name().unwrap_or_default()
    }

    /// Section flags/attributes/characteristics
    pub fn flags(&self) -> SectionFlags {
        self.header.attributes
    }

    /// Slice of the section data
    ///
    /// Returns [`None`] if not called on a loaded image, or if the section is
    /// outside the loaded image.
    pub fn virtual_data(&self) -> Option<&'data [u8]> {
        if let Some((base, size)) = self.base {
            if size
                .checked_sub(self.mem_ptr() as usize)
                .and_then(|s| s.checked_sub(self.mem_size() as usize))
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
                    base.wrapping_add(self.mem_ptr() as usize),
                    self.mem_size() as usize,
                )
            })
        } else {
            None
        }
    }
}

/// A PE Data Directory
#[derive(Debug)]
pub struct DataDir<'data> {
    header: OwnedOrRef<'data, RawDataDirectory>,
}

impl<'data> DataDir<'data> {
    pub(crate) fn new(header: OwnedOrRef<'data, RawDataDirectory>) -> Self {
        Self { header }
    }

    /// Address of the data directory, relative to the image base.
    pub fn address(&self) -> u32 {
        self.header.address
    }

    /// Size of the data directory
    pub fn size(&self) -> u32 {
        self.header.size
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    // #![allow(
    //     unused_variables,
    //     unused_imports,
    //     unused_mut,
    //     unused_assignments,
    //     dead_code,
    //     clippy::let_unit_value,
    //     clippy::diverging_sub_expression,
    //     clippy::new_without_default,
    //     clippy::too_many_arguments,
    //     unreachable_code
    // )]
    use anyhow::Result;

    use super::{builder::*, *};
    use crate::{
        exec::ExecHeader,
        internal::test_util::*,
        raw::{
            coff::{CoffFlags, MachineType},
            dos::RawDos,
            exec::{ExecFlags, RawExec64, Subsystem},
            pe::*,
        },
    };

    /// Test ability to write a copy of rustup-init.exe, from our own parsed
    /// data structures.
    #[test]
    fn write_rustup_helper() -> Result<()> {
        let in_pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        let pe = PeBuilder::from_pe(&in_pe, RUSTUP_IMAGE);

        let mut out = Vec::new();
        pe.write(&mut out)?;

        assert_eq!(RUSTUP_IMAGE, &out[..]);
        Ok(())
    }

    /// Test ability to write a copy of rustup-init.exe,
    /// semi-manually using known values
    #[test]
    fn write_rustup_manual() -> Result<()> {
        let in_pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        let mut pe = PeBuilder::new();
        let pe = pe.machine(MachineType::AMD64, true);
        {
            pe.subsystem(Subsystem::WINDOWS_CLI)
                .dos(*in_pe.dos(), VecOrSlice::Slice(in_pe.dos_stub()))
                .stack((1048576, 4096))
                .heap((1048576, 4096))
                .entry(in_pe.entry())
                .timestamp(in_pe.timestamp())
                .dll_attributes(
                    ExecFlags::DYNAMIC_BASE
                        | ExecFlags::HIGH_ENTROPY_VA
                        | ExecFlags::NX_COMPAT
                        | ExecFlags::TERMINAL_SERVER,
                )
                .image_base(in_pe.image_base())
                .os_version(in_pe.os_version())
                .image_version(in_pe.image_version())
                .subsystem_version(in_pe.subsystem_version())
                .linker_version(in_pe.linker_version())
                .data_dir(DataDirIdent::Import, 9719132, 260)
                .data_dir(DataDirIdent::Exception, 9752576, 276660)
                .data_dir(DataDirIdent::BaseReloc, 10035200, 61240)
                .data_dir(DataDirIdent::Debug, 8757424, 84)
                .data_dir(DataDirIdent::ThreadLocalStorage, 8757632, 40)
                .data_dir(DataDirIdent::LoadConfig, 8757104, 320)
                .data_dir(DataDirIdent::Iat, 7176192, 2248);
        }
        {
            pe.section({
                let sec = in_pe.section(".text").unwrap();
                SectionBuilder::new()
                    .name(".text")
                    .data({
                        &RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize]
                    })
                    .mem_size(sec.mem_size())
                    .disk_offset(1024)
                    .attributes(SectionFlags::CODE | SectionFlags::EXEC | SectionFlags::READ)
            })
            .section({
                let sec = in_pe.section(".rdata").unwrap();
                SectionBuilder::new()
                    .name(".rdata")
                    .data({
                        &RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize]
                    })
                    .mem_size(sec.mem_size())
                    .attributes(SectionFlags::INITIALIZED | SectionFlags::READ)
            })
            .section({
                let sec = in_pe.section(".data").unwrap();
                SectionBuilder::new()
                    .name(".data")
                    .data(&RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize])
                    .mem_size(sec.mem_size())
                    .attributes(
                        SectionFlags::INITIALIZED | SectionFlags::READ | SectionFlags::WRITE,
                    )
            })
            .section({
                let sec = in_pe.section(".pdata").unwrap();
                SectionBuilder::new()
                    .name(".pdata")
                    .data({
                        &RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize]
                    })
                    .mem_size(sec.mem_size())
                    .attributes(SectionFlags::INITIALIZED | SectionFlags::READ)
            })
            .section({
                let sec = in_pe.section("_RDATA").unwrap();
                SectionBuilder::new()
                    .name("_RDATA")
                    .data({
                        &RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize]
                    })
                    .mem_size(sec.mem_size())
                    .attributes(SectionFlags::INITIALIZED | SectionFlags::READ)
            })
            .section({
                let sec = in_pe.section(".reloc").unwrap();
                SectionBuilder::new()
                    .name(".reloc")
                    .data({
                        &RUSTUP_IMAGE[sec.disk_offset() as usize..][..sec.disk_size() as usize]
                    })
                    .mem_size(sec.mem_size())
                    .attributes(
                        SectionFlags::INITIALIZED | SectionFlags::READ | SectionFlags::DISCARDABLE,
                    )
            });
        }
        // NOTE: Rustup's value isn't correct
        pe.code_size(in_pe.opt().code_size());
        pe.init_size(in_pe.opt().init_size());
        // pe.uninit_size(in_pe.opt().uninit_size());
        let mut out: Vec<u8> = Vec::new();
        pe.write(&mut out)?;
        //
        let out_pe = Pe::from_bytes(&out);
        dbg!(&out_pe);
        if let Ok(out_pe) = out_pe {
            assert_eq!(in_pe.dos_stub(), out_pe.dos_stub());
            assert_eq!({ in_pe.dos().pe_offset }, { out_pe.dos().pe_offset });
        }

        let x = size_of::<RawDos>()
            + in_pe.dos_stub().len()
            + size_of::<RawPe>()
            + size_of::<RawExec64>()
            + in_pe.data_dirs_len() as usize * size_of::<RawDataDirectory>()
            + in_pe.sections_len() * size_of::<RawSectionHeader>()
            + in_pe
                .sections()
                .map(|s| s.disk_size() as usize)
                .sum::<usize>();
        let y = size_of::<RawDos>()
            + in_pe.dos_stub().len()
            + size_of::<RawPe>()
            + size_of::<RawExec64>()
            + in_pe.data_dirs_len() as usize * size_of::<RawDataDirectory>()
            + in_pe.sections_len() * size_of::<RawSectionHeader>()
            + in_pe
                .sections()
                .take(0)
                .map(|s| s.disk_size() as usize)
                .sum::<usize>();
        let x = x - y;
        assert_eq!(&RUSTUP_IMAGE[y..][..x], &out[y..][..x]);
        assert_eq!(&RUSTUP_IMAGE[..x], &out[..x]);
        assert_eq!(RUSTUP_IMAGE, &out[..]);

        Ok(())
    }

    /// Test ability to correctly read rustup-init.exe
    #[test]
    fn read_rustup() -> Result<()> {
        let pe = Pe::from_bytes(RUSTUP_IMAGE)?;

        assert_eq!(pe.machine_type(), MachineType::AMD64);
        assert_eq!(pe.sections_len(), 6);
        assert_eq!(pe.timestamp(), 1657657359);
        assert_eq!(pe.subsystem(), Subsystem::WINDOWS_CLI);
        assert_eq!(
            pe.attributes(),
            CoffFlags::IMAGE | CoffFlags::LARGE_ADDRESS_AWARE
        );
        assert_eq!(pe.image_base(), 5368709120);
        assert_eq!(pe.section_align(), 4096);
        assert_eq!(pe.file_align(), 512);
        assert_eq!(pe.os_version(), (6, 0));
        assert_eq!(pe.image_size(), 10096640);
        assert_eq!(pe.headers_size(), 1024);
        assert_eq!(
            pe.dll_attributes(),
            ExecFlags::HIGH_ENTROPY_VA
                | ExecFlags::DYNAMIC_BASE
                | ExecFlags::NX_COMPAT
                | ExecFlags::TERMINAL_SERVER
        );
        assert_eq!(pe.stack(), (1048576, 4096));
        assert_eq!(pe.heap(), (1048576, 4096));
        assert_eq!(pe.data_dirs_len(), 16);

        assert_eq!(pe.data_dirs().count(), 16);
        assert_eq!(pe.sections().count(), 6);

        assert_eq!({ pe.coff().machine }, MachineType::AMD64);
        assert_eq!({ pe.coff().sections }, 6);
        assert_eq!({ pe.coff().time }, 1657657359);
        assert_eq!({ pe.coff().sym_offset }, 0);
        assert_eq!({ pe.coff().sym_len }, 0);
        assert_eq!({ pe.coff().exec_header_size }, 240);
        assert_eq!(
            { pe.coff().file_attributes },
            CoffFlags::IMAGE | CoffFlags::LARGE_ADDRESS_AWARE
        );
        let opt = match pe.opt() {
            ExecHeader::Raw64(o) => *o,
            ExecHeader::Raw32(_) => panic!("Invalid PE Optional Header"),
        };
        assert_eq!({ opt.standard.linker_major }, 14);
        assert_eq!({ opt.standard.linker_minor }, 32);
        assert_eq!({ opt.standard.code_size }, 7170048);
        assert_eq!({ opt.standard.init_size }, 2913792);
        assert_eq!({ opt.standard.uninit_size }, 0);
        assert_eq!({ opt.standard.entry_ptr }, 6895788);
        assert_eq!({ opt.standard.code_ptr }, 4096);
        assert_eq!({ opt.image_base }, 5368709120);
        assert_eq!({ opt.mem_align }, 4096);
        assert_eq!({ opt.disk_align }, 512);
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
            { opt.dll_attributes },
            ExecFlags::HIGH_ENTROPY_VA
                | ExecFlags::DYNAMIC_BASE
                | ExecFlags::NX_COMPAT
                | ExecFlags::TERMINAL_SERVER
        );
        assert_eq!({ opt.stack_reserve }, 1048576);
        assert_eq!({ opt.stack_commit }, 4096);
        assert_eq!({ opt.stack_reserve }, 1048576);
        assert_eq!({ opt.stack_commit }, 4096);
        assert_eq!({ opt._reserved_loader_attributes }, 0);
        assert_eq!({ opt.data_dirs }, 16);

        Ok(())
    }
}
