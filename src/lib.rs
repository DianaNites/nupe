//! `no_std` COFF/PE image handling library
//!
//! # Examples
//!
//! ```rust
//! use nupe::Pe;
//! ```
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
        let small_pe = Pe::from_bytes(SMALLEST_PE)?;
        let nothing = Pe::from_bytes(NOTHING)?;
        let smallest_sections = Pe::from_bytes(SMALLEST_SECTIONS)?;
        let smallest_no_overlap = Pe::from_bytes(SMALLEST_NO_OVERLAP)?;

        let mut pe_out: Vec<u8> = Vec::new();
        let mut small_pe_out: Vec<u8> = Vec::new();
        let mut nothing_out: Vec<u8> = Vec::new();
        let mut smallest_sections_out: Vec<u8> = Vec::new();
        let mut smallest_no_overlap_out: Vec<u8> = Vec::new();

        let pe_build = PeBuilder::from_pe(&pe, RUSTUP_IMAGE);
        let small_pe_build = PeBuilder::from_pe(&small_pe, SMALLEST_PE);
        let nothing_build = PeBuilder::from_pe(&nothing, NOTHING);
        let smallest_sections_build = PeBuilder::from_pe(&smallest_sections, SMALLEST_SECTIONS);
        let smallest_no_overlap_build =
            PeBuilder::from_pe(&smallest_no_overlap, SMALLEST_NO_OVERLAP);

        pe_build.write(&mut pe_out)?;
        // small_pe_build.write(&mut small_pe_out)?;
        // nothing_build.write(&mut nothing_out)?;
        // smallest_sections_build.write(&mut smallest_sections_out)?;
        // smallest_no_overlap_build.write(&mut smallest_no_overlap_out)?;

        let pe_ = Pe::from_bytes(&pe_out)?;
        // let small_pe_ = Pe::from_bytes(&small_pe_out)?;
        // let nothing_ = Pe::from_bytes(&nothing_out)?;
        // let smallest_sections_ = Pe::from_bytes(&smallest_sections_out)?;
        // let smallest_no_overlap_ = Pe::from_bytes(&smallest_no_overlap_out)?;

        assert_eq!(pe, pe_);
        // assert_eq!(small_pe, small_pe_);
        // assert_eq!(nothing, nothing_);
        // assert_eq!(smallest_sections, smallest_sections_);
        // assert_eq!(smallest_no_overlap, smallest_no_overlap_);

        // Miri and insta don't work well together
        // But we only care about UB, which can only happen above.
        #[cfg(not(miri))]
        {
            insta::assert_debug_snapshot!(pe, @r###"
        Pe {
            dos: Dos {
                dos: Ref(
                    RawDos {
                        magic: b"MZ",
                        last_bytes: 144,
                        pages: 3,
                        relocations: 0,
                        header_size: 4,
                        min_alloc: 0,
                        max_alloc: 65535,
                        initial_ss: 0,
                        initial_sp: 184,
                        checksum: 0,
                        initial_ip: 0,
                        initial_cs: 0,
                        relocation_offset: 64,
                        overlay_num: 0,
                        _reserved: [0u16; 4],
                        oem_id: 0,
                        oem_info: 0,
                        _reserved2: [0u8; 20],
                        pe_offset: 272,
                    },
                ),
                stub: DOS code (len 208),
            },
            coff: Ref(
                RawCoff {
                    machine: MachineType::AMD64,
                    sections: 6,
                    time: 1657657359,
                    sym_offset: 0,
                    sym_len: 0,
                    exec_header_size: 240,
                    file_attributes: CoffFlags(
                        IMAGE | LARGE_ADDRESS_AWARE,
                    ),
                },
            ),
            rich: Some(
                Rich {
                    header: Ref(
                        RawRich {
                            magic: b"Rich",
                            key: 3516315803,
                        },
                    ),
                    entries: [
                        RawRichEntry {
                            id: 17004619,
                            - product_id: 259,
                            - build_id: 30795,
                            count: 9,
                        },
                        RawRichEntry {
                            id: 17135691,
                            - product_id: 261,
                            - build_id: 30795,
                            count: 188,
                        },
                        RawRichEntry {
                            id: 17070155,
                            - product_id: 260,
                            - build_id: 30795,
                            count: 12,
                        },
                        RawRichEntry {
                            id: 16611936,
                            - product_id: 253,
                            - build_id: 31328,
                            count: 5,
                        },
                        RawRichEntry {
                            id: 17136224,
                            - product_id: 261,
                            - build_id: 31328,
                            count: 41,
                        },
                        RawRichEntry {
                            id: 17070688,
                            - product_id: 260,
                            - build_id: 31328,
                            count: 18,
                        },
                        RawRichEntry {
                            id: 17005152,
                            - product_id: 259,
                            - build_id: 31328,
                            count: 10,
                        },
                        RawRichEntry {
                            id: 16873857,
                            - product_id: 257,
                            - build_id: 31105,
                            count: 22,
                        },
                        RawRichEntry {
                            id: 16873547,
                            - product_id: 257,
                            - build_id: 30795,
                            count: 5,
                        },
                        RawRichEntry {
                            id: 65536,
                            - product_id: 1,
                            - build_id: 0,
                            count: 283,
                        },
                        RawRichEntry {
                            id: 17070692,
                            - product_id: 260,
                            - build_id: 31332,
                            count: 148,
                        },
                        RawRichEntry {
                            id: 0,
                            - product_id: 0,
                            - build_id: 0,
                            count: 15,
                        },
                        RawRichEntry {
                            id: 16939620,
                            - product_id: 258,
                            - build_id: 31332,
                            count: 1,
                        },
                    ],
                },
            ),
            exec: Raw64(
                Ref(
                    RawExec64 {
                        standard: RawPeImageStandard {
                            magic: PE32_64_MAGIC,
                            linker_major: 14,
                            linker_minor: 32,
                            code_size: 7170048,
                            init_size: 2913792,
                            uninit_size: 0,
                            entry_ptr: 6895788,
                            code_ptr: 4096,
                        },
                        image_base: 5368709120,
                        mem_align: 4096,
                        disk_align: 512,
                        os_major: 6,
                        os_minor: 0,
                        image_major: 0,
                        image_minor: 0,
                        subsystem_major: 6,
                        subsystem_minor: 0,
                        _reserved_win32: 0,
                        image_size: 10096640,
                        headers_size: 1024,
                        checksum: 0,
                        subsystem: Subsystem::WINDOWS_CLI,
                        dll_attributes: ExecFlags(
                            HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER,
                        ),
                        stack_reserve: 1048576,
                        stack_commit: 4096,
                        heap_reserve: 1048576,
                        heap_commit: 4096,
                        _reserved_loader_attributes: 0,
                        data_dirs: 16,
                    },
                ),
            ),
            data_dirs: [
                "Export Table" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Import Table" RawDataDirectory {
                    address: 9719132,
                    size: 260,
                },
                "Resource Table" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Exception Table" RawDataDirectory {
                    address: 9752576,
                    size: 276660,
                },
                "Certificate Table" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Base Relocations Table" RawDataDirectory {
                    address: 10035200,
                    size: 61240,
                },
                "Debug Data" RawDataDirectory {
                    address: 8757424,
                    size: 84,
                },
                "Architecture" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Global Ptr" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Thread Local Storage Table" RawDataDirectory {
                    address: 8757632,
                    size: 40,
                },
                "Load Config Table" RawDataDirectory {
                    address: 8757104,
                    size: 320,
                },
                "Bound Import Table" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "IAT" RawDataDirectory {
                    address: 7176192,
                    size: 2248,
                },
                "Delay Import Descriptor" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "CLR Runtime Header" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
                "Reserved" RawDataDirectory {
                    address: 0,
                    size: 0,
                },
            ],
            sections: Slice(
                [
                    RawSectionHeader {
                        name(str): ".text",
                        virtual_size: 7169808,
                        virtual_address: 4096,
                        raw_size: 7170048,
                        raw_ptr: 1024,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | CODE | EXEC | READ,
                        ),
                    },
                    RawSectionHeader {
                        name(str): ".rdata",
                        virtual_size: 2550960,
                        virtual_address: 7176192,
                        raw_size: 2551296,
                        raw_ptr: 7171072,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | INITIALIZED | READ,
                        ),
                    },
                    RawSectionHeader {
                        name(str): ".data",
                        virtual_size: 23152,
                        virtual_address: 9728000,
                        raw_size: 16384,
                        raw_ptr: 9722368,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | INITIALIZED | READ | WRITE,
                        ),
                    },
                    RawSectionHeader {
                        name(str): ".pdata",
                        virtual_size: 276660,
                        virtual_address: 9752576,
                        raw_size: 276992,
                        raw_ptr: 9738752,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | INITIALIZED | READ,
                        ),
                    },
                    RawSectionHeader {
                        name(str): "_RDATA",
                        virtual_size: 348,
                        virtual_address: 10031104,
                        raw_size: 512,
                        raw_ptr: 10015744,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | INITIALIZED | READ,
                        ),
                    },
                    RawSectionHeader {
                        name(str): ".reloc",
                        virtual_size: 61240,
                        virtual_address: 10035200,
                        raw_size: 61440,
                        raw_ptr: 10016256,
                        reloc_ptr: 0,
                        line_ptr: 0,
                        num_reloc: 0,
                        num_lines: 0,
                        characteristics: SectionFlags(
                            RESERVED_0 | INITIALIZED | DISCARDABLE | READ,
                        ),
                    },
                ],
            ),
            _phantom: PhantomData<&u8>,
        }
            "###);

            insta::assert_debug_snapshot!(small_pe, @r###"
        Pe {
            dos: Dos {
                dos: Ref(
                    RawDos {
                        magic: b"MZ",
                        last_bytes: 0,
                        pages: 17744,
                        relocations: 0,
                        header_size: 332,
                        min_alloc: 0,
                        max_alloc: 0,
                        initial_ss: 0,
                        initial_sp: 0,
                        checksum: 0,
                        initial_ip: 0,
                        initial_cs: 0,
                        relocation_offset: 96,
                        overlay_num: 259,
                        _reserved: [
                            267,
                            0,
                            3,
                            0,
                        ],
                        oem_id: 0,
                        oem_info: 0,
                        _reserved2: [
                            0,
                            0,
                            0,
                            0,
                            124,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            64,
                            0,
                        ],
                        pe_offset: 4,
                    },
                ),
                stub: DOS code (len 0),
            },
            coff: Ref(
                RawCoff {
                    machine: MachineType::I386,
                    sections: 0,
                    time: 0,
                    sym_offset: 0,
                    sym_len: 0,
                    exec_header_size: 96,
                    file_attributes: CoffFlags(
                        RELOC_STRIPPED | IMAGE | BIT32,
                    ),
                },
            ),
            rich: None,
            exec: Raw32(
                Ref(
                    RawExec32 {
                        standard: RawPeImageStandard {
                            magic: PE32_MAGIC,
                            linker_major: 0,
                            linker_minor: 0,
                            code_size: 3,
                            init_size: 0,
                            uninit_size: 0,
                            entry_ptr: 124,
                            code_ptr: 0,
                        },
                        data_ptr: 0,
                        image_base: 4194304,
                        mem_align: 4,
                        disk_align: 4,
                        os_major: 0,
                        os_minor: 0,
                        image_major: 0,
                        image_minor: 0,
                        subsystem_major: 5,
                        subsystem_minor: 0,
                        _reserved_win32: 0,
                        image_size: 128,
                        headers_size: 124,
                        checksum: 0,
                        subsystem: Subsystem::WINDOWS_GUI,
                        dll_attributes: ExecFlags(
                            NO_SEH,
                        ),
                        stack_reserve: 1048576,
                        stack_commit: 4096,
                        heap_reserve: 1048576,
                        heap_commit: 4096,
                        _reserved_loader_attributes: 0,
                        data_dirs: 0,
                    },
                ),
            ),
            data_dirs: [],
            sections: Slice(
                [],
            ),
            _phantom: PhantomData<&u8>,
        }
            "###);

            insta::assert_debug_snapshot!(nothing, @r###"
            Pe {
                dos: Dos {
                    dos: Ref(
                        RawDos {
                            magic: b"MZ",
                            last_bytes: 144,
                            pages: 3,
                            relocations: 0,
                            header_size: 4,
                            min_alloc: 0,
                            max_alloc: 65535,
                            initial_ss: 0,
                            initial_sp: 184,
                            checksum: 0,
                            initial_ip: 0,
                            initial_cs: 0,
                            relocation_offset: 64,
                            overlay_num: 0,
                            _reserved: [0u16; 4],
                            oem_id: 0,
                            oem_info: 0,
                            _reserved2: [0u8; 20],
                            pe_offset: 176,
                        },
                    ),
                    stub: DOS code (len 112),
                },
                coff: Ref(
                    RawCoff {
                        machine: MachineType::I386,
                        sections: 2,
                        time: 1546627702,
                        sym_offset: 0,
                        sym_len: 0,
                        exec_header_size: 224,
                        file_attributes: CoffFlags(
                            IMAGE | BIT32,
                        ),
                    },
                ),
                rich: Some(
                    Rich {
                        header: Ref(
                            RawRich {
                                magic: b"Rich",
                                key: 2320755653,
                            },
                        ),
                        entries: [
                            RawRichEntry {
                                id: 0,
                                - product_id: 0,
                                - build_id: 0,
                                count: 1,
                            },
                            RawRichEntry {
                                id: 16931794,
                                - product_id: 258,
                                - build_id: 23506,
                                count: 1,
                            },
                        ],
                    },
                ),
                exec: Raw32(
                    Ref(
                        RawExec32 {
                            standard: RawPeImageStandard {
                                magic: PE32_MAGIC,
                                linker_major: 14,
                                linker_minor: 0,
                                code_size: 512,
                                init_size: 512,
                                uninit_size: 0,
                                entry_ptr: 4096,
                                code_ptr: 4096,
                            },
                            data_ptr: 8192,
                            image_base: 4194304,
                            mem_align: 4096,
                            disk_align: 512,
                            os_major: 6,
                            os_minor: 0,
                            image_major: 0,
                            image_minor: 0,
                            subsystem_major: 6,
                            subsystem_minor: 0,
                            _reserved_win32: 0,
                            image_size: 12288,
                            headers_size: 512,
                            checksum: 0,
                            subsystem: Subsystem::WINDOWS_GUI,
                            dll_attributes: ExecFlags(
                                DYNAMIC_BASE | NX_COMPAT | NO_SEH | TERMINAL_SERVER,
                            ),
                            stack_reserve: 1048576,
                            stack_commit: 4096,
                            heap_reserve: 1048576,
                            heap_commit: 4096,
                            _reserved_loader_attributes: 0,
                            data_dirs: 16,
                        },
                    ),
                ),
                data_dirs: [
                    "Export Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Resource Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Exception Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Certificate Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Base Relocations Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Debug Data" RawDataDirectory {
                        address: 8192,
                        size: 28,
                    },
                    "Architecture" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Global Ptr" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Thread Local Storage Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Load Config Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Bound Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "IAT" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Delay Import Descriptor" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "CLR Runtime Header" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Reserved" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                ],
                sections: Slice(
                    [
                        RawSectionHeader {
                            name(str): ".text",
                            virtual_size: 3,
                            virtual_address: 4096,
                            raw_size: 512,
                            raw_ptr: 512,
                            reloc_ptr: 0,
                            line_ptr: 0,
                            num_reloc: 0,
                            num_lines: 0,
                            characteristics: SectionFlags(
                                RESERVED_0 | CODE | EXEC | READ,
                            ),
                        },
                        RawSectionHeader {
                            name(str): ".rdata",
                            virtual_size: 88,
                            virtual_address: 8192,
                            raw_size: 512,
                            raw_ptr: 1024,
                            reloc_ptr: 0,
                            line_ptr: 0,
                            num_reloc: 0,
                            num_lines: 0,
                            characteristics: SectionFlags(
                                RESERVED_0 | INITIALIZED | READ,
                            ),
                        },
                    ],
                ),
                _phantom: PhantomData<&u8>,
            }
            "###);

            insta::assert_debug_snapshot!(smallest_sections, @r###"
            Pe {
                dos: Dos {
                    dos: Ref(
                        RawDos {
                            magic: b"MZ",
                            last_bytes: 0,
                            pages: 0,
                            relocations: 0,
                            header_size: 0,
                            min_alloc: 0,
                            max_alloc: 0,
                            initial_ss: 0,
                            initial_sp: 0,
                            checksum: 0,
                            initial_ip: 0,
                            initial_cs: 0,
                            relocation_offset: 0,
                            overlay_num: 0,
                            _reserved: [0u16; 4],
                            oem_id: 0,
                            oem_info: 0,
                            _reserved2: [0u8; 20],
                            pe_offset: 64,
                        },
                    ),
                    stub: DOS code (len 0),
                },
                coff: Ref(
                    RawCoff {
                        machine: MachineType::I386,
                        sections: 1,
                        time: 0,
                        sym_offset: 0,
                        sym_len: 0,
                        exec_header_size: 224,
                        file_attributes: CoffFlags(
                            RELOC_STRIPPED | IMAGE | BIT32,
                        ),
                    },
                ),
                rich: None,
                exec: Raw32(
                    Ref(
                        RawExec32 {
                            standard: RawPeImageStandard {
                                magic: PE32_MAGIC,
                                linker_major: 14,
                                linker_minor: 0,
                                code_size: 512,
                                init_size: 0,
                                uninit_size: 0,
                                entry_ptr: 4096,
                                code_ptr: 0,
                            },
                            data_ptr: 0,
                            image_base: 4194304,
                            mem_align: 4096,
                            disk_align: 512,
                            os_major: 5,
                            os_minor: 1,
                            image_major: 0,
                            image_minor: 0,
                            subsystem_major: 5,
                            subsystem_minor: 1,
                            _reserved_win32: 0,
                            image_size: 8192,
                            headers_size: 512,
                            checksum: 0,
                            subsystem: Subsystem::WINDOWS_GUI,
                            dll_attributes: ExecFlags(
                                NO_SEH,
                            ),
                            stack_reserve: 1048576,
                            stack_commit: 4096,
                            heap_reserve: 1048576,
                            heap_commit: 4096,
                            _reserved_loader_attributes: 0,
                            data_dirs: 16,
                        },
                    ),
                ),
                data_dirs: [
                    "Export Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Resource Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Exception Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Certificate Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Base Relocations Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Debug Data" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Architecture" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Global Ptr" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Thread Local Storage Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Load Config Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Bound Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "IAT" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Delay Import Descriptor" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "CLR Runtime Header" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Reserved" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                ],
                sections: Slice(
                    [
                        RawSectionHeader {
                            name(str): ".text",
                            virtual_size: 3,
                            virtual_address: 4096,
                            raw_size: 512,
                            raw_ptr: 512,
                            reloc_ptr: 0,
                            line_ptr: 0,
                            num_reloc: 0,
                            num_lines: 0,
                            characteristics: SectionFlags(
                                RESERVED_0 | CODE | EXEC | READ,
                            ),
                        },
                    ],
                ),
                _phantom: PhantomData<&u8>,
            }
            "###);

            insta::assert_debug_snapshot!(smallest_no_overlap, @r###"
            Pe {
                dos: Dos {
                    dos: Ref(
                        RawDos {
                            magic: b"MZ",
                            last_bytes: 0,
                            pages: 0,
                            relocations: 0,
                            header_size: 0,
                            min_alloc: 0,
                            max_alloc: 0,
                            initial_ss: 0,
                            initial_sp: 0,
                            checksum: 0,
                            initial_ip: 0,
                            initial_cs: 0,
                            relocation_offset: 0,
                            overlay_num: 0,
                            _reserved: [0u16; 4],
                            oem_id: 0,
                            oem_info: 0,
                            _reserved2: [0u8; 20],
                            pe_offset: 64,
                        },
                    ),
                    stub: DOS code (len 0),
                },
                coff: Ref(
                    RawCoff {
                        machine: MachineType::I386,
                        sections: 0,
                        time: 0,
                        sym_offset: 0,
                        sym_len: 0,
                        exec_header_size: 224,
                        file_attributes: CoffFlags(
                            RELOC_STRIPPED | IMAGE | BIT32,
                        ),
                    },
                ),
                rich: None,
                exec: Raw32(
                    Ref(
                        RawExec32 {
                            standard: RawPeImageStandard {
                                magic: PE32_MAGIC,
                                linker_major: 0,
                                linker_minor: 0,
                                code_size: 8,
                                init_size: 0,
                                uninit_size: 0,
                                entry_ptr: 312,
                                code_ptr: 0,
                            },
                            data_ptr: 0,
                            image_base: 4194304,
                            mem_align: 1,
                            disk_align: 1,
                            os_major: 0,
                            os_minor: 0,
                            image_major: 0,
                            image_minor: 0,
                            subsystem_major: 5,
                            subsystem_minor: 0,
                            _reserved_win32: 0,
                            image_size: 320,
                            headers_size: 312,
                            checksum: 0,
                            subsystem: Subsystem::WINDOWS_GUI,
                            dll_attributes: ExecFlags(
                                NO_SEH,
                            ),
                            stack_reserve: 1048576,
                            stack_commit: 4096,
                            heap_reserve: 1048576,
                            heap_commit: 4096,
                            _reserved_loader_attributes: 0,
                            data_dirs: 16,
                        },
                    ),
                ),
                data_dirs: [
                    "Export Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Resource Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Exception Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Certificate Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Base Relocations Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Debug Data" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Architecture" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Global Ptr" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Thread Local Storage Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Load Config Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Bound Import Table" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "IAT" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Delay Import Descriptor" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "CLR Runtime Header" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                    "Reserved" RawDataDirectory {
                        address: 0,
                        size: 0,
                    },
                ],
                sections: Slice(
                    [],
                ),
                _phantom: PhantomData<&u8>,
            }
            "###);
        }

        Ok(())
    }
}
