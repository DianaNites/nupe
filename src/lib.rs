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
extern crate alloc;

pub mod builder;
pub mod error;
mod internal;
mod pe;
pub mod raw;

use core::{mem::size_of, ptr::addr_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    raw::*,
};
pub use crate::{
    internal::{
        CoffFlags,
        DataDirIdent,
        ExecFlags,
        MachineType,
        OwnedOrRef,
        SectionFlags,
        Subsystem,
        VecOrSlice,
    },
    pe::*,
};

/// Executable header, otherwise known as the "optional" header
///
/// Provides an abstraction over the meaningless 32 and 64 bit difference
#[derive(Debug, Clone, Copy)]
pub enum ExecHeader<'data> {
    Raw32(OwnedOrRef<'data, RawExec32>),
    Raw64(OwnedOrRef<'data, RawExec64>),
}

impl<'data> ExecHeader<'data> {
    /// Wrapper around [`RawExec32::new`] and [`RawExec64::new`]
    ///
    /// Always takes arguments in 64-bit, errors if out of bounds
    ///
    /// if `plus` is true then the PE32+ / 64-bit header is used
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        plus: bool,
        standard: RawExec,
        data_ptr: u32,
        image_ptr: u64,
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
        dll_attributes: ExecFlags,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        data_dirs: u32,
    ) -> Result<Self> {
        if plus {
            Ok(ExecHeader::Raw64(OwnedOrRef::Owned(RawExec64::new(
                standard,
                image_ptr,
                mem_align,
                disk_align,
                os_major,
                os_minor,
                image_major,
                image_minor,
                subsystem_major,
                subsystem_minor,
                image_size,
                headers_size,
                subsystem,
                dll_attributes,
                stack_reserve,
                stack_commit,
                heap_reserve,
                heap_commit,
                data_dirs,
            ))))
        } else {
            Ok(ExecHeader::Raw32(OwnedOrRef::Owned(RawExec32::new(
                standard,
                data_ptr,
                image_ptr.try_into().map_err(|_| Error::TooMuchData)?,
                mem_align,
                disk_align,
                os_major,
                os_minor,
                image_major,
                image_minor,
                subsystem_major,
                subsystem_minor,
                image_size,
                headers_size,
                subsystem,
                dll_attributes,
                stack_reserve.try_into().map_err(|_| Error::TooMuchData)?,
                stack_commit.try_into().map_err(|_| Error::TooMuchData)?,
                heap_reserve.try_into().map_err(|_| Error::TooMuchData)?,
                heap_commit.try_into().map_err(|_| Error::TooMuchData)?,
                data_dirs,
            ))))
        }
    }

    /// Get header as a byte slice
    pub(crate) const fn as_slice(&self) -> &[u8] {
        match self {
            ExecHeader::Raw32(h) => {
                //
                let ptr = h.as_ref() as *const RawExec32 as *const u8;
                unsafe { from_raw_parts(ptr, size_of::<RawExec32>()) }
            }
            ExecHeader::Raw64(h) => {
                //
                let ptr = h.as_ref() as *const RawExec64 as *const u8;
                unsafe { from_raw_parts(ptr, size_of::<RawExec64>()) }
            }
        }
    }

    pub(crate) const fn code_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.code_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.code_size,
        }
    }
    pub(crate) const fn init_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.init_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.init_size,
        }
    }
    pub(crate) const fn uninit_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.uninit_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.uninit_size,
        }
    }

    /// Convenience function to get the common [`RawExec`]
    pub const fn raw_exec(&self) -> &RawExec {
        match self {
            ExecHeader::Raw32(h) => &h.as_ref().standard,
            ExecHeader::Raw64(h) => &h.as_ref().standard,
        }
    }

    /// Convenience function to get the correct size in bytes of the exec header
    pub const fn size_of(&self) -> usize {
        match self {
            ExecHeader::Raw32(_) => size_of::<RawExec32>(),
            ExecHeader::Raw64(_) => size_of::<RawExec64>(),
        }
    }
}

#[doc(hidden)]
impl<'data> ExecHeader<'data> {
    /// How many data directories
    const fn data_dirs(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => match h {
                OwnedOrRef::Owned(h) => h.data_dirs,
                OwnedOrRef::Ref(h) => h.data_dirs,
            },
            ExecHeader::Raw64(h) => match h {
                OwnedOrRef::Owned(h) => h.data_dirs,
                OwnedOrRef::Ref(h) => h.data_dirs,
            },
        }
    }

    /// Subsystem
    fn subsystem(&self) -> Subsystem {
        match self {
            ExecHeader::Raw32(h) => h.subsystem,
            ExecHeader::Raw64(h) => h.subsystem,
        }
    }

    /// Entry point address relative to the image base
    fn entry(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.standard.entry_ptr,
            ExecHeader::Raw64(h) => h.standard.entry_ptr,
        }
    }

    /// OS (major, minor)
    fn os_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.os_major, h.os_minor),
            ExecHeader::Raw64(h) => (h.os_major, h.os_minor),
        }
    }

    /// Image (major, minor)
    fn image_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.image_major, h.image_minor),
            ExecHeader::Raw64(h) => (h.image_major, h.image_minor),
        }
    }

    /// Subsystem (major, minor)
    fn subsystem_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.subsystem_major, h.subsystem_minor),
            ExecHeader::Raw64(h) => (h.subsystem_major, h.subsystem_minor),
        }
    }

    /// Linker (major, minor)
    fn linker_version(&self) -> (u8, u8) {
        match self {
            ExecHeader::Raw32(h) => (h.standard.linker_major, h.standard.linker_minor),
            ExecHeader::Raw64(h) => (h.standard.linker_major, h.standard.linker_minor),
        }
    }

    /// Preferred Base of the image in memory.
    ///
    /// Coerced to u64 even on/for 32bit.
    fn image_base(&self) -> u64 {
        match self {
            ExecHeader::Raw32(h) => h.image_base.into(),
            ExecHeader::Raw64(h) => h.image_base,
        }
    }

    /// DLL Attributes
    fn dll_attributes(&self) -> ExecFlags {
        match self {
            ExecHeader::Raw32(h) => h.dll_attributes,
            ExecHeader::Raw64(h) => h.dll_attributes,
        }
    }

    /// Stack (reserve, commit)
    pub(crate) fn stack(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (h.stack_reserve.into(), h.stack_commit.into()),
            ExecHeader::Raw64(h) => (h.stack_reserve, h.stack_commit),
        }
    }

    /// Heap (reserve, commit)
    pub(crate) fn heap(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (h.heap_reserve.into(), h.heap_commit.into()),
            ExecHeader::Raw64(h) => (h.heap_reserve, h.heap_commit),
        }
    }

    /// File alignment
    fn file_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.disk_align,
            ExecHeader::Raw64(h) => h.disk_align,
        }
    }

    /// Section alignment
    fn section_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.mem_align,
            ExecHeader::Raw64(h) => h.mem_align,
        }
    }

    /// Image size
    fn image_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.image_size,
            ExecHeader::Raw64(h) => h.image_size,
        }
    }

    /// Headers size
    fn headers_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.headers_size,
            ExecHeader::Raw64(h) => h.headers_size,
        }
    }
}

#[doc(hidden)]
impl<'data> ExecHeader<'data> {
    /// Get a [`ExecHeader`] from a pointer to an exec header.
    ///
    /// This function validates that `size` is enough to contain this header,
    /// and that the magic is correct.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        if data.is_null() {
            return Err(Error::InvalidData);
        }
        // Ensure that `size` is enough for the common header
        size.checked_sub(size_of::<RawExec>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`, so read the magic.
        let magic = addr_of!((*(data as *const RawExec)).magic).read_unaligned();

        if magic == PE32_64_MAGIC {
            let opt = RawExec64::from_ptr(data, size)?;

            Ok(ExecHeader::Raw64(OwnedOrRef::Ref(opt)))
        } else if magic == PE32_MAGIC {
            let opt = RawExec32::from_ptr(data, size)?;

            Ok(ExecHeader::Raw32(OwnedOrRef::Ref(opt)))
        } else {
            Err(Error::InvalidPeMagic)
        }
    }
}

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

    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

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
