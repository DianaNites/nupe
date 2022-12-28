//! PE image handling
#![cfg_attr(not(any(feature = "std", test)), no_std)]
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
extern crate alloc;

pub mod builder;
pub mod error;
mod internal;
pub mod raw;

use core::{fmt, marker::PhantomData, mem::size_of};

use raw::*;

pub use crate::internal::{
    CoffAttributes,
    DataDirIdent,
    DllCharacteristics,
    MachineType,
    OwnedOrRef,
    SectionFlags,
    Subsystem,
    VecOrSlice,
};
use crate::{
    error::{Error, Result},
    internal::debug::RawDataDirectoryHelper,
};

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

    /// Preferred Base of the image in memory.
    ///
    /// Coerced to u64 even on/for 32bit.
    fn image_base(&self) -> u64 {
        match self {
            ImageHeader::Raw32(h) => h.image_base.into(),
            ImageHeader::Raw64(h) => h.image_base,
        }
    }

    /// DLL Attributes
    fn dll_attributes(&self) -> DllCharacteristics {
        match self {
            ImageHeader::Raw32(h) => h.dll_characteristics,
            ImageHeader::Raw64(h) => h.dll_characteristics,
        }
    }

    /// Stack (commit, reserve)
    pub fn stack(&self) -> (u64, u64) {
        match self {
            ImageHeader::Raw32(h) => (h.stack_commit.into(), h.stack_reserve.into()),
            ImageHeader::Raw64(h) => (h.stack_commit, h.stack_reserve),
        }
    }

    /// Heap (commit, reserve)
    pub fn heap(&self) -> (u64, u64) {
        match self {
            ImageHeader::Raw32(h) => (h.heap_commit.into(), h.heap_reserve.into()),
            ImageHeader::Raw64(h) => (h.heap_commit, h.heap_reserve),
        }
    }

    /// File alignment
    fn file_align(&self) -> u32 {
        match self {
            ImageHeader::Raw32(h) => h.file_align,
            ImageHeader::Raw64(h) => h.file_align,
        }
    }

    /// Section alignment
    fn section_align(&self) -> u32 {
        match self {
            ImageHeader::Raw32(h) => h.section_align,
            ImageHeader::Raw64(h) => h.section_align,
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

/// A PE Data Directory
#[derive(Debug)]
pub struct DataDir<'data> {
    header: OwnedOrRef<'data, RawDataDirectory>,
    #[allow(dead_code)]
    base: Option<(*const u8, usize)>,
}

impl<'data> DataDir<'data> {
    /// Address of the data directory, relative to the image base.
    pub fn address(&self) -> u32 {
        self.header.address
    }

    /// Size of the data directory
    pub fn size(&self) -> u32 {
        self.header.size
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
    /// Get a [`crate::Pe`] from `data`, checking to make sure its valid.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - `data` SHOULD be a valid pointer to a LOADED PE image in memory
    pub unsafe fn from_loaded_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size, true)
    }

    /// Get a [`crate::Pe`] from `data`, checking to make sure its valid.
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
            .map(|s| Section::new(OwnedOrRef::Ref(s), self.file_align(), self.base))
    }

    /// Iterator over [`Section`]s
    pub fn sections(&self) -> impl Iterator<Item = Section> {
        self.sections
            .iter()
            .map(|s| Section::new(OwnedOrRef::Ref(s), self.file_align(), self.base))
    }

    /// Get a known [`DataDir`]s by its [`DataDirIdent`] identifier.
    pub fn data_dir(&self, id: DataDirIdent) -> Option<DataDir> {
        let index = id.index();
        self.data_dirs.get(index).map(|s| DataDir {
            header: OwnedOrRef::Ref(s),
            base: self.base,
        })
    }

    /// Iterator over [`DataDir`]s
    pub fn data_dirs(&self) -> impl Iterator<Item = DataDir> {
        self.data_dirs.iter().map(|s| DataDir {
            header: OwnedOrRef::Ref(s),
            base: self.base,
        })
    }

    /// Number of sections
    pub fn sections_len(&self) -> usize {
        self.coff.sections.into()
    }

    /// Number of sections
    pub fn data_dirs_len(&self) -> u32 {
        self.opt.data_dirs()
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

    /// DLL Attributes
    pub fn dll_attributes(&self) -> DllCharacteristics {
        self.opt.dll_attributes()
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

    /// Stack (commit, reserve)
    pub fn stack(&self) -> (u64, u64) {
        self.opt.stack()
    }

    /// Heap (commit, reserve)
    pub fn heap(&self) -> (u64, u64) {
        self.opt.heap()
    }

    /// File alignment
    pub fn file_align(&self) -> u32 {
        self.opt().file_align()
    }

    /// Section alignment
    pub fn section_align(&self) -> u32 {
        self.opt().section_align()
    }
}

impl<'data> Pe<'data> {
    /// Raw COFF header for this PE file
    ///
    /// This is only for advanced users.
    pub fn coff(&self) -> &RawCoff {
        &self.coff
    }

    /// Raw Optional header for this PE file
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
            .field("opt", &self.opt);

        s.field("data_dirs", &{
            RawDataDirectoryHelper::new(&self.data_dirs)
        });

        s.field("sections", &self.sections)
            .field("base", &self.base)
            .field("_phantom", &self._phantom)
            .finish()
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

    // EFI Stub kernel
    static _TEST_IMAGE: &[u8] =
        include_bytes!("../../uefi-stub/target/x86_64-unknown-uefi/debug/uefi-stub.efi");
    // static TEST_IMAGE: &[u8] = include_bytes!("/boot/vmlinuz-linux");
    static TEST_IMAGE: &[u8] = include_bytes!("/boot/EFI/Linux/linux.efi");
    static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[test]
    fn dev() -> Result<()> {
        // let mut pe = PeHeader::from_bytes(TEST_IMAGE);
        let pe = unsafe { Pe::from_ptr(TEST_IMAGE.as_ptr(), TEST_IMAGE.len()) };
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

        // Ok(())
    }

    /// Test ability to write a copy of rustup-init.exe, from our own parsed
    /// data structures.
    #[test]
    fn write_rustup() -> Result<()> {
        let in_pe = Pe::from_bytes(RUSTUP_IMAGE)?;
        dbg!(&in_pe);
        let mut pe = PeBuilder::new();
        let pe = pe.machine(MachineType::AMD64);
        {
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
                .data_dir(DataDirIdent::Import, 9719132, 260)
                .data_dir(DataDirIdent::Exception, 9752576, 276660)
                .data_dir(DataDirIdent::BaseReloc, 10035200, 61240)
                .data_dir(DataDirIdent::Debug, 8757424, 84)
                .data_dir(DataDirIdent::ThreadLocalStorage, 8757632, 40)
                .data_dir(DataDirIdent::LoadConfig, 8757104, 320)
                .data_dir(DataDirIdent::Iat, 7176192, 2248)
                .section(
                    SectionBuilder::new()
                        .name(".text")
                        .data(
                            {
                                //
                                let sec = in_pe.section(".text").unwrap();
                                &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                    [..sec.virtual_size() as usize]
                            },
                            None,
                        )
                        .file_offset(1024)
                        .attributes(SectionFlags::CODE | SectionFlags::EXEC | SectionFlags::READ),
                )
                .section(
                    SectionBuilder::new()
                        .name(".rdata")
                        .data(
                            {
                                //
                                let sec = in_pe.section(".rdata").unwrap();
                                &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                    [..sec.virtual_size() as usize]
                            },
                            None,
                        )
                        .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
                )
                .section({
                    let sec = in_pe.section(".data").unwrap();
                    SectionBuilder::new()
                        .name(".data")
                        .data(
                            &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                [..sec.virtual_size() as usize],
                            Some(sec.file_size()),
                        )
                        .attributes(
                            SectionFlags::INITIALIZED | SectionFlags::READ | SectionFlags::WRITE,
                        )
                })
                .section(
                    SectionBuilder::new()
                        .name(".pdata")
                        .data(
                            {
                                //
                                let sec = in_pe.section(".pdata").unwrap();
                                &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                    [..sec.virtual_size() as usize]
                            },
                            None,
                        )
                        .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
                )
                .section(
                    SectionBuilder::new()
                        .name("_RDATA")
                        .data(
                            {
                                //
                                let sec = in_pe.section("_RDATA").unwrap();
                                &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                    [..sec.virtual_size() as usize]
                            },
                            None,
                        )
                        .attributes(SectionFlags::INITIALIZED | SectionFlags::READ),
                )
                .section(
                    SectionBuilder::new()
                        .name(".reloc")
                        .data(
                            {
                                //
                                let sec = in_pe.section(".reloc").unwrap();
                                &RUSTUP_IMAGE[sec.file_offset() as usize..]
                                    [..sec.virtual_size() as usize]
                            },
                            None,
                        )
                        .attributes(
                            SectionFlags::INITIALIZED
                                | SectionFlags::READ
                                | SectionFlags::DISCARDABLE,
                        ),
                );
        }
        let mut out: Vec<u8> = Vec::new();
        pe.write(&mut out)?;
        //
        let out_pe = Pe::from_bytes(&out);
        dbg!(&out_pe);
        let out_pe = out_pe?;

        assert_eq!(in_pe.dos_stub(), out_pe.dos_stub());
        assert_eq!({ in_pe.dos().pe_offset }, { out_pe.dos().pe_offset });

        assert_eq!(RUSTUP_IMAGE, &out[..]);

        Ok(())
    }

    /// Test ability to read rustup-init.exe
    #[test]
    fn read_rustup() -> Result<()> {
        let pe = Pe::from_bytes(RUSTUP_IMAGE)?;

        assert_eq!(pe.machine_type(), MachineType::AMD64);
        assert_eq!(pe.sections_len(), 6);
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
        assert_eq!(
            pe.dll_attributes(),
            DllCharacteristics::HIGH_ENTROPY_VA
                | DllCharacteristics::DYNAMIC_BASE
                | DllCharacteristics::NX_COMPAT
                | DllCharacteristics::TERMINAL_SERVER
        );
        assert_eq!(pe.stack(), (4096, 1048576));
        assert_eq!(pe.heap(), (4096, 1048576));
        assert_eq!(pe.data_dirs_len(), 16);

        assert_eq!(pe.data_dirs().count(), 16);
        assert_eq!(pe.sections().count(), 6);

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

        Ok(())
    }
}
