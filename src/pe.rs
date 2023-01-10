//! PE type
use core::{fmt, marker::PhantomData};

use crate::{
    error::{Error, Result},
    internal::{
        debug::{DosHelper, RawDataDirectoryHelper},
        CoffAttributes,
        DataDirIdent,
        DllAttributes,
        MachineType,
        OwnedOrRef,
        Subsystem,
        VecOrSlice,
    },
    raw::*,
    DataDir,
    ImageHeader,
    Section,
};

/// A PE file
#[derive(Clone)]
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

/// Internal base API
impl<'data> Pe<'data> {
    /// Create a [`Pe`]
    ///
    /// `loaded` determines whether this pointer represents a loaded PE or not
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    unsafe fn from_ptr_internal(data: *const u8, size: usize, loaded: bool) -> Result<Self> {
        let (dos, (pe_ptr, pe_size), (stub_ptr, stub_size)) = RawDos::from_ptr(data, size)
            .map_err(|e| match e {
                Error::NotEnoughData => Error::MissingDOS,
                _ => e,
            })?;
        let (pe, (opt_ptr, opt_size), (section_ptr, section_size)) =
            RawPe::from_ptr(pe_ptr, pe_size).map_err(|e| match e {
                Error::NotEnoughData => Error::MissingPE,
                _ => e,
            })?;
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

/// Public deserialization API
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

/// Public data API
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
        self.data_dirs
            .get(index)
            .map(|s| DataDir::new(OwnedOrRef::Ref(s)))
    }

    /// Iterator over [`DataDir`]s
    pub fn data_dirs(&self) -> impl Iterator<Item = DataDir> {
        self.data_dirs
            .iter()
            .map(|s| DataDir::new(OwnedOrRef::Ref(s)))
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
        self.coff.file_attributes
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
    pub fn dll_attributes(&self) -> DllAttributes {
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

    /// Stack (reserve, commit)
    pub fn stack(&self) -> (u64, u64) {
        self.opt.stack()
    }

    /// Heap (reserve, commit)
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

    /// Image size
    pub fn image_size(&self) -> u32 {
        self.opt().image_size()
    }

    /// Headers size
    pub fn headers_size(&self) -> u32 {
        self.opt().headers_size()
    }
}

/// Public advanced API
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

/// Public modification API
impl<'data> Pe<'data> {
    pub fn append_section(&mut self, _section: ()) -> Result<()> {
        if let VecOrSlice::Vec(_v) = &mut self.sections {
            // v.push(value);
            Ok(())
        } else {
            Err(Error::ImmutableData)
        }
    }

    /// Remove a section by name
    pub fn remove_section(&mut self, _name: &str) {
        //
    }

    /// Remove a section by zero-based index
    ///
    /// # Panics
    ///
    /// If `index` is out of bounds
    pub fn remove_section_index(&mut self, index: usize) {
        self.sections[index] = RawSectionHeader::zeroed();
    }
}

impl<'data> fmt::Debug for Pe<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Pe");
        s.field("dos", &self.dos)
            .field("dos_stub", &DosHelper::new(&self.dos_stub))
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
