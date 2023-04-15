//! PE type
use core::{fmt, marker::PhantomData, mem::size_of};

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
    ExecHeader,
    Section,
};

/// A PE file
#[derive(Clone)]
pub struct Pe<'data> {
    dos: OwnedOrRef<'data, RawDos>,
    dos_stub: VecOrSlice<'data, u8>,
    coff: OwnedOrRef<'data, RawCoff>,
    opt: ExecHeader<'data>,
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
    unsafe fn from_ptr_internal(data: *const u8, input_size: usize, loaded: bool) -> Result<Self> {
        let dos = RawDos::from_ptr(data, input_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingDOS,
            _ => e,
        })?;

        // Pointer to the PE signature, and the size of the remainder of the input after
        // the DOS stub.
        let (pe_ptr, pe_size) = {
            // Offset in the file to the PE signature
            let off: usize = dos.pe_offset.try_into().map_err(|_| Error::InvalidData)?;

            // Ensure the PE offset is within `size`
            input_size.checked_sub(off).ok_or(Error::NotEnoughData)?;

            // Offset to the PE signature
            //
            // Safety:
            // - `data` is guaranteed to be valid for this size by the caller and the above
            //   check.
            // - `data` is guaranteed to be in-bounds by the caller
            // - Caller guarantees `data + size` does not overflow `isize`
            let pe_ptr = data.add(off);

            // Size of the entire input minus the offset to the PE section,
            // the missing space being the preceding DOS stub.
            //
            // This is strictly less than `size`
            let pe_size = input_size - off;

            (pe_ptr, pe_size)
        };

        // Pointer to the DOS stub code, and size of the code before the PE header
        let (stub_ptr, stub_size) = {
            // Offset to the DOS stub code
            //
            // Safety:
            // - `data` is guaranteed to be valid by `RawDos::from_ptr` not having returned
            //   an error.
            // - `data` is guaranteed to be in-bounds by the caller
            let stub_ptr = data.add(size_of::<RawDos>());

            // Size of the DOS stub code is the size of the input,
            // minus the size of the PE and DOS header
            let stub_size = input_size - pe_size - size_of::<RawDos>();

            (stub_ptr, stub_size)
        };

        // PE signature and COFF header
        let pe = RawPe::from_ptr(pe_ptr, pe_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingPE,
            _ => e,
        })?;

        // Pointer to the exec header, and its size.
        let (exec_ptr, exec_size) = {
            // Size of the exec header
            let exec_size: usize = pe.coff.exec_header_size.into();

            let off = size_of::<RawPe>()
                .checked_add(exec_size)
                .ok_or(Error::NotEnoughData)?;

            // Ensure that `exec_size` is within `pe_size`
            pe_size.checked_sub(off).ok_or(Error::MissingExecHeader)?;

            // Exec header appears directly after PE sig and COFF header
            //
            // Safety:
            // - `pe_ptr` and this operation is guaranteed to be valid by earlier code.
            let exec_ptr = pe_ptr.add(size_of::<RawPe>());

            (exec_ptr, exec_size)
        };

        // Pointer to section table, and its size in elements.
        let (section_ptr, section_size) = {
            // Size of the section table in bytes
            let section_size = size_of::<RawSectionHeader>()
                .checked_mul(pe.coff.sections.into())
                .ok_or(Error::TooMuchData)?;

            let off = size_of::<RawPe>()
                .checked_add(section_size)
                .ok_or(Error::NotEnoughData)?;

            // Ensure `section_size` is within `pe_size`
            pe_size.checked_sub(off).ok_or(Error::MissingSectionTable)?;

            // Section table appears directly after the exec header
            //
            // Safety:
            // - `exec_ptr` and this operation is guaranteed to be valid by earlier code.
            let section_ptr = exec_ptr.add(exec_size) as *const RawSectionHeader;

            (section_ptr, pe.coff.sections.into())
        };

        let (header, (data_ptr, data_size)) = ExecHeader::from_ptr(exec_ptr, exec_size)?;

        let data_dirs = unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
        let sections = unsafe { core::slice::from_raw_parts(section_ptr, section_size) };
        let stub = unsafe { core::slice::from_raw_parts(stub_ptr, stub_size) };
        for s in sections {
            if !s.name.is_ascii() {
                return Err(Error::InvalidData);
            }
        }
        let base = if loaded {
            Some((data, input_size))
        } else {
            None
        };

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
    pub fn opt(&self) -> &'data ExecHeader {
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
