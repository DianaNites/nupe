//! PE type
use core::{fmt, marker::PhantomData, mem::size_of};

use crate::{
    error::{Error, Result},
    internal::{
        debug::{DosHelper, RawDataDirectoryHelper},
        CoffFlags,
        DataDirIdent,
        ExecFlags,
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

/// Helper to read the PE signature and COFF header
///
/// # Errors
///
/// - [`Error::TooMuchData`] If the DOS does not fit in [`usize`].
/// - [`Error::NotEnoughData`] If `input_offset` does not fit a [`RawPe`] and
///   the DOS pe offset
///
/// # Safety
///
/// - `input` must be non-null and valid for `input_size` bytes.
unsafe fn read_sig(
    dos: &RawDos,
    input: *const u8,
    input_size: usize,
) -> Result<(*const u8, usize)> {
    // Offset in the file to the PE signature
    // This is untrusted input
    let off: usize = dos.pe_offset.try_into().map_err(|_| Error::TooMuchData)?;

    // Ensure that `size` is enough for the common header
    // After this, it is trusted.
    input_size
        .checked_sub(off)
        .ok_or(Error::NotEnoughData)?
        .checked_sub(size_of::<RawPe>())
        .ok_or(Error::NotEnoughData)?;

    // Offset to the PE signature
    //
    // Safety:
    // - We just ensured `off` is within bounds of `input` above
    // - Caller ensures `input` validity
    let pe_ptr = input.add(off);

    // Size of the entire input minus the offset to the PE section,
    // the missing space being the preceding DOS stub.
    //
    // This is strictly less than `size`
    let pe_size = input_size - off;

    Ok((pe_ptr.cast(), pe_size))
}

/// Helper to read DOS stub code
///
/// This assumes stub code can only exist before the PE offset.
///
/// Returns a pointer to the DOS stub after the header, and its size.
///
/// In the event the PE offset lays *inside* the header, the stub size
/// will be returned as zero without error.
///
/// # Errors
///
/// - [`Error::NotEnoughData`] If `input_size` does not fit a [`RawDos`]
///
/// # Safety
///
/// - `input` must be non-null and valid for `input_size` bytes.
unsafe fn read_stub(
    input: *const u8,
    input_size: usize,
    pe_size: usize,
) -> Result<(*const u8, usize)> {
    // Ensure that `input_size` is enough for the DOS header
    input_size
        .checked_sub(size_of::<RawDos>())
        .ok_or(Error::NotEnoughData)?;

    // Offset to the DOS stub code
    //
    // Safety:
    // - We just ensured this offset is within bounds of `input` above
    // - Caller ensures `input` validity
    let stub_ptr = input.add(size_of::<RawDos>());

    // Size of the DOS stub code is the size of the input,
    // minus the size of the PE and DOS header, saturating if RawDoes would
    // overflow.
    let stub_size = (input_size - pe_size).saturating_sub(size_of::<RawDos>());

    Ok((stub_ptr, stub_size))
}

/// Helper to read exec header
///
/// Returns a pointer to the exec header, and its size.
/// The size may be zero, in which case the returned pointer is
/// one past the end the [`RawCoff`] COFF header.
///
/// # Errors
///
/// - [`Error::TooMuchData`] If the exec header is too large
/// - [`Error::NotEnoughData`] If `pe_size` does not fit the entire exec header,
/// as reported by [`RawCoff::exec_header_size`].
///
/// # Safety
///
/// - `pe_ptr` must be non-null and valid for `pe_size` bytes.
unsafe fn read_exec(
    coff: &RawCoff,
    pe_ptr: *const u8,
    pe_size: usize,
) -> Result<(*const u8, usize)> {
    // Size of the exec header
    // This is untrusted input
    let exec_size: usize = coff.exec_header_size.into();

    // Offset from pe_ptr to exec header
    //
    // This can in theory overflow because `usize` can be 16 bits, the same as
    // `exec_header_size`
    let off = size_of::<RawPe>()
        .checked_add(exec_size)
        .ok_or(Error::TooMuchData)?;

    // Ensure that `exec_size` is within `pe_size`
    // After this, it is trusted.
    pe_size.checked_sub(off).ok_or(Error::NotEnoughData)?;

    // Exec header appears directly after PE sig and COFF header
    //
    // Safety:
    // - `pe_ptr` and this operation is guaranteed to be valid by earlier code.
    let exec_ptr = pe_ptr.add(size_of::<RawPe>());

    Ok((exec_ptr, exec_size))
}

/// An executable PE file following Microsoft Windows conventions
#[derive(Clone)]
pub struct Pe<'data> {
    /// DOS header
    dos: OwnedOrRef<'data, RawDos>,

    /// DOS stub code
    dos_stub: VecOrSlice<'data, u8>,

    /// COFF header
    coff: OwnedOrRef<'data, RawCoff>,

    /// Exec header
    exec: ExecHeader<'data>,

    /// Data directories
    data_dirs: VecOrSlice<'data, RawDataDirectory>,

    /// Sections
    sections: VecOrSlice<'data, RawSectionHeader>,

    /// Phantom type for `'data`
    _phantom: PhantomData<&'data u8>,
}

/// Internal base API
impl<'data> Pe<'data> {
    /// See [`Pe::from_ptr`] for safety and error details
    unsafe fn from_ptr_internal(data: *const u8, input_size: usize) -> Result<Self> {
        let dos = RawDos::from_ptr(data, input_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingDOS,
            _ => e,
        })?;

        // Pointer to the PE signature, and the size of the remainder of the input after
        // the DOS stub.
        let (pe_ptr, pe_size) = read_sig(dos, data, input_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingPE,
            _ => e,
        })?;

        // Pointer to the DOS stub code, and size of the code before the PE header
        let (stub_ptr, stub_size) = read_stub(data, input_size, pe_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingDOS,
            _ => e,
        })?;

        // PE signature and COFF header
        let pe = RawPe::from_ptr(pe_ptr, pe_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingPE,
            _ => e,
        })?;

        // Pointer to the exec header, and its size.
        let (exec_ptr, exec_size) = read_exec(&pe.coff, pe_ptr, pe_size)?;

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

        let exec = ExecHeader::from_ptr(exec_ptr, exec_size).map_err(|e| match e {
            Error::NotEnoughData => Error::MissingExecHeader,
            _ => e,
        })?;

        // Pointer to data directory, and its size in elements.
        let (data_ptr, data_size) = {
            let elems = exec
                .data_dirs()
                .try_into()
                .map_err(|_| Error::TooMuchData)?;

            // Size in bytes of the data directories
            let data_size = size_of::<RawDataDirectory>()
                .checked_mul(elems)
                .ok_or(Error::NotEnoughData)?;

            // Ensure the data directories all fit within `exec_size`
            exec_size
                .checked_sub(
                    exec.size_of()
                        .checked_add(data_size)
                        .ok_or(Error::NotEnoughData)?,
                )
                .ok_or(Error::NotEnoughData)?;

            // Data dirs appear directly after the exec header
            //
            // Safety:
            // - `exec_ptr` and this operation is guaranteed to be valid by earlier code.
            let data_ptr = exec_ptr.add(exec.size_of()) as *const RawDataDirectory;

            (data_ptr, elems)
        };

        let data_dirs = unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
        let sections = unsafe { core::slice::from_raw_parts(section_ptr, section_size) };
        let stub = unsafe { core::slice::from_raw_parts(stub_ptr, stub_size) };

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            dos_stub: VecOrSlice::Slice(stub),
            coff: OwnedOrRef::Ref(&pe.coff),
            exec,
            data_dirs: VecOrSlice::Slice(data_dirs),
            sections: VecOrSlice::Slice(sections),
            _phantom: PhantomData,
        })
    }

    /// Create a [`Pe`] with a mutable pointer
    ///
    /// See [`Pe::from_ptr_internal`] for additional safety and error details.
    ///
    /// # Safety
    ///
    /// - See [`Pe::from_ptr_internal`]
    /// - `data` MUST be a legitimate mutable pointer
    unsafe fn from_ptr_internal_mut(data: *mut u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data.cast_const(), size)
    }
}

/// Public deserialization API
impl<'data> Pe<'data> {
    /// Get a [`Pe`] from a pointer to a PE, while ensuring its validity.
    ///
    /// This validates that:
    ///
    /// - All header data is within bounds of `input_size`
    ///   - Other data, such as sections and data directories, remains untrusted
    ///     and must be validated later
    /// - All magic values and signatures are correct
    ///
    /// # Errors
    ///
    /// - [`Error::MissingDOS`] If the DOS header could not be read
    /// - [`Error::MissingPE`] If the PE signature and COFF header could not be
    ///   read
    /// - [`Error::InvalidDosMagic`] If the DOS header magic value was incorrect
    /// - See [`RawDos::from_ptr`]
    /// - [`Error::TooMuchData`] If the DOS `pe_offset` does not fit in `usize`.
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size)
    }

    /// Get a [`Pe`] that references a PE file `bytes`,
    /// while ensuring its validity.
    ///
    /// This function validates that:
    ///
    /// - All magic values and signatures are correct
    pub fn from_bytes(bytes: &'data [u8]) -> Result<Self> {
        // Safety: Slice pointer is trivially valid for its own length.
        unsafe { Self::from_ptr_internal(bytes.as_ptr(), bytes.len()) }
    }

    /// Get a [`Pe`] that mutably references a PE file `bytes`,
    /// while ensuring its validity.
    ///
    /// This function validates that:
    ///
    /// - All magic values and signatures are correct
    pub fn from_bytes_mut(bytes: &'data mut [u8]) -> Result<Self> {
        // Safety: Slice pointer is trivially valid for its own length.
        unsafe { Self::from_ptr_internal_mut(bytes.as_mut_ptr(), bytes.len()) }
    }
}

/// Public data API
impl<'data> Pe<'data> {
    /// Get a [`Section`] by `name`. Ignores nul.
    ///
    /// Section names are limited to 8 bytes max.
    pub fn section(&self, name: &str) -> Option<Section> {
        if name.len() > 8 {
            return None;
        }
        self.sections
            .iter()
            .find(|s| s.name().unwrap_or_default() == name)
            .map(|s| Section::new(OwnedOrRef::Ref(s), self.file_align(), None))
    }

    /// Iterator over [`Section`]s
    pub fn sections(&self) -> impl Iterator<Item = Section> {
        self.sections
            .iter()
            .map(|s| Section::new(OwnedOrRef::Ref(s), self.file_align(), None))
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
        self.exec.data_dirs()
    }

    /// Machine type
    pub fn machine_type(&self) -> MachineType {
        self.coff.machine
    }

    /// COFF Attributes
    pub fn attributes(&self) -> CoffFlags {
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
        self.exec.subsystem()
    }

    /// DLL Attributes
    pub fn dll_attributes(&self) -> ExecFlags {
        self.exec.dll_attributes()
    }

    /// Entry point address relative to the image base
    pub fn entry(&self) -> u32 {
        self.exec.entry()
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
        self.exec.image_base()
    }

    /// OS (major, minor)
    pub fn os_version(&self) -> (u16, u16) {
        self.exec.os_version()
    }

    /// Image (major, minor)
    pub fn image_version(&self) -> (u16, u16) {
        self.exec.image_version()
    }

    /// Subsystem (major, minor)
    pub fn subsystem_version(&self) -> (u16, u16) {
        self.exec.subsystem_version()
    }

    /// Linker (major, minor)
    pub fn linker_version(&self) -> (u8, u8) {
        self.exec.linker_version()
    }

    /// Stack (reserve, commit)
    pub fn stack(&self) -> (u64, u64) {
        self.exec.stack()
    }

    /// Heap (reserve, commit)
    pub fn heap(&self) -> (u64, u64) {
        self.exec.heap()
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
        &self.exec
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
            .field("opt", &self.exec);

        s.field("data_dirs", &{
            RawDataDirectoryHelper::new(&self.data_dirs)
        });

        s.field("sections", &self.sections)
            .field("_phantom", &self._phantom)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use core::slice::from_raw_parts;

    use super::*;

    /// Ensures that a "evil" PE can be parsed safely
    ///
    /// An "evil" PE has:
    /// - a DOS PE offset pointing inside the DOS header
    /// - `mem_align` with the lower half set to `2`
    /// - `disk_align` with the upper half set to `0`
    #[test]
    fn evil_dos() -> Result<()> {
        let machine = MachineType::AMD64;
        let subsystem = Subsystem::WINDOWS_CLI;
        let flags = CoffFlags::IMAGE | CoffFlags::LARGE_ADDRESS_AWARE;
        let dll_flags = ExecFlags::HIGH_ENTROPY_VA | ExecFlags::NX_COMPAT;
        let pe_offset: u32 = 2;
        let image_base: u64 = 0x00400000;

        // Note that this will end up actually being 0x100002 due to `pe_offset`
        // FIXME: Is there a way to resolve this?
        let mem_align: u32 = 4096;

        // FIXME: Upper two bytes overridden by lower two of `pe_offset`
        let disk_align: u32 = 512;

        let mut dos = RawDos::new();
        dos.last_bytes = u16::from_ne_bytes([PE_MAGIC[0], PE_MAGIC[1]]);
        dos.pages = u16::from_ne_bytes([PE_MAGIC[2], PE_MAGIC[3]]);

        // COFF header starts at offset 6 in DOS header
        dos.relocations = machine.value();

        // Exec header size
        //
        // RawCoff - exec_header_size
        // offset 16 in COFF header, 22 in DOS.
        dos.initial_cs = (size_of::<RawExec64>() - 36) as u16;

        // Flags
        //
        // RawCoff - file_attributes
        // offset 18 in COFF header, 24 in DOS.
        dos.relocation_offset = flags.bits();

        // The common Exec header starts at offset 26 in the DOS header
        //
        // The full exec header is 112 bytes, but only 38 bytes are left in the DOS
        // header, so it will run over outside it.
        dos.overlay_num = PE32_64_MAGIC;

        // Offset 60, the DOS PE offset, will override
        // the second half of `RawExec64::mem_align`.
        dos.pe_offset = pe_offset;

        // The 64-bit exec header starts at offset `26 + 24` aka `50`, in the DOS header
        let hdr = &mut &mut dos._reserved2[10..];

        // RawExec64 - image_base
        // Offset 50 in the DOS header, offset 24 in the exec header
        hdr[..8].copy_from_slice(&image_base.to_ne_bytes());
        *hdr = &mut hdr[8..];

        // RawExec64 - mem_align, upper half
        // Only the upper two bytes will be used.
        //
        // `mem_align` is 4 bytes, but only 2 are left in `RawDos::_reserved2`
        // The lower 2 bytes come from `RawDos::pe_offset`.
        //
        // But `RawDos::pe_offset` is 32-bits, so it ALSO has 2 "extra" bytes,
        // which will override the upper two bytes of `RawExec64::disk_align`
        // with `pe_offset`s lower two, which will be zero.
        hdr[..2].copy_from_slice(&mem_align.to_ne_bytes()[..2]);

        // Total image size
        // - DOS header
        // - RawExec64 size, minus the parts that fit in the DOS header.
        //   - `36` is the offset to `RawExec64::disk_align`
        //     - Offset two bytes inside because `disk_align` is partially made up of
        //       `pe_offset`
        // -
        let size = size_of::<RawDos>() + (size_of::<RawExec64>() - 38);

        let mut evil_out: Vec<u8> = Vec::with_capacity(size);

        // RawDos
        // Contains entire PE sig and COFF header
        {
            let bytes = unsafe {
                let ptr = &dos as *const RawDos as *const u8;
                from_raw_parts(ptr, size_of::<RawDos>())
            };

            evil_out.extend_from_slice(bytes);
        }

        // RawExec64 - Disk align
        // Offset 36 in RawExec64, actually at offset 38
        evil_out.extend_from_slice(&[0, 0]);

        // RawExec64 - zero pad fields
        evil_out.resize(evil_out.len() + 16, 0);

        // RawExec64 - image_size
        evil_out.extend_from_slice(&(size as u32).to_ne_bytes());

        // RawExec64 - headers_size
        {
            let disk_align = disk_align as usize;

            let diff = size % disk_align;
            let a = size + (disk_align - diff);

            let aligned_size = size.max(a) as u32;
            evil_out.extend_from_slice(&aligned_size.to_ne_bytes());
        }

        // RawExec64 - checksum
        evil_out.extend_from_slice(&0u32.to_ne_bytes());

        // RawExec64 - subsystem
        evil_out.extend_from_slice(&subsystem.value().to_ne_bytes());

        // RawExec64 - dll_attributes
        evil_out.extend_from_slice(&dll_flags.bits().to_ne_bytes());

        // RawExec64 - zero pad remaining fields
        evil_out.resize(evil_out.len() + 40, 0);

        assert_eq!(evil_out.len(), size, "evil_out was not the expected size");

        unsafe {
            // let ptr = (&mut dos) as *mut RawDos;
            // let ptr = ptr as *const u8;
            let ptr = evil_out.as_ptr();

            // #[cfg(no)]
            {
                let raw_pe = RawPe::from_ptr(ptr.add(2), size);

                eprintln!("raw pe = {raw_pe:#?}");

                if let Ok(raw_pe) = raw_pe {
                    assert_eq!({ raw_pe.coff.machine }, machine, "Evil PE wasn't correct");
                    assert_eq!(
                        { raw_pe.coff.file_attributes },
                        flags,
                        "Evil PE wasn't correct"
                    );
                }

                let exec = ExecHeader::from_ptr(ptr.add(2).add(size_of::<RawPe>()), size);

                eprintln!("raw exec = {exec:#?}");

                if let Ok(exec) = exec {
                    let raw_dos = &*(ptr as *const RawDos);

                    assert_eq!(raw_dos, &dos, "Evil dos wasn't correct");

                    assert_eq!(
                        { exec.raw_exec().magic },
                        PE32_64_MAGIC,
                        "Evil exec magic wasn't correct"
                    );

                    assert_eq!(
                        exec.image_base(),
                        image_base,
                        "Evil exec image base wasn't correct"
                    );

                    #[cfg(no)]
                    assert_eq!(
                        exec.file_align(),
                        disk_align,
                        "Evil exec disk_align wasn't correct"
                    );

                    assert_eq!(
                        exec.image_size() as usize,
                        size,
                        "Evil exec image size wasn't correct"
                    );

                    assert_eq!(
                        { exec.subsystem() },
                        subsystem,
                        "Evil exec subsystem wasn't correct"
                    );
                }
            }

            let pe = Pe::from_ptr(ptr, size);

            eprintln!("pe = {pe:#?}");

            if let Ok(pe) = pe {
                let exec = &pe.exec;
                assert_eq!(exec.image_base(), image_base, "Evil exec wasn't correct");
                assert_eq!(exec.file_align(), disk_align, "Evil exec wasn't correct");
                assert_eq!({ exec.subsystem() }, subsystem, "Evil exec wasn't correct");
            }

            // assert!(
            //     matches!(pe, Err(Error::MissingExecHeader)),
            //     "Pe::from_ptr returned the incorrect error for an out of bounds PE
            // offset" );

            // panic!();
            Ok(())
        }
    }

    /// Ensure that various invalid PE offsets behave correctly
    #[test]
    fn pe_offset() -> Result<()> {
        unsafe {
            let values = [
                512,
                u32::MAX,
                u32::MAX - 1,
                u32::MAX - 64,
                u32::MAX - 63,
                u32::MAX - 65,
                (size_of::<RawDos>() - 1) as u32,
                size_of::<RawDos>() as u32,
            ];
            for v in values {
                eprintln!("{v:#?}");

                let mut dos = RawDos::new();
                dos.pe_offset = v;

                let ptr = (&mut dos) as *mut RawDos;
                let ptr = ptr as *const u8;

                let pe = Pe::from_ptr(ptr, size_of::<RawDos>());
                eprintln!("{pe:#?}");

                assert!(
                    matches!(pe, Err(Error::MissingPE)),
                    "Pe::from_ptr returned the incorrect error for an out of bounds PE offset"
                );
            }

            Ok(())
        }
    }
}
