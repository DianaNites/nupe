//! Builders and stuff
use alloc::{vec, vec::Vec};
use core::{fmt, marker::PhantomData, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    raw::{
        RawCoff,
        RawDos,
        RawPe,
        RawPe32,
        RawPe32x64,
        RawPeOptStandard,
        RawSectionHeader,
        PE32_64_MAGIC,
        PE32_MAGIC,
        PE_MAGIC,
    },
    CoffAttributes,
    DataDirIdent,
    DllCharacteristics,
    MachineType,
    OwnedOrRef,
    Pe,
    RawDataDirectory,
    Section,
    SectionFlags,
    Subsystem,
    VecOrSlice,
};

/// Default image base to use
const DEFAULT_IMAGE_BASE: u64 = 0x10000000;

mod states {
    //! States for [`crate::Pe`]

    #[derive(Debug, Clone, Copy)]
    pub struct Empty;

    #[derive(Debug, Clone, Copy)]
    pub struct Machine;
}

/// Builder for a [`crate::Pe`] file
pub struct PeBuilder<'data, State> {
    /// Type state.
    state: PhantomData<State>,

    /// Sections to write to the image.
    sections: VecOrSlice<'data, (Section<'data>, VecOrSlice<'data, u8>)>,

    /// Data dirs to write to the image, defaults to all 16, zeroed.
    data_dirs: VecOrSlice<'data, RawDataDirectory>,

    /// Machine type. Required.
    machine: MachineType,

    /// Timestamp. Defaults to 0.
    timestamp: u32,

    /// Defaults to [`DEFAULT_IMAGE_BASE`]
    image_base: u64,

    /// Defaults to 4096
    section_align: u64,

    /// Defaults to 512
    file_align: u64,

    /// Defaults to 0
    entry: u32,

    /// DOS Header and stub to use. Defaults to empty, no stub.
    dos: Option<(RawDos, VecOrSlice<'data, u8>)>,

    /// COFF Attributes
    attributes: CoffAttributes,

    /// DLL Attributes
    dll_attributes: DllCharacteristics,

    /// Subsystem
    subsystem: Subsystem,

    /// Stack reserve and commit
    stack: (u64, u64),

    /// Heap reserve and commit
    heap: (u64, u64),

    /// OS version
    os_ver: (u16, u16),

    /// Image version
    image_ver: (u16, u16),

    /// Subsystem version
    subsystem_ver: (u16, u16),

    /// Subsystem version
    linker_ver: (u8, u8),
}

impl<'data> PeBuilder<'data, states::Empty> {
    /// Create a new [`PeBuilder`]
    pub fn new() -> Self {
        Self {
            state: PhantomData,
            sections: VecOrSlice::Vec(Vec::new()),
            data_dirs: VecOrSlice::Vec(vec![RawDataDirectory::new(0, 0); 16]),
            machine: MachineType::UNKNOWN,
            timestamp: 0,
            image_base: DEFAULT_IMAGE_BASE,
            section_align: 4096,
            file_align: 512,
            entry: 0,
            dos: None,
            attributes: CoffAttributes::IMAGE | CoffAttributes::LARGE_ADDRESS_AWARE,
            subsystem: Subsystem::UNKNOWN,
            dll_attributes: DllCharacteristics::empty(),
            stack: (0, 0),
            heap: (0, 0),
            os_ver: (0, 0),
            image_ver: (0, 0),
            subsystem_ver: (0, 0),
            linker_ver: (0, 0),
        }
    }

    /// Machine Type. This is required.
    pub fn machine(&mut self, machine: MachineType) -> &mut PeBuilder<'data, states::Machine> {
        self.machine = machine;
        unsafe { &mut *(self as *mut Self as *mut PeBuilder<'data, states::Machine>) }
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Offset from image base to entry point
    ///
    /// Defaults to 0
    pub fn entry(&mut self, entry: u32) -> &mut Self {
        self.entry = entry;
        self
    }

    /// Stack reserve and commit, respectively
    pub fn stack(&mut self, stack: (u64, u64)) -> &mut Self {
        self.stack = stack;
        self
    }

    /// Heap reserve and commit, respectively
    pub fn heap(&mut self, heap: (u64, u64)) -> &mut Self {
        self.heap = heap;
        self
    }

    /// OS (major, minor)
    pub fn os_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.os_ver = ver;
        self
    }

    /// Image (major, minor)
    pub fn image_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.image_ver = ver;
        self
    }

    /// Subsystem (major, minor)
    pub fn subsystem_version(&mut self, ver: (u16, u16)) -> &mut Self {
        self.subsystem_ver = ver;
        self
    }

    /// Linker (major, minor)
    pub fn linker_version(&mut self, ver: (u8, u8)) -> &mut Self {
        self.linker_ver = ver;
        self
    }

    /// Stack reserve and commit, respectively
    pub fn subsystem(&mut self, subsystem: Subsystem) -> &mut Self {
        self.subsystem = subsystem;
        self
    }

    /// Attributes for the [`crate::Pe`] file.
    ///
    /// If unset, this defaults to `IMAGE | LARGE_ADDRESS_AWARE`.
    ///
    /// This completely overwrites the attributes.
    pub fn attributes(&mut self, attr: CoffAttributes) -> &mut Self {
        self.attributes = attr;
        self
    }

    /// DOS Header and stub
    ///
    /// If unset, this defaults to an empty header, except for the PE offset,
    /// and no DOS stub.
    ///
    /// This completely overwrites the header and stub.
    pub fn dos(&mut self, dos: RawDos, stub: VecOrSlice<'data, u8>) -> &mut Self {
        self.dos = Some((dos, stub));
        self
    }

    /// Low 32 bits of the unix timestamp for this image.
    pub fn timestamp(&mut self, time: u32) -> &mut Self {
        self.timestamp = time;
        self
    }

    /// Preferred base address of the image
    pub fn image_base(&mut self, image_base: u64) -> &mut Self {
        self.image_base = image_base;
        self
    }

    /// DLL Attributes for the [`crate::Pe`] image.
    pub fn dll_attributes(&mut self, attr: DllCharacteristics) -> &mut Self {
        self.dll_attributes = attr;
        self
    }

    /// Append a section
    pub fn section(&mut self, section: &mut SectionBuilder) -> &mut Self {
        let len = section.data.len().try_into().unwrap();
        let va = self.next_virtual_address();
        let file_offset = section.offset.unwrap_or_else(|| self.next_file_offset());
        let file_size = section.size.unwrap_or(len);
        let file_size = if file_size % self.file_align as u32 != 0 {
            file_size + (self.file_align as u32 - (file_size % self.file_align as u32))
        } else {
            file_size
        };
        let header = RawSectionHeader {
            name: section.name,
            virtual_size: { len },
            virtual_address: va,
            raw_size: file_size,
            raw_ptr: file_offset,
            reloc_ptr: 0,
            line_ptr: 0,
            num_reloc: 0,
            num_lines: 0,
            characteristics: section.attr,
        };

        match &mut self.sections {
            VecOrSlice::Vec(v) => v.push((
                Section::new(OwnedOrRef::Owned(header), self.file_align as u32, None),
                // FIXME: to_vec
                VecOrSlice::Vec(section.data.to_vec()),
                // VecOrSlice::Slice(&section.data),
            )),
            VecOrSlice::Slice(_) => todo!(),
        }

        // self.sections
        //     .sort_unstable_by(|a, b| a.0.file_offset().cmp(&b.0.file_offset()));

        self
    }

    /// Add the data directory `id`
    pub fn data_dir(&mut self, id: DataDirIdent, address: u32, size: u32) -> &mut Self {
        if let Some(dir) = self.data_dirs.get_mut(id.index()) {
            dir.address = address;
            dir.size = size;
        }
        self
    }

    /// Append a data directory to the header.
    ///
    /// Only use this if you know wat you're doing.
    /// The standard data directories are always included.
    pub fn append_data_dir(&mut self, address: u32, size: u32) -> &mut Self {
        match &mut self.data_dirs {
            VecOrSlice::Vec(v) => v.push(RawDataDirectory::new(address, size)),
            VecOrSlice::Slice(_) => todo!(),
        }
        self
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Calculate the size on disk this file would take
    ///
    /// Ignores file alignment
    #[cfg(no)]
    fn calculate_size(&self) -> usize {
        const DOS_STUB: usize = 0;
        let opt_size = match self.machine {
            MachineType::AMD64 => size_of::<RawPe32x64>(),
            MachineType::I386 => size_of::<RawPe32>(),
            _ => unimplemented!(),
        };
        #[allow(clippy::erasing_op)]
        let data_dirs = size_of::<RawDataDirectory>() * 0;
        #[allow(clippy::erasing_op)]
        let sections = size_of::<RawSectionHeader>() * 0;
        let sections_sum: u32 = self.sections.iter().map(|s| s.header.raw_size).sum();
        let sections_sum = sections_sum as usize;
        size_of::<RawDos>()
            + DOS_STUB
            + size_of::<RawPe>()
            + opt_size
            + data_dirs
            + sections
            + sections_sum
    }

    /// Write the DOS header
    ///
    /// The PE offset is expected to point directly after the DOS header and
    /// stub, aligned up to 8 bytes.
    ///
    /// TODO: May need to support more of the DOS format to be able to perfectly
    /// represent this, because of hidden metadata between the stub and PE.
    ///
    /// By default there is no stub, and the header only contains the offset.
    fn write_dos(out: &mut Vec<u8>, dos: &Option<(RawDos, VecOrSlice<u8>)>) -> Result<()> {
        if let Some((dos, stub)) = dos {
            // Provided header and stub, PE expected directly after this, aligned.
            let bytes = unsafe {
                let ptr = dos as *const RawDos as *const u8;
                from_raw_parts(ptr, size_of::<RawDos>())
            };
            out.reserve(bytes.len() + stub.len() + 8);
            out.extend_from_slice(bytes);
            // Stub
            out.extend_from_slice(stub);
            // Align
            let size = size_of::<RawDos>() + stub.len();
            if size % 8 != 0 {
                let align = size + (8 - (size % 8));
                let align = align - size;
                out.reserve(align);
                for _ in 0..align {
                    out.push(b'\0')
                }
            }
        } else {
            // No stub, PE expected directly after this, 64 is already 8 aligned.
            let dos = RawDos::new(size_of::<RawDos>() as u32);
            let bytes = unsafe {
                let ptr = &dos as *const RawDos as *const u8;
                from_raw_parts(ptr, size_of::<RawDos>())
            };
            out.extend_from_slice(bytes);
        };
        Ok(())
    }

    /// Write the PE header.
    ///
    /// If `plus` is true then expect PE32+ for the optional header.
    ///
    /// Returns the expected/computed size of the optional header
    fn write_pe(
        out: &mut Vec<u8>,
        machine: MachineType,
        plus: bool,
        sections: u16,
        timestamp: u32,
        attributes: CoffAttributes,
        data_dirs: usize,
    ) -> Result<usize> {
        out.extend_from_slice(PE_MAGIC);

        let optional_size = (data_dirs * size_of::<RawDataDirectory>())
            + if plus {
                size_of::<RawPe32x64>()
            } else {
                size_of::<RawPe32>()
            };

        let coff = OwnedOrRef::Owned(RawCoff::new(
            machine,
            sections,
            timestamp,
            optional_size.try_into().map_err(|_| Error::InvalidData)?,
            attributes,
        ));

        let bytes = unsafe {
            let ptr = coff.as_ref() as *const RawCoff as *const u8;
            from_raw_parts(ptr, size_of::<RawCoff>())
        };
        out.extend_from_slice(bytes);
        Ok(optional_size)
    }

    /// Write the optional header, including data dirs.
    fn write_opt(&mut self, out: &mut Vec<u8>, plus: bool) -> Result<()> {
        let mut code_sum = 0;
        let mut init_sum = 0;
        let mut uninit_sum = 0;
        let mut code_base = 0;
        let mut data_base = 0;
        // Get section sizes
        for (section, _) in self.sections.iter() {
            if section.flags() & SectionFlags::CODE != SectionFlags::empty() {
                code_sum += section.file_size();
                code_base = section.virtual_address();
            } else if section.flags() & SectionFlags::INITIALIZED != SectionFlags::empty() {
                init_sum += section.file_size().max({
                    let size = section.virtual_size();
                    if size % self.file_align as u32 != 0 {
                        size + (self.file_align as u32 - (size % self.file_align as u32))
                    } else {
                        size
                    }
                });
                data_base = section.virtual_address();
            } else if section.flags() & SectionFlags::UNINITIALIZED != SectionFlags::empty() {
                uninit_sum += section.virtual_size()
            }
        }

        // Create standard subset
        let opt = RawPeOptStandard::new(
            if plus { PE32_64_MAGIC } else { PE32_MAGIC },
            self.linker_ver.0,
            self.linker_ver.1,
            code_sum,
            init_sum,
            uninit_sum,
            // FIXME: Entry point will be incredibly error prone.
            self.entry,
            code_base,
        );
        let headers_size = (size_of::<RawDos>()
            + self
                .dos
                .as_ref()
                .map(|(_, stub)| stub.len())
                .unwrap_or_default()
            + size_of::<RawPe>()
            + (size_of::<RawSectionHeader>() * self.sections.len()))
            as u64;

        // NOTE: SizeOfImage is, apparently, just the next offset a section *would* go.
        let image_size = self.next_virtual_address() as u64;

        let headers_size = headers_size + (self.file_align - (headers_size % self.file_align));
        // 568 + (512 - (568 % 512))
        if plus {
            let pe = RawPe32x64::new(
                opt,
                self.image_base,
                self.section_align as u32,
                self.file_align as u32,
                self.os_ver.0,
                self.os_ver.1,
                self.image_ver.0,
                self.image_ver.1,
                self.subsystem_ver.0,
                self.subsystem_ver.1,
                image_size as u32,
                headers_size as u32,
                self.subsystem,
                self.dll_attributes,
                self.stack.0,
                self.stack.1,
                self.heap.0,
                self.heap.1,
                self.data_dirs
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidData)?,
            );
            let bytes = unsafe {
                let ptr = &pe as *const RawPe32x64 as *const u8;
                from_raw_parts(ptr, size_of::<RawPe32x64>())
            };
            out.extend_from_slice(bytes);
        } else {
            let pe = RawPe32::new(
                opt,
                self.image_base as u32,
                data_base,
                self.section_align as u32,
                self.file_align as u32,
                self.os_ver.0,
                self.os_ver.1,
                self.image_ver.0,
                self.image_ver.1,
                self.subsystem_ver.0,
                self.subsystem_ver.1,
                image_size as u32,
                headers_size as u32,
                self.subsystem,
                self.dll_attributes,
                self.stack.0 as u32,
                self.stack.1 as u32,
                self.heap.0 as u32,
                self.heap.1 as u32,
                self.data_dirs
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidData)?,
            );
            let bytes = unsafe {
                let ptr = &pe as *const RawPe32 as *const u8;
                from_raw_parts(ptr, size_of::<RawPe32>())
            };
            out.extend_from_slice(bytes);
        };

        // Data dirs
        let bytes = unsafe {
            let ptr = self.data_dirs.as_ptr() as *const u8;
            from_raw_parts(ptr, size_of::<RawDataDirectory>() * self.data_dirs.len())
        };
        out.extend_from_slice(bytes);

        Ok(())
    }

    /// Write section table and data
    fn write_sections(&mut self, out: &mut Vec<u8>) -> Result<()> {
        // Reserve all the needed on-disk space
        // - The section table
        // - The section data
        out.reserve(
            (size_of::<RawSectionHeader>() * self.sections.len())
                + self
                    .sections
                    .iter()
                    .map(|(s, _)| s.file_offset() + s.file_size())
                    .map(|s| s as usize)
                    .sum::<usize>(),
        );

        // Section table
        for (s, _) in self.sections.iter() {
            let bytes = unsafe {
                let ptr = s.header.as_ref() as *const RawSectionHeader as *const u8;
                from_raw_parts(ptr, size_of::<RawSectionHeader>())
            };
            out.extend_from_slice(bytes);
            // panic!("{}", bytes.len());
        }

        // FIXME: Have to be able to write to arbitrary offsets, actually.
        // Need a Seek, Read, Write, and Cursor impl?

        // Section data
        for (s, bytes) in self.sections.iter() {
            // &out[s.file_offset() as usize..][..s.file_size() as usize];
            if out.len()
                < (s.file_offset() as usize
                    + s.file_size() as usize
                    + (s.file_size().abs_diff(s.virtual_size()) as usize))
            {
                let start = out.len();
                let end = s.file_offset() as usize + s.file_size() as usize;
                let diff = end - start;
                for _ in 0..(diff / 128) {
                    out.extend_from_slice(&[0; 128])
                }
                for _ in 0..(diff % 128) {
                    out.push(b'\0')
                }
            }
            let end = s.virtual_size();
            let end = end.min(s.file_size()) as usize;
            out[s.file_offset() as usize..][..end].copy_from_slice(&bytes[..end]);
        }
        Ok(())
    }

    /// Truncates `out` and writes [`crate::Pe`] to it
    pub fn write(&mut self, out: &mut Vec<u8>) -> Result<()> {
        /// The way we create and write a PE file is primarily virtually.
        /// This means we pretend we've written a file and fill things in based
        /// on that.
        ///
        /// This should be exactly the same as just writing the file (correctly)
        /// and then reading it.
        ///
        /// The first and most basic things needed are the sections and data
        /// directories.
        ///
        /// Most other structures cant be created without
        /// information from or about these.
        ///
        /// The first structure we can create is [`RawDos`], and this is then
        /// written, followed by the PE COFF magic and COFF header.
        ///
        /// Next is the optional header,
        /// which needs to go through all sections to sum up their sizes before
        /// being written.
        struct _DummyHoverWriteDocs;
        // TODO: Go through sections, assign virtual addresses
        // Now knowing the full scope of sections, assign file offsets
        out.clear();
        let machine = self.machine;
        let plus = match machine {
            MachineType::AMD64 => Ok(true),
            MachineType::I386 => Ok(false),
            _ => Err(Error::InvalidData),
        }?;

        Self::write_dos(out, &self.dos)?;

        let expected_opt_size = Self::write_pe(
            out,
            machine,
            plus,
            self.sections
                .len()
                .try_into()
                .map_err(|_| Error::InvalidData)?,
            self.timestamp,
            self.attributes,
            self.data_dirs.len(),
        )?;

        let size = out.len();
        self.write_opt(out, plus)?;
        let size = out.len() - size;
        // dbg!(expected_opt_size, size);
        assert_eq!(expected_opt_size, size);

        self.write_sections(out)?;

        Ok(())
    }

    /// Get the next virtual address available for a section, or section align
    /// as a default.
    fn next_virtual_address(&mut self) -> u32 {
        // Highest VA seen, and its size
        let mut max_va = (self.section_align as u32, 0);
        for (section, _) in self.sections.iter() {
            let va = max_va.0.max(section.virtual_address());
            let size = section.virtual_size();
            max_va = (va, size);
        }
        let ret = max_va.0 + max_va.1;
        if ret % self.section_align as u32 != 0 {
            ret + (self.section_align as u32 - (ret % self.section_align as u32))
        } else {
            ret
        }
    }

    /// Get the next file offset available for a section, or file align
    /// as a default.
    fn next_file_offset(&mut self) -> u32 {
        // Highest offset seen, and its size
        let mut max_off = (self.file_align as u32, 0);
        for (section, _) in self.sections.iter() {
            let off = max_off.0.max(section.file_offset());
            let size = section.file_size();
            max_off = (off, size);
        }

        let ret = max_off.0 + max_off.1;
        if ret % self.file_align as u32 != 0 {
            ret + (self.file_align as u32 - (ret % self.file_align as u32))
        } else {
            ret
        }
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    pub fn from_pe(pe: &'data Pe, pe_bytes: &'data [u8]) -> Self {
        let this = Self {
            state: PhantomData,
            sections: VecOrSlice::Vec(
                pe.sections()
                    .map(|s| {
                        let v = VecOrSlice::Vec(
                            pe_bytes[s.file_offset() as usize..][..s.virtual_size() as usize]
                                .to_vec(),
                        );
                        (s, v)
                    })
                    .collect(),
            ),
            data_dirs: VecOrSlice::Vec(pe.data_dirs().map(|d| *d.header).collect()),
            machine: pe.machine_type(),
            timestamp: pe.timestamp(),
            image_base: pe.image_base(),
            section_align: pe.section_align().into(),
            file_align: pe.file_align().into(),
            entry: pe.entry(),
            dos: Some((*pe.dos, VecOrSlice::Vec(pe.dos_stub().into()))),
            attributes: pe.attributes(),
            subsystem: pe.subsystem(),
            dll_attributes: pe.dll_attributes(),
            stack: pe.stack(),
            heap: pe.heap(),
            os_ver: pe.os_version(),
            image_ver: pe.image_version(),
            subsystem_ver: pe.subsystem_version(),
            linker_ver: pe.linker_version(),
        };
        #[cfg(no)]
        for (i, s) in pe.sections().enumerate() {
            this.section(
                SectionBuilder::new()
                    .name(s.name())
                    .data(
                        &in_bytes[s.file_offset() as usize..][..s.virtual_size() as usize],
                        Some(s.file_size()),
                    )
                    .attributes(s.flags())
                    .file_offset(s.file_offset()),
            );
        }
        #[cfg(no)]
        for (i, d) in in_pe.data_dirs().enumerate() {
            if let Ok(id) = DataDirIdent::try_from(i) {
                pe.data_dir(id, d.address(), d.size());
            } else {
                pe.append_data_dir(d.address(), d.size());
            }
        }
        this
    }
}

impl<'data> Default for PeBuilder<'data, states::Empty> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'data, State> fmt::Debug for PeBuilder<'data, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeBuilder")
            .field("state", &self.state)
            // TODO: Add helper
            // .field("sections", &self.sections)
            .field("data_dirs", &self.data_dirs)
            .field("machine", &self.machine)
            .field("timestamp", &self.timestamp)
            .field("image_base", &self.image_base)
            .field("section_align", &self.section_align)
            .field("file_align", &self.file_align)
            .field("entry", &self.entry)
            // .field("dos", &self.dos)
            .field("attributes", &self.attributes)
            .field("dll_attributes", &self.dll_attributes)
            .field("subsystem", &self.subsystem)
            .field("stack", &self.stack)
            .field("heap", &self.heap)
            .field("os_ver", &self.os_ver)
            .field("image_ver", &self.image_ver)
            .field("subsystem_ver", &self.subsystem_ver)
            .field("linker_ver", &self.linker_ver)
            .finish()
    }
}

/// Build a section for a [`crate::Pe`] file.
pub struct SectionBuilder<'data> {
    name: [u8; 8],
    data: VecOrSlice<'data, u8>,
    attr: SectionFlags,
    offset: Option<u32>,
    size: Option<u32>,
}

impl<'data> SectionBuilder<'data> {
    pub fn new() -> Self {
        Self {
            name: [b'\0'; 8],
            data: VecOrSlice::Slice(&[]),
            attr: SectionFlags::empty(),
            offset: None,
            size: None,
        }
    }

    /// Name of the section. Required.
    ///
    /// If `name` is more than 8 bytes, it is truncated.
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name[..name.len().min(8)].copy_from_slice(name.as_bytes());
        self
    }

    /// Name of the section
    ///
    /// # Errors
    ///
    /// - If `name` is more than 8 bytes.
    pub fn try_name(&mut self, name: &str) -> Result<&mut Self> {
        if name.len() > 8 {
            return Err(Error::InvalidData);
        }
        self.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(self)
    }

    /// Data in the section. Required.
    ///
    /// The length of the slice is used as virtual_size,
    /// and `file_size` is the size on disk, or the same as virtual_size
    ///
    /// This is useful for partially uninitialized sections
    pub fn data(&mut self, data: &'data [u8], file_size: Option<u32>) -> &mut Self {
        self.data = VecOrSlice::Slice(data);
        self.size = file_size;
        self
    }

    /// Data in the section. Required.
    pub fn data_vec(&mut self, data: Vec<u8>) -> &mut Self {
        // TODO: From/Into impl
        self.data = VecOrSlice::Vec(data);
        self
    }

    /// File offset. Defaults to next available, or file alignment.
    ///
    /// This MUST be a power of 2 between 512 and 64K.
    ///
    /// If not it will silently be rounded up to the next alignment.
    pub fn file_offset(&mut self, offset: u32) -> &mut Self {
        self.offset = Some(offset);
        self
    }

    /// Flags/Attributes for the section
    pub fn attributes(&mut self, attr: SectionFlags) -> &mut Self {
        self.attr = attr;
        self
    }
}

impl<'data> Default for SectionBuilder<'data> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'data> fmt::Debug for SectionBuilder<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("SectionBuilder");
        if let Ok(name) = core::str::from_utf8(&self.name) {
            s.field("name", &name);
        } else {
            s.field("name", &self.name);
        }
        s.field("data", &"VecOrSlice")
            .field("attr", &self.attr)
            .field("offset", &self.offset)
            .field("size", &self.size)
            .finish()
    }
}
