//! Builders and stuff
use alloc::{vec, vec::Vec};
use core::{fmt, marker::PhantomData, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    internal::debug::{DosHelper, RawDataDirectoryHelper},
    raw::{coff::RawCoff, dos::RawDos, exec::*, pe::*, RawSectionHeader},
    CoffFlags,
    DataDirIdent,
    ExecFlags,
    ExecHeader,
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
// TODO: Limit by internal trait
// TODO: Methods available on as many states as possible
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
    disk_align: u64,

    /// Defaults to 0
    entry: u32,

    /// DOS Header and stub to use. Defaults to empty, no stub.
    dos: Option<(RawDos, VecOrSlice<'data, u8>)>,

    /// COFF Attributes
    attributes: CoffFlags,

    /// DLL Attributes
    dll_attributes: ExecFlags,

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

    /// PE32 vs PE32+
    plus: bool,

    code_size: Option<u32>,
    init_size: Option<u32>,
    uninit_size: Option<u32>,
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
            disk_align: 512,
            entry: 0,
            dos: None,
            attributes: CoffFlags::IMAGE | CoffFlags::LARGE_ADDRESS_AWARE,
            subsystem: Subsystem::UNKNOWN,
            dll_attributes: ExecFlags::empty(),
            stack: (0, 0),
            heap: (0, 0),
            os_ver: (0, 0),
            image_ver: (0, 0),
            subsystem_ver: (0, 0),
            linker_ver: (0, 0),
            plus: false,
            code_size: None,
            init_size: None,
            uninit_size: None,
        }
    }

    /// Machine Type. This is required.
    ///
    /// `plus` determines whether the image is a PE32 or a PE32+ image,
    /// or in other words whether it uses 32-bit or 64-bit pointers.
    pub fn machine(
        &mut self,
        machine: MachineType,
        plus: bool,
    ) -> &mut PeBuilder<'data, states::Machine> {
        self.machine = machine;
        self.plus = plus;
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
    pub fn attributes(&mut self, attr: CoffFlags) -> &mut Self {
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
    pub fn dll_attributes(&mut self, attr: ExecFlags) -> &mut Self {
        self.dll_attributes = attr;
        self
    }

    /// Append a section
    pub fn section(&mut self, section: &mut SectionBuilder) -> &mut Self {
        let header = section.to_raw_section(
            self.next_mem_ptr(),
            self.next_disk_offset(),
            self.disk_align as u32,
        );

        match &mut self.sections {
            VecOrSlice::Vec(v) => v.push((
                Section::new(OwnedOrRef::Owned(header), self.disk_align as u32, None),
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
    /// Only use this if you know what you're doing.
    /// The standard data directories are always included.
    pub fn append_data_dir(&mut self, address: u32, size: u32) -> &mut Self {
        match &mut self.data_dirs {
            VecOrSlice::Vec(v) => v.push(RawDataDirectory::new(address, size)),
            VecOrSlice::Slice(_) => todo!(),
        }
        self
    }

    /// Manually set the CodeSize in the image
    ///
    /// This is very advanced and should only be used if you know what you're
    /// doing. By default this is given a sensible value.
    pub fn code_size(&mut self, size: u32) -> &mut Self {
        self.code_size = Some(size);
        self
    }

    /// Manually set the InitSize in the image
    ///
    /// This is very advanced and should only be used if you know what you're
    /// doing. By default this is given a sensible value.
    pub fn init_size(&mut self, size: u32) -> &mut Self {
        self.init_size = Some(size);
        self
    }

    /// Manually set the UninitSize in the image
    ///
    /// This is very advanced and should only be used if you know what you're
    /// doing. By default this is given a sensible value.
    pub fn uninit_size(&mut self, size: u32) -> &mut Self {
        self.uninit_size = Some(size);
        self
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Write the Image, appending to `out`
    // TODO: It should be perfectly possible to calculate the exact size of
    // the buffer needed, so allowing two different functions,
    // with `MaybeUninit`.
    // Caller can allocate exact buffer, `write` won't need to
    // allocate itself anymore.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        // Provided stub or default empty stub
        // TODO: Add default "standard" stub?
        let (dos, stub) = self
            .dos
            .as_ref()
            .map(|f| (f.0, VecOrSlice::Slice(&f.1)))
            .unwrap_or_else(|| (RawDos::sized(), VecOrSlice::Slice(&[])));

        let sections_len: u16 = self
            .sections
            .len()
            .try_into()
            .map_err(|_| Error::TooMuchData)?;
        let sections_size = self.sections.len() * size_of::<RawSectionHeader>();
        let section_data_size: u32 = self.sections.iter().map(|(s, _)| s.disk_size()).sum();
        let section_data_size: usize = section_data_size
            .try_into()
            .map_err(|_| Error::TooMuchData)?;

        let img_hdr_size: u16 = if self.plus {
            size_of::<RawExec64>()
                .try_into()
                .map_err(|_| Error::TooMuchData)?
        } else {
            size_of::<RawExec32>()
                .try_into()
                .map_err(|_| Error::TooMuchData)?
        };
        let data_size = self.data_dirs.len() * size_of::<RawDataDirectory>();
        let data_size: u16 = data_size.try_into().map_err(|_| Error::TooMuchData)?;

        let coff = OwnedOrRef::Owned(RawCoff::new(
            self.machine,
            sections_len,
            self.timestamp,
            img_hdr_size + data_size,
            self.attributes,
        ));

        let mut code_sum = 0;
        let mut init_sum = 0;
        let mut uninit_sum = 0;
        let mut code_ptr = 0;
        let mut data_ptr = 0;
        // Get section sizes
        for (section, _) in self.sections.iter() {
            if section.flags() & SectionFlags::CODE != SectionFlags::empty() {
                // FIXME: Should this be disk_size / only init size??
                // Rustup exe seems to use that calculation???
                code_sum += section.mem_size();
                code_ptr = section.mem_ptr();
            } else if section.flags() & SectionFlags::INITIALIZED != SectionFlags::empty() {
                init_sum += section.mem_size();
                data_ptr = section.mem_ptr();
            } else if section.flags() & SectionFlags::UNINITIALIZED != SectionFlags::empty() {
                uninit_sum += section.mem_size()
            }
        }

        let image_size = self.next_mem_ptr();

        // HeaderSize is the DOS stub, COFF Header, Image/Exec Header,
        // section headers, and is aligned to `DiskAlign`.
        // FIXME: What about pe offset? need to account for null space there?
        let headers_size: u64 = (size_of::<RawDos>()
            + stub.len()
            + size_of::<RawPe>()
            + ((img_hdr_size + data_size) as usize)
            + sections_size) as u64;
        // FIXME: Check alignment first?
        let headers_size: u64 = headers_size + (self.disk_align - (headers_size % self.disk_align));
        let headers_size: u32 = headers_size.try_into().map_err(|_| Error::TooMuchData)?;

        let exec = RawExec::new(
            if self.plus { PE32_64_MAGIC } else { PE32_MAGIC },
            self.linker_ver.0,
            self.linker_ver.1,
            self.code_size.unwrap_or(code_sum),
            self.init_size.unwrap_or(init_sum),
            self.uninit_size.unwrap_or(uninit_sum),
            // FIXME: Entry point will be incredibly error prone.
            // Surely we can provide nicer here?
            self.entry,
            code_ptr,
        );
        let exec = ExecHeader::new(
            true,
            exec,
            data_ptr,
            self.image_base,
            self.section_align as u32,
            self.disk_align as u32,
            self.os_ver.0,
            self.os_ver.1,
            self.image_ver.0,
            self.image_ver.1,
            self.subsystem_ver.0,
            self.subsystem_ver.1,
            image_size,
            headers_size,
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
        )?;

        // FIXME: Account for padding and alignment between areas
        let min_size: usize = size_of::<RawDos>()
            + stub.len()
            + (dos.pe_offset as usize).saturating_sub(size_of::<RawDos>() + stub.len())
            + size_of::<RawPe>()
            + <u16 as Into<usize>>::into(img_hdr_size)
            + <u16 as Into<usize>>::into(data_size)
            + sections_size
            + section_data_size;
        out.reserve(min_size);
        let mut written = 0;

        // Write the PE DOS stub
        let bytes = unsafe {
            let ptr = &dos as *const RawDos as *const u8;
            from_raw_parts(ptr, size_of::<RawDos>())
        };
        out.extend_from_slice(bytes);
        out.extend_from_slice(&stub);
        // Align to PE offset
        written += bytes.len() + stub.len();
        if written != dos.pe_offset as usize {
            let diff = (dos.pe_offset as usize)
                .checked_sub(written)
                .ok_or(Error::InvalidData)?;
            for _ in 0..diff {
                out.push(b'\0')
            }
            written += diff;
        }

        // PE Header
        let bytes = unsafe {
            let ptr = coff.as_ref() as *const RawCoff as *const u8;
            from_raw_parts(ptr, size_of::<RawCoff>())
        };
        out.extend_from_slice(&PE_MAGIC);
        out.extend_from_slice(bytes);
        written += PE_MAGIC.len() + bytes.len();

        // Image header
        let bytes = exec.as_slice();
        out.extend_from_slice(bytes);
        written += bytes.len();
        // Data Directories
        let bytes = unsafe {
            let ptr = self.data_dirs.as_ptr() as *const u8;
            from_raw_parts(ptr, data_size.into())
        };
        out.extend_from_slice(bytes);
        written += bytes.len();

        // Section Headers
        for (s, _) in self.sections.iter() {
            let bytes = unsafe {
                let ptr = s.header.as_ref() as *const RawSectionHeader as *const u8;
                from_raw_parts(ptr, size_of::<RawSectionHeader>())
            };
            out.extend_from_slice(bytes);
            written += bytes.len();
        }
        // FIXME: Have to be able to write to arbitrary offsets, actually.
        // Need a Seek, Read, Write, and Cursor impl?

        // Section Data
        for (s, bytes) in self.sections.iter() {
            if out.len()
                < (s.disk_offset() as usize
                    + s.disk_size() as usize
                    + (s.disk_size().abs_diff(s.mem_size()) as usize))
            {
                let start = out.len();
                let end = s.disk_offset() as usize + s.disk_size() as usize;
                let diff = end - start;
                for _ in 0..(diff / 128) {
                    out.extend_from_slice(&[0; 128]);
                }
                for _ in 0..(diff % 128) {
                    out.push(b'\0');
                }
            }
            let end = s.mem_size();
            let end = end.min(s.disk_size()) as usize;
            out[s.disk_offset() as usize..][..end].copy_from_slice(&bytes[..end]);
            written += s.disk_size() as usize;
        }

        assert_eq!(min_size, written, "Min size didn't equal written");
        Ok(())
    }

    /// Get the next virtual address available for a section, or section align
    /// as a default.
    fn next_mem_ptr(&self) -> u32 {
        // Highest VA seen, and its size
        let mut max_va = (self.section_align as u32, 0);
        for (section, _) in self.sections.iter() {
            let va = max_va.0.max(section.mem_ptr());
            let size = section.mem_size();
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
    fn next_disk_offset(&self) -> u32 {
        // FIXME: Account for header size, don't collide with headers.
        // Highest offset seen, and its size
        let mut max_off = (self.disk_align as u32, 0);
        for (section, _) in self.sections.iter() {
            // FIXME: Am I just high or is this wrong
            // size will be wrong????
            let off = max_off.0.max(section.disk_offset());
            let size = section.disk_size();
            max_off = (off, size);
        }

        let ret = max_off.0 + max_off.1;
        if ret % self.disk_align as u32 != 0 {
            ret + (self.disk_align as u32 - (ret % self.disk_align as u32))
        } else {
            ret
        }
    }
}

impl<'data> PeBuilder<'data, states::Machine> {
    /// Create a [`PeBuilder`] from an existing [`Pe`],
    /// with `pe_bytes` being the data from the PE
    pub fn from_pe(pe: &'data Pe, pe_bytes: &'data [u8]) -> Self {
        let this = Self {
            state: PhantomData,
            sections: VecOrSlice::Vec(
                pe.sections()
                    .map(|s| {
                        // FIXME: Why Vec?
                        let v = VecOrSlice::Vec(
                            pe_bytes[s.disk_offset() as usize..][..s.disk_size() as usize].to_vec(),
                        );
                        (s, v)
                    })
                    .collect(),
            ),
            data_dirs: VecOrSlice::Vec({
                // FIXME: Why Vec?
                let mut v: Vec<_> = pe.data_dirs().map(|d| *d.header).collect();
                let len = v.len().max(16);
                v.resize(len, RawDataDirectory::new(0, 0));
                v
            }),
            machine: pe.machine_type(),
            timestamp: pe.timestamp(),
            image_base: pe.image_base(),
            section_align: pe.section_align().into(),
            disk_align: pe.file_align().into(),
            entry: pe.entry(),
            dos: Some((*pe.dos(), VecOrSlice::Vec(pe.dos_stub().into()))),
            attributes: pe.attributes(),
            subsystem: pe.subsystem(),
            dll_attributes: pe.dll_attributes(),
            stack: pe.stack(),
            heap: pe.heap(),
            os_ver: pe.os_version(),
            image_ver: pe.image_version(),
            subsystem_ver: pe.subsystem_version(),
            linker_ver: pe.linker_version(),
            plus: matches!(pe.opt(), ExecHeader::Raw64(_)),
            code_size: Some(pe.opt().code_size()),
            init_size: Some(pe.opt().init_size()),
            uninit_size: Some(pe.opt().uninit_size()),
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
            .field("sections", &{
                struct Helper<'data>(
                    &'data VecOrSlice<'data, (Section<'data>, VecOrSlice<'data, u8>)>,
                );
                impl<'data> fmt::Debug for Helper<'data> {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.debug_list()
                            .entries(self.0.iter().map(|(s, _)| s))
                            .finish()
                    }
                }
                Helper(&self.sections)
            })
            .field("data_dirs", &{
                RawDataDirectoryHelper::new(&self.data_dirs)
            })
            .field("machine", &self.machine)
            .field("timestamp", &self.timestamp)
            .field("image_base", &self.image_base)
            .field("section_align", &self.section_align)
            .field("file_align", &self.disk_align)
            .field("entry", &self.entry)
            .field(
                "dos",
                &self.dos.as_ref().map(|(d, b)| (d, DosHelper::new(b))),
            )
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
    disk_offset: Option<u32>,
    disk_size: Option<u32>,
    mem_size: Option<u32>,
}

impl<'data> SectionBuilder<'data> {
    #[cfg(no)]
    fn to_raw_section(&self) -> RawSectionHeader {
        todo!()
    }

    /// Convert to a [`RawSectionHeader`] using the supplied
    /// values.
    ///
    /// It is important to make sure these uphold the PE invariants.
    // #[cfg(no)]
    fn to_raw_section(&self, mem_ptr: u32, disk_offset: u32, disk_align: u32) -> RawSectionHeader {
        let mem_size = self.mem_size.unwrap();
        let len = mem_size;
        let disk_offset = self.disk_offset.unwrap_or(disk_offset);

        let disk_size = self.disk_size.unwrap_or(mem_size);
        let disk_size = if disk_size % disk_align != 0 {
            disk_size + (disk_align - (disk_size % disk_align))
        } else {
            disk_size
        };

        RawSectionHeader {
            name: self.name,
            mem_size: len,
            mem_ptr,
            disk_size,
            disk_offset,
            reloc_offset: 0,
            line_offset: 0,
            reloc_len: 0,
            lines_len: 0,
            attributes: self.attr,
        }
    }
}

impl<'data> SectionBuilder<'data> {
    /// Create a new [`SectionBuilder`]
    pub fn new() -> Self {
        Self {
            name: [b'\0'; 8],
            data: VecOrSlice::Slice(&[]),
            attr: SectionFlags::empty(),
            disk_offset: None,
            disk_size: None,
            mem_size: None,
        }
    }

    pub fn from_section(_sec: &'data Section<'data>) -> Self {
        todo!()
    }

    /// Name of the section. Required.
    ///
    /// If `name` is more than 8 bytes, it is truncated.
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name[..name.len().min(8)].copy_from_slice(name.as_bytes());
        self
    }

    /// Data in the section. Required.
    ///
    /// The length of `data` is used as `DiskSize` and `MemSize`.
    ///
    /// Note that `DiskSize` will be aligned to `DiskAlign`, but
    /// `MemSize` is not aligned.
    pub fn data(&mut self, data: &'data [u8]) -> &mut Self {
        // TODO: From/Into impl
        self.data = VecOrSlice::Slice(data);
        self.mem_size = Some(data.len() as u32);
        self.disk_size = Some(data.len() as u32);
        self
    }

    /// Manually set `MemSize`
    ///
    /// Defaults to the size of data
    ///
    /// This is for advanced use-cases
    pub fn mem_size(&mut self, size: u32) -> &mut Self {
        self.mem_size = Some(size);
        self
    }

    /// Disk offset to the section.
    /// Defaults to next available, or the file alignment, aligned as needed.
    /// TODO: Absolutely must account for header size here.
    ///
    /// This MUST be a power of 2 between 512 and 64K.
    ///
    /// If not it will silently be rounded up to the next alignment.
    ///
    /// This MUST not overlap with another section
    pub fn disk_offset(&mut self, offset: u32) -> &mut Self {
        self.disk_offset = Some(offset);
        self
    }

    /// Manually set the size of the section on disk
    ///
    /// See [`SectionBuilder::data`] for details on the default value of this.
    ///
    /// By default this is the size of the slice given in
    /// [`SectionBuilder::data`], rounded up to a multiple of the file
    /// alignment.
    ///
    /// TODO: *Don't* enforce alignment here
    pub fn disk_size(&mut self, size: u32) -> &mut Self {
        self.disk_size = Some(size);
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
            .field("offset", &self.disk_offset)
            .field("size", &self.disk_size)
            .finish()
    }
}
