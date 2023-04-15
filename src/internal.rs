//! Internal traits and utilities
use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use bitflags::bitflags;

#[cfg(no)]
mod no {
    /// Helper trait providing an interface to I/O in both no_std and std
    #[cfg(no)]
    pub trait PeWrite {
        /// Error type returned by this trait
        type Error: fmt::Debug + fmt::Display;

        /// Write all bytes in `buf`, or return an error.
        ///
        /// Behavior on errors is implementation defined
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    }

    /// Blanket impl for `&mut CpioWrite`
    #[cfg(no)]
    impl<'a, T: PeWrite> PeWrite for &'a mut T {
        type Error = T::Error;

        fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            (*self).write_all(buf)
        }
    }

    /// Helper trait providing an interface to I/O in both no_std and std
    #[cfg(no)]
    pub trait PeRead {
        /// Error type returned by this trait
        type Error: fmt::Debug + fmt::Display;

        /// Read bytes to fill `buf`, or return an error.
        ///
        /// Behavior on errors is implementation defined
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

        fn read_exact_uninit(&mut self, buf: &mut [MaybeUninit<u8>]) -> Result<(), Self::Error> {
            todo!()
        }
    }

    /// Blanket impl for `&mut CpioRead`
    #[cfg(no)]
    impl<'a, T: PeRead> PeRead for &'a mut T {
        type Error = T::Error;

        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            (*self).read_exact(buf)
        }
    }

    /// Blanket impl for `&mut &[u8]`
    #[cfg(no)]
    impl PeRead for &[u8] {
        type Error = &'static str;

        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            let sub = self.get(..buf.len()).ok_or("Too big")?;
            buf.copy_from_slice(sub);
            *self = &self[buf.len()..];
            Ok(())
        }
    }
}

/// Helper enum for a reference to a type, or owning it
#[derive(Debug, Clone, Copy)]
pub enum OwnedOrRef<'data, T> {
    Owned(T),
    Ref(&'data T),
}

impl<'data, T> Deref for OwnedOrRef<'data, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

impl<'data, T> AsRef<T> for OwnedOrRef<'data, T> {
    fn as_ref(&self) -> &T {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

#[cfg(no)]
impl<'data, T> DerefMut for OwnedOrRef<'data, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

#[cfg(no)]
impl<'data, T> AsMut<T> for OwnedOrRef<'data, T> {
    fn as_mut(&mut self) -> &mut T {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

/// Helper enum for a reference to a slice of type, or a vec of it
#[derive(Debug, Clone)]
pub enum VecOrSlice<'data, T> {
    Vec(Vec<T>),
    Slice(&'data [T]),
}

impl<'data, T> Deref for VecOrSlice<'data, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        match self {
            VecOrSlice::Vec(v) => v,
            VecOrSlice::Slice(r) => r,
        }
    }
}

impl<'data, T> AsRef<[T]> for VecOrSlice<'data, T> {
    fn as_ref(&self) -> &[T] {
        match self {
            VecOrSlice::Vec(v) => v,
            VecOrSlice::Slice(r) => r,
        }
    }
}

/// Bad DerefMut, sometimes fails.
#[doc(hidden)]
impl<'data, T> DerefMut for VecOrSlice<'data, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            VecOrSlice::Vec(v) => v,
            VecOrSlice::Slice(_) => unimplemented!("DerefMut on VecOrSlice::Slice"),
        }
    }
}

/// Machine type, or architecture, of the PE file.
///
/// This is what architectures the file will run on.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachineType(u16);

impl MachineType {
    /// Unknown/Any/All machine type
    pub const UNKNOWN: Self = Self(0);

    /// x64
    pub const AMD64: Self = Self(0x8664);

    /// x86
    pub const I386: Self = Self(0x14C);

    /// EFI Byte Code
    pub const EBC: Self = Self(0xEBC);
}

impl fmt::Debug for MachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "MachineType::UNKNOWN"),
            Self::AMD64 => write!(f, "MachineType::AMD64"),
            Self::I386 => write!(f, "MachineType::I386"),
            Self::EBC => write!(f, "MachineType::EBC"),
            _ => f.debug_tuple("MachineType").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for MachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "UNKNOWN"),
            Self::AMD64 => write!(f, "AMD64"),
            Self::I386 => write!(f, "I386"),
            Self::EBC => write!(f, "EBC"),
            _ => f.debug_tuple("MachineType").field(&self.0).finish(),
        }
    }
}

/// Subsystem, or type, of the PE file.
///
/// This determines a few things, such as the expected signature of the
/// application entry point, expected existence and contents of sections, etc.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Subsystem(u16);

impl Subsystem {
    /// Unknown subsystem
    pub const UNKNOWN: Self = Self(0);

    /// Native kernel code
    pub const NATIVE: Self = Self(1);

    /// Windows GUI
    pub const WINDOWS_GUI: Self = Self(2);

    /// Windows CLI
    pub const WINDOWS_CLI: Self = Self(3);

    /// OS2 CLI
    pub const OS2_CLI: Self = Self(5);

    /// POSIX CLI
    pub const POSIX_CLI: Self = Self(7);

    /// Native Win9x
    pub const NATIVE_WINDOWS: Self = Self(8);

    /// Windows CE
    pub const WINDOWS_CE_GUI: Self = Self(9);

    /// EFI Application
    ///
    /// The result of this is the applications memory type becomes EfiLoader
    pub const EFI_APPLICATION: Self = Self(10);

    /// EFI Boot Driver
    ///
    /// The result of this is the drivers memory type becomes EfiBootServices
    pub const EFI_BOOT_DRIVER: Self = Self(11);

    /// EFI Runtime driver
    ///
    /// The result of this is the drivers memory type becomes EiRuntimeServices
    pub const EFI_RUNTIME_DRIVER: Self = Self(12);

    /// EFI ROM?
    ///
    /// The result of this is the applications memory type becomes ?
    pub const EFI_ROM: Self = Self(13);

    /// XBOX
    pub const XBOX: Self = Self(14);

    /// Windows boot?
    pub const WINDOWS_BOOT: Self = Self(16);
}

impl fmt::Debug for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "Subsystem::UNKNOWN"),
            Self::NATIVE => write!(f, "Subsystem::NATIVE"),
            Self::WINDOWS_GUI => write!(f, "Subsystem::WINDOWS_GUI"),
            Self::WINDOWS_CLI => write!(f, "Subsystem::WINDOWS_CLI"),
            Self::OS2_CLI => write!(f, "Subsystem::OS2_CLI"),
            Self::POSIX_CLI => write!(f, "Subsystem::POSIX_CLI"),
            Self::NATIVE_WINDOWS => write!(f, "Subsystem::NATIVE_WINDOWS"),
            Self::WINDOWS_CE_GUI => write!(f, "Subsystem::WINDOWS_CE_GUI"),
            Self::EFI_APPLICATION => write!(f, "Subsystem::EFI_APPLICATION"),
            Self::EFI_BOOT_DRIVER => write!(f, "Subsystem::EFI_BOOT_DRIVER"),
            Self::EFI_RUNTIME_DRIVER => write!(f, "Subsystem::EFI_RUNTIME_DRIVER"),
            Self::EFI_ROM => write!(f, "Subsystem::EFI_ROM"),
            Self::XBOX => write!(f, "Subsystem::XBOX"),
            Self::WINDOWS_BOOT => write!(f, "Subsystem::WINDOWS_BOOT"),
            _ => f.debug_tuple("Subsystem").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UNKNOWN => write!(f, "UNKNOWN"),
            Self::NATIVE => write!(f, "NATIVE"),
            Self::WINDOWS_GUI => write!(f, "WINDOWS_GUI"),
            Self::WINDOWS_CLI => write!(f, "WINDOWS_CLI"),
            Self::OS2_CLI => write!(f, "OS2_CLI"),
            Self::POSIX_CLI => write!(f, "POSIX_CLI"),
            Self::NATIVE_WINDOWS => write!(f, "NATIVE_WINDOWS"),
            Self::WINDOWS_CE_GUI => write!(f, "WINDOWS_CE_GUI"),
            Self::EFI_APPLICATION => write!(f, "EFI_APPLICATION"),
            Self::EFI_BOOT_DRIVER => write!(f, "EFI_BOOT_DRIVER"),
            Self::EFI_RUNTIME_DRIVER => write!(f, "EFI_RUNTIME_DRIVER"),
            Self::EFI_ROM => write!(f, "EFI_ROM"),
            Self::XBOX => write!(f, "XBOX"),
            Self::WINDOWS_BOOT => write!(f, "WINDOWS_BOOT"),
            _ => f.debug_tuple("Subsystem").field(&self.0).finish(),
        }
    }
}

/// Known tables/data directories
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DataDirIdent {
    /// Export table
    Export,

    /// Import table
    Import,

    /// Resource table
    Resource,

    /// Exception table
    Exception,

    /// Certificate table
    Certificate,

    /// Base relocations table
    BaseReloc,

    /// Debug data
    Debug,

    /// Reserved, 0.
    Architecture,

    /// Global Ptr
    ///
    /// Address is the RVA to store in the register
    ///
    /// Size is always 0
    GlobalPtr,

    /// Thread Local Storage table
    ThreadLocalStorage,

    /// Load Config table
    LoadConfig,

    /// Bound Import table
    BoundImport,

    /// IAT table
    Iat,

    /// Delay Import Descriptor
    DelayImport,

    /// CLR Runtime header
    ClrRuntime,

    /// Reserved, zero
    Reserved,
}

impl DataDirIdent {
    /// Maps a known data directory to its index in the data directory array
    pub fn index(&self) -> usize {
        match self {
            DataDirIdent::Export => 0,
            DataDirIdent::Import => 1,
            DataDirIdent::Resource => 2,
            DataDirIdent::Exception => 3,
            DataDirIdent::Certificate => 4,
            DataDirIdent::BaseReloc => 5,
            DataDirIdent::Debug => 6,
            DataDirIdent::Architecture => 7,
            DataDirIdent::GlobalPtr => 8,
            DataDirIdent::ThreadLocalStorage => 9,
            DataDirIdent::LoadConfig => 10,
            DataDirIdent::BoundImport => 11,
            DataDirIdent::Iat => 12,
            DataDirIdent::DelayImport => 13,
            DataDirIdent::ClrRuntime => 14,
            DataDirIdent::Reserved => 15,
        }
    }
}

impl TryFrom<usize> for DataDirIdent {
    type Error = ();

    fn try_from(value: usize) -> core::result::Result<Self, ()> {
        match value {
            0 => Ok(DataDirIdent::Export),
            1 => Ok(DataDirIdent::Import),
            2 => Ok(DataDirIdent::Resource),
            3 => Ok(DataDirIdent::Exception),
            4 => Ok(DataDirIdent::Certificate),
            5 => Ok(DataDirIdent::BaseReloc),
            6 => Ok(DataDirIdent::Debug),
            7 => Ok(DataDirIdent::Architecture),
            8 => Ok(DataDirIdent::GlobalPtr),
            9 => Ok(DataDirIdent::ThreadLocalStorage),
            10 => Ok(DataDirIdent::LoadConfig),
            11 => Ok(DataDirIdent::BoundImport),
            12 => Ok(DataDirIdent::Iat),
            13 => Ok(DataDirIdent::DelayImport),
            14 => Ok(DataDirIdent::ClrRuntime),
            15 => Ok(DataDirIdent::Reserved),
            _ => Err(()),
        }
    }
}

impl fmt::Display for DataDirIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataDirIdent::Export => write!(f, "Export Table"),
            DataDirIdent::Import => write!(f, "Import Table"),
            DataDirIdent::Resource => write!(f, "Resource Table"),
            DataDirIdent::Exception => write!(f, "Exception Table"),
            DataDirIdent::Certificate => write!(f, "Certificate Table"),
            DataDirIdent::BaseReloc => write!(f, "Base Relocations Table"),
            DataDirIdent::Debug => write!(f, "Debug Data"),
            DataDirIdent::Architecture => write!(f, "Architecture"),
            DataDirIdent::GlobalPtr => write!(f, "Global Ptr"),
            DataDirIdent::ThreadLocalStorage => write!(f, "Thread Local Storage Table"),
            DataDirIdent::LoadConfig => write!(f, "Load Config Table"),
            DataDirIdent::BoundImport => write!(f, "Bound Import Table"),
            DataDirIdent::Iat => write!(f, "IAT"),
            DataDirIdent::DelayImport => write!(f, "Delay Import Descriptor"),
            DataDirIdent::ClrRuntime => write!(f, "CLR Runtime Header"),
            DataDirIdent::Reserved => write!(f, "Reserved"),
        }
    }
}

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct CoffAttributes: u16 {
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

bitflags! {
    /// DLL Characteristics
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct DllAttributes: u16 {
        const EMPTY = 0x0;
        const RESERVED_1 = 0x1;
        const RESERVED_2 = 0x2;
        const RESERVED_3 = 0x4;
        const RESERVED_4 = 0x8;
        const HIGH_ENTROPY_VA = 0x20;
        const DYNAMIC_BASE = 0x40;

        /// Enforce image is signed before execution
        const FORCE_INTEGRITY = 0x80;

        /// Disable executable stack
        const NX_COMPAT = 0x100;
        const NO_ISOLATION = 0x200;

        /// Disables Structured Exception Handling in the Image
        const NO_SEH = 0x400;
        const NO_BIND = 0x800;

        /// Windows 8 Metro App
        const APP_CONTAINER = 0x1000;
        const WDM_DRIVER = 0x2000;

        /// Image supports Control Flow Guard data
        const GUARD_CF = 0x4000;
        const TERMINAL_SERVER = 0x8000;
    }
}

bitflags! {
    /// COFF Section flags
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    pub struct SectionAttributes: u32 {
        const EMPTY = 0x0;
        const RESERVED_1 = 0x1;
        const RESERVED_2 = 0x2;
        const RESERVED_3 = 0x4;

        /// Obsolete [`SectionFlags::ALIGN_1`]
        ///
        /// Only valid on object files
        const NO_PAD = 0x8;

        const RESERVED_4 = 0x10;

        /// Section contains executable code
        const CODE = 0x20;

        /// Section contains initialized data
        const INITIALIZED = 0x40;

        /// Section contains uninitialized data
        const UNINITIALIZED = 0x80;

        const RESERVED_OTHER = 0x100;

        /// Section contains comments or other info
        ///
        /// Only valid on object files
        const INFO = 0x200;

        const RESERVED_6 = 0x400;

        /// Section will not become part of the image
        ///
        /// Only valid on object files
        const REMOVE = 0x800;

        /// Section contains COMDAT data
        ///
        /// Only valid on object files
        const COMDAT = 0x1000;

        /// Section contains data referenced through the global pointer
        const GLOBAL_REL = 0x8000;

        const RESERVED_MEM_PURGE = 0x20000;
        const RESERVED_MEM_16BIT = 0x20000;
        const RESERVED_MEM_LOCKED = 0x40000;
        const RESERVED_MEM_PRELOAD = 0x80000;
        const ALIGN_1 = 0x100000;
        const ALIGN_2 = 0x200000;
        const ALIGN_4 = 0x300000;
        const ALIGN_8 = 0x400000;
        const ALIGN_16 = 0x500000;
        const ALIGN_32 = 0x600000;
        const ALIGN_64 = 0x700000;
        const ALIGN_128 = 0x800000;
        const ALIGN_256 = 0x900000;
        const ALIGN_512 = 0xA00000;
        const ALIGN_1024 = 0xB00000;
        const ALIGN_2048 = 0xC00000;
        const ALIGN_4096 = 0xD00000;
        const ALIGN_8192 = 0xE00000;

        /// Section contains extended relocations
        const EXTENDED_RELOC = 0x1000000;

        /// Section can be discarded
        const DISCARDABLE = 0x2000000;

        /// Section cannot be cached
        const NO_CACHE = 0x4000000;

        /// Section cannot be paged
        const NO_PAGE = 0x8000000;

        /// Section can be shared
        const SHARED = 0x10000000;

        /// Section can be executed
        const EXEC = 0x20000000;

        /// Section can be read
        const READ = 0x40000000;

        /// Section can be written
        const WRITE = 0x80000000;
    }
}

pub(crate) mod debug {
    //! Debug/Display helpers
    use core::fmt;

    use crate::{raw::RawDataDirectory, DataDirIdent, VecOrSlice};

    struct Helper2<'data>(usize, &'data RawDataDirectory);
    impl<'data> fmt::Debug for Helper2<'data> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name = DataDirIdent::try_from(self.0);
            let name: &dyn fmt::Display = &name
                .as_ref()
                .map(|d| d as &dyn fmt::Display)
                .unwrap_or_else(|_| &self.0 as &dyn fmt::Display);
            if f.alternate() {
                write!(f, r#""{}" {:#?}"#, name, self.1)
            } else {
                write!(f, r#""{}" {:?}"#, name, self.1)
            }
        }
    }

    /// Displays lists of data dirs with their known names
    ///
    /// # Example
    ///
    /// ```
    /// [
    ///     "Export Table" RawDataDirectory {
    ///         address: 0,
    ///         size: 0,
    ///     },
    ///     "Import Table" RawDataDirectory {
    ///         address: 0,
    ///         size: 0,
    ///     }
    /// ]
    /// ```
    pub struct RawDataDirectoryHelper<'data>(&'data VecOrSlice<'data, RawDataDirectory>);

    impl<'data> RawDataDirectoryHelper<'data> {
        pub fn new(data_dirs: &'data VecOrSlice<'data, RawDataDirectory>) -> Self {
            Self(data_dirs)
        }
    }

    impl<'data> fmt::Debug for RawDataDirectoryHelper<'data> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list()
                .entries(self.0.iter().enumerate().map(|(i, r)| Helper2(i, r)))
                .finish()
        }
    }

    /// Displays the DOS header and minimal stub
    pub struct DosHelper<'data>(usize, &'data VecOrSlice<'data, u8>);

    impl<'data> DosHelper<'data> {
        pub fn new(data: &'data VecOrSlice<'data, u8>) -> Self {
            Self(data.len(), data)
        }
    }

    impl<'data> fmt::Debug for DosHelper<'data> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, r#"DOS code (len {})"#, self.0)
        }
    }
}
