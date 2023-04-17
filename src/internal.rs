//! Internal traits and utilities
use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use bitflags::bitflags;

/// Helper enum for a reference to a type, or owning it
#[derive(Debug, Clone, Copy)]
pub enum OwnedOrRef<'data, T> {
    Owned(T),
    Ref(&'data T),
}

impl<'data, T> OwnedOrRef<'data, T> {
    #[inline]
    pub const fn from_ref(value: &'data T) -> Self {
        Self::Ref(value)
    }
}

impl<T> OwnedOrRef<'static, T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self::Owned(value)
    }
}

impl<'data, T> OwnedOrRef<'data, T> {
    /// Constant method to get a reference to `T`
    #[inline]
    pub const fn as_ref(&self) -> &T {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

impl<'data, T> Deref for OwnedOrRef<'data, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        OwnedOrRef::as_ref(self)
    }
}

impl<'data, T> AsRef<T> for OwnedOrRef<'data, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        OwnedOrRef::as_ref(self)
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

impl<'data, T> VecOrSlice<'data, T> {
    #[inline]
    pub const fn from_slice(value: &'data [T]) -> Self {
        Self::Slice(value)
    }
}

impl<T> VecOrSlice<'static, T> {
    #[inline]
    pub const fn new(value: Vec<T>) -> Self {
        Self::Vec(value)
    }
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

/// Machine type, or target architecture, of the PE file.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MachineType(u16);

impl MachineType {
    /// Integer value for this machine type
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl MachineType {
    /// Unknown/Any/All machine type
    pub const UNKNOWN: Self = Self(0);

    /// x64
    pub const AMD64: Self = Self(0x8664);

    /// x86
    pub const I386: Self = Self(0x14C);

    /// EFI Byte Code
    pub const EBC: Self = Self(0xEBC);

    // TODO: Fill out rest of machine types
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
    /// Integer value for this machine type
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

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
    /// COFF Header flags
    ///
    /// Otherwise known as "characteristics"
    ///
    /// See [`RawCoff`][`crate::raw::RawCoff`]
    ///
    /// See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics>
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    #[doc(alias = "characteristics")]
    pub struct CoffFlags: u16 {
        /// Indicates file has no base relocations and must be loaded at
        /// its preferred address
        const RELOC_STRIPPED = 0x1;

        /// Indicates this is a valid executable image
        const IMAGE = 0x2;

        /// Deprecated and should not be set
        const COFF_LINE_STRIPPED = 0x4;

        /// Deprecated and should not be set
        const COFF_SYM_STRIPPED = 0x8;

        /// Deprecated and should not be set
        const AGGRESSIVE_WS_TRIM = 0x10;

        /// Indicates application can handle addresses larger than 2 GiB
        const LARGE_ADDRESS_AWARE = 0x20;

        /// Reserved
        const RESERVED = 0x40;

        /// Deprecated and should not be set
        const BYTES_REVERSED_LO = 0x80;

        /// Machine is based on a 32-bit-word architecture.
        const BIT32 = 0x100;

        /// Indicates debug information was stripped
        const DEBUG_STRIPPED = 0x200;

        /// If the image is on removable media, fully load and copy it to swap
        ///
        /// ??? why microsoft?
        const REMOVABLE_SWAP = 0x400;

        /// If the image is on the network media, fully load and copy it to swap
        ///
        /// ??? why microsoft?
        const NET_SWAP = 0x800;

        /// The image is a system file
        const SYSTEM = 0x1000;

        /// The image is a DLL
        const DLL = 0x2000;

        /// Indicates image should only be run on a uniprocessor machine
        ///
        /// ??? why microsoft?
        const UP_SYSTEM = 0x4000;

        /// Deprecated and should not be set
        const BYTES_REVERSED_HI = 0x8000;
    }
}

bitflags! {
    /// Exec header flags
    ///
    /// See [`RawExec{64|32}`][`crate::raw::RawExec64`]
    ///
    /// Otherwise known as "DLL Characteristics"
    ///
    /// See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics>
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    #[doc(alias = "DllCharacteristics")]
    pub struct ExecFlags: u16 {
        /// Reserved and must not be set
        const RESERVED_1 = 0x1;

        /// Reserved and must not be set
        const RESERVED_2 = 0x2;

        /// Reserved and must not be set
        const RESERVED_3 = 0x4;

        /// Reserved and must not be set
        const RESERVED_4 = 0x8;

        /// Indicates image can handle a high-entropy 64-bit address space
        const HIGH_ENTROPY_VA = 0x20;

        /// Indicates image can be relocated at runtime
        const DYNAMIC_BASE = 0x40;

        /// Enforce code integrity checks
        const FORCE_INTEGRITY = 0x80;

        /// Disable executable stack
        ///
        /// Indicates image is Data Execution Prevention / NX compatible /
        /// No eXecute compatible
        ///
        /// Specifically, compatible with code not being run from memory
        /// pages without the execute permission.
        ///
        /// See <https://learn.microsoft.com/en-us/windows/win32/Memory/data-execution-prevention>
        const NX_COMPAT = 0x100;

        /// Indicates image is Isolation aware, but should not be isolated.
        ///
        /// Setting this tells the Windows loader not to use application manifests
        ///
        /// See <https://learn.microsoft.com/en-us/cpp/build/reference/allowisolation?view=msvc-170>
        const NO_ISOLATION = 0x200;

        /// Indicates Structured Exception Handling is not used and no SE handler may be called
        const NO_SEH = 0x400;

        /// Indicates not to bind the image
        ///
        /// This may be desired because binding invalidates digital signatures
        ///
        /// Binding pre-resolves addresses to entry points in the images import table.
        ///
        /// See <https://learn.microsoft.com/en-us/cpp/build/reference/allowbind-prevent-dll-binding?view=msvc-170>
        ///
        /// See <https://learn.microsoft.com/en-us/cpp/build/reference/bind?view=msvc-170>
        const NO_BIND = 0x800;

        /// Indicates image must execute in the AppContainer isolation environment
        ///
        /// Usually this will be UWP or Microsoft Store apps.
        ///
        /// See <https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation>
        ///
        /// See <https://learn.microsoft.com/en-us/cpp/build/reference/appcontainer-windows-store-app?view=msvc-170>
        const APP_CONTAINER = 0x1000;

        /// Indicates a Windows Driver Model / WDM Driver
        const WDM_DRIVER = 0x2000;

        /// Indicates image supports Control Flow Guard data
        const GUARD_CF = 0x4000;

        /// Indicates image is terminal server aware
        ///
        /// This means that the image:
        ///
        /// - Does not rely on per-user `.ini` files
        /// - Does not write to `HKEY_CURRENT_USER` during setup
        /// - Does not run as a system service
        /// - Does not expect exclusive access to system directories
        ///   or store per-user temporary o configuration data in them
        /// - Does not write to `HKEY_LOCAL_MACHINE` for user specific data
        /// - Generally follows the Remote Desktop Services compatibility guidelines
        ///
        /// See <https://learn.microsoft.com/en-us/windows/win32/termserv/application-compatibility-layer>
        ///
        /// See <https://learn.microsoft.com/en-us/cpp/build/reference/tsaware-create-terminal-server-aware-application?view=msvc-170>
        const TERMINAL_SERVER = 0x8000;
    }
}

bitflags! {
    /// Section header flags
    ///
    /// See [`RawSectionHeader`][`crate::raw::RawSectionHeader`]
    ///
    /// See <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags>
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    #[repr(transparent)]
    #[doc(alias = "characteristics")]
    pub struct SectionFlags: u32 {
        /// Reserved and must not be set
        const RESERVED_0 = 0x0;

        /// Reserved and must not be set
        const RESERVED_1 = 0x1;

        /// Reserved and must not be set
        const RESERVED_2 = 0x2;

        /// Reserved and must not be set
        const RESERVED_3 = 0x4;

        /// Obsolete and replaced by [`SectionFlags::ALIGN_1`]
        const NO_PAD = 0x8;

        /// Reserved and must not be set
        const RESERVED_4 = 0x10;

        /// Section contains executable code
        const CODE = 0x20;

        /// Section contains initialized data
        const INITIALIZED = 0x40;

        /// Section contains uninitialized data
        const UNINITIALIZED = 0x80;

        /// Reserved and must not be set
        const RESERVED_OTHER = 0x100;

        /// Section contains comments or other info
        ///
        /// Only valid on object files
        const INFO = 0x200;

        /// Reserved and must not be set
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

        /// Reserved and must not be set
        const RESERVED_MEM_PURGE = 0x20000;

        /// Reserved and must not be set
        const RESERVED_MEM_16BIT = 0x20000;

        /// Reserved and must not be set
        const RESERVED_MEM_LOCKED = 0x40000;

        /// Reserved and must not be set
        const RESERVED_MEM_PRELOAD = 0x80000;

        /// Align data on 1-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_1 = 0x100000;

        /// Align data on 2-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_2 = 0x200000;

        /// Align data on 4-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_4 = 0x300000;

        /// Align data on 8-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_8 = 0x400000;

        /// Align data on 16-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_16 = 0x500000;

        /// Align data on 32-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_32 = 0x600000;

        /// Align data on 64-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_64 = 0x700000;

        /// Align data on 128-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_128 = 0x800000;

        /// Align data on 256-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_256 = 0x900000;

        /// Align data on 512-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_512 = 0xA00000;

        /// Align data on 1024-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_1024 = 0xB00000;

        /// Align data on 2048-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_2048 = 0xC00000;

        /// Align data on 4096-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_4096 = 0xD00000;

        /// Align data on 8192-byte boundary.
        ///
        /// Only valid on object files
        const ALIGN_8192 = 0xE00000;

        /// Section contains extended relocations
        const EXTENDED_RELOC = 0x1000000;

        /// Section can be discarded as needed
        const DISCARDABLE = 0x2000000;

        /// Section cannot be cached
        const NO_CACHE = 0x4000000;

        /// Section cannot be paged
        const NO_PAGE = 0x8000000;

        /// Section can be shared in memory
        const SHARED = 0x10000000;

        /// Section can be executed
        const EXEC = 0x20000000;

        /// Section can be read
        const READ = 0x40000000;

        /// Section can be written to
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
