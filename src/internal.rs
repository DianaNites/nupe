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
}

#[cfg(test)]
pub mod test_util {
    //! Utilities helpful across unit tests

    use crate::raw::dos::RawDos;

    pub static RUSTUP_IMAGE: &[u8] = include_bytes!("../tests/data/rustup-init.exe");

    #[cfg(not(kani))]
    pub mod kani {
        //! Helps RA provide a usable experience with stub impls
        //! because kani is terrible ootb.
        //!
        //! Everything here is for the sake of getting it to compile for RA.
        use core::mem::MaybeUninit;

        pub mod slice {
            use core::{
                mem::{transmute_copy, MaybeUninit},
                ops::{Deref, DerefMut},
            };

            pub struct AnySlice<T, const MAX_SLICE_LENGTH: usize> {
                _t: *mut T,
            }

            impl<T, const MAX_SLICE_LENGTH: usize> AnySlice<T, MAX_SLICE_LENGTH> {
                fn new() -> Self {
                    Self {
                        _t: core::ptr::null_mut(),
                    }
                }

                fn alloc_slice() -> Self {
                    Self {
                        _t: core::ptr::null_mut(),
                    }
                }

                pub fn get_slice(&self) -> &[T] {
                    &[]
                }

                pub fn get_slice_mut(&mut self) -> &mut [T] {
                    &mut []
                }
            }

            impl<T, const MAX_SLICE_LENGTH: usize> Drop for AnySlice<T, MAX_SLICE_LENGTH> {
                fn drop(&mut self) {}
            }

            impl<T, const MAX_SLICE_LENGTH: usize> Deref for AnySlice<T, MAX_SLICE_LENGTH> {
                type Target = [T];

                fn deref(&self) -> &Self::Target {
                    &[]
                }
            }

            impl<T, const MAX_SLICE_LENGTH: usize> DerefMut for AnySlice<T, MAX_SLICE_LENGTH> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut []
                }
            }

            pub fn any_slice<T, const MAX_SLICE_LENGTH: usize>() -> AnySlice<T, MAX_SLICE_LENGTH> {
                AnySlice::new()
            }

            pub fn any_slice_of_array<T, const LENGTH: usize>(arr: &[T; LENGTH]) -> &[T] {
                &[]
            }

            /// A mutable version of the previous function
            pub fn any_slice_of_array_mut<T, const LENGTH: usize>(
                arr: &mut [T; LENGTH],
            ) -> &mut [T] {
                &mut []
            }
        }

        pub trait Arbitrary
        where
            Self: Sized,
        {
            fn any() -> Self;

            fn any_array<const MAX_ARRAY_LENGTH: usize>() -> [Self; MAX_ARRAY_LENGTH] {
                [(); MAX_ARRAY_LENGTH].map(|_| Self::any())
            }
        }

        impl<T> Arbitrary for T {
            fn any() -> Self {
                // // Safety: no, but kani won't call it and real testing code shouldn't either
                unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
            }
        }

        pub fn any<T: Arbitrary>() -> T {
            T::any()
        }

        pub fn any_where<T: Arbitrary, F: FnOnce(&T) -> bool>(f: F) -> T {
            T::any()
        }

        pub fn assume(_: bool) {}

        #[allow(unused_macros)]
        macro_rules! cover {
            () => {};
            ($cond:expr $(,)?) => {};
            ($cond:expr, $msg:literal) => {};
        }
        pub(crate) use cover;
    }

    #[cfg(kani)]
    pub use kani;

    pub fn kani_raw_dos(magic: [u8; 2]) -> RawDos {
        RawDos {
            magic,
            pe_offset: kani::any(),
            last_bytes: kani::any(),
            pages: kani::any(),
            relocations: kani::any(),
            header_size: kani::any(),
            min_alloc: kani::any(),
            max_alloc: kani::any(),
            initial_ss: kani::any(),
            initial_sp: kani::any(),
            checksum: kani::any(),
            initial_ip: kani::any(),
            initial_cs: kani::any(),
            relocation_offset: kani::any(),
            overlay_num: kani::any(),
            _reserved: kani::any(),
            oem_id: kani::any(),
            oem_info: kani::any(),
            _reserved2: kani::any(),
        }
    }
}

/// Help miri/tests catch invalid `size`, since we otherwise will never go
/// beyond Self
macro_rules! miri_helper {
    ($data:expr, $size:expr) => {
        #[cfg(any(miri, test))]
        let _ = ::core::slice::from_raw_parts($data, $size);
    };
}
pub(crate) use miri_helper;
