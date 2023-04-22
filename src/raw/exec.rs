//! The Executable header
//!
//! Also known as the "Optional" header in [Microsoft PE documentation][pe_ref]
//!
//! The executable header should only exist for PE executables, and
//! follows the [COFF header].
//!
//! The size of this structure differs depending on whether
//! the executable is 32 or 64 bit.
//!
//! [pe_ref]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
use core::{fmt, mem::size_of};

use bitflags::bitflags;

use crate::{
    error::{Error, Result},
    internal::miri_helper,
};

/// PE32 Magic signature
pub const PE32_MAGIC: u16 = 0x10B;

/// PE32+ Magic signature
pub const PE32_64_MAGIC: u16 = 0x20B;

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

/// Common subset of the PE Executable header,
/// otherwise known as the "optional" header.
///
/// Parts of this structure differ depending on whether the input is
/// 32 or 64 bit.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec {
    /// Magic identifying PE32 vs PE32+
    pub magic: u16,

    /// Linker major version
    pub linker_major: u8,

    /// Linker minor version
    pub linker_minor: u8,

    /// Virtual Size or sum of all code/text sections
    pub code_size: u32,

    /// Virtual Size or sum of all initialized/data sections
    pub init_size: u32,

    /// Virtual Size or sum of all uninitialized/data sections
    pub uninit_size: u32,

    /// Offset to image entry point, relative to image base.
    pub entry_ptr: u32,

    /// Offset to beginning-of-code section, relative to image base.
    pub code_ptr: u32,
}

/// Public Serialization API
impl RawExec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        magic: u16,
        linker_major: u8,
        linker_minor: u8,
        code_size: u32,
        init_size: u32,
        uninit_size: u32,
        entry_offset: u32,
        code_base: u32,
    ) -> Self {
        Self {
            magic,
            linker_major,
            linker_minor,
            code_size,
            init_size,
            uninit_size,
            entry_ptr: entry_offset,
            code_ptr: code_base,
        }
    }
}

/// Public Deserialization API
impl RawExec {
    /// Get a [`RawExec`] from a pointer to an exec header.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawExec`]
    ///   - Note this may not be enough for the full [`RawExec32`] or
    ///     [`RawExec64`]
    ///   - Note also that the magic may not indicate a PE32 or PE32+
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }
}

/// Internal API
impl RawExec {
    /// # Safety
    /// See [`RawExec::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawExec::from_ptr");
        miri_helper!(data, size);

        // Ensure that size is enough
        size.checked_sub(size_of::<RawExec>())
            .ok_or(Error::NotEnoughData)?;

        Ok(data.cast())
    }
}

impl fmt::Debug for RawExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Helper2<const B: u16>;
        impl fmt::Debug for Helper2<PE32_64_MAGIC> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PE32_64_MAGIC")
            }
        }
        impl fmt::Debug for Helper2<PE32_MAGIC> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PE32_MAGIC")
            }
        }

        let mut s = f.debug_struct("RawPeImageStandard");
        if self.magic == PE32_64_MAGIC {
            s.field("magic", &Helper2::<PE32_64_MAGIC>);
        } else if self.magic == PE32_MAGIC {
            s.field("magic", &Helper2::<PE32_MAGIC>);
        } else {
            struct Helper(u16);
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "(Unknown) {}", &self.0)
                }
            }
            s.field("magic", &Helper(self.magic));
        }

        s.field("linker_major", &{ self.linker_major })
            .field("linker_minor", &{ self.linker_minor })
            .field("code_size", &{ self.code_size })
            .field("init_size", &{ self.init_size })
            .field("uninit_size", &{ self.uninit_size })
            .field("entry_ptr", &{ self.entry_ptr })
            .field("code_ptr", &{ self.code_ptr })
            .finish()
    }
}

/// 32-bit Executable header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec32 {
    /// Standard/common subset
    pub standard: RawExec,

    /// Offset to beginning-of-data section, relative to image base.
    pub data_ptr: u32,

    /// Preferred base address of the image when loaded in memory.
    pub image_base: u32,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub mem_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub disk_align: u32,

    /// Required OS major version
    pub os_major: u16,

    /// Required OS minor version
    pub os_minor: u16,

    /// Image major version
    pub image_major: u16,

    /// Image minor version
    pub image_minor: u16,

    /// Subsystem major version
    pub subsystem_major: u16,

    /// Subsystem minor version
    pub subsystem_minor: u16,

    /// Reserved, 0.
    pub _reserved_win32: u32,

    /// Size in bytes of the image as loaded in memory, aligned to
    /// section_align.
    pub image_size: u32,

    /// Combined size of the DOS stub, PE header, and section headers, aligned
    /// to file_align.
    pub headers_size: u32,

    /// A checksum
    pub checksum: u32,

    /// Subsystem required to run image
    pub subsystem: Subsystem,

    /// Flags for windows
    pub dll_attributes: ExecFlags,

    /// Size of the stack to reserve.
    pub stack_reserve: u32,

    /// Size of the stack to commit. Made available one page at a time until
    /// reserve.
    pub stack_commit: u32,

    /// Size of the heap to reserve.
    pub heap_reserve: u32,

    /// Size of the heap to commit. Made available one page at a time until
    /// reserve.
    pub heap_commit: u32,

    /// Reserved, 0.
    pub _reserved_loader_attributes: u32,

    /// Number of data directories following the header.
    pub data_dirs: u32,
}

/// Public Serialization API
impl RawExec32 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        standard: RawExec,
        data_ptr: u32,
        image_ptr: u32,
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
        dll_characteristics: ExecFlags,
        stack_reserve: u32,
        stack_commit: u32,
        heap_reserve: u32,
        heap_commit: u32,
        data_dirs: u32,
    ) -> Self {
        Self {
            standard,
            data_ptr,
            image_base: image_ptr,
            mem_align,
            disk_align,
            os_major,
            os_minor,
            image_major,
            image_minor,
            subsystem_major,
            subsystem_minor,
            _reserved_win32: 0,
            image_size,
            headers_size,
            checksum: 0,
            subsystem,
            dll_attributes: dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            _reserved_loader_attributes: 0,
            data_dirs,
        }
    }
}

/// Public Deserialization API
impl RawExec32 {
    /// Get a [`RawExec32`] from a pointer to an exec header.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawExec32`]
    /// - [`Error::InvalidPeMagic`] If the [magic][`PE32_MAGIC`] is incorrect
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Get a [`RawExec32`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { Self::from_ptr(bytes.as_ptr(), bytes.len()) }
    }
}

/// Internal API
impl RawExec32 {
    /// # Safety
    /// See [`RawExec32::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawExec32::from_ptr");
        miri_helper!(data, size);

        // Ensure that size is enough
        size.checked_sub(size_of::<RawExec32>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawExec32` is POD.
        let exec = unsafe { &*(data as *const RawExec32) };
        if exec.standard.magic != PE32_MAGIC {
            return Err(Error::InvalidPeMagic);
        }

        Ok(data.cast())
    }
}

/// 64-bit Executable header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RawExec64 {
    /// Standard/common subset
    pub standard: RawExec,

    /// Preferred base address of the image when loaded in memory.
    ///
    /// Windows default for DLLs is `0x10000000`
    ///
    /// Windows default for EXEs is `0x00400000`
    pub image_base: u64,

    /// Alignment, in bytes, of the section in memory.
    ///
    /// Must be greater or equal to file_align.
    ///
    /// Default is architecture page size.
    pub mem_align: u32,

    /// Alignment, in bytes, of the section on disk.
    ///
    /// Must be a power of two, between 512 and 64K inclusive.
    ///
    /// Default is 512
    pub disk_align: u32,

    /// Required OS major version
    pub os_major: u16,

    /// Required OS minor version
    pub os_minor: u16,

    /// Image major version
    pub image_major: u16,

    /// Image minor version
    pub image_minor: u16,

    /// Subsystem major version
    pub subsystem_major: u16,

    /// Subsystem minor version
    pub subsystem_minor: u16,

    /// Reserved, 0.
    pub _reserved_win32: u32,

    /// Size in bytes of the entire image as loaded in memory
    ///
    /// "must" be aligned to [`mem_align`][`RawExec64::mem_align`].
    pub image_size: u32,

    /// Combined size of the DOS stub, PE header, and section headers
    ///
    /// "must" be aligned to [`disk_align`][`RawExec64::disk_align`].
    pub headers_size: u32,

    /// A checksum
    pub checksum: u32,

    /// Subsystem required to run image
    pub subsystem: Subsystem,

    /// Flags for windows
    pub dll_attributes: ExecFlags,

    /// Size of the stack to reserve.
    pub stack_reserve: u64,

    /// Size of the stack to commit. Made available one page at a time until
    /// reserve.
    pub stack_commit: u64,

    /// Size of the heap to reserve.
    pub heap_reserve: u64,

    /// Size of the heap to commit. Made available one page at a time until
    /// reserve.
    pub heap_commit: u64,

    /// Reserved, 0.
    pub _reserved_loader_attributes: u32,

    /// Number of data directories following the header.
    pub data_dirs: u32,
}

/// Public Serialization API
impl RawExec64 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        standard: RawExec,
        image_base: u64,
        section_align: u32,
        file_align: u32,
        os_major: u16,
        os_minor: u16,
        image_major: u16,
        image_minor: u16,
        subsystem_major: u16,
        subsystem_minor: u16,
        image_size: u32,
        headers_size: u32,
        subsystem: Subsystem,
        dll_characteristics: ExecFlags,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        data_dirs: u32,
    ) -> Self {
        Self {
            standard,
            image_base,
            mem_align: section_align,
            disk_align: file_align,
            os_major,
            os_minor,
            image_major,
            image_minor,
            subsystem_major,
            subsystem_minor,
            _reserved_win32: 0,
            image_size,
            headers_size,
            checksum: 0,
            subsystem,
            dll_attributes: dll_characteristics,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            _reserved_loader_attributes: 0,
            data_dirs,
        }
    }
}

/// Public Deserialization API
impl RawExec64 {
    /// Get a [`RawExec64`] from a pointer to an exec header.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawExec64`]
    /// - [`Error::InvalidPeMagic`] If the [magic][`PE32_64_MAGIC`] is incorrect
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Get a [`RawExec64`] from `bytes`. Checks for the magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        unsafe { Self::from_ptr(bytes.as_ptr(), bytes.len()) }
    }
}

/// Internal API
impl RawExec64 {
    /// # Safety
    /// See [`RawExec64::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawExec64::from_ptr");
        miri_helper!(data, size);

        // Ensure that size is enough
        size.checked_sub(size_of::<RawExec64>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Have just verified theres enough `size`
        // and `RawExec32` is POD.
        let exec = unsafe { &*(data as *const RawExec64) };
        if exec.standard.magic != PE32_64_MAGIC {
            return Err(Error::InvalidPeMagic);
        }

        Ok(data.cast())
    }
}

#[cfg(test)]
mod r_tests {
    use core::mem::{align_of, size_of};

    use super::*;

    /// Ensure expected ABI
    #[test]
    fn abi() {
        assert!(size_of::<RawExec>() == 24);
        assert!(align_of::<RawExec>() == 1);

        assert!(size_of::<RawExec32>() == 96);
        assert!(align_of::<RawExec32>() == 1);

        assert!(size_of::<RawExec64>() == 112);
        assert!(align_of::<RawExec64>() == 1);

        assert!(size_of::<Subsystem>() == size_of::<u16>());
        assert!(align_of::<Subsystem>() == align_of::<u16>());

        assert!(size_of::<ExecFlags>() == size_of::<u16>());
        assert!(align_of::<ExecFlags>() == align_of::<u16>());
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::internal::test_util::kani;

    /// Test, fuzz, and model [`RawExec::from_ptr`]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_exec_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawExec::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    // Should only be `Ok` if `len` is this
                    assert!(len >= size_of::<RawExec>(), "Invalid `Ok` len");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawExec>());
                }

                // Ensure no other errors happen
                Err(e) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!("{e:#?}");
                }
            };
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_exec32_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawExec32::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    assert_eq!({ d.standard.magic }, PE32_MAGIC);

                    // Should only be `Ok` if `len` is this
                    assert!(len >= size_of::<RawExec32>(), "Invalid `Ok` len");
                }

                // Ensure `InvalidPeMagic` error happens
                Err(Error::InvalidPeMagic) => {
                    kani::cover!(true, "InvalidPeMagic");

                    // Should have gotten NotEnoughData otherwise
                    assert!(len >= size_of::<RawExec32>());
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawExec32>());
                }

                // Ensure no other errors happen
                Err(e) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!("{e:#?}");
                }
            };
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_exec64_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawExec64::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    assert_eq!({ d.standard.magic }, PE32_64_MAGIC);

                    // Should only be `Ok` if `len` is this
                    assert!(len >= size_of::<RawExec64>(), "Invalid `Ok` len");
                }

                // Ensure `InvalidPeMagic` error happens
                Err(Error::InvalidPeMagic) => {
                    kani::cover!(true, "InvalidPeMagic");

                    // Should have gotten NotEnoughData otherwise
                    assert!(len >= size_of::<RawExec64>());
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawExec64>());
                }

                // Ensure no other errors happen
                Err(e) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!("{e:#?}");
                }
            };
        });
    }
}
