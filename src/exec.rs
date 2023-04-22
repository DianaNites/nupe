//! Higher level wrappers around the [Executable Header][RawExec],
//! see there for more details.

use core::{mem::size_of, ptr::addr_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    raw::exec::{ExecFlags, RawExec, RawExec32, RawExec64, Subsystem, PE32_64_MAGIC, PE32_MAGIC},
    OwnedOrRef,
};

/// Executable header, otherwise known as the "optional" header
///
/// Provides an abstraction over the meaningless 32 and 64 bit difference
#[derive(Debug, Clone, Copy)]
pub enum ExecHeader<'data> {
    Raw32(OwnedOrRef<'data, RawExec32>),
    Raw64(OwnedOrRef<'data, RawExec64>),
}

impl<'data> ExecHeader<'data> {
    /// Get header as a byte slice
    pub(crate) const fn as_slice(&self) -> &[u8] {
        match self {
            ExecHeader::Raw32(h) => {
                //
                let ptr = h.as_ref() as *const RawExec32 as *const u8;
                unsafe { from_raw_parts(ptr, size_of::<RawExec32>()) }
            }
            ExecHeader::Raw64(h) => {
                //
                let ptr = h.as_ref() as *const RawExec64 as *const u8;
                unsafe { from_raw_parts(ptr, size_of::<RawExec64>()) }
            }
        }
    }

    pub(crate) const fn code_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.code_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.code_size,
        }
    }
    pub(crate) const fn init_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.init_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.init_size,
        }
    }
    pub(crate) const fn uninit_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.uninit_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.uninit_size,
        }
    }

    /// Convenience function to get the common [`RawExec`]
    pub const fn raw_exec(&self) -> &RawExec {
        match self {
            ExecHeader::Raw32(h) => &h.as_ref().standard,
            ExecHeader::Raw64(h) => &h.as_ref().standard,
        }
    }

    /// Convenience function to get the correct size in bytes of the exec header
    pub const fn size_of(&self) -> usize {
        match self {
            ExecHeader::Raw32(_) => size_of::<RawExec32>(),
            ExecHeader::Raw64(_) => size_of::<RawExec64>(),
        }
    }
}

/// Public Data API
impl<'data> ExecHeader<'data> {
    /// How many data directories
    pub(crate) const fn data_dirs(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => match h {
                OwnedOrRef::Owned(h) => h.data_dirs,
                OwnedOrRef::Ref(h) => h.data_dirs,
            },
            ExecHeader::Raw64(h) => match h {
                OwnedOrRef::Owned(h) => h.data_dirs,
                OwnedOrRef::Ref(h) => h.data_dirs,
            },
        }
    }

    /// Subsystem
    pub(crate) fn subsystem(&self) -> Subsystem {
        match self {
            ExecHeader::Raw32(h) => h.subsystem,
            ExecHeader::Raw64(h) => h.subsystem,
        }
    }

    /// Entry point address relative to the image base
    pub(crate) fn entry(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.standard.entry_ptr,
            ExecHeader::Raw64(h) => h.standard.entry_ptr,
        }
    }

    /// OS (major, minor)
    pub(crate) fn os_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.os_major, h.os_minor),
            ExecHeader::Raw64(h) => (h.os_major, h.os_minor),
        }
    }

    /// Image (major, minor)
    pub(crate) fn image_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.image_major, h.image_minor),
            ExecHeader::Raw64(h) => (h.image_major, h.image_minor),
        }
    }

    /// Subsystem (major, minor)
    pub(crate) fn subsystem_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.subsystem_major, h.subsystem_minor),
            ExecHeader::Raw64(h) => (h.subsystem_major, h.subsystem_minor),
        }
    }

    /// Linker (major, minor)
    pub(crate) fn linker_version(&self) -> (u8, u8) {
        match self {
            ExecHeader::Raw32(h) => (h.standard.linker_major, h.standard.linker_minor),
            ExecHeader::Raw64(h) => (h.standard.linker_major, h.standard.linker_minor),
        }
    }

    /// Preferred Base of the image in memory.
    ///
    /// Coerced to u64 even on/for 32bit.
    pub(crate) fn image_base(&self) -> u64 {
        match self {
            ExecHeader::Raw32(h) => h.image_base.into(),
            ExecHeader::Raw64(h) => h.image_base,
        }
    }

    /// DLL Attributes
    pub(crate) fn dll_attributes(&self) -> ExecFlags {
        match self {
            ExecHeader::Raw32(h) => h.dll_attributes,
            ExecHeader::Raw64(h) => h.dll_attributes,
        }
    }

    /// Stack (reserve, commit)
    pub(crate) fn stack(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (h.stack_reserve.into(), h.stack_commit.into()),
            ExecHeader::Raw64(h) => (h.stack_reserve, h.stack_commit),
        }
    }

    /// Heap (reserve, commit)
    pub(crate) fn heap(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (h.heap_reserve.into(), h.heap_commit.into()),
            ExecHeader::Raw64(h) => (h.heap_reserve, h.heap_commit),
        }
    }

    /// File alignment
    pub(crate) fn file_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.disk_align,
            ExecHeader::Raw64(h) => h.disk_align,
        }
    }

    /// Section alignment
    pub(crate) fn section_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.mem_align,
            ExecHeader::Raw64(h) => h.mem_align,
        }
    }

    /// Image size
    pub(crate) fn image_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.image_size,
            ExecHeader::Raw64(h) => h.image_size,
        }
    }

    /// Headers size
    pub(crate) fn headers_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.headers_size,
            ExecHeader::Raw64(h) => h.headers_size,
        }
    }
}

/// Public Serialization API
impl<'data> ExecHeader<'data> {
    /// Wrapper around [`RawExec32::new`] and [`RawExec64::new`]
    ///
    /// Always takes arguments in 64-bit, errors if out of bounds
    ///
    /// if `plus` is true then the PE32+ / 64-bit header is used
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        plus: bool,
        standard: RawExec,
        data_ptr: u32,
        image_ptr: u64,
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
        dll_attributes: ExecFlags,
        stack_reserve: u64,
        stack_commit: u64,
        heap_reserve: u64,
        heap_commit: u64,
        data_dirs: u32,
    ) -> Result<Self> {
        if plus {
            Ok(ExecHeader::Raw64(OwnedOrRef::Owned(RawExec64::new(
                standard,
                image_ptr,
                mem_align,
                disk_align,
                os_major,
                os_minor,
                image_major,
                image_minor,
                subsystem_major,
                subsystem_minor,
                image_size,
                headers_size,
                subsystem,
                dll_attributes,
                stack_reserve,
                stack_commit,
                heap_reserve,
                heap_commit,
                data_dirs,
            ))))
        } else {
            Ok(ExecHeader::Raw32(OwnedOrRef::Owned(RawExec32::new(
                standard,
                data_ptr,
                image_ptr.try_into().map_err(|_| Error::TooMuchData)?,
                mem_align,
                disk_align,
                os_major,
                os_minor,
                image_major,
                image_minor,
                subsystem_major,
                subsystem_minor,
                image_size,
                headers_size,
                subsystem,
                dll_attributes,
                stack_reserve.try_into().map_err(|_| Error::TooMuchData)?,
                stack_commit.try_into().map_err(|_| Error::TooMuchData)?,
                heap_reserve.try_into().map_err(|_| Error::TooMuchData)?,
                heap_commit.try_into().map_err(|_| Error::TooMuchData)?,
                data_dirs,
            ))))
        }
    }
}

/// Public Deserialization API
impl<'data> ExecHeader<'data> {
    /// Get a [`ExecHeader`] from a pointer to an exec header.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawExec64`] or [`RawExec64`]
    /// - [`Error::MissingDOS`] If the DOS header or its stub code is missing
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
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawPe::from_ptr");

        // Safety: Caller
        let magic = RawExec::from_ptr(data, size)?.magic;

        if magic == PE32_64_MAGIC {
            let opt = RawExec64::from_ptr(data, size)?;

            Ok(ExecHeader::Raw64(OwnedOrRef::Ref(opt)))
        } else if magic == PE32_MAGIC {
            let opt = RawExec32::from_ptr(data, size)?;

            Ok(ExecHeader::Raw32(OwnedOrRef::Ref(opt)))
        } else {
            Err(Error::InvalidPeMagic)
        }
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::internal::test_util::kani;

    /// Test, fuzz, and model [`ExecHeader::from_ptr`]
    // #[cfg(no)]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn exec_from_ptr() {
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
}
