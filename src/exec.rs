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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecHeader<'data> {
    Raw32(OwnedOrRef<'data, RawExec32>),
    Raw64(OwnedOrRef<'data, RawExec64>),
}

/// Public Data API
impl<'data> ExecHeader<'data> {
    /// Get the header as a byte slice
    pub const fn as_slice(&self) -> &[u8] {
        match self {
            ExecHeader::Raw32(h) => {
                let ptr = h.as_ref() as *const RawExec32 as *const u8;
                // Safety: bytes over POD type, tied to `self`
                unsafe { from_raw_parts(ptr, size_of::<RawExec32>()) }
            }
            ExecHeader::Raw64(h) => {
                let ptr = h.as_ref() as *const RawExec64 as *const u8;
                // Safety: bytes over POD type, tied to `self`
                unsafe { from_raw_parts(ptr, size_of::<RawExec64>()) }
            }
        }
    }

    pub const fn code_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.code_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.code_size,
        }
    }

    pub const fn init_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.init_size,
            ExecHeader::Raw64(h) => h.as_ref().standard.init_size,
        }
    }

    pub const fn uninit_size(&self) -> u32 {
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

    /// How many data directories
    pub const fn data_dirs(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().data_dirs,
            ExecHeader::Raw64(h) => h.as_ref().data_dirs,
        }
    }

    /// Subsystem
    pub const fn subsystem(&self) -> Subsystem {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().subsystem,
            ExecHeader::Raw64(h) => h.as_ref().subsystem,
        }
    }

    /// Entry point address relative to the image base
    pub const fn entry(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().standard.entry_ptr,
            ExecHeader::Raw64(h) => h.as_ref().standard.entry_ptr,
        }
    }

    /// OS (major, minor)
    pub const fn os_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.as_ref().os_major, h.as_ref().os_minor),
            ExecHeader::Raw64(h) => (h.as_ref().os_major, h.as_ref().os_minor),
        }
    }

    /// Image (major, minor)
    pub const fn image_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.as_ref().image_major, h.as_ref().image_minor),
            ExecHeader::Raw64(h) => (h.as_ref().image_major, h.as_ref().image_minor),
        }
    }

    /// Subsystem (major, minor)
    pub const fn subsystem_version(&self) -> (u16, u16) {
        match self {
            ExecHeader::Raw32(h) => (h.as_ref().subsystem_major, h.as_ref().subsystem_minor),
            ExecHeader::Raw64(h) => (h.as_ref().subsystem_major, h.as_ref().subsystem_minor),
        }
    }

    /// Linker (major, minor)
    pub const fn linker_version(&self) -> (u8, u8) {
        match self {
            ExecHeader::Raw32(h) => (
                h.as_ref().standard.linker_major,
                h.as_ref().standard.linker_minor,
            ),
            ExecHeader::Raw64(h) => (
                h.as_ref().standard.linker_major,
                h.as_ref().standard.linker_minor,
            ),
        }
    }

    /// Preferred Base of the image in memory.
    ///
    /// Coerced to u64 even on/for 32bit.
    pub const fn image_base(&self) -> u64 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().image_base as u64,
            ExecHeader::Raw64(h) => h.as_ref().image_base,
        }
    }

    /// DLL Attributes
    pub const fn dll_attributes(&self) -> ExecFlags {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().dll_attributes,
            ExecHeader::Raw64(h) => h.as_ref().dll_attributes,
        }
    }

    /// Stack (reserve, commit)
    pub const fn stack(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (
                h.as_ref().stack_reserve as u64,
                h.as_ref().stack_commit as u64,
            ),
            ExecHeader::Raw64(h) => (h.as_ref().stack_reserve, h.as_ref().stack_commit),
        }
    }

    /// Heap (reserve, commit)
    pub const fn heap(&self) -> (u64, u64) {
        match self {
            ExecHeader::Raw32(h) => (
                h.as_ref().heap_reserve as u64,
                h.as_ref().heap_commit as u64,
            ),
            ExecHeader::Raw64(h) => (h.as_ref().heap_reserve, h.as_ref().heap_commit),
        }
    }

    /// File alignment
    pub const fn file_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().disk_align,
            ExecHeader::Raw64(h) => h.as_ref().disk_align,
        }
    }

    /// Section alignment
    pub const fn section_align(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().mem_align,
            ExecHeader::Raw64(h) => h.as_ref().mem_align,
        }
    }

    /// Image size
    pub const fn image_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().image_size,
            ExecHeader::Raw64(h) => h.as_ref().image_size,
        }
    }

    /// Headers size
    pub const fn headers_size(&self) -> u32 {
        match self {
            ExecHeader::Raw32(h) => h.as_ref().headers_size,
            ExecHeader::Raw64(h) => h.as_ref().headers_size,
        }
    }
}

/// Public Serialization API
impl<'data> ExecHeader<'data> {}

/// Public Deserialization API
impl<'data> ExecHeader<'data> {
    /// Get a [`ExecHeader`] from a pointer to an exec header.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawExec64`] or [`RawExec64`]
    /// - [`Error::InvalidPeMagic`] If the PE magic is not PE32 or PE32+
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
        debug_assert!(!data.is_null(), "`data` was null in ExecHeader::from_ptr");

        // Safety: Caller
        let exec = RawExec::from_ptr(data, size)?;
        let magic = exec.magic;

        if magic == PE32_64_MAGIC {
            // Safety: Caller
            let opt = RawExec64::from_ptr(data, size)?;

            Ok(ExecHeader::Raw64(OwnedOrRef::Ref(opt)))
        } else if magic == PE32_MAGIC {
            // Safety: Caller
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
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn exec_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { ExecHeader::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");
                    let magic = d.raw_exec().magic;

                    // Magic must be known
                    assert!(magic == PE32_MAGIC || magic == PE32_64_MAGIC);

                    // Should only be `Ok` if `len` is at least this
                    assert!(len >= size_of::<RawExec32>(), "Invalid `Ok` len");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawExec64>());
                }

                // Ensure `InvalidPeMagic` error happens
                Err(Error::InvalidPeMagic) => {
                    kani::cover!(true, "InvalidPeMagic");

                    // Should have gotten NotEnoughData otherwise
                    assert!(len >= size_of::<RawExec>());
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
