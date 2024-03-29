//! Raw DOS Header data structures
//!
//! The Microsoft DOS Header, in the context of PE files,
//! is a legacy stub they insist on still adding for DOS compatibility.
//! Conventionally this stub program does nothing more than print it cannot
//! run in DOS.
//!
//! The DOS Stub contains one field of interest, the offset to the start
//! of the actual PE headers.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::internal::miri_helper;

mod error {
    use super::*;

    pub type Result<T> = core::result::Result<T, Error>;

    /// Error type for [`RawDos`]
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    pub enum RawDosError {
        /// Invalid DOS magic
        InvalidDosMagic([u8; 2]),

        /// Not enough data for operation
        NotEnoughData,
    }

    impl fmt::Display for RawDosError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidDosMagic(m) => {
                    write!(f, "invalid DOS magic, found {m:?} expected {DOS_MAGIC:?}")
                }
                Self::NotEnoughData => write!(f, "not enough data, expected more than received"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for RawDosError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }
}
pub use error::RawDosError;
use error::{RawDosError as Error, Result};

/// DOS Magic signature
pub const DOS_MAGIC: [u8; 2] = *b"MZ";

/// Size of a DOS page
pub const DOS_PAGE: usize = 512;

/// Size of a DOS paragraph
pub const DOS_PARAGRAPH: usize = 16;

/// Calculate the [DOS checksum][`RawDos::checksum`]
///
/// If the checksum in the header is `0`, this will calculate the checksum.
///
/// If the checksum in the header is set, and the checksum is valid,
/// this will be equal to `0`/`!0xFFFF`
///
/// # Algorithms
///
/// The checksum is the one's of every 16-bit word in the DOS file,
/// padded with zero to an even number of bytes.
///
/// A valid checksum is determined by calculating the checksum
/// with this set, and seeing if it equals `0xFFFF`
pub fn calculate_checksum(dos: &RawDos, stub: &[u8]) -> u16 {
    let mut chk: u16 = 0;

    // Safety: RawDos as byte slice is trivially valid
    let db = unsafe { from_raw_parts(dos as *const RawDos as *const u8, size_of::<RawDos>()) };

    db.chunks_exact(2)
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
        .for_each(|b| {
            chk = chk.wrapping_add(b);
        });

    let mut stub_iter = stub.chunks_exact(2);

    stub_iter
        .by_ref()
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
        .for_each(|b| {
            chk = chk.wrapping_add(b);
        });

    if let Some(b) = stub_iter.remainder().first() {
        chk = chk.wrapping_add(u16::from_ne_bytes([*b, 0]));
    }

    !chk
}

/// Legacy MS-DOS header for executable PE images
///
/// The only thing really relevant for loading a PE image is
/// [`RawDos::pe_offset`]
///
/// Most of this headers fields are irrelevant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
pub struct RawDos {
    /// Constant of value [`DOS_MAGIC`] identifying the PE executable
    pub magic: [u8; 2],

    /// Number of bytes in the last [`DOS_PAGE`] in the file
    pub last_bytes: u16,

    /// Number of [`DOS_PAGE`]s in the DOS file
    pub pages: u16,

    /// Number of entries in the relocations table
    pub relocations: u16,

    /// Number of [`DOS_PARAGRAPH`]s taken up by the header
    pub header_size: u16,

    /// Min number of [`DOS_PARAGRAPH`]s required by the program
    pub min_alloc: u16,

    /// Max number of [`DOS_PARAGRAPH`]s requested by the program
    ///
    /// Should be at least `1`
    pub max_alloc: u16,

    /// Relocatable Stack Segment address
    pub initial_ss: u16,

    /// Initial stack pointer
    pub initial_sp: u16,

    /// Checksum
    ///
    /// See [`calculate_checksum`]
    pub checksum: u16,

    /// Initial IP
    pub initial_ip: u16,

    /// Relocatable Code Segment address
    pub initial_cs: u16,

    /// Absolute offset to relocation table
    pub relocation_offset: u16,

    /// Overlay management
    pub overlay_num: u16,

    /// Reserved in PE
    pub _reserved: [u16; 4],

    /// Useless
    pub oem_id: u16,

    /// Useless
    pub oem_info: u16,

    /// Reserved in PE
    pub _reserved2: [u8; 20],

    /// Absolute offset in the file to the PE header
    ///
    /// "must" be aligned to 8 bytes
    ///
    /// Note that this value is untrusted user input, and can be anything.
    /// It could even point inside the DOS header.
    ///
    /// This must be handled appropriately.
    pub pe_offset: u32,
}

/// Public deserialization API
impl RawDos {
    /// Create a new, empty, [`RawDos`].
    ///
    /// Sets the DOS magic, with all other fields zeroed.
    pub const fn new() -> Self {
        Self {
            magic: DOS_MAGIC,
            pe_offset: 0,
            last_bytes: 0,
            pages: 0,
            relocations: 0,
            header_size: 0,
            min_alloc: 0,
            max_alloc: 0,
            initial_ss: 0,
            initial_sp: 0,
            checksum: 0,
            initial_ip: 0,
            initial_cs: 0,
            relocation_offset: 0,
            overlay_num: 0,
            _reserved: [0; 4],
            oem_id: 0,
            oem_info: 0,
            _reserved2: [0; 20],
        }
    }

    /// Empty header, with NO DOS stub, with pe offset immediately after it
    ///
    /// `pe_offset` will be 8 byte aligned because [`RawDos`] is 64 bytes.
    pub const fn sized() -> Self {
        Self {
            pe_offset: size_of::<Self>() as u32,
            ..Self::new()
        }
    }

    /// Get a [`RawDos`] from a pointer to the DOS header
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the DOS magic is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawDos`]
    /// - [`Error::InvalidDosMagic`] If the [DOS magic][`DOS_MAGIC`] is
    ///   incorrect
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        // Safety:
        // - Caller asserts `data` is valid for `size`
        // - `RawDos` has no alignment requirements or invalid values.
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Get a mutable [`RawDos`] from a mutable pointer to a DOS header
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawDos`]
    /// - [`Error::InvalidDosMagic`] If the [DOS magic][`DOS_MAGIC`] is
    ///   incorrect
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for reads and writes of `size` bytes.
    pub unsafe fn from_ptr_mut<'data>(data: *mut u8, size: usize) -> Result<&'data mut Self> {
        // Safety:
        // - caller asserts `data` is valid for writes
        // - const casting pointers like has no safety requirements besides the above
        // - `RawDos` has no alignment requirements or invalid values.
        Ok(&mut *(Self::from_ptr_internal(data.cast_const(), size)?).cast_mut())
    }
}

/// Internal base API
impl RawDos {
    /// See [`RawDos::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawDos::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawDos>())
            .ok_or(Error::NotEnoughData)?;

        // Safety:
        // - We just checked `data` would fit a `RawDos`
        // - Caller guarantees `data` is valid
        let data = data as *const RawDos;
        let dos = &*data;
        if dos.magic != DOS_MAGIC {
            return Err(Error::InvalidDosMagic(dos.magic));
        }

        miri_helper!(data as *const u8, size);

        Ok(data)
    }
}

/// Same as [`RawDos::new`]
impl Default for RawDos {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RawDos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RawDos");
        if self.magic == DOS_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"MZ""#)
                }
            }
            s.field("magic", &Helper);
        } else {
            s.field("magic", &{ self.magic });
        }

        s.field("last_bytes", &{ self.last_bytes })
            .field("pages", &{ self.pages })
            .field("relocations", &{ self.relocations })
            .field("header_size", &{ self.header_size })
            .field("min_alloc", &{ self.min_alloc })
            .field("max_alloc", &{ self.max_alloc })
            .field("initial_ss", &{ self.initial_ss })
            .field("initial_sp", &{ self.initial_sp })
            .field("checksum", &{ self.checksum })
            .field("initial_ip", &{ self.initial_ip })
            .field("initial_cs", &{ self.initial_cs })
            .field("relocation_offset", &{ self.relocation_offset })
            .field("overlay_num", &{ self.overlay_num });
        if { self._reserved } == [0; 4] {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "[0u16; 4]")
                }
            }
            s.field("_reserved", &Helper);
        } else {
            s.field("_reserved", &{ self._reserved });
        }

        s.field("oem_id", &{ self.oem_id })
            .field("oem_info", &{ self.oem_info });
        if { self._reserved2 } == [0; 20] {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "[0u8; 20]")
                }
            }
            s.field("_reserved2", &Helper);
        } else {
            s.field("_reserved2", &{ self._reserved2 });
        }
        s.field("pe_offset", &{ self.pe_offset }).finish()
    }
}

#[cfg(all(test, kani))]
impl kani::Arbitrary for RawDos {
    #[inline(always)]
    fn any() -> Self {
        crate::internal::test_util::kani_raw_dos(kani::any())
    }
}

#[cfg(test)]
mod r_tests {
    use core::mem::align_of;

    use super::*;

    /// Ensure expected ABI
    #[test]
    fn abi() {
        assert!(size_of::<RawDos>() == 64);
        assert!(align_of::<RawDos>() == 1);
    }

    /// Ensure this simple operation passes miri / in general
    #[test]
    fn miri() -> Result<()> {
        let dos = RawDos::new();
        let dos2 = unsafe { RawDos::from_ptr(&dos as *const _ as *const u8, size_of::<RawDos>())? };
        assert_eq!(&dos, dos2);
        Ok(())
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::internal::test_util::kani;

    /// Test, fuzz, and model [`RawDos::from_ptr`]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_dos_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawDos::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    assert_eq!(d.magic, DOS_MAGIC, "Incorrect `Ok` DOS magic");

                    // Should only be `Ok` if `len` is this
                    assert!(len >= size_of::<RawDos>(), "Invalid `Ok` len");
                }

                // Ensure `InvalidDosMagic` error happens
                Err(Error::InvalidDosMagic(m)) => {
                    kani::cover!(true, "InvalidDosMagic");

                    // Should have gotten NotEnoughData if there wasn't enough
                    assert!(len >= size_of::<RawDos>(), "Invalid InvalidDosMagic len");

                    assert_ne!(m, DOS_MAGIC, "Invalid InvalidDosMagic magic??");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` is too small
                    assert!(len < size_of::<RawDos>());
                }
            };
        });
    }
}
