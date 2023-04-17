//! Raw Rich Header data structures
//!
//! The Rich Header is an undocumented data structure added to PE files by
//! the Microsoft Visual Studio compiler
//!
//! It appears after the DOS header but before the PE offset,
//! and can be found by searching for the signature [`RICH_MAGIC`] backwards
//! from the PE offset.
//!
//! The rich header length must be a multiple of 8.
//!
//! The rich header consists of XORed data of variable size,
//! followed by [`RICH_MAGIC`], followed by the 32-bit XOR key.
//! [`RawRich`]
//!
//! The start of the data is indicated by [`ARRAY_MAGIC`]
//! and 3 [`u32`] zeros. [`RawRichArray`]
//!
//! This location will be the first entry in the Rich Header array,
//! [`RawRichEntry`]

use core::{fmt, mem::size_of, slice::from_raw_parts};

use bstr::{BStr, ByteSlice};

use super::dos::{RawDos, DOS_MAGIC};
use crate::error::{Error, Result};

/// Undocumented VS-specific rich header signature
pub const RICH_MAGIC: [u8; 4] = *b"Rich";

/// Rich Header array magic signature
pub const ARRAY_MAGIC: [u8; 4] = *b"DanS";

/// Microsoft Rich Header
///
/// The actual rich header *precedes* this structure in memory.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
pub struct RawRich {
    /// Constant of value [`RICH_MAGIC`] identifying the PE executable
    pub magic: [u8; 4],

    /// XOR key for the data preceding this header
    pub key: u32,
}

/// Public deserialization API
impl RawRich {
    /// Create a new, empty, [`RawRich`].
    ///
    /// Sets the Rich magic and the key to `0`
    pub const fn new() -> Self {
        Self {
            magic: RICH_MAGIC,
            key: 0,
        }
    }

    /// Get a [`RawRich`] from a pointer to the first byte after the
    /// DOS Header [`RawDOS`].
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the rich signature is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawRich`]
    /// - [`Error::InvalidRichMagic`] If the rich magic is incorrect
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    ///
    /// [`RawDos`]: crate::raw::RawDos
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Find the Rich Header given a pointer to the first byte after the
    /// DOS Header [`RawDOS`].
    ///
    /// `Size` must be only the length until [`RawDos::pe_offset`]
    ///
    /// Returns a pointer to [`RawDOS`], and it's offset from `data`.
    ///
    /// # Returns
    ///
    /// - [`Ok(Some)`] If a valid Rich Header was found.
    /// - [`Ok(None)`] If no rich header was found, and no errors occurred.
    /// - [`Err`] See Errors
    ///
    /// # Errors
    ///
    /// - See [`RawRich::from_ptr`]
    ///
    /// # Safety
    ///
    /// - `data` must be valid for `size` bytes
    /// - `size` must be only until [`RawDos::pe_offset`], not the entire PE
    ///   image.
    ///
    /// [`RawDos`]: crate::raw::dos::RawDos
    /// [`RawDos::pe_offset`]: crate::raw::dos::RawDos::pe_offset
    pub unsafe fn find_rich<'data>(
        data: *const u8,
        size: usize,
    ) -> Result<Option<(&'data Self, usize)>> {
        match Self::find_rich_internal(data, size)? {
            Some((r, o)) => Ok(Some((&*r, o))),
            None => Ok(None),
        }
    }
}

/// Internal base API
impl RawRich {
    /// See [`RawRich::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, size: usize) -> Result<*const Self> {
        debug_assert!(!data.is_null(), "`data` was null in RawRich::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawRich>())
            .ok_or(Error::NotEnoughData)?;

        // Safety:
        // - We just checked `data` would fit a `RawRich`
        // - Caller guarantees `data` is valid
        let rich = &*(data as *const RawRich);
        if rich.magic != RICH_MAGIC {
            return Err(Error::InvalidRichMagic);
        }

        Ok(data.cast())
    }

    /// See [`RawRich::find_rich`]
    unsafe fn find_rich_internal(
        data: *const u8,
        size: usize,
    ) -> Result<Option<(*const Self, usize)>> {
        // Ensure that size is enough
        size.checked_sub(size_of::<RawRich>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Caller
        let b = BStr::new(from_raw_parts(data, size));

        // Safety:
        // - `o` is guaranteed in-bounds by `rfind`
        let o = b.rfind(RICH_MAGIC);
        let o = match o {
            Some(o) => o,
            None => return Ok(None),
        };
        let ptr = data.add(o);

        // Safety:
        // - `ptr` is guaranteed to be valid for `size - o`
        Ok(Some((Self::from_ptr_internal(ptr, size - o)?, o)))
    }
}

impl fmt::Debug for RawRich {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RawRich");
        if self.magic == RICH_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"Rich""#)
                }
            }
            s.field("magic", &Helper);
        } else {
            s.field("magic", &{ self.magic });
        }

        s.field("key", &{ self.key }).finish()
    }
}

/// Rich Header Array header
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
pub struct RawRichArray {
    /// Constant of value [`ARRAY_MAGIC`] identifying the PE executable
    pub magic: [u8; 4],

    /// Padding array entry that should be all zeros
    pub padding1: u32,

    /// Padding array entry that should be all zeros
    pub padding2: u32,

    /// Padding array entry that should be all zeros
    pub padding3: u32,
}

/// Public deserialization API
impl RawRichArray {
    /// Create a new, empty, [`RawRichArray`].
    ///
    /// Sets the magic
    pub const fn new() -> Self {
        Self {
            magic: ARRAY_MAGIC,
            padding1: 0,
            padding2: 0,
            padding3: 0,
        }
    }

    /// Get a [`RawRichArray`] from a pointer to the rich array header
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the signature is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawRichArray`]
    /// - [`Error::InvalidRichArrayMagic`] If the rich magic is incorrect
    ///
    /// # Safety
    ///
    /// - `data` MUST be valid for `size` bytes.
    /// - You must ensure the returned reference does not outlive `data`, and is
    ///   not mutated for the duration of lifetime `'data`.
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size, None)?))
    }

    /// The same as [`RawRichArray::from_ptr`], but XORs `key` before attempting
    /// to read fields.
    ///
    /// `key` should be [`RawRich::key`]
    ///
    /// # Safety
    ///
    /// See [`RawRichArray::from_ptr`] for error and safety details
    pub unsafe fn from_ptr_xor<'data>(
        data: *const u8,
        size: usize,
        key: u32,
    ) -> Result<&'data Self> {
        Ok(&*(Self::from_ptr_internal(data, size, Some(key))?))
    }

    /// Find the Rich Header Array given a pointer to the first byte after the
    /// DOS Header [`RawDOS`].
    ///
    /// `Size` must be only the length until [`RawDos::pe_offset`]
    ///
    /// `key` should be [`RawRich::key`]
    ///
    /// Returns a pointer to [`RawRichArray`], and it's offset from `data`.
    ///
    /// # Returns
    ///
    /// - [`Ok(Some)`] If a valid array was found.
    /// - [`Ok(None)`] If no array was found, and no errors occurred.
    /// - [`Err`] See Errors
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a
    ///   [`RawRichArray`]
    ///
    /// # Safety
    ///
    /// - `data` must be valid for `size` bytes
    /// - `size` must be only until [`RawDos::pe_offset`], not the entire PE
    ///   image.
    ///
    /// [`RawDos`]: crate::raw::RawDos
    /// [`RawDos::pe_offset`]: crate::raw::RawDos::pe_offset
    pub unsafe fn find_array<'data>(
        data: *const u8,
        size: usize,
        key: u32,
    ) -> Result<Option<(&'data Self, usize)>> {
        match Self::find_array_internal(data, size, Some(key))? {
            Some((r, o)) => Ok(Some((&*r, o))),
            None => Ok(None),
        }
    }
}

/// Public data API
impl RawRichArray {
    /// Allows calling [`Debug`][`fmt::Debug`] while providing a XOR key,
    /// for printing of correct values in memory without copying.
    pub const fn debug_with_key(&self, key: u32) -> impl fmt::Debug + '_ {
        struct Helper<'a>(&'a RawRichArray, u32);
        impl<'a> fmt::Debug for Helper<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.debug_fmt(f, self.1)
            }
        }
        Helper(self, key)
    }
}

/// Internal base API
impl RawRichArray {
    /// See [`RawRichArray::from_ptr`]
    ///
    /// `key` is the XOR key or [`None`]
    unsafe fn from_ptr_internal(
        data: *const u8,
        size: usize,
        key: Option<u32>,
    ) -> Result<*const Self> {
        let key = key.unwrap_or(0);
        debug_assert!(!data.is_null(), "`data` was null in RawRichArray::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawRichArray>())
            .ok_or(Error::NotEnoughData)?;

        let n = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let n = n.to_ne_bytes();

        // Safety:
        // - We just checked `data` would fit a `RawRich`
        // - Caller guarantees `data` is valid
        let arr = &*(data as *const RawRichArray);
        if arr.magic != n {
            return Err(Error::InvalidRichArrayMagic);
        }
        if (arr.padding1 ^ key) + (arr.padding2 ^ key) + (arr.padding3 ^ key) != 0 {
            // TODO: More specific error?
            return Err(Error::InvalidData);
        }

        Ok(data.cast())
    }

    /// See [`RawRichArray::find_array`]
    ///
    /// `key` is the XOR key or [`None`]
    unsafe fn find_array_internal(
        data: *const u8,
        size: usize,
        key: Option<u32>,
    ) -> Result<Option<(*const Self, usize)>> {
        let key = key.unwrap_or(0);
        // Ensure that size is enough
        size.checked_sub(size_of::<RawRichArray>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Caller
        let b = BStr::new(from_raw_parts(data, size));

        let n = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let n = n.to_ne_bytes();
        // Safety:
        // - `o` is guaranteed in-bounds by `rfind`
        let o = b.rfind(n);
        let o = match o {
            Some(o) => o,
            None => return Ok(None),
        };
        let ptr = data.add(o);

        // Safety:
        // - `ptr` is guaranteed to be valid for `size - o`
        Ok(Some((
            Self::from_ptr_internal(ptr, size - o, Some(key))?,
            o,
        )))
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>, key: u32) -> fmt::Result {
        let n = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let n = n.to_ne_bytes();

        let mut s = f.debug_struct("RawRichArray");
        if self.magic == ARRAY_MAGIC {
            struct Helper;
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"DanS""#)
                }
            }
            s.field("magic", &Helper);
        } else if self.magic == n {
            struct Helper([u8; 4]);
            impl fmt::Debug for Helper {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, r#"b"DanS" (XOR {:?})"#, self.0)
                }
            }
            s.field("magic", &Helper(self.magic));
        } else {
            s.field("magic", &{ self.magic });
        }

        s.field("padding1", &{ self.padding1 ^ key });
        s.field("padding2", &{ self.padding2 ^ key });
        s.field("padding3", &{ self.padding3 ^ key });
        s.finish()
    }
}

impl fmt::Debug for RawRichArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug_fmt(f, 0)
    }
}

/// An entry in the Rich Header array
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C, packed)]
pub struct RawRichEntry {
    /// Contains the product/type ID in the high half, and the build id
    ///
    /// Also referred to as the @comp.id, and the fields by ProdID and mCV
    pub id: u32,

    /// Number of times tool has been used
    pub count: u32,
}

/// Public data API
impl RawRichEntry {
    /// Build ID
    #[inline]
    pub const fn build_id(&self) -> u16 {
        self.id().0
    }

    /// Product ID
    #[inline]
    pub const fn product_id(&self) -> u16 {
        self.id().1
    }

    /// Product and Build ID pair
    #[inline]
    pub const fn id(&self) -> (u16, u16) {
        self.id_with_key(0)
    }

    /// Product and Build ID pair
    #[inline]
    pub const fn id_with_key(&self, key: u32) -> (u16, u16) {
        let id = self.id ^ key;
        let product_high = (id >> 16) as u16;
        let build_low = (id & 0xFFFF) as u16;
        (product_high, build_low)
    }

    /// Allows calling [`Debug`][`fmt::Debug`] while providing a XOR key,
    /// for printing of correct values in memory without copying.
    pub const fn debug_with_key(&self, key: u32) -> impl fmt::Debug + '_ {
        struct Helper<'a>(&'a RawRichEntry, u32);
        impl<'a> fmt::Debug for Helper<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.debug_fmt(f, self.1)
            }
        }
        Helper(self, key)
    }
}

/// Internal base API
impl RawRichEntry {
    /// See [`RawRichEntry::from_ptr`]
    ///
    /// `key` is the XOR key or [`None`]
    unsafe fn from_ptr_internal(
        data: *const u8,
        size: usize,
        key: Option<u32>,
    ) -> Result<*const Self> {
        let key = key.unwrap_or(0);
        debug_assert!(!data.is_null(), "`data` was null in RawRichArray::from_ptr");

        // Ensure that size is enough
        size.checked_sub(size_of::<RawRichArray>())
            .ok_or(Error::NotEnoughData)?;

        let n = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let n = n.to_ne_bytes();

        // Safety:
        // - We just checked `data` would fit a `RawRich`
        // - Caller guarantees `data` is valid
        let arr = &*(data as *const RawRichArray);
        if arr.magic != n {
            return Err(Error::InvalidRichArrayMagic);
        }
        if (arr.padding1 ^ key) + (arr.padding2 ^ key) + (arr.padding3 ^ key) != 0 {
            // TODO: More specific error?
            return Err(Error::InvalidData);
        }

        Ok(data.cast())
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>, key: u32) -> fmt::Result {
        let mut s = f.debug_struct("RawRichEntry");

        let (product_id, build_id) = self.id_with_key(key);

        s.field("id", &{ self.id ^ key });
        s.field("product_id", &product_id);
        s.field("build_id", &build_id);
        s.field("count", &{ self.count ^ key });
        s.finish()
    }
}

impl fmt::Debug for RawRichEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug_fmt(f, 0)
    }
}

/// Calculate the checksum in the [Rich Header],
/// given a pointer to PE image.
///
/// `key` will be XORed before reading [Rich Header] or [Array Entry] fields.
/// It can be zero if `data` is not XORed.
///
/// `Size` should be only the length until [`RawDos::pe_offset`]
///
/// # Safety
///
/// - `data` MUST point to a valid PE image
/// - `data` MUST be valid for `size`
///
/// [Rich Header]: RawRich
/// [Array Entry]: RawRichEntry
#[cfg(no)]
pub unsafe fn calculate_checksum_with_key(data: *const u8, size: usize, key: u32) -> u32 {
    let end = 0;

    let dos = from_raw_parts(data as *const u8, end);

    let initial = 0;
    let mut check: u32 = initial;
    let iter = dos.iter().copied().enumerate();
    let iter2 = iter.clone();

    for (i, b) in iter.take(60) {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    for (i, b) in iter2.take(initial as usize).skip(63) {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    // check = check.wrapping_add(0u32.rotate_left(60));
    // check = check.wrapping_add(0u32.rotate_left(61));
    // check = check.wrapping_add(0u32.rotate_left(62));
    // check = check.wrapping_add(0u32.rotate_left(63));

    let array = from_raw_parts(array, count);
    for entry in array {
        let id = entry.id ^ key;
        let count = entry.count ^ key;
        check = check.wrapping_add(id.rotate_left(count));
        // check = check.wrapping_add(id ^ count);
    }

    check
}

/// Calculate the checksum in the [Rich Header],
/// given a pointer to the [DOS Header],
/// a pointer to the first [Array Entry], and a count of elements.
///
/// `key` will be XORed before reading [Rich Header] or [Array Entry] fields.
/// It can be zero if these are not XORed.
///
/// `size` ***should*** be only up to [`RawPe`] / the PE signature,
/// this function does not need and will not work efficiently with the
/// full image.
///
/// `initial` must be
///
/// # Safety
///
/// - `data` MUST point to a PE file
/// - `data` MUST be valid for `size`
/// - `array` must point to a valid [`RawRichEntry`] valid for `count` elements
///
/// [Rich Header]: RawRich
/// [DOS Header]: RawDos
/// [Array Entry]: RawRichEntry
/// [`RawPe`]: crate::raw::pe::RawPe
pub unsafe fn calculate_checksum_with_key(
    data: *const u8,
    size: usize,
    array: *const RawRichEntry,
    count: usize,
    key: u32,
    initial: u32,
) -> u32 {
    let mut check: u32 = initial;

    let dos = from_raw_parts(data, size_of::<RawDos>() - 4);
    for (i, b) in dos.iter().copied().enumerate() {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    let stub_size = size - size_of::<RawDos>();
    let stub = from_raw_parts(data.add(size_of::<RawDos>()), stub_size);

    for (i, b) in stub.iter().copied().enumerate().take(initial as usize) {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    let array = from_raw_parts(array, count);
    for entry in array {
        let id = entry.id ^ key;
        let count = entry.count ^ key;
        check = check.wrapping_add(id.rotate_left(count));
    }

    check
}

#[cfg(test)]
mod tests {
    use super::*;

    static RUSTUP_IMAGE: &[u8] = include_bytes!("../../tests/data/rustup-init.exe");

    #[test]
    fn rich_header() -> Result<()> {
        unsafe {
            let size = 0x1000;
            let y = &RUSTUP_IMAGE[..size];
            let size = y.len();
            let data = y.as_ptr();

            let rich = RawRich::find_rich(data, size);
            dbg!(&rich);
            let (rich, rich_o) = rich?.unwrap();

            let arr = RawRichArray::find_array(data, size, rich.key);
            dbg!(&arr);
            let (arr, arr_o) = arr?.unwrap();
            dbg!(&arr.debug_with_key(rich.key));
            eprintln!();

            let entries = data.add(arr_o).add(size_of::<RawRichArray>());

            let entry = &*(entries as *const RawRichEntry);
            // assert_eq!({ entry.build_id }, 30795, "");
            // assert_eq!({ entry.product_id }, 259, "");

            let end = data.add(rich_o);
            let mut count = 0;

            let mut cur = entries;
            while cur != end {
                let entry = &*(cur as *const RawRichEntry);
                dbg!(&entry.debug_with_key(rich.key));
                eprintln!();

                cur = cur.add(size_of::<RawRichEntry>());
                count += 1;
            }

            let initial = arr_o as u32;
            dbg!(initial);
            // let calc = calculate_checksum_with_key(data.cast(), count, rich.key);
            let calc =
                calculate_checksum_with_key(data, arr_o, entries.cast(), count, rich.key, initial);

            assert_eq!({ rich.key }, calc, "Rich header checksum mismatch");

            // panic!();
            Ok(())
        }
    }
}
