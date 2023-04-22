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

use super::dos::RawDos;
use crate::{
    error::{Error, Result},
    internal::miri_helper,
    rich::Rich,
};

/// Undocumented VS-specific rich header signature
pub const RICH_MAGIC: [u8; 4] = *b"Rich";

/// Rich Header array magic signature
pub const ARRAY_MAGIC: [u8; 4] = *b"DanS";

/// Helper to find `search` in `bytes` in a way that works in and
/// out of kani model checking
///
/// Should be [`RICH_MAGIC`] or [`ARRAY_MAGIC`]
///
/// Returns the index of `search`, or [`None`].
fn find_rich_helper(bytes: &[u8], search: [u8; 4]) -> Option<usize> {
    #[cfg(test)]
    use crate::internal::test_util::kani;

    // Safety: Caller
    let b = BStr::new(bytes);

    // Need to fake this for `kani` because `rfind` is super slow
    // Make sure to uphold the invariants we expect from `rfind`
    //
    // Namely:
    // `offset` is always in bounds of `size`
    // for `offset` to be in bounds it must have space for `RICH_MAGIC`
    // Theres no guarantee it has space for the XOR key, it's user input.
    //
    // Note that this will not actually "search" from the "end",
    // this over-estimates `rfind`. This shouldn't matter.
    // FIXME: This should be removed and support extended when possible.
    #[cfg(any(kani, test))]
    let offset: Option<usize> = {
        let bound = bytes.len() - search.len();
        kani::any_where(|x| match *x {
            Some(x) => {
                let o = x <= bound;
                kani::assume(o);
                let magic = bytes[x..][..search.len()] == search;
                kani::assume(magic);
                o && magic
            }
            None => true,
        })
    };

    // Put this after the above so that non-kani testing uses it
    // This is because the above uses `any` with `test` for dev experience.
    #[cfg(not(kani))]
    let offset = b.rfind(search);

    // TODO: Add negative test, ensure this always returning None fails.
    // Note that kani does catch it as `Ok(Some)` being UNREACHABLE though.
    // But ideally we have a better test than noticing that.
    offset
}

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

    /// Get a [`RawRich`] from a pointer to the Rich header
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the magic is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawRich`]
    /// - [`Error::InvalidRichMagic`] If the rich magic is incorrect
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` MUST be valid for reads of `size` bytes.
    ///
    /// ## Post-conditions
    ///
    /// - Only the documented errors will ever be returned
    pub unsafe fn from_ptr<'data>(data: *const u8, size: usize) -> Result<&'data Self> {
        // Safety:
        // - Caller asserts `data` is valid for `size`
        // - `RawRich` has no alignment requirements or invalid values.
        Ok(&*(Self::from_ptr_internal(data, size)?))
    }

    /// Find the Rich Header given a pointer to the
    /// [DOS stub code][`crate::dos::Dos::stub`]
    ///
    /// `size` must be *at least* [`RawDos::pe_offset`] to be able to find the
    /// Rich Header in a PE file.
    ///
    /// Higher values may lead to slower performance,
    /// and incorrect results in the case of PE files or untrusted user input.
    ///
    /// Returns a reference to [`RawRich`], and it's offset from `data`.
    ///
    /// # Returns
    ///
    /// - [`Ok(Some)`] If a valid Rich Header was found.
    /// - [`Ok(None)`] If no Rich Header was found, and no errors occurred.
    /// - [`Err`] See Errors
    ///
    /// # Errors
    ///
    /// - [`Error::NotEnoughData`] If `size` is not enough to fit a [`RawRich`]
    ///
    /// # Safety
    ///
    /// ## Pre-conditions
    ///
    /// - `data` must be valid for `size` bytes
    ///
    /// ## Post-conditions
    ///
    /// - The returned offset is less than `size`
    ///   - e.g. `data.add(offset)` is always safe if `data.add(size)` is.
    /// - `data.add(offset)` is valid for at least
    ///   [`size_of::<RawRich>()`][`RawRich`] bytes.
    pub unsafe fn find_rich<'data>(
        data: *const u8,
        size: usize,
    ) -> Result<Option<(&'data Self, usize)>> {
        match Self::find_rich_internal(data, size)? {
            Some((r, o)) => {
                debug_assert!(o < size, "RawRich::find_rich guarantee violated");
                // Safety:
                // - Caller asserts `data` is valid for `size`
                // - `RawRich` has no alignment requirements or invalid values.
                Ok(Some((&*r, o)))
            }
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
        let data = data as *const RawRich;
        let rich = &*data;
        if rich.magic != RICH_MAGIC {
            return Err(Error::InvalidRichMagic);
        }

        miri_helper!(data as *const u8, size);

        Ok(data.cast())
    }

    /// See [`RawRich::find_rich`]
    unsafe fn find_rich_internal(
        data: *const u8,
        size: usize,
    ) -> Result<Option<(*const Self, usize)>> {
        #[cfg(test)]
        use crate::internal::test_util::kani;

        // Ensure that size is enough
        size.checked_sub(size_of::<RawRich>())
            .ok_or(Error::NotEnoughData)?;

        // Safety: Caller
        let offset = find_rich_helper(from_raw_parts(data, size), RICH_MAGIC);

        let offset = match offset {
            Some(o) => o,
            None => return Ok(None),
        };

        // Safety:
        // - `o` is guaranteed to be within bounds by `rfind`
        let ptr = data.add(offset);
        let len = size - offset;

        miri_helper!(ptr, len);

        // Safety:
        // - `ptr` is guaranteed to be valid for `size - offset`
        let rich = Self::from_ptr_internal(ptr, len);

        match rich {
            Ok(p) => Ok(Some((p, offset))),
            Err(e @ Error::NotEnoughData) => Err(e),

            // `rfind` guarantees the magic, at least, is valid
            Err(Error::InvalidRichMagic) => unreachable!(),

            // No other errors are ever returned
            Err(_) => unreachable!(),
        }
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
    /// Constant of value [`ARRAY_MAGIC`] identifying the rich array
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
    /// `size` must be *at least* [`RawDos::pe_offset`] to be able to find the
    /// Rich Header in a PE file.
    ///
    /// Higher values may lead to slower performance,
    /// and incorrect results in the case of PE files or untrusted user input.
    ///
    /// `key` should be [`RawRich::key`]
    ///
    /// Returns a reference to [`RawRichArray`], and it's offset from `data`.
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
    /// ## Pre-conditions
    ///
    /// - `data` must be valid for `size` bytes
    ///
    /// ## Post-conditions
    ///
    /// - The returned offset is less than `size`
    ///   - e.g. `data.add(offset)` is always safe if `data.add(size)` is.
    /// - `data.add(offset)` is valid for at least
    ///   [`size_of::<RawRichArray>()`][`RawRichArray`] bytes.
    ///
    /// [`RawDos`]: crate::raw::dos::RawDos
    /// [`RawDos::pe_offset`]: crate::raw::dos::RawDos::pe_offset
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

        let magic_xor = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let magic_xor = magic_xor.to_ne_bytes();

        // Safety:
        // - We just checked `data` would fit a `RawRich`
        // - Caller guarantees `data` is valid
        let arr = &*(data as *const RawRichArray);
        if arr.magic != magic_xor {
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

        let magic_xor = u32::from_ne_bytes(ARRAY_MAGIC) ^ key;
        let magic_xor = magic_xor.to_ne_bytes();

        let offset = find_rich_helper(from_raw_parts(data, size), magic_xor);
        let offset = match offset {
            Some(o) => o,
            None => return Ok(None),
        };

        // Safety:
        // - `o` is guaranteed in-bounds by `rfind`
        let ptr = data.add(offset);

        // Safety:
        // - `ptr` is guaranteed to be valid for `size - o`
        match Self::from_ptr_internal(ptr, size - offset, Some(key)) {
            Ok(p) => Ok(Some((p, offset))),
            Err(e @ Error::NotEnoughData) => Err(e),

            // `rfind` guarantees the magic, at least, is valid
            Err(Error::InvalidRichMagic) => unreachable!(),

            // No other errors are ever returned
            Err(_) => unreachable!(),
        }
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

/// Return the [XOR key][`RawRich::key`], calculated over `dos` and `stub`.
///
/// `key` will be XORed before reading [Rich Header][`RawRich`] or
/// [Array Entry][`RawRichEntry`] fields inside `stub`.
/// It may be zero if these are not XORed.
///
/// Returns zero if it cant find the rich header in `stub`
///
/// # Algorithm
///
/// The key is calculated with an initial value of the absolute
/// position to the [rich header array][`RawRichArray`], summed with every byte
/// of the DOS header XORed with its offset, except for the last 4 bytes,
/// followed by every remaining byte, until the [Rich Header][RawRich]
pub fn calculate_key(dos: &RawDos, stub: &[u8], key: u32) -> u32 {
    // Safety: Trivial
    let array_hdr_offset = match unsafe { RawRichArray::find_array(stub.as_ptr(), stub.len(), key) }
    {
        Ok(Some(it)) => it.1,
        _ => return 0,
    };
    // Plus RawDos because our offset is `stub`, not a PE file.
    // FIXME: find_array docs
    let array_hdr_offset = array_hdr_offset + size_of::<RawDos>();

    let mut check: u32 = array_hdr_offset as u32;

    // Safety: Trivially valid
    let dos = unsafe { from_raw_parts(dos as *const _ as *const u8, size_of::<RawDos>() - 4) };
    for (i, b) in dos.iter().copied().enumerate() {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    // DOS stub and rich header
    for (i, b) in stub
        .iter()
        .copied()
        .enumerate()
        .take(array_hdr_offset - size_of::<RawDos>())
    {
        let b = b as u32;
        let i = i as u32;
        check = check.wrapping_add(b.rotate_left(i));
    }

    // Safety: `stub` is trivially valid for `stub.len()`
    let rich = unsafe { Rich::from_ptr(stub.as_ptr(), stub.len()) };
    let rich = match rich {
        Ok(r) => r,
        _ => return 0,
    };

    for entry in rich.entries() {
        let id = entry.id ^ key;
        let count = entry.count ^ key;
        check = check.wrapping_add(id.rotate_left(count));
    }

    check
}

#[cfg(test)]
mod r_tests {
    use core::mem::align_of;

    use kani::Arbitrary;

    use super::*;
    use crate::{internal::test_util::kani, raw::dos::DOS_MAGIC};

    /// Ensure expected ABI
    #[test]
    fn abi() {
        assert!(size_of::<RawRich>() == 8);
        assert!(align_of::<RawRich>() == 1);

        assert!(size_of::<RawRichArray>() == 16);
        assert!(align_of::<RawRichArray>() == 1);

        assert!(size_of::<RawRichEntry>() == 8);
        assert!(align_of::<RawRichEntry>() == 1);
    }

    /// Ensure this simple operation passes miri / in general
    #[test]
    fn miri() -> Result<()> {
        let rich = RawRich::new();
        let rich2 = unsafe { RawRich::from_ptr(&rich as *const _ as *const u8, 8)? };
        assert_eq!(&rich, rich2);
        // TODO: Rest of rich
        Ok(())
    }

    /// Test, fuzz, and model RawRich::from_ptr
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn raw_rich_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawRich::from_ptr(ptr, len) };

            match d {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    assert_eq!(d.magic, RICH_MAGIC, "Incorrect `Ok` Rich magic");

                    // Should only be `Ok` if `len` is enough
                    assert!(len >= size_of::<RawRich>(), "Invalid `Ok` len");
                }

                // Ensure `InvalidRichMagic` error happens
                Err(Error::InvalidRichMagic) => {
                    kani::cover!(true, "InvalidRichMagic");

                    // Should have gotten NotEnoughData if there wasn't enough
                    assert!(len >= size_of::<RawRich>(), "Invalid InvalidRichMagic len");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` isn't enough
                    assert!(len < size_of::<RawRich>());
                }

                // Ensure no other errors happen
                Err(_) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!();
                }
            };
        });
    }

    /// Test, fuzz, and model RawRich::find_rich
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn find_rich() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let d = unsafe { RawRich::find_rich(ptr, len) };

            match d {
                // Ensure the `Ok(Some)` branch is hit
                Ok(Some((d, o))) => {
                    kani::cover!(true, "Ok(Some)");

                    assert_eq!(d.magic, RICH_MAGIC, "Incorrect `Ok(Some)` Rich magic");

                    // Should only be `Ok(Some)` if `len` is enough
                    assert!(len >= size_of::<RawRich>(), "Invalid `Ok(Some)` len");

                    // Offset has to leave enough space in `len` to fit RawRich
                    assert!(o <= (len - size_of::<RawRich>()), "Invalid `Ok(Some)` len");
                }

                // Ensure the `Ok(Some)` branch is hit
                Ok(None) => {
                    kani::cover!(true, "Ok(None)");

                    // Should only be `Ok(None)` if `len` is enough
                    assert!(len >= size_of::<RawRich>(), "Invalid `Ok(None)` len");
                }

                // Ensure `NotEnoughData` error happens
                Err(Error::NotEnoughData) => {
                    kani::cover!(true, "NotEnoughData");

                    // Should only get this when `len` isn't enough
                    // Or when the rich magic is at the end,
                    // but NOT followed by enough bytes for the XOR key.
                    let too_small = len < size_of::<RawRich>();
                    let no_xor = bytes.ends_with(&RICH_MAGIC);

                    if !(too_small || no_xor) {
                        kani::cover!(true, "NotEnoughData - Offset XOR");
                        let end = bytes
                            .get(bytes.len().saturating_sub(size_of::<RawRich>() - 1)..)
                            .unwrap_or(&[]);
                        let l = end.len();

                        // Do this weirdness because kani cannot handle using
                        // `Iterator::windows`, the initial implementation.
                        let off1_xor = end.ends_with(&[
                            //
                            b'R',
                            b'i',
                            b'c',
                            b'h',
                            end[l - 1],
                        ]);
                        let off2_xor = end.ends_with(&[
                            //
                            b'R',
                            b'i',
                            b'c',
                            b'h',
                            end[l - 2],
                            end[l - 1],
                        ]);
                        let off3_xor = end.ends_with(&[
                            b'R',
                            b'i',
                            b'c',
                            b'h',
                            end[l - 3],
                            end[l - 2],
                            end[l - 1],
                        ]);
                        let off4_xor = end.ends_with(&[
                            b'R',
                            b'i',
                            b'c',
                            b'h',
                            end[l - 4],
                            end[l - 3],
                            end[l - 2],
                            end[l - 1],
                        ]);

                        let off_xor = off1_xor || off2_xor || off3_xor || off4_xor;
                        assert!(off_xor);
                    }

                    #[cfg(no)]
                    let off_xor = bytes
                        .get(bytes.len().saturating_sub(size_of::<RawRich>() - 1)..)
                        .unwrap_or(&[])
                        .windows(4)
                        .any(|b| b == RICH_MAGIC);
                }

                // Ensure no other errors happen
                Err(_) => {
                    kani::cover!(false, "Unexpected Error");
                    unreachable!();
                }
            };
        })
    }
}
