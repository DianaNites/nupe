//! Higher level wrappers around the [DOS Header][RawDos],
//! see there for more details.
use core::{fmt, mem::size_of, slice::from_raw_parts};

use crate::{
    error::{Error, Result},
    raw::dos::RawDos,
    OwnedOrRef,
    VecOrSlice,
};

/// Default DOS Stub, header and code, for prepending to PE files.
// See `generate_stub` for how this is made
pub static DEFAULT_STUB: &[u8] = &[
    0x4D, 0x5A, 0x73, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x96, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00,
    0xB4, 0x09, 0xBA, 0x0B, 0x01, 0xCD, 0x21, 0xB4, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20,
    0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62,
    0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64,
    0x65, 0x2E, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub use crate::raw::dos::calculate_checksum;

#[cfg(no)]
fn generate_stub() {
    use std::{fs, io::Write, slice::from_raw_parts};

    use iced_x86::code_asm::*;

    const MSG: &[u8] = b"This program cannot be run in DOS mode.$";

    let mut a = CodeAssembler::new(16).unwrap();

    #[cfg(not(miri))]
    {
        // Print string
        // https://stanislavs.org/helppc/int_21-9.html
        a.mov(ah, 9).unwrap();
        // Code starts at 0x100 relative to DS? DOS PSP?
        // Our code is 11 bytes, so theres our string.
        a.mov(dx, 0x100 + 11).unwrap();
        a.int(0x21).unwrap();

        // Program Terminate
        // https://stanislavs.org/helppc/int_21-4c.html
        a.mov(ah, 0x4C).unwrap();
        a.int(0x21).unwrap();

        // String
        a.db(MSG).unwrap();
    }

    #[cfg(not(miri))]
    let mut stub = a.assemble(0).unwrap();
    #[cfg(miri)]
    let stub = &DEFAULT_STUB[size_of::<RawDos>()..];

    let s = size_of::<RawDos>() + stub.len();
    dbg!(s);

    // Pad stub to 8 bytes;
    #[cfg(not(miri))]
    {
        stub.push(0);
        stub.push(0);
        stub.push(0);
        stub.push(0);
        stub.push(0);
    }

    let lb = ((s) % 512) as u16;

    let p = ((s) / 512) + 1;
    let p = p as u16;

    // Align PE offset to 8 bytes
    let po = s + (8 - (s % 8));
    let po = if s % 8 == 0 { s } else { po };
    let po = po as u32;

    let mut dos = RawDos {
        // One page
        pages: p,

        // With X bytes
        last_bytes: lb,

        // Entry point
        // DOS starts executing at 0, relative to CS
        // <https://en.wikipedia.org/wiki/DOS_MZ_executable>
        initial_ip: 0,

        // Need to allow allocation of at least one paragraph
        max_alloc: 1,

        // Header takes 4 paragraphs, 64 / 16
        header_size: 4,

        // PE offset will start after header and code
        pe_offset: po,

        ..RawDos::new()
    };

    dos.checksum = calculate_checksum(&dos, &stub);
    dbg!(&dos);

    let db = unsafe { from_raw_parts(&dos as *const _ as *const u8, size_of::<RawDos>()) };
    dbg!(calculate_checksum(&dos, &stub));

    #[cfg(no)]
    // #[cfg(not(miri))]
    {
        let mut f = fs::File::create("hi.exe").unwrap();
        f.write_all(db).unwrap();
        f.write_all(&stub).unwrap();
    }

    // eprintln!("Header");
    eprint!("[");
    db.iter().for_each(|b| eprint!("0x{b:02X},"));
    // eprintln!("]\n");

    // eprintln!("Stub");
    // eprint!("[");
    stub.iter().for_each(|b| eprint!("0x{b:02X},"));
    eprintln!("]\n");
}

pub type DosArg<'data> = OwnedOrRef<'data, RawDos>;

pub type DosStubArg<'data> = VecOrSlice<'data, u8>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dos<'data> {
    /// DOS header
    dos: DosArg<'data>,

    /// DOS stub code
    stub: DosStubArg<'data>,
}

/// Public Serialization API
impl<'data> Dos<'data> {
    #[inline]
    pub const fn new(dos: DosArg<'data>, stub: DosStubArg<'data>) -> Self {
        Self { dos, stub }
    }
}

/// Public Serialization API
impl Dos<'static> {
    /// Create a new [`Dos`] with a DOS stub that will print
    /// "This program cannot be run in DOS mode."
    ///
    /// The stub:
    ///
    /// - Indicates the PE offset is at 120 bytes
    /// - Is 120 bytes
    /// - Has a valid DOS checksum
    pub fn new_stub() -> Self {
        // generate_stub();
        // todo!();
        let dos = &DEFAULT_STUB[..size_of::<RawDos>()];
        let stub = &DEFAULT_STUB[size_of::<RawDos>()..];
        unsafe {
            Self {
                dos: DosArg::Ref(RawDos::from_ptr(dos.as_ptr(), dos.len()).unwrap_unchecked()),
                stub: DosStubArg::Slice(stub),
            }
        }
    }
}

/// Public Deserialization API
impl<'data> Dos<'data> {
    /// Get a [`Dos`] from a pointer to the [DOS Header][`RawDos`]
    ///
    /// This function validates that `size` is enough to contain the header,
    /// and that the DOS magic is correct.
    ///
    /// # Errors
    ///
    /// - [`Error::TooMuchData`] If the size of the DOS stub does not fit in
    ///   [`usize`]
    ///   - Stub size is determined to be everything between the end of
    ///     [header][`RawDos`] and until [`RawDos::pe_offset`]
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
    /// - Only the documented errors will ever be returned
    /// - [`Dos::stub().len()`][`slice::len`] will always be less than `size`
    /// - [`RawDos::pe_offset`] will always be less than or equal to `size`
    pub unsafe fn from_ptr(data: *const u8, size: usize) -> Result<Self> {
        Self::from_ptr_internal(data, size)
    }
}

/// Public Data API
impl<'data> Dos<'data> {
    /// Reference to the stub code
    ///
    /// The "stub code" is everything after the [DOS header][`RawDos`] but
    /// before the [PE header][RawPe].
    ///
    /// [RawPe]: crate::raw::pe::RawPe
    #[inline]
    pub fn stub(&self) -> &[u8] {
        &self.stub
    }

    /// Absolute offset in the file to the PE header
    ///
    /// "must" be aligned to 8 bytes
    ///
    /// Note that this value is untrusted input, and can be anything.
    /// This should be handled appropriately when using it to find the PE header
    #[inline]
    pub const fn pe_offset(&self) -> u32 {
        self.dos.as_ref().pe_offset
    }

    /// Reference to the [Raw DOS header][`RawDos`]
    #[inline]
    pub const fn raw_dos(&self) -> &RawDos {
        self.dos.as_ref()
    }

    /// Calculate the [DOS checksum][`RawDos::checksum`]
    ///
    /// If the checksum in the header is `0`, this will calculate the checksum.
    ///
    /// If the checksum in the header is set, and the checksum is valid,
    /// this should be equal to `0xFFFF`
    pub fn calculate_checksum(&self) -> u16 {
        calculate_checksum(&self.dos, &self.stub)
    }

    /// Validate the DOS checksum.
    ///
    /// Returns true if the DOS checksum is valid
    pub fn validate_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}

/// Internal API
impl<'data> Dos<'data> {
    /// See [`Dos::from_ptr`]
    unsafe fn from_ptr_internal(data: *const u8, input_size: usize) -> Result<Self> {
        let dos = RawDos::from_ptr(data, input_size).map_err(|_| Error::MissingDOS)?;

        // Pointer to the DOS stub code, and size of the code before the PE header
        // The Rich header may be hidden somewhere in here
        let stub_size: usize = dos
            .pe_offset
            .saturating_sub(size_of::<RawDos>() as u32)
            .try_into()
            .map_err(|_| Error::TooMuchData)?;

        // Ensure that `input_size` is enough for the DOS stub
        input_size
            .checked_sub(size_of::<RawDos>())
            .ok_or(Error::MissingDOS)?
            .checked_sub(stub_size)
            .ok_or(Error::MissingDOS)?;

        // This operation MUST be done after size is checked, otherwise
        // it is unsound.
        let stub_ptr = data.add(size_of::<RawDos>());

        // Safety:
        // - We ensure `stub_size` can never exceed `input_size`
        let stub = from_raw_parts(stub_ptr, stub_size);

        Ok(Self {
            dos: OwnedOrRef::Ref(dos),
            stub: VecOrSlice::Slice(stub),
        })
    }
}

impl<'data> fmt::Debug for Dos<'data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Dos");
        s.field("dos", &self.dos);

        s.field("stub", &debug::DosHelper::new(&self.stub));

        s.finish()
    }
}

pub mod debug {
    //! [`fmt::Debug`] helper types

    use core::fmt;

    use crate::VecOrSlice;

    /// Helper struct for [`fmt::Debug`] to display "DOS code (len N)"
    /// instead of a huge byte array.
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

#[cfg(test)]
mod tests {
    use core::mem::align_of;

    use super::*;
    use crate::internal::test_util::RUSTUP_IMAGE;

    /// Just so we know what to expect.
    #[test]
    fn abi() {
        assert_eq!(size_of::<Dos>(), 104);
        assert_eq!(align_of::<Dos>(), 8);
    }

    #[test]
    fn dos() -> Result<()> {
        unsafe {
            let data = RUSTUP_IMAGE.as_ptr();
            let size = RUSTUP_IMAGE.len();

            let dos = Dos::from_ptr(data, size);
            dbg!(&dos);

            // panic!();
            Ok(())
        }
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::{internal::test_util::kani, raw::dos::DOS_MAGIC};

    /// Test, fuzz, and model [`Dos::from_ptr`]
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn dos_from_ptr() {
        bolero::check!().for_each(|bytes: &[u8]| {
            let len = bytes.len();
            let ptr = bytes.as_ptr();

            let dos = unsafe { Dos::from_ptr(ptr, len) };

            match dos {
                // Ensure the `Ok` branch is hit
                Ok(d) => {
                    kani::cover!(true, "Ok");

                    let stub = d.stub();

                    kani::cover!(!stub.is_empty(), "Ok - Non-empty stub");
                    kani::cover!(stub.is_empty(), "Ok - Empty stub");

                    let expected = (d.pe_offset() as usize).saturating_sub(size_of::<RawDos>());

                    assert_eq!(
                        stub.len(),
                        expected,
                        "mismatch between expected and actual stub size"
                    );
                    assert!((stub.len() < len), "stub was larger than len");
                    assert!((d.pe_offset() as usize) <= len, "pe offset out of bounds");
                }

                // Ensure `MissingDOS` error happens
                Err(Error::MissingDOS) => {
                    kani::cover!(true, "MissingDOS");

                    // Should only get this when `len` is too small
                    // or when the dos magic is wrong
                    // or when the stub code is missing
                    let too_small = len < size_of::<RawDos>();
                    let no_magic = !bytes.starts_with(&DOS_MAGIC);

                    // If its not too small, or has no magic
                    if !(too_small || no_magic) {
                        // Then it must have a magic, but a missing stub
                        kani::cover!(true, "MissingDOS - Missing Stub");
                        assert!(!no_magic);

                        let dos = unsafe { RawDos::from_ptr(ptr, len) };
                        let dos = dos.unwrap();

                        let expected = (dos.pe_offset as usize).saturating_sub(size_of::<RawDos>());

                        assert_eq!(dos.magic, DOS_MAGIC);

                        assert!((len - size_of::<RawDos>()) < expected);

                        kani::cover!(true, "Too small for dos stub");
                    }
                }

                // Ensure `TooMuchData` error happens on 16-bit platforms
                #[cfg(target_pointer_width = "16")]
                Err(Error::TooMuchData) => {
                    kani::cover!(true, "TooMuchData (16bit)");
                }

                // Ensure `TooMuchData` error doesn't happen on larger platforms
                #[cfg(not(target_pointer_width = "16"))]
                Err(Error::TooMuchData) => {
                    kani::cover!(false, "TooMuchData (not 16bit)");
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
