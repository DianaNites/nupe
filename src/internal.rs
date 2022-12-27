//! Internal traits and utilities
use core::{fmt, mem::MaybeUninit};

/// Helper trait providing an interface to I/O in both no_std and std
pub trait PeWrite {
    /// Error type returned by this trait
    type Error: fmt::Debug + fmt::Display;

    /// Write all bytes in `buf`, or return an error.
    ///
    /// Behavior on errors is implementation defined
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

/// Blanket impl for `&mut CpioWrite`
impl<'a, T: PeWrite> PeWrite for &'a mut T {
    type Error = T::Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        (*self).write_all(buf)
    }
}

/// Helper trait providing an interface to I/O in both no_std and std
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
impl<'a, T: PeRead> PeRead for &'a mut T {
    type Error = T::Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        (*self).read_exact(buf)
    }
}

/// Blanket impl for `&mut &[u8]`
impl PeRead for &[u8] {
    type Error = &'static str;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        let sub = self.get(..buf.len()).ok_or("Too big")?;
        buf.copy_from_slice(sub);
        *self = &self[buf.len()..];
        Ok(())
    }
}
