//! Internal traits and utilities
use alloc::vec::Vec;
use core::{
    fmt,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

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

/// Enum for a reference to a type, or owning it
#[derive(Debug, Clone, Copy)]
pub enum OwnedOrRef<'data, T> {
    Owned(T),
    Ref(&'data T),
}

impl<'data, T> Deref for OwnedOrRef<'data, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
    }
}

impl<'data, T> AsRef<T> for OwnedOrRef<'data, T> {
    fn as_ref(&self) -> &T {
        match self {
            OwnedOrRef::Owned(s) => s,
            OwnedOrRef::Ref(r) => r,
        }
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

/// Enum for a reference to a slice of type, or a vec of it
#[derive(Debug, Clone)]
pub enum VecOrSlice<'data, T> {
    Vec(Vec<T>),
    Slice(&'data [T]),
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
