//! Error types
use core::{fmt, fmt::Write};
pub type Result<T> = core::result::Result<T, Error>;

/// NuPe Error type
#[derive(Debug)]
pub enum Error {
    InvalidDosMagic,
    InvalidPeMagic,
    NotEnoughData,
    MissingOpt,
    InvalidData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
