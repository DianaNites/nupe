//! Error types
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// NuPe Error type
#[derive(Debug)]
pub enum Error {
    InvalidDosMagic,
    InvalidPeMagic,
    NotEnoughData,
    MissingOpt,
    InvalidData,

    /// Tried to modify data that was immutable
    ImmutableData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDosMagic => write!(f, "invalid DOS magic"),
            Self::InvalidPeMagic => write!(f, "invalid PE magic"),
            Self::NotEnoughData => write!(f, "not enough data"),
            Self::MissingOpt => write!(f, "missing optional header"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::ImmutableData => write!(f, "immutable data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
