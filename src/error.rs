//! Error types
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// NuPe Error type
#[derive(Debug)]
pub enum Error {
    InvalidDosMagic,

    ///
    InvalidPeMagic,
    NotEnoughData,
    MissingOpt,
    InvalidData,

    /// The operation is unsupported
    Unsupported,

    /// Tried to modify data that was immutable
    ImmutableData,

    /// Too much data was provided and couldn't fit within the image
    TooMuchData,

    /// Not enough data, missing DOS header
    MissingDOS,

    /// Not enough data, missing PE header
    MissingPE,

    /// Not enough data, missing Exec Header
    MissingExecHeader,

    /// Missing the Section Table
    MissingSectionTable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDosMagic => write!(f, "invalid DOS magic"),
            Self::InvalidPeMagic => write!(f, "invalid PE magic"),
            Self::NotEnoughData => write!(f, "not enough data"),
            Self::MissingOpt => write!(f, "missing optional header"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::Unsupported => write!(f, "operation is unsupported"),
            Self::ImmutableData => write!(f, "immutable data"),
            Self::TooMuchData => write!(
                f,
                "too much data was provided and couldn't fit within the image"
            ),
            Self::MissingDOS => write!(f, "missing DOS header"),
            Self::MissingPE => write!(f, "missing PE header"),
            Self::MissingExecHeader => write!(f, "missing exec header"),
            Self::MissingSectionTable => write!(f, "missing section table"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
