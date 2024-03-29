//! Error types
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// NuPe Error type
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// Invalid Rich Header magic
    InvalidRichMagic,

    /// Invalid Rich Header Array Header magic
    InvalidRichArrayMagic,

    ///
    InvalidPeMagic,

    /// Expected more data than received
    NotEnoughData,

    MissingOpt,
    InvalidData,

    /// Invalid UTF-8 was encountered
    InvalidUtf8,

    /// The operation is unsupported
    Unsupported,

    /// Tried to modify data that was immutable
    ImmutableData,

    /// Too much data was provided and couldn't fit within the image
    TooMuchData,

    /// Not enough data, missing DOS header
    MissingDOS,

    /// Not enough data, missing rich header
    MissingRich,

    /// Not enough data, missing rich array
    MissingRichArray,

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
            Self::InvalidRichMagic => write!(f, "invalid rich header magic"),
            Self::InvalidRichArrayMagic => write!(f, "invalid rich header array header magic"),
            Self::InvalidPeMagic => write!(f, "invalid PE magic"),
            Self::NotEnoughData => write!(f, "not enough data, expected more than received"),
            Self::MissingOpt => write!(f, "missing optional header"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 was encountered"),
            Self::Unsupported => write!(f, "operation is unsupported"),
            Self::ImmutableData => write!(f, "tried to modify data that was immutable"),
            Self::TooMuchData => write!(f, "too much data was provided"),
            Self::MissingDOS => write!(f, "missing DOS header"),
            Self::MissingRich => write!(f, "missing rich header"),
            Self::MissingRichArray => write!(f, "missing rich array"),
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
