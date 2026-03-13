use std::io;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Io,
    Format,
    Crypto,
    Compression,
    Bounds,
    UnsupportedFeature,
    NotFound,
    InvalidInput,
}

#[derive(Debug, Error)]
pub enum StormError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid format: {0}")]
    Format(&'static str),

    #[error("invalid format: {message}")]
    FormatOwned { message: String },

    #[error("crypto error: {0}")]
    Crypto(&'static str),

    #[error("compression error: {0}")]
    Compression(&'static str),

    #[error("compression error: {message}")]
    CompressionOwned { message: String },

    #[error("out of bounds: {0}")]
    Bounds(&'static str),

    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}

impl StormError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            StormError::Io(_) => ErrorKind::Io,
            StormError::Format(_) | StormError::FormatOwned { .. } => ErrorKind::Format,
            StormError::Crypto(_) => ErrorKind::Crypto,
            StormError::Compression(_) | StormError::CompressionOwned { .. } => {
                ErrorKind::Compression
            }
            StormError::Bounds(_) => ErrorKind::Bounds,
            StormError::UnsupportedFeature(_) => ErrorKind::UnsupportedFeature,
            StormError::NotFound(_) => ErrorKind::NotFound,
            StormError::InvalidInput(_) => ErrorKind::InvalidInput,
        }
    }
}

pub type Result<T> = std::result::Result<T, StormError>;
