//! Top-level error type for the dictyon crate.
//!
//! [`DictyonError`] is a unified error that wraps all sub-layer errors:
//! wire I/O errors, control-protocol errors, and Noise handshake errors.
//! It is the error type returned by the public async API.

use snafu::Snafu;

use crate::control::ControlError;
use crate::noise::NoiseError;
use crate::wire::WireError;

/// Unified error for all dictyon operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum DictyonError {
    /// A wire-layer I/O or TLS error.
    #[snafu(display("wire error: {source}"))]
    Wire {
        /// The underlying wire error.
        source: WireError,
    },

    /// A control-protocol error.
    #[snafu(display("control error: {source}"))]
    Control {
        /// The underlying control error.
        source: ControlError,
    },

    /// A Noise handshake or transport error.
    #[snafu(display("noise error: {source}"))]
    Noise {
        /// The underlying noise error.
        source: NoiseError,
    },
}

impl From<WireError> for DictyonError {
    fn from(source: WireError) -> Self {
        Self::Wire { source }
    }
}

impl From<ControlError> for DictyonError {
    fn from(source: ControlError) -> Self {
        Self::Control { source }
    }
}

impl From<NoiseError> for DictyonError {
    fn from(source: NoiseError) -> Self {
        Self::Noise { source }
    }
}
