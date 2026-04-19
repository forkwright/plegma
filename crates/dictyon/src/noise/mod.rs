//! Noise IK handshake for the Tailscale control protocol.
//!
//! Implements `Noise_IK_25519_ChaChaPoly_BLAKE2s` using the `snow` crate.
//! The IK pattern means the client (initiator) knows the server's static
//! public key in advance (fetched via `/key?v=N`). The client's static key
//! (machine key) is encrypted and sent to the server during the handshake.
//!
//! # Protocol framing
//!
//! - Initiation message: `[2B version][1B type=0x01][2B payload_len][noise_msg]`
//! - Response message: `[1B type=0x02][2B payload_len][noise_msg]`
//! - Post-handshake transport frames: `[1B type=0x04][2B BE length][ciphertext]`
//!
//! See `control/controlbase/` in the Tailscale Go source for reference.

use hamma_core::config::NoiseConfig;
use hamma_core::keys::{MachinePrivate, MachinePublic};
use snafu::Snafu;
use snow::{Builder, HandshakeState, TransportState};

// ---------------------------------------------------------------------------
// Protocol-fixed constants (NOT parameterizable)
// ---------------------------------------------------------------------------
//
// Each constant below is a wire-format or cryptographic invariant: changing
// it is a protocol break, not a tuning operation. They stay `const` at the
// module scope so the boundary between "what the peer expects" and "what
// the operator may tune" is syntactically obvious.

/// Noise protocol parameters for the Tailscale control plane.
///
/// Cryptographic invariant: changing this changes the handshake algorithm
/// and breaks wire compatibility with every peer. Do not parameterize.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Current protocol version for the Noise handshake.
///
/// Wire-format invariant: peers key their prologue off this value.
const PROTOCOL_VERSION: u16 = 1;

/// Message type for the initiator's first message.
const MSG_TYPE_INITIATION: u8 = 0x01;

/// Message type for the responder's reply.
const MSG_TYPE_RESPONSE: u8 = 0x02;

/// Message type for post-handshake transport frames.
const MSG_TYPE_TRANSPORT: u8 = 0x04;

/// Poly1305 tag length added by AEAD encryption.
///
/// Cryptographic invariant of ChaCha20-Poly1305. Do not parameterize.
const TAG_LEN: usize = 16;

// Tuning knobs (payload size, scratch-buffer size) live on
// [`hamma_core::config::NoiseConfig`]. See [`NoiseHandshake::with_config`]
// and [`NoiseTransport::encrypt`] for consumption.

/// Prologue mixed into the handshake hash, binding the session to the
/// Tailscale control protocol and its version.
fn prologue() -> Vec<u8> {
    format!("Tailscale Control Protocol v{PROTOCOL_VERSION}").into_bytes()
}

/// Errors that can occur during the Noise handshake or transport.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum NoiseError {
    /// The Noise handshake failed.
    #[snafu(display("noise handshake failed: {message}"))]
    HandshakeFailed {
        /// Description of the failure.
        message: String,
    },

    /// Decryption of a transport message failed.
    #[snafu(display("decryption failed: {message}"))]
    DecryptionFailed {
        /// Description of the failure.
        message: String,
    },

    /// Operation attempted in an invalid state (e.g., encrypting before
    /// the handshake is complete).
    #[snafu(display("invalid state: {message}"))]
    InvalidState {
        /// Description of the invalid state.
        message: String,
    },

    /// An error from the underlying `snow` library.
    #[snafu(display("snow error: {source}"))]
    Snow {
        /// The underlying snow error.
        source: snow::Error,
    },
}

impl From<snow::Error> for NoiseError {
    fn from(source: snow::Error) -> Self {
        Self::Snow { source }
    }
}

/// Drives the Noise IK handshake from the client (initiator) side.
///
/// Usage:
/// 1. Create with [`NoiseHandshake::new`].
/// 2. Call [`initiation_message`](NoiseHandshake::initiation_message) to get
///    the bytes for the `X-Tailscale-Handshake` header.
/// 3. Send the HTTP upgrade request.
/// 4. Call [`process_response`](NoiseHandshake::process_response) with the
///    server's response to complete the handshake.
pub struct NoiseHandshake {
    state: HandshakePhase,
    config: NoiseConfig,
}

/// Internal state machine for the handshake.
enum HandshakePhase {
    /// Ready to generate the initiation message.
    Ready {
        machine_key: MachinePrivate,
        server_public: MachinePublic,
    },
    /// Initiation sent, waiting for the response.
    AwaitingResponse { handshake: Box<HandshakeState> },
    /// Handshake consumed (moved into transport).
    Completed,
}

impl NoiseHandshake {
    /// Create a new handshake initiator.
    ///
    /// # Arguments
    ///
    /// * `machine_key` - The client's machine identity key.
    /// * `server_public` - The server's static public key (from `/key?v=N`).
    pub fn new(machine_key: MachinePrivate, server_public: MachinePublic) -> Self {
        Self::with_config(machine_key, server_public, NoiseConfig::default())
    }

    /// Create a new handshake initiator with a custom [`NoiseConfig`].
    ///
    /// # Arguments
    ///
    /// * `machine_key` - The client's machine identity key.
    /// * `server_public` - The server's static public key (from `/key?v=N`).
    /// * `config` - Framing tuning knobs (scratch buffer sizes, payload cap).
    pub fn with_config(
        machine_key: MachinePrivate,
        server_public: MachinePublic,
        config: NoiseConfig,
    ) -> Self {
        Self {
            state: HandshakePhase::Ready {
                machine_key,
                server_public,
            },
            config,
        }
    }

    /// Generate the initiator message (Noise IK pattern, message 1).
    ///
    /// Returns the framed initiation message bytes suitable for base64
    /// encoding into the `X-Tailscale-Handshake` header value.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidState`] if called more than once, or
    /// [`NoiseError::Snow`] if the snow library fails.
    pub fn initiation_message(&mut self) -> Result<Vec<u8>, NoiseError> {
        let (machine_key, server_public) =
            match core::mem::replace(&mut self.state, HandshakePhase::Completed) {
                HandshakePhase::Ready {
                    machine_key,
                    server_public,
                } => (machine_key, server_public),
                HandshakePhase::AwaitingResponse { .. } | HandshakePhase::Completed => {
                    return Err(NoiseError::InvalidState {
                        message: "initiation already generated".into(),
                    });
                }
            };

        let params = NOISE_PARAMS.parse().map_err(NoiseError::from)?;
        let prologue = prologue();

        let mut handshake = Builder::new(params)
            .local_private_key(machine_key.as_bytes())?
            .remote_public_key(server_public.as_bytes())?
            .prologue(&prologue)?
            .build_initiator()?;

        // IK message 1: e, es, s, ss
        // snow needs a buffer large enough for the handshake message.
        // IK msg1 = 32 (ephemeral pub) + 32 (static pub encrypted) + 16 (tag) + 16 (empty payload tag) = 96.
        // Scratch buffer size is a tuning knob -- see NoiseConfig::handshake_scratch_bytes.
        let mut noise_msg = vec![0u8; self.config.handshake_scratch_bytes];
        let noise_len = handshake.write_message(&[], &mut noise_msg)?;
        noise_msg.truncate(noise_len);

        // Frame: [2B version LE][1B msg_type][2B payload_len BE][noise_msg]
        let payload_len = u16::try_from(noise_len).map_err(|_| NoiseError::HandshakeFailed {
            message: "initiation message too large".into(),
        })?;

        let mut framed = Vec::with_capacity(5 + noise_len);
        framed.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        framed.push(MSG_TYPE_INITIATION);
        framed.extend_from_slice(&payload_len.to_be_bytes());
        framed.extend_from_slice(&noise_msg);

        self.state = HandshakePhase::AwaitingResponse {
            handshake: Box::new(handshake),
        };

        Ok(framed)
    }

    /// Process the responder message (Noise IK pattern, message 2) and
    /// complete the handshake.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::InvalidState`] if called before
    /// [`initiation_message`](NoiseHandshake::initiation_message), or
    /// [`NoiseError::Snow`] / [`NoiseError::HandshakeFailed`] if the
    /// response is invalid.
    pub fn process_response(mut self, response: &[u8]) -> Result<NoiseTransport, NoiseError> {
        let config = self.config.clone();
        let mut handshake = match core::mem::replace(&mut self.state, HandshakePhase::Completed) {
            HandshakePhase::AwaitingResponse { handshake } => *handshake,
            HandshakePhase::Ready { .. } => {
                return Err(NoiseError::InvalidState {
                    message: "initiation not yet sent".into(),
                });
            }
            HandshakePhase::Completed => {
                return Err(NoiseError::InvalidState {
                    message: "handshake already completed".into(),
                });
            }
        };

        // Parse framed response: [1B msg_type][2B payload_len BE][noise_msg]
        let header: [u8; 3] = response
            .get(..3)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| NoiseError::HandshakeFailed {
                message: "response too short".into(),
            })?;

        let [msg_type, len_hi, len_lo] = header;
        if msg_type != MSG_TYPE_RESPONSE {
            return Err(NoiseError::HandshakeFailed {
                message: format!("unexpected message type: 0x{msg_type:02x}"),
            });
        }

        let payload_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        let noise_msg =
            response
                .get(3..3 + payload_len)
                .ok_or_else(|| NoiseError::HandshakeFailed {
                    message: "response payload truncated".into(),
                })?;

        // IK message 2: e, ee, se
        // Scratch buffer size is a tuning knob -- see NoiseConfig::handshake_scratch_bytes.
        let mut payload_buf = vec![0u8; config.handshake_scratch_bytes];
        let _payload_len = handshake.read_message(noise_msg, &mut payload_buf)?;

        let transport = handshake.into_transport_mode()?;

        Ok(NoiseTransport { transport, config })
    }
}

/// Established Noise transport -- encrypts/decrypts control protocol messages.
///
/// Created after a successful [`NoiseHandshake`]. All messages are framed as
/// `[1B type=0x04][2B BE length][ciphertext]`.
pub struct NoiseTransport {
    transport: TransportState,
    config: NoiseConfig,
}

impl NoiseTransport {
    /// Encrypt a plaintext message for sending to the server.
    ///
    /// Returns the Noise transport frame: `[1B type][2B BE len][ciphertext]`.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::HandshakeFailed`] if the plaintext exceeds
    /// the maximum frame payload size, or [`NoiseError::Snow`] on
    /// encryption failure.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let max_payload = self.config.max_frame_payload;
        if plaintext.len() > max_payload {
            return Err(NoiseError::HandshakeFailed {
                message: format!("payload too large: {} > {max_payload}", plaintext.len()),
            });
        }

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let ct_len = self.transport.write_message(plaintext, &mut ciphertext)?;
        ciphertext.truncate(ct_len);

        let frame_len = u16::try_from(ct_len).map_err(|_| NoiseError::HandshakeFailed {
            message: "ciphertext too large for frame".into(),
        })?;

        let mut frame = Vec::with_capacity(3 + ct_len);
        frame.push(MSG_TYPE_TRANSPORT);
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }

    /// Decrypt a ciphertext message received from the server.
    ///
    /// Expects raw ciphertext bytes (without the frame header -- the caller
    /// is responsible for stripping the `[1B type][2B len]` prefix).
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::DecryptionFailed`] or [`NoiseError::Snow`]
    /// if decryption fails.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() < TAG_LEN {
            return Err(NoiseError::DecryptionFailed {
                message: "ciphertext too short for authentication tag".into(),
            });
        }

        let mut plaintext = vec![0u8; ciphertext.len()];
        let pt_len = self
            .transport
            .read_message(ciphertext, &mut plaintext)
            .map_err(|e| NoiseError::DecryptionFailed {
                message: format!("{e}"),
            })?;
        plaintext.truncate(pt_len);

        Ok(plaintext)
    }

    /// Create a `NoiseTransport` directly from a `snow::TransportState`.
    ///
    /// This is exposed for testing -- production code should go through
    /// [`NoiseHandshake`].
    ///
    /// # Note
    ///
    /// This function is intended for test helpers that need to construct a
    /// paired transport state without going through the full handshake flow.
    #[doc(hidden)]
    pub fn from_snow(transport: TransportState) -> Self {
        Self {
            transport,
            config: NoiseConfig::default(),
        }
    }

    /// Construct a [`NoiseTransport`] from a raw `snow::TransportState` with
    /// a custom [`NoiseConfig`].
    ///
    /// Exposed for tests that need to exercise non-default framing limits
    /// without running the full handshake.
    #[doc(hidden)]
    pub fn from_snow_with_config(transport: TransportState, config: NoiseConfig) -> Self {
        Self { transport, config }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
