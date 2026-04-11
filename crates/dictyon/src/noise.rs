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

use plegma_core::keys::{MachinePrivate, MachinePublic};
use snafu::Snafu;
use snow::{Builder, HandshakeState, TransportState};

/// Noise protocol parameters for the Tailscale control plane.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Current protocol version for the Noise handshake.
const PROTOCOL_VERSION: u16 = 1;

/// Message type for the initiator's first message.
const MSG_TYPE_INITIATION: u8 = 0x01;

/// Message type for the responder's reply.
const MSG_TYPE_RESPONSE: u8 = 0x02;

/// Message type for post-handshake transport frames.
const MSG_TYPE_TRANSPORT: u8 = 0x04;

/// Maximum Noise transport frame payload size (before encryption).
const MAX_FRAME_PAYLOAD: usize = 4096;

/// Poly1305 tag length added by AEAD encryption.
const TAG_LEN: usize = 16;

/// Prologue mixed into the handshake hash, binding the session to the
/// Tailscale control protocol and its version.
fn prologue() -> Vec<u8> {
    format!("Tailscale Control Protocol v{PROTOCOL_VERSION}").into_bytes()
}

/// Errors that can occur during the Noise handshake or transport.
#[derive(Debug, Snafu)]
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
        Self {
            state: HandshakePhase::Ready {
                machine_key,
                server_public,
            },
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
        // IK msg1 = 32 (ephemeral pub) + 32 (static pub encrypted) + 16 (tag) + 16 (empty payload tag) = 96
        let mut noise_msg = vec![0u8; 256];
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
        if response.len() < 3 {
            return Err(NoiseError::HandshakeFailed {
                message: "response too short".into(),
            });
        }

        let msg_type = response[0];
        if msg_type != MSG_TYPE_RESPONSE {
            return Err(NoiseError::HandshakeFailed {
                message: format!("unexpected message type: 0x{msg_type:02x}"),
            });
        }

        let payload_len = u16::from_be_bytes([response[1], response[2]]) as usize;
        let noise_msg =
            response
                .get(3..3 + payload_len)
                .ok_or_else(|| NoiseError::HandshakeFailed {
                    message: "response payload truncated".into(),
                })?;

        // IK message 2: e, ee, se
        let mut payload_buf = vec![0u8; 256];
        let _payload_len = handshake.read_message(noise_msg, &mut payload_buf)?;

        let transport = handshake.into_transport_mode()?;

        Ok(NoiseTransport { transport })
    }
}

/// Established Noise transport -- encrypts/decrypts control protocol messages.
///
/// Created after a successful [`NoiseHandshake`]. All messages are framed as
/// `[1B type=0x04][2B BE length][ciphertext]`.
pub struct NoiseTransport {
    transport: TransportState,
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
        if plaintext.len() > MAX_FRAME_PAYLOAD {
            return Err(NoiseError::HandshakeFailed {
                message: format!(
                    "payload too large: {} > {MAX_FRAME_PAYLOAD}",
                    plaintext.len()
                ),
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
    #[cfg(test)]
    pub(crate) fn from_snow(transport: TransportState) -> Self {
        Self { transport }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper: build a snow responder for testing against our initiator.
    fn build_responder(server_private: &[u8; 32]) -> Result<HandshakeState, NoiseError> {
        let params = NOISE_PARAMS.parse().map_err(NoiseError::from)?;
        let prologue = prologue();
        let responder = Builder::new(params)
            .local_private_key(server_private)?
            .prologue(&prologue)?
            .build_responder()?;
        Ok(responder)
    }

    #[test]
    fn handshake_initiation_produces_message() {
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        let mut handshake = NoiseHandshake::new(machine_key, server_pub);
        let msg = handshake
            .initiation_message()
            .expect("initiation should succeed");

        // Framed message: 2B version + 1B type + 2B length + noise payload
        assert!(msg.len() > 5, "message should contain header + payload");

        // Check version (LE u16)
        assert_eq!(msg[0], 0x01); // version 1 low byte
        assert_eq!(msg[1], 0x00); // version 1 high byte

        // Check message type
        assert_eq!(msg[2], MSG_TYPE_INITIATION);
    }

    #[test]
    fn noise_ik_handshake_completes() {
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        // --- Initiator side ---
        let mut handshake = NoiseHandshake::new(machine_key, server_pub);
        let init_msg = handshake
            .initiation_message()
            .expect("initiation should succeed");

        // --- Responder side (simulated server) ---
        let mut responder =
            build_responder(server_key.as_bytes()).expect("responder build should succeed");

        // Strip our framing to get raw noise message
        let payload_len = u16::from_be_bytes([init_msg[3], init_msg[4]]) as usize;
        let noise_init = &init_msg[5..5 + payload_len];

        let mut payload_buf = vec![0u8; 256];
        let _pt_len = responder
            .read_message(noise_init, &mut payload_buf)
            .expect("responder should read msg1");

        // Responder writes msg2
        let mut resp_noise = vec![0u8; 256];
        let resp_noise_len = responder
            .write_message(&[], &mut resp_noise)
            .expect("responder should write msg2");

        // Frame the response: [1B type][2B BE len][noise_msg]
        let mut framed_resp = Vec::new();
        framed_resp.push(MSG_TYPE_RESPONSE);
        let len_be = u16::try_from(resp_noise_len)
            .expect("response length fits u16")
            .to_be_bytes();
        framed_resp.extend_from_slice(&len_be);
        framed_resp.extend_from_slice(&resp_noise[..resp_noise_len]);

        // --- Complete handshake on initiator ---
        let _transport = handshake
            .process_response(&framed_resp)
            .expect("handshake completion should succeed");
    }

    #[test]
    fn transport_encrypt_decrypt_round_trips() {
        // Do a full handshake to get paired transport states.
        let (mut client_transport, mut server_transport) = paired_transports();

        let plaintext = b"hello from the dictyon client";
        let frame = client_transport
            .encrypt(plaintext)
            .expect("encrypt should succeed");

        // Verify it's framed
        assert_eq!(frame[0], MSG_TYPE_TRANSPORT);

        // Strip frame header for decryption
        let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let ciphertext = &frame[3..3 + ct_len];

        let decrypted = server_transport
            .decrypt(ciphertext)
            .expect("decrypt should succeed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let (mut client_transport, _server_transport) = paired_transports();

        let plaintext = b"secret message";
        let frame = client_transport
            .encrypt(plaintext)
            .expect("encrypt should succeed");

        // Strip frame header
        let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let ciphertext = &frame[3..3 + ct_len];

        // Build a completely different transport (wrong keys)
        let (_other_client, mut other_server) = paired_transports();

        let result = other_server.decrypt(ciphertext);
        assert!(result.is_err(), "decrypting with wrong key should fail");
    }

    /// Helper: perform a full handshake and return paired transport states.
    fn paired_transports() -> (NoiseTransport, NoiseTransport) {
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        // Initiator
        let params = NOISE_PARAMS
            .parse::<snow::params::NoiseParams>()
            .expect("params should parse");
        let prologue_bytes = prologue();

        let mut initiator = Builder::new(params)
            .local_private_key(machine_key.as_bytes())
            .expect("local_private_key should succeed")
            .remote_public_key(server_pub.as_bytes())
            .expect("remote_public_key should succeed")
            .prologue(&prologue_bytes)
            .expect("prologue should succeed")
            .build_initiator()
            .expect("build_initiator should succeed");

        // Responder
        let params2 = NOISE_PARAMS
            .parse::<snow::params::NoiseParams>()
            .expect("params should parse");
        let mut responder = Builder::new(params2)
            .local_private_key(server_key.as_bytes())
            .expect("local_private_key should succeed")
            .prologue(&prologue_bytes)
            .expect("prologue should succeed")
            .build_responder()
            .expect("build_responder should succeed");

        let mut buf = vec![0u8; 65535];
        let mut payload = vec![0u8; 65535];

        // msg1: initiator -> responder
        let len = initiator.write_message(&[], &mut buf).expect("write msg1");
        responder
            .read_message(&buf[..len], &mut payload)
            .expect("read msg1");

        // msg2: responder -> initiator
        let len = responder.write_message(&[], &mut buf).expect("write msg2");
        initiator
            .read_message(&buf[..len], &mut payload)
            .expect("read msg2");

        let client = NoiseTransport::from_snow(
            initiator
                .into_transport_mode()
                .expect("initiator transport"),
        );
        let server = NoiseTransport::from_snow(
            responder
                .into_transport_mode()
                .expect("responder transport"),
        );

        (client, server)
    }
}
