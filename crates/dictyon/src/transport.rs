//! HTTP transport skeleton for the Tailscale control protocol.
//!
//! Implements the framing and encryption layer that wraps control plane
//! messages. The actual TCP I/O is deferred to a future milestone -- this
//! module provides the request construction, response parsing, and
//! encrypt/decrypt plumbing.
//!
//! # Protocol flow
//!
//! 1. Client sends `POST /ts2021` with `Upgrade: tailscale-control-protocol`
//!    and the Noise initiation in `X-Tailscale-Handshake` (base64).
//! 2. Server responds `101 Switching Protocols`.
//! 3. Client completes the Noise handshake.
//! 4. All subsequent messages are Noise-encrypted frames:
//!    `[1B type=0x04][2B BE length][ciphertext]`.

use base64::Engine;

use crate::noise::{NoiseError, NoiseHandshake, NoiseTransport};
use snafu::Snafu;

/// The HTTP upgrade path for the Tailscale Noise protocol.
const UPGRADE_PATH: &str = "/ts2021";

/// The HTTP `Upgrade` header value.
const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";

/// Errors specific to the control connection transport.
#[derive(Debug, Snafu)]
pub enum TransportError {
    /// A Noise-layer error occurred.
    #[snafu(display("noise error: {source}"))]
    Noise {
        /// The underlying Noise error.
        source: NoiseError,
    },

    /// The control URL was invalid.
    #[snafu(display("invalid control URL: {url}"))]
    InvalidUrl {
        /// The URL that failed validation.
        url: String,
    },
}

impl From<NoiseError> for TransportError {
    fn from(source: NoiseError) -> Self {
        Self::Noise { source }
    }
}

/// An established control connection with Noise encryption.
///
/// This is currently a skeleton -- it holds the [`NoiseTransport`] and
/// provides encrypt/decrypt operations, but does not own a TCP stream.
/// Actual I/O will be added in a future milestone using tokio.
pub struct ControlConnection {
    noise: NoiseTransport,
}

/// A prepared HTTP upgrade request for the `/ts2021` endpoint.
///
/// Contains the URL and headers needed to initiate the Noise handshake
/// over HTTP. The caller is responsible for sending this with an HTTP
/// client.
#[derive(Debug)]
pub struct UpgradeRequest {
    /// The full URL to POST to (e.g., `https://controlplane.tailscale.com/ts2021`).
    pub url: String,
    /// HTTP headers to include in the request.
    pub headers: Vec<(String, String)>,
}

impl ControlConnection {
    /// Create a `ControlConnection` directly from a [`NoiseTransport`].
    ///
    /// The caller is responsible for ensuring the transport has completed
    /// the Noise handshake. This is the constructor used after manually
    /// completing the handshake outside the HTTP upgrade flow.
    pub fn from_transport(noise: NoiseTransport) -> Self {
        Self { noise }
    }

    /// Build the HTTP upgrade request for `/ts2021`.
    ///
    /// Generates the Noise initiation message, base64-encodes it, and
    /// returns the URL and headers to send with an HTTP client.
    ///
    /// # Arguments
    ///
    /// * `handshake` - A mutable reference to the [`NoiseHandshake`] that
    ///   will generate the initiation message.
    /// * `control_url` - The base URL of the control server (e.g.,
    ///   `https://controlplane.tailscale.com`).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Noise`] if the Noise initiation fails,
    /// or [`TransportError::InvalidUrl`] if the control URL is empty.
    pub fn build_upgrade_request(
        handshake: &mut NoiseHandshake,
        control_url: &str,
    ) -> Result<UpgradeRequest, TransportError> {
        if control_url.is_empty() {
            return Err(TransportError::InvalidUrl {
                url: control_url.to_string(),
            });
        }

        let init_msg = handshake.initiation_message()?;

        let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

        let url = format!("{}{UPGRADE_PATH}", control_url.trim_end_matches('/'));

        let headers = vec![
            ("Upgrade".to_string(), UPGRADE_HEADER_VALUE.to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("X-Tailscale-Handshake".to_string(), init_b64),
        ];

        Ok(UpgradeRequest { url, headers })
    }

    /// Process the HTTP 101 response and complete the Noise handshake.
    ///
    /// # Arguments
    ///
    /// * `handshake` - The [`NoiseHandshake`] used to build the upgrade
    ///   request. Consumed to produce the transport.
    /// * `response_body` - The raw bytes of the server's Noise response
    ///   (from the HTTP 101 response body).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Noise`] if the handshake completion fails.
    pub fn complete_handshake(
        handshake: NoiseHandshake,
        response_body: &[u8],
    ) -> Result<Self, TransportError> {
        let noise = handshake.process_response(response_body)?;
        Ok(Self { noise })
    }

    /// Encrypt a control protocol message for sending to the server.
    ///
    /// Returns the Noise-framed ciphertext ready to write to the wire.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Noise`] if encryption fails.
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let frame = self.noise.encrypt(payload)?;
        Ok(frame)
    }

    /// Decrypt a control protocol message received from the server.
    ///
    /// Expects raw ciphertext bytes (without the frame header). The caller
    /// is responsible for reading the `[1B type][2B len]` frame header and
    /// extracting the ciphertext payload.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Noise`] if decryption fails.
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let plaintext = self.noise.decrypt(data)?;
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use plegma_core::keys::MachinePrivate;

    use super::*;

    #[test]
    fn build_upgrade_request_sets_correct_headers() {
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        let mut handshake = NoiseHandshake::new(machine_key, server_pub);
        let req = ControlConnection::build_upgrade_request(
            &mut handshake,
            "https://controlplane.tailscale.com",
        )
        .expect("build_upgrade_request should succeed");

        // URL should end with /ts2021
        assert!(
            req.url.ends_with("/ts2021"),
            "URL should end with /ts2021: {}",
            req.url
        );
        assert_eq!(req.url, "https://controlplane.tailscale.com/ts2021");

        // Check headers
        let header_map: std::collections::HashMap<&str, &str> = req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(
            header_map.get("Upgrade"),
            Some(&"tailscale-control-protocol")
        );
        assert_eq!(header_map.get("Connection"), Some(&"Upgrade"));
        assert!(
            header_map.contains_key("X-Tailscale-Handshake"),
            "should have X-Tailscale-Handshake header"
        );

        // Handshake value should be valid base64
        let handshake_b64 = header_map["X-Tailscale-Handshake"];
        assert!(!handshake_b64.is_empty(), "handshake should be non-empty");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(handshake_b64)
            .expect("handshake header should be valid base64");
        assert!(
            decoded.len() > 5,
            "decoded handshake should contain framed noise message"
        );
    }

    #[test]
    fn build_upgrade_request_strips_trailing_slash() {
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        let mut handshake = NoiseHandshake::new(machine_key, server_pub);
        let req = ControlConnection::build_upgrade_request(
            &mut handshake,
            "https://controlplane.tailscale.com/",
        )
        .expect("should succeed");

        assert_eq!(req.url, "https://controlplane.tailscale.com/ts2021");
    }

    #[test]
    fn send_encrypts_payload() {
        // Build a full handshake to get a working ControlConnection
        let machine_key = MachinePrivate::generate();
        let server_key = MachinePrivate::generate();
        let server_pub = server_key.public_key();

        // Do the handshake manually through snow
        let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("params should parse");
        let prologue_bytes = "Tailscale Control Protocol v1".as_bytes();

        let mut initiator = snow::Builder::new(params.clone())
            .local_private_key(machine_key.as_bytes())
            .expect("set key")
            .remote_public_key(server_pub.as_bytes())
            .expect("set remote key")
            .prologue(prologue_bytes)
            .expect("set prologue")
            .build_initiator()
            .expect("build initiator");

        let params2: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("params should parse");

        let mut responder = snow::Builder::new(params2)
            .local_private_key(server_key.as_bytes())
            .expect("set key")
            .prologue(prologue_bytes)
            .expect("set prologue")
            .build_responder()
            .expect("build responder");

        let mut buf = vec![0u8; 65535];
        let mut payload_buf = vec![0u8; 65535];

        let len = initiator.write_message(&[], &mut buf).expect("write msg1");
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .expect("read msg1");

        let len = responder.write_message(&[], &mut buf).expect("write msg2");
        initiator
            .read_message(&buf[..len], &mut payload_buf)
            .expect("read msg2");

        let client_transport = crate::noise::NoiseTransport::from_snow(
            initiator
                .into_transport_mode()
                .expect("initiator transport"),
        );

        let mut conn = ControlConnection {
            noise: client_transport,
        };

        let plaintext = b"test control message";
        let encrypted = conn.send(plaintext).expect("send should succeed");

        // Encrypted output should differ from plaintext
        assert_ne!(
            &encrypted[3..],
            plaintext,
            "encrypted payload should differ from plaintext"
        );
        // And should be longer (due to auth tag)
        assert!(
            encrypted.len() > plaintext.len(),
            "encrypted should be longer than plaintext"
        );
    }
}
