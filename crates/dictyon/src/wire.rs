//! TCP/TLS connection and Noise handshake for the Tailscale control plane.
//!
//! This module owns the actual network I/O: it opens a TCP connection,
//! wraps it in TLS, performs the HTTP upgrade to switch the connection into
//! the Tailscale Noise protocol, and exposes an [`AsyncControlStream`] for
//! sending/receiving encrypted control messages.
//!
//! # Protocol flow
//!
//! 1. GET `{control_url}/key?v=71` → parse `{"PublicKey":"mkey:hex..."}` → [`MachinePublic`].
//! 2. TCP connect → TLS handshake.
//! 3. POST `/ts2021` with `Upgrade: tailscale-control-protocol` and
//!    `X-Tailscale-Handshake: base64(noise_initiation)`.
//! 4. Read HTTP 101 response headers.
//! 5. The bytes after the headers are the server's Noise response; complete
//!    the Noise IK handshake via [`ControlConnection::complete_handshake`].
//! 6. All subsequent I/O uses [`AsyncControlStream::send_message`] /
//!    [`AsyncControlStream::recv_message`].

use std::sync::Arc;

use base64::Engine;
use plegma_core::keys::{KeyError, MachinePrivate, MachinePublic};
use rustls::ClientConfig;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::noise::NoiseHandshake;
use crate::transport::ControlConnection;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Noise upgrade path.
const UPGRADE_PATH: &str = "/ts2021";

/// Key endpoint path (v=71 is the protocol version dictyon speaks).
const KEY_PATH: &str = "/key?v=71";

/// HTTP Upgrade header value for the Tailscale control protocol.
const UPGRADE_HEADER: &str = "tailscale-control-protocol";

/// Maximum HTTP response header block we'll buffer (8 KiB).
const MAX_HEADER_BYTES: usize = 8192;

/// Transport frame type byte for post-handshake messages.
const FRAME_TYPE_TRANSPORT: u8 = 0x04;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in the wire layer.
#[derive(Debug, Snafu)]
pub enum WireError {
    /// DNS resolution or TCP connect failed.
    #[snafu(display("TCP connect failed: {source}"))]
    TcpConnect {
        /// The I/O error.
        source: std::io::Error,
    },

    /// TLS handshake or I/O failed.
    #[snafu(display("TLS error: {source}"))]
    Tls {
        /// The I/O error.
        source: std::io::Error,
    },

    /// The control URL is missing a valid host.
    #[snafu(display("invalid control URL (no host): {url}"))]
    InvalidUrl {
        /// The bad URL.
        url: String,
    },

    /// The server returned a non-101 HTTP status.
    #[snafu(display("expected HTTP 101, got: {status_line}"))]
    UnexpectedStatus {
        /// First line of the HTTP response.
        status_line: String,
    },

    /// The HTTP response headers were malformed or truncated.
    #[snafu(display("malformed HTTP headers: {message}"))]
    MalformedHeaders {
        /// Description of the problem.
        message: String,
    },

    /// The `/key` response was not valid JSON or was missing the field.
    #[snafu(display("key endpoint parse error: {message}"))]
    KeyParse {
        /// Description of the problem.
        message: String,
    },

    /// The key returned by the server failed to parse.
    #[snafu(display("server key invalid: {source}"))]
    ServerKey {
        /// The key parse error.
        source: KeyError,
    },

    /// Noise handshake or transport encryption failed.
    #[snafu(display("noise error: {source}"))]
    Noise {
        /// The noise error.
        source: crate::noise::NoiseError,
    },

    /// A message frame was too short or malformed.
    #[snafu(display("frame error: {message}"))]
    Frame {
        /// Description of the problem.
        message: String,
    },
}

impl From<crate::noise::NoiseError> for WireError {
    fn from(source: crate::noise::NoiseError) -> Self {
        Self::Noise { source }
    }
}

// ---------------------------------------------------------------------------
// Public configuration type
// ---------------------------------------------------------------------------

/// Configuration for a control-plane connection.
pub struct ControlConfig {
    /// Base URL of the control server (e.g. `https://controlplane.tailscale.com`).
    pub control_url: String,
    /// This machine's private key.
    pub machine_key: MachinePrivate,
}

// ---------------------------------------------------------------------------
// AsyncControlStream
// ---------------------------------------------------------------------------

/// An established, Noise-encrypted control connection over TLS.
///
/// Obtain via [`connect`]. Use [`send_message`](Self::send_message) and
/// [`recv_message`](Self::recv_message) to exchange control-plane messages.
pub struct AsyncControlStream {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    conn: ControlConnection,
}

impl AsyncControlStream {
    /// Encrypt `payload` and write it to the TLS stream.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Noise`] if encryption fails, or
    /// [`WireError::Tls`] if the write fails.
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), WireError> {
        let frame = self.conn.send(payload).map_err(|e| WireError::Noise {
            source: match e {
                crate::transport::TransportError::Noise { source } => source,
                crate::transport::TransportError::InvalidUrl { url } => {
                    crate::noise::NoiseError::InvalidState { message: url }
                }
            },
        })?;
        self.stream.write_all(&frame).await.context(TlsSnafu)?;
        Ok(())
    }

    /// Read one Noise-framed message from the TLS stream and decrypt it.
    ///
    /// Frame format: `[1B type=0x04][2B BE len][ciphertext]`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Frame`] if the header is malformed,
    /// [`WireError::Noise`] if decryption fails, or [`WireError::Tls`]
    /// on I/O errors.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, WireError> {
        // Read 3-byte frame header.
        let mut header = [0u8; 3];
        self.stream
            .read_exact(&mut header)
            .await
            .context(TlsSnafu)?;

        if header[0] != FRAME_TYPE_TRANSPORT {
            return Err(WireError::Frame {
                message: format!("unexpected frame type: 0x{:02x}", header[0]),
            });
        }

        let body_len = u16::from_be_bytes([header[1], header[2]]) as usize;
        let mut ciphertext = vec![0u8; body_len];
        self.stream
            .read_exact(&mut ciphertext)
            .await
            .context(TlsSnafu)?;

        let plaintext = self
            .conn
            .receive(&ciphertext)
            .map_err(|e| WireError::Noise {
                source: match e {
                    crate::transport::TransportError::Noise { source } => source,
                    crate::transport::TransportError::InvalidUrl { url } => {
                        crate::noise::NoiseError::InvalidState { message: url }
                    }
                },
            })?;
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch the control server's public machine key from `GET /key?v=71`.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key(control_url: &str) -> Result<MachinePublic, WireError> {
    let (host, port) = parse_host_port(control_url)?;
    let tls = build_tls_config();
    let connector = TlsConnector::from(Arc::new(tls));

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.context(TcpConnectSnafu)?;

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|_| {
            WireError::InvalidUrl {
                url: control_url.to_string(),
            }
        })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context(TlsSnafu)?;

    let request = format!("GET {KEY_PATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    let response = read_full_response(&mut tls_stream).await?;
    parse_server_key_response(&response)
}

/// Connect to the control server, complete the Noise IK handshake, and
/// return an [`AsyncControlStream`] ready for control messages.
///
/// # Errors
///
/// Returns [`WireError`] on any I/O, TLS, HTTP, or Noise failure.
pub async fn connect(config: &ControlConfig) -> Result<AsyncControlStream, WireError> {
    let server_key = fetch_server_key(&config.control_url).await?;
    connect_with_key(config, server_key).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Inner connect, separated so tests can inject a server key.
async fn connect_with_key(
    config: &ControlConfig,
    server_key: MachinePublic,
) -> Result<AsyncControlStream, WireError> {
    let (host, port) = parse_host_port(&config.control_url)?;
    let tls_cfg = build_tls_config();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.context(TcpConnectSnafu)?;

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|_| {
            WireError::InvalidUrl {
                url: config.control_url.clone(),
            }
        })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context(TlsSnafu)?;

    // Build Noise initiation.
    let machine_key_copy = MachinePrivate::from_bytes(*config.machine_key.as_bytes());
    let mut handshake = NoiseHandshake::new(machine_key_copy, server_key);
    let init_msg = handshake.initiation_message()?;
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // Send HTTP upgrade request.
    let request = build_upgrade_request(&host, &init_b64);
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    // Read HTTP headers and collect leftover bytes (Noise response body).
    let (status_line, noise_body) = read_upgrade_response(&mut tls_stream).await?;

    if !status_line.contains("101") {
        return Err(WireError::UnexpectedStatus { status_line });
    }

    // Complete the Noise handshake.
    let conn = ControlConnection::complete_handshake(handshake, &noise_body).map_err(|e| {
        WireError::Noise {
            source: match e {
                crate::transport::TransportError::Noise { source } => source,
                crate::transport::TransportError::InvalidUrl { url } => {
                    crate::noise::NoiseError::InvalidState { message: url }
                }
            },
        }
    })?;

    Ok(AsyncControlStream {
        stream: tls_stream,
        conn,
    })
}

/// Build the TLS client config using the webpki root certificates.
fn build_tls_config() -> ClientConfig {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Extract the hostname and port from a URL like `https://host` or
/// `https://host:port`.
fn parse_host_port(url: &str) -> Result<(String, u16), WireError> {
    let without_scheme = url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| url.trim_end_matches('/').strip_prefix("http://"))
        .ok_or_else(|| WireError::InvalidUrl {
            url: url.to_string(),
        })?;

    // Strip any path component.
    let host_port = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| WireError::InvalidUrl {
            url: url.to_string(),
        })?;

    if let Some(bracket_end) = host_port.rfind(']') {
        // IPv6 address: `[::1]:443` or `[::1]`
        let after = &host_port[bracket_end + 1..];
        let host = host_port[..=bracket_end].to_string();
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str.parse::<u16>().map_err(|_| WireError::InvalidUrl {
                url: url.to_string(),
            })?
        } else {
            443
        };
        return Ok((host, port));
    }

    match host_port.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().map_err(|_| WireError::InvalidUrl {
                url: url.to_string(),
            })?;
            Ok((host.to_string(), port))
        }
        None => Ok((host_port.to_string(), 443)),
    }
}

/// Build the HTTP upgrade request string.
fn build_upgrade_request(host: &str, init_b64: &str) -> String {
    format!(
        "POST {UPGRADE_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_HEADER}\r\n\
         Connection: Upgrade\r\n\
         X-Tailscale-Handshake: {init_b64}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
}

/// Read until `\r\n\r\n`, returning (`first_line`, `bytes_after_headers`).
async fn read_upgrade_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(String, Vec<u8>), WireError> {
    let buf = read_until_header_end(stream).await?;

    // Split at the header terminator.
    let sep = b"\r\n\r\n";
    let sep_pos =
        buf.windows(4)
            .position(|w| w == sep)
            .ok_or_else(|| WireError::MalformedHeaders {
                message: "header terminator not found".to_string(),
            })?;

    let headers_bytes = &buf[..sep_pos];
    let body = buf[sep_pos + 4..].to_vec();

    let headers_str =
        std::str::from_utf8(headers_bytes).map_err(|_| WireError::MalformedHeaders {
            message: "headers are not valid UTF-8".to_string(),
        })?;

    let first_line = headers_str.lines().next().unwrap_or("").to_string();

    Ok((first_line, body))
}

/// Read from the stream until we see `\r\n\r\n` or hit the size limit.
async fn read_until_header_end(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    loop {
        stream.read_exact(&mut byte).await.context(TlsSnafu)?;
        buf.push(byte[0]);

        if buf.len() > MAX_HEADER_BYTES {
            return Err(WireError::MalformedHeaders {
                message: format!("headers exceeded {MAX_HEADER_BYTES} bytes"),
            });
        }

        // Check for \r\n\r\n
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }

    Ok(buf)
}

/// Read the full HTTP/1.1 response body (for the /key endpoint).
async fn read_full_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(WireError::Tls { source: e }),
        }
        if buf.len() > MAX_HEADER_BYTES * 4 {
            return Err(WireError::KeyParse {
                message: "response too large".to_string(),
            });
        }
    }
    Ok(buf)
}

/// Parse `{"PublicKey":"mkey:hex..."}` from the raw HTTP response bytes.
fn parse_server_key_response(response: &[u8]) -> Result<MachinePublic, WireError> {
    // Find the JSON body after the headers.
    let sep = b"\r\n\r\n";
    let body_start = response
        .windows(4)
        .position(|w| w == sep)
        .map_or(0, |p| p + 4);

    let body = &response[body_start..];
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| WireError::KeyParse {
            message: e.to_string(),
        })?;

    let key_str = json
        .get("PublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WireError::KeyParse {
            message: "missing 'PublicKey' field".to_string(),
        })?;

    MachinePublic::from_hex(key_str).context(ServerKeySnafu)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_https_default() {
        let (host, port) =
            parse_host_port("https://controlplane.tailscale.com").expect("should parse");
        assert_eq!(host, "controlplane.tailscale.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_with_explicit_port() {
        let (host, port) = parse_host_port("https://localhost:8443").expect("should parse");
        assert_eq!(host, "localhost");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_host_port_trailing_slash() {
        let (host, port) =
            parse_host_port("https://controlplane.tailscale.com/").expect("should parse");
        assert_eq!(host, "controlplane.tailscale.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn build_upgrade_request_contains_required_headers() {
        let req = build_upgrade_request("controlplane.tailscale.com", "base64data==");
        assert!(req.contains("POST /ts2021"), "should POST to /ts2021");
        assert!(req.contains("Upgrade: tailscale-control-protocol"));
        assert!(req.contains("X-Tailscale-Handshake: base64data=="));
    }

    #[test]
    fn parse_server_key_response_extracts_key() {
        // A known 32-byte all-zeros key in mkey: format.
        let hex = "0".repeat(64);
        let json_body = format!(r#"{{"PublicKey":"mkey:{hex}"}}"#);
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json_body}");

        let key = parse_server_key_response(response.as_bytes()).expect("should parse");
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn parse_server_key_response_missing_field_errors() {
        let response = b"HTTP/1.1 200 OK\r\n\r\n{}";
        let result = parse_server_key_response(response);
        assert!(result.is_err());
    }
}
