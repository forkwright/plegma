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
use hamma_core::config::{Config, WireConfig};
use hamma_core::keys::{KeyError, MachinePrivate, MachinePublic};
use rustls::ClientConfig;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::noise::NoiseHandshake;
use crate::transport::ControlConnection;

// ---------------------------------------------------------------------------
// Protocol-fixed constants (NOT parameterizable)
// ---------------------------------------------------------------------------
//
// The path, upgrade-header value, key-endpoint version, and frame-type byte
// are wire-contract values: changing any of them breaks compatibility with
// every tailscale-compatible control server. They stay `const` here so the
// intent is syntactically obvious.

/// Noise upgrade path (Tailscale ts2021 wire contract).
const UPGRADE_PATH: &str = "/ts2021";

/// Key endpoint path. `v=71` is the wire version dictyon speaks; bumping
/// it is a protocol break, not a tuning operation.
const KEY_PATH: &str = "/key?v=71";

/// HTTP Upgrade header value for the Tailscale control protocol.
const UPGRADE_HEADER: &str = "tailscale-control-protocol";

/// Transport frame type byte for post-handshake messages.
const FRAME_TYPE_TRANSPORT: u8 = 0x04;

// Tuning knobs (max header bytes, read chunk size, buffer capacity hints)
// live on [`hamma_core::config::WireConfig`]. The free functions below
// accept a `&Config` or fall back to `Config::default()`.

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in the wire layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
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
    /// Behavioral tuning knobs (buffer sizes, timeouts, framing limits).
    ///
    /// Defaults to [`Config::default`]; override to expose operator-set or
    /// agent-queried values to the wire and Noise layers.
    pub config: Config,
}

impl ControlConfig {
    /// Build a [`ControlConfig`] with default tuning knobs.
    ///
    /// Equivalent to setting `config: Config::default()` in a struct literal
    /// and kept as the one-call-site constructor for callers that only care
    /// about URL + key.
    #[must_use]
    pub fn new(control_url: String, machine_key: MachinePrivate) -> Self {
        Self {
            control_url,
            machine_key,
            config: Config::default(),
        }
    }
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

        let [frame_type, len_hi, len_lo] = header;
        if frame_type != FRAME_TYPE_TRANSPORT {
            return Err(WireError::Frame {
                message: format!("unexpected frame type: 0x{frame_type:02x}"),
            });
        }

        let body_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
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
/// Uses [`WireConfig::default`] for buffer/limit knobs. For a caller-tuned
/// variant see [`fetch_server_key_with_config`].
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key(control_url: &str) -> Result<MachinePublic, WireError> {
    fetch_server_key_with_config(control_url, &WireConfig::default()).await
}

/// Fetch the control server's public machine key using a caller-supplied
/// [`WireConfig`] for I/O buffer/limit tuning.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_config(
    control_url: &str,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
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

    let response = read_full_response(&mut tls_stream, cfg).await?;
    parse_server_key_response(&response)
}

/// Connect to the control server, complete the Noise IK handshake, and
/// return an [`AsyncControlStream`] ready for control messages.
///
/// Uses the tuning knobs on `config.config`. Default-construct `ControlConfig`
/// with [`Config::default`] to match pre-config behavior.
///
/// # Errors
///
/// Returns [`WireError`] on any I/O, TLS, HTTP, or Noise failure.
pub async fn connect(config: &ControlConfig) -> Result<AsyncControlStream, WireError> {
    let server_key = fetch_server_key_with_config(&config.control_url, &config.config.wire).await?;
    connect_with_key(config, server_key).await
}

/// Connect with a custom [`ClientConfig`], bypassing the default webpki roots.
///
/// This is the same as [`connect`] but accepts a caller-supplied TLS
/// configuration. Intended for testing (custom CA) and environments where the
/// caller manages certificate trust.
///
/// # Errors
///
/// Returns [`WireError`] on any I/O, TLS, HTTP, or Noise failure.
pub async fn connect_with_tls(
    config: &ControlConfig,
    tls_config: ClientConfig,
) -> Result<AsyncControlStream, WireError> {
    let server_key = fetch_server_key_with_tls_and_config(
        &config.control_url,
        tls_config.clone(),
        &config.config.wire,
    )
    .await?;
    connect_with_key_and_tls(config, server_key, tls_config).await
}

/// Fetch the server key using a caller-supplied TLS config.
///
/// Uses [`WireConfig::default`] for buffer/limit knobs.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_tls(
    control_url: &str,
    tls_config: ClientConfig,
) -> Result<MachinePublic, WireError> {
    fetch_server_key_with_tls_and_config(control_url, tls_config, &WireConfig::default()).await
}

/// Fetch the server key using caller-supplied TLS config *and* wire-layer
/// tuning knobs.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_tls_and_config(
    control_url: &str,
    tls_config: ClientConfig,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
    let (host, port) = parse_host_port(control_url)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

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

    let response = read_full_response(&mut tls_stream, cfg).await?;
    parse_server_key_response(&response)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Inner connect, separated so tests can inject a server key.
async fn connect_with_key(
    config: &ControlConfig,
    server_key: MachinePublic,
) -> Result<AsyncControlStream, WireError> {
    connect_with_key_and_tls(config, server_key, build_tls_config()).await
}

/// Inner connect with caller-supplied TLS config and a pre-fetched server key.
async fn connect_with_key_and_tls(
    config: &ControlConfig,
    server_key: MachinePublic,
    tls_cfg: ClientConfig,
) -> Result<AsyncControlStream, WireError> {
    let (host, port) = parse_host_port(&config.control_url)?;
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

    // Build Noise initiation using the handshake/framing knobs.
    let machine_key_copy = MachinePrivate::from_bytes(*config.machine_key.as_bytes());
    let mut handshake =
        NoiseHandshake::with_config(machine_key_copy, server_key, config.config.noise.clone());
    let init_msg = handshake.initiation_message()?;
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // Send HTTP upgrade request.
    let request = build_upgrade_request(&host, &init_b64);
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    // Read HTTP headers; the Noise response frame follows in the stream.
    let (status_line, _) = read_upgrade_response(&mut tls_stream, &config.config.wire).await?;

    if !status_line.contains("101") {
        return Err(WireError::UnexpectedStatus { status_line });
    }

    // Read the Noise response frame from the stream.
    // Frame format: [1B type=0x02][2B BE payload_len][noise_msg]
    let noise_body = read_noise_response_frame(&mut tls_stream).await?;

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
///
/// Only `https://` URLs are accepted; plain HTTP is rejected because all
/// control-plane traffic carries credentials and must be TLS-wrapped.
fn parse_host_port(url: &str) -> Result<(String, u16), WireError> {
    let without_scheme = url
        .trim_end_matches('/')
        .strip_prefix("https://")
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
        let after = host_port
            .get(bracket_end + 1..)
            .ok_or_else(|| WireError::InvalidUrl {
                url: url.to_string(),
            })?;
        let host = host_port
            .get(..=bracket_end)
            .ok_or_else(|| WireError::InvalidUrl {
                url: url.to_string(),
            })?
            .to_string();
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

/// Read the Noise response frame from the stream after the HTTP 101 headers.
///
/// The server sends the Noise response frame directly in the stream after
/// `\r\n\r\n`. Frame format: `[1B type=0x02][2B BE payload_len][noise_msg]`.
/// Returns the full framed bytes for `NoiseHandshake::process_response`.
async fn read_noise_response_frame(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, WireError> {
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).await.context(TlsSnafu)?;

    let [_msg_type, len_hi, len_lo] = header;
    let payload_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    let mut noise_msg = vec![0u8; payload_len];
    stream.read_exact(&mut noise_msg).await.context(TlsSnafu)?;

    let mut framed = Vec::with_capacity(3 + payload_len);
    framed.extend_from_slice(&header);
    framed.extend_from_slice(&noise_msg);
    Ok(framed)
}

/// Read until `\r\n\r\n`, returning (`first_line`, `bytes_after_headers`).
async fn read_upgrade_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    cfg: &WireConfig,
) -> Result<(String, Vec<u8>), WireError> {
    let buf = read_until_header_end(stream, cfg).await?;

    // Split at the header terminator.
    let sep = b"\r\n\r\n";
    let sep_pos =
        buf.windows(4)
            .position(|w| w == sep)
            .ok_or_else(|| WireError::MalformedHeaders {
                message: "header terminator not found".to_string(),
            })?;

    let headers_bytes = buf
        .get(..sep_pos)
        .ok_or_else(|| WireError::MalformedHeaders {
            message: "header separator position out of bounds".to_string(),
        })?;
    let body = buf
        .get(sep_pos + 4..)
        .ok_or_else(|| WireError::MalformedHeaders {
            message: "header body position out of bounds".to_string(),
        })?
        .to_vec();

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
    cfg: &WireConfig,
) -> Result<Vec<u8>, WireError> {
    let max_header_bytes = cfg.max_header_bytes;
    let mut buf = Vec::with_capacity(cfg.header_read_initial_capacity);
    let mut byte = [0u8; 1];

    loop {
        stream.read_exact(&mut byte).await.context(TlsSnafu)?;
        buf.extend_from_slice(&byte);

        if buf.len() > max_header_bytes {
            return Err(WireError::MalformedHeaders {
                message: format!("headers exceeded {max_header_bytes} bytes"),
            });
        }

        // Check for \r\n\r\n
        if buf.len() >= 4
            && buf
                .get(buf.len() - 4..)
                .is_some_and(|tail| tail == b"\r\n\r\n")
        {
            break;
        }
    }

    Ok(buf)
}

/// Read the full HTTP/1.1 response body (for the /key endpoint).
async fn read_full_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    cfg: &WireConfig,
) -> Result<Vec<u8>, WireError> {
    let max_body = cfg.key_response_max_bytes();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; cfg.response_read_chunk_bytes];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let slice = chunk.get(..n).ok_or_else(|| WireError::KeyParse {
                    message: "read returned more bytes than buffer".to_string(),
                })?;
                buf.extend_from_slice(slice);
            }
            Err(e) => return Err(WireError::Tls { source: e }),
        }
        if buf.len() > max_body {
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
#[expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]
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
