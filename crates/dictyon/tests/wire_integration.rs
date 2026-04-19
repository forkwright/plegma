//! Integration tests for the wire layer with a mock TLS control server.
//!
//! These tests spin up a real TCP listener with TLS (self-signed cert
//! generated at test time via rcgen) and exercise the full protocol
//! flow: key fetch → Noise handshake → register → map.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use base64::Engine;
use hamma_core::keys::MachinePrivate;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use snow::Builder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Constants (must match dictyon's wire.rs)
// ---------------------------------------------------------------------------

const MSG_TYPE_INITIATION: u8 = 0x01;
const MSG_TYPE_RESPONSE: u8 = 0x02;
const MSG_TYPE_TRANSPORT: u8 = 0x04;
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_PROLOGUE: &[u8] = b"Tailscale Control Protocol v1";

// ---------------------------------------------------------------------------
// Test TLS helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed certificate for `127.0.0.1` and return:
/// - `(ServerConfig, ClientConfig)` pair where the client trusts the cert.
fn make_test_tls_pair() -> (rustls::ServerConfig, rustls::ClientConfig) {
    let cert_key = generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate_simple_self_signed should succeed");

    let cert_der: CertificateDer<'static> = CertificateDer::from(cert_key.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .expect("ServerConfig::with_single_cert should succeed");

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert_der)
        .expect("adding test cert to root store should succeed");

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, client_config)
}

// ---------------------------------------------------------------------------
// Mock server helpers
// ---------------------------------------------------------------------------

/// Read from `stream` byte by byte until `\r\n\r\n` is seen.
///
/// Returns the full buffer including the terminator.
async fn read_http_headers(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("read byte");
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        assert!(buf.len() <= 8192, "headers too large");
    }
    buf
}

/// Extract the value of an HTTP header from a raw header block.
fn extract_header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.lines() {
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix(": ") {
                return Some(value.trim());
            }
        }
    }
    None
}

/// Parse the Noise initiation message from the base64-encoded
/// `X-Tailscale-Handshake` header value.
///
/// Wire format: `[2B version LE][1B type=0x01][2B payload_len BE][noise_msg]`
fn decode_handshake_header(b64: &str) -> Vec<u8> {
    let framed = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("X-Tailscale-Handshake should be valid base64");
    assert!(framed.len() >= 5, "handshake too short");
    assert_eq!(framed[2], MSG_TYPE_INITIATION, "wrong message type");
    let noise_len = u16::from_be_bytes([framed[3], framed[4]]) as usize;
    framed[5..5 + noise_len].to_vec()
}

/// Frame a Noise response message as `[1B type=0x02][2B BE len][msg]`.
fn frame_noise_response(noise_msg: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(3 + noise_msg.len());
    framed.push(MSG_TYPE_RESPONSE);
    let len = u16::try_from(noise_msg.len()).expect("noise response fits u16");
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(noise_msg);
    framed
}

/// Read a single Noise transport frame from `stream`:
/// `[1B type=0x04][2B BE len][ciphertext]`.
async fn read_noise_frame(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut header = [0u8; 3];
    stream
        .read_exact(&mut header)
        .await
        .expect("read noise frame header");
    assert_eq!(header[0], MSG_TYPE_TRANSPORT, "expected transport frame");
    let body_len = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut ciphertext = vec![0u8; body_len];
    stream
        .read_exact(&mut ciphertext)
        .await
        .expect("read noise frame body");
    ciphertext
}

/// Write a Noise transport frame to `stream`.
async fn write_noise_frame(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    transport: &mut snow::TransportState,
    plaintext: &[u8],
) {
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let ct_len = transport
        .write_message(plaintext, &mut ciphertext)
        .expect("encrypt should succeed");
    ciphertext.truncate(ct_len);

    let len = u16::try_from(ct_len).expect("fits u16");
    let mut frame = Vec::with_capacity(3 + ct_len);
    frame.push(MSG_TYPE_TRANSPORT);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    stream.write_all(&frame).await.expect("write noise frame");
}

// ---------------------------------------------------------------------------
// Mock server: full protocol handler
// ---------------------------------------------------------------------------

/// State for the mock server across the two upgrade → register → map flow.
struct MockServerKeys {
    /// The server's Noise static private key (32 bytes, raw Curve25519).
    noise_private: [u8; 32],
}

impl MockServerKeys {
    fn generate() -> Self {
        let priv_key = MachinePrivate::generate();
        Self {
            noise_private: *priv_key.as_bytes(),
        }
    }

    fn public_hex(&self) -> String {
        let priv_key = MachinePrivate::from_bytes(self.noise_private);
        let pub_key = priv_key.public_key();
        pub_key.to_hex()
    }
}

/// Run the mock server's `/key` endpoint handler for one request.
///
/// Reads the GET request, responds with the server's Noise public key JSON,
/// then closes the connection.
async fn handle_key_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    keys: &MockServerKeys,
) {
    let headers = read_http_headers(stream).await;
    let header_str = std::str::from_utf8(&headers).expect("headers should be UTF-8");
    assert!(
        header_str.starts_with("GET /key"),
        "expected GET /key, got: {header_str}"
    );

    let pub_hex = keys.public_hex();
    let body = format!(r#"{{"PublicKey":"{pub_hex}"}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write key response");
    stream.shutdown().await.expect("shutdown key connection");
}

/// Run the mock server's `/ts2021` upgrade + Noise handshake handler.
///
/// Returns the paired `snow::TransportState` for subsequent message I/O.
async fn handle_noise_upgrade(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    keys: &MockServerKeys,
) -> snow::TransportState {
    // Read HTTP headers.
    let headers = read_http_headers(stream).await;
    let header_str = std::str::from_utf8(&headers).expect("headers should be UTF-8");
    assert!(
        header_str.contains("POST /ts2021"),
        "expected POST /ts2021: {header_str}"
    );

    // Extract the Noise initiation from the X-Tailscale-Handshake header.
    let handshake_b64 = extract_header(header_str, "X-Tailscale-Handshake")
        .expect("missing X-Tailscale-Handshake header");
    let noise_init = decode_handshake_header(handshake_b64);

    // Build Noise IK responder.
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("noise params");
    let mut responder = Builder::new(params)
        .local_private_key(&keys.noise_private)
        .expect("set local key")
        .prologue(NOISE_PROLOGUE)
        .expect("set prologue")
        .build_responder()
        .expect("build responder");

    // Process Noise msg1.
    let mut payload_buf = vec![0u8; 65535];
    responder
        .read_message(&noise_init, &mut payload_buf)
        .expect("responder read msg1");

    // Write Noise msg2.
    let mut noise_msg2 = vec![0u8; 65535];
    let msg2_len = responder
        .write_message(&[], &mut noise_msg2)
        .expect("responder write msg2");
    let framed_msg2 = frame_noise_response(&noise_msg2[..msg2_len]);

    // Send HTTP 101 with the Noise response in the body.
    let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: Upgrade\r\n\r\n";
    stream
        .write_all(response.as_bytes())
        .await
        .expect("write 101 response");
    stream
        .write_all(&framed_msg2)
        .await
        .expect("write noise msg2");
    stream.flush().await.expect("flush after handshake");

    responder
        .into_transport_mode()
        .expect("into_transport_mode")
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connects_and_completes_noise_handshake() {
    let (server_tls_cfg, client_tls_cfg) = make_test_tls_pair();
    let keys = Arc::new(MockServerKeys::generate());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));

    let keys_clone = Arc::clone(&keys);
    let server = tokio::spawn(async move {
        // Connection 1: key fetch.
        let (tcp1, _) = listener.accept().await.expect("accept key conn");
        let mut tls1 = acceptor.accept(tcp1).await.expect("tls accept key conn");
        handle_key_request(&mut tls1, &keys_clone).await;

        // Connection 2: Noise upgrade.
        let (tcp2, _) = listener.accept().await.expect("accept noise conn");
        let mut tls2 = acceptor.accept(tcp2).await.expect("tls accept noise conn");
        let _transport = handle_noise_upgrade(&mut tls2, &keys_clone).await;
        // Handshake complete — test just verifies connect() returns Ok.
    });

    let config = dictyon::wire::ControlConfig::new(
        format!("https://127.0.0.1:{}", addr.port()),
        MachinePrivate::generate(),
    );

    let result = dictyon::wire::connect_with_tls(&config, client_tls_cfg).await;
    assert!(result.is_ok(), "connect_with_tls should succeed");

    server.await.expect("mock server should not panic");
}

#[tokio::test]
async fn fetch_server_key_parses_response() {
    let (server_tls_cfg, client_tls_cfg) = make_test_tls_pair();
    let keys = Arc::new(MockServerKeys::generate());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));

    let pub_hex_expected = keys.public_hex();
    let keys_clone = Arc::clone(&keys);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
        handle_key_request(&mut tls, &keys_clone).await;
    });

    let url = format!("https://127.0.0.1:{}", addr.port());
    let server_key = dictyon::wire::fetch_server_key_with_tls(&url, client_tls_cfg)
        .await
        .expect("fetch_server_key_with_tls should succeed");

    assert_eq!(
        server_key.to_hex(),
        pub_hex_expected,
        "fetched key should match mock server's public key"
    );

    server.await.expect("mock server should not panic");
}

#[tokio::test]
async fn register_returns_authorized_with_preauth_key() {
    let (server_tls_cfg, client_tls_cfg) = make_test_tls_pair();
    let keys = Arc::new(MockServerKeys::generate());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));

    let keys_clone = Arc::clone(&keys);
    let server = tokio::spawn(async move {
        // Connection 1: key fetch.
        let (tcp1, _) = listener.accept().await.expect("accept key conn");
        let mut tls1 = acceptor.accept(tcp1).await.expect("tls accept key conn");
        handle_key_request(&mut tls1, &keys_clone).await;

        // Connection 2: Noise upgrade + register RPC.
        let (tcp2, _) = listener.accept().await.expect("accept noise conn");
        let mut tls2 = acceptor.accept(tcp2).await.expect("tls accept noise conn");
        let mut transport = handle_noise_upgrade(&mut tls2, &keys_clone).await;

        // Read one Noise transport frame (the register request).
        let ciphertext = read_noise_frame(&mut tls2).await;
        let mut plaintext_buf = vec![0u8; ciphertext.len()];
        let pt_len = transport
            .read_message(&ciphertext, &mut plaintext_buf)
            .expect("decrypt register request");
        let plaintext = &plaintext_buf[..pt_len];

        // Plaintext is [4B LE size][JSON RegisterRequest].
        assert!(plaintext.len() >= 4, "register frame too short");
        let payload_len =
            u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
        let json_payload = &plaintext[4..4 + payload_len];
        let req: serde_json::Value =
            serde_json::from_slice(json_payload).expect("register request should be valid JSON");
        assert!(
            req.get("NodeKey").is_some(),
            "register request missing NodeKey"
        );

        // Send register response: raw JSON as Noise plaintext (no LE-size framing).
        // The ControlClient's recv_message() decrypts the Noise frame and
        // passes the plaintext directly to serde_json::from_slice.
        let resp_json = br#"{"MachineAuthorized":true}"#;
        write_noise_frame(&mut tls2, &mut transport, resp_json).await;
        tls2.flush().await.expect("flush after register response");
    });

    let machine_key = MachinePrivate::generate();
    let node_key = hamma_core::keys::NodePrivate::generate();
    let disco_key = hamma_core::keys::DiscoPrivate::generate();

    let config = dictyon::wire::ControlConfig::new(
        format!("https://127.0.0.1:{}", addr.port()),
        MachinePrivate::from_bytes(*machine_key.as_bytes()),
    );

    let mut stream = dictyon::wire::connect_with_tls(&config, client_tls_cfg)
        .await
        .expect("connect should succeed");

    // Need a ControlConnection to build a ControlClient — use the helper
    // pattern from control.rs tests.
    let (conn, ()) = make_dummy_transport();
    let mut client = dictyon::control::ControlClient::new(conn, machine_key, node_key, disco_key);

    let outcome = client
        .register(&mut stream, Some("tskey-auth-test"))
        .await
        .expect("register should succeed");

    assert!(
        matches!(outcome, dictyon::control::RegisterOutcome::Authorized(_)),
        "expected Authorized outcome"
    );

    server.await.expect("mock server should not panic");
}

#[tokio::test]
async fn connection_to_unreachable_host_returns_error() {
    // Port 1 is reserved; connection should fail immediately.
    let config = dictyon::wire::ControlConfig::new(
        "https://127.0.0.1:1".to_string(),
        MachinePrivate::generate(),
    );

    // Use the default (webpki) TLS config — we expect a TCP connect failure
    // before TLS is even attempted.
    let result = dictyon::wire::connect(&config).await;
    assert!(
        result.is_err(),
        "connecting to port 1 should return an error"
    );
}

// ---------------------------------------------------------------------------
// Helpers shared across test cases
// ---------------------------------------------------------------------------

/// Build a dummy (but valid) `ControlConnection` for tests that need
/// a `ControlClient` but only use the stream-based API.
fn make_dummy_transport() -> (dictyon::transport::ControlConnection, ()) {
    let machine_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("params");

    let mut initiator = Builder::new(params)
        .local_private_key(machine_key.as_bytes())
        .expect("local_private_key")
        .remote_public_key(server_pub.as_bytes())
        .expect("remote_public_key")
        .prologue(NOISE_PROLOGUE)
        .expect("prologue")
        .build_initiator()
        .expect("build_initiator");

    let params2: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("params2");
    let mut responder = Builder::new(params2)
        .local_private_key(server_key.as_bytes())
        .expect("local_private_key")
        .prologue(NOISE_PROLOGUE)
        .expect("prologue")
        .build_responder()
        .expect("build_responder");

    let mut buf = vec![0u8; 65535];
    let mut payload = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).expect("write msg1");
    responder
        .read_message(&buf[..len], &mut payload)
        .expect("read msg1");
    let len = responder.write_message(&[], &mut buf).expect("write msg2");
    initiator
        .read_message(&buf[..len], &mut payload)
        .expect("read msg2");

    let client_noise = dictyon::noise::NoiseTransport::from_snow(
        initiator
            .into_transport_mode()
            .expect("initiator transport"),
    );
    let conn = dictyon::transport::ControlConnection::from_transport(client_noise);
    (conn, ())
}
