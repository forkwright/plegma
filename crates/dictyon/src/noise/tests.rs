//! Unit and property tests for the Noise handshake and transport.
//!
//! Split into a sibling file because mod.rs + tests exceeded the
//! `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use hamma_core::config::DEFAULT_MAX_FRAME_PAYLOAD;

use super::*;

/// Legacy alias for the default max-frame-payload; kept local to the test
/// module so existing test bodies stay readable without re-importing the
/// full `NoiseConfig` default path at every use site.
const MAX_FRAME_PAYLOAD: usize = DEFAULT_MAX_FRAME_PAYLOAD;

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

// -----------------------------------------------------------------------
// New comprehensive crypto-validation tests
// -----------------------------------------------------------------------

/// Full IK round-trip using the public `NoiseHandshake` API on the
/// initiator side and a raw `snow` responder on the server side.
#[test]
fn handshake_full_ik_round_trip() {
    let machine_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    // --- Initiator: generate msg1 via NoiseHandshake ---
    let mut handshake = NoiseHandshake::new(machine_key, server_pub);
    let init_frame = handshake
        .initiation_message()
        .expect("initiation should succeed");

    // Extract noise payload from frame: [2B version][1B type][2B BE len][noise...]
    let payload_len = u16::from_be_bytes([init_frame[3], init_frame[4]]) as usize;
    let noise_init = &init_frame[5..5 + payload_len];

    // --- Responder: process msg1, generate msg2 ---
    let mut responder =
        build_responder(server_key.as_bytes()).expect("responder build should succeed");

    let mut payload_buf = vec![0u8; 256];
    responder
        .read_message(noise_init, &mut payload_buf)
        .expect("responder should read msg1");

    let mut resp_noise = vec![0u8; 256];
    let resp_noise_len = responder
        .write_message(&[], &mut resp_noise)
        .expect("responder should write msg2");

    // Frame the response: [1B type][2B BE len][noise...]
    let mut framed_resp = Vec::new();
    framed_resp.push(MSG_TYPE_RESPONSE);
    framed_resp.extend_from_slice(
        &u16::try_from(resp_noise_len)
            .expect("fits u16")
            .to_be_bytes(),
    );
    framed_resp.extend_from_slice(&resp_noise[..resp_noise_len]);

    // --- Initiator: complete handshake ---
    let mut client_transport = handshake
        .process_response(&framed_resp)
        .expect("handshake completion should succeed");

    // --- Both sides now have transport; verify they can communicate ---
    let mut server_transport = NoiseTransport::from_snow(
        responder
            .into_transport_mode()
            .expect("responder into transport"),
    );

    let plaintext = b"round-trip verified";
    let frame = client_transport
        .encrypt(plaintext)
        .expect("client encrypt should succeed");
    let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let decrypted = server_transport
        .decrypt(&frame[3..3 + ct_len])
        .expect("server decrypt should succeed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

/// After handshake both directions encrypt and decrypt correctly.
#[test]
fn transport_encrypt_decrypt_round_trip() {
    let (mut client, mut server) = paired_transports();

    // Client → Server
    let plaintext_cs = b"hello world";
    let frame_cs = client.encrypt(plaintext_cs).expect("client encrypt");
    let ct_len_cs = u16::from_be_bytes([frame_cs[1], frame_cs[2]]) as usize;
    let decrypted_cs = server
        .decrypt(&frame_cs[3..3 + ct_len_cs])
        .expect("server decrypt");
    assert_eq!(decrypted_cs.as_slice(), plaintext_cs);

    // Server → Client
    let plaintext_sc = b"goodbye";
    let frame_sc = server.encrypt(plaintext_sc).expect("server encrypt");
    let ct_len_sc = u16::from_be_bytes([frame_sc[1], frame_sc[2]]) as usize;
    let decrypted_sc = client
        .decrypt(&frame_sc[3..3 + ct_len_sc])
        .expect("client decrypt");
    assert_eq!(decrypted_sc.as_slice(), plaintext_sc);
}

/// Handshake with a mismatched server key must fail or produce
/// undecryptable output.
#[test]
fn transport_decrypt_with_wrong_key_fails() {
    let (mut client, _correct_server) = paired_transports();

    let frame = client.encrypt(b"secret").expect("encrypt should succeed");
    let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let ciphertext = &frame[3..3 + ct_len];

    // Build a completely independent session (different keys)
    let (_other_client, mut wrong_server) = paired_transports();

    let result = wrong_server.decrypt(ciphertext);
    assert!(result.is_err(), "decrypting with wrong key must fail");
}

/// Exact byte layout of the initiation frame.
#[test]
fn initiation_frame_has_correct_structure() {
    let machine_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let mut handshake = NoiseHandshake::new(machine_key, server_pub);
    let frame = handshake
        .initiation_message()
        .expect("initiation should succeed");

    // Bytes 0-1: version LE u16 = 1
    let version = u16::from_le_bytes([frame[0], frame[1]]);
    assert_eq!(version, 1, "version should be 1");

    // Byte 2: type = 0x01
    assert_eq!(frame[2], MSG_TYPE_INITIATION, "type byte should be 0x01");

    // Bytes 3-4: length BE u16
    let declared_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;

    // Remaining bytes: the noise message
    assert_eq!(
        frame.len(),
        5 + declared_len,
        "frame length should match 5-byte header + declared payload"
    );

    // IK msg1: 32 (e) + 32 (s encrypted) + 16 (tag) + 16 (empty payload tag) = 96 bytes
    assert_eq!(declared_len, 96, "IK msg1 noise payload should be 96 bytes");
}

/// A framed response with the wrong message type byte must be rejected.
#[test]
fn process_response_rejects_wrong_type_byte() {
    let machine_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let mut handshake = NoiseHandshake::new(machine_key, server_pub);
    handshake
        .initiation_message()
        .expect("initiation should succeed");

    // Frame with wrong type (0x03 instead of 0x02)
    let mut bad_frame = vec![0x03u8, 0x00, 0x20];
    bad_frame.extend_from_slice(&[0u8; 32]);
    let result = handshake.process_response(&bad_frame);
    assert!(result.is_err(), "wrong type byte must be rejected");
    let err_msg = result.err().map(|e| format!("{e}")).unwrap_or_default();
    assert!(
        err_msg.contains("0x03"),
        "error should name the unexpected byte: {err_msg}"
    );
}

/// A frame shorter than the 3-byte header must be rejected.
#[test]
fn process_response_rejects_truncated_frame() {
    let machine_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let mut handshake = NoiseHandshake::new(machine_key, server_pub);
    handshake
        .initiation_message()
        .expect("initiation should succeed");

    // Only 2 bytes — shorter than the 3-byte minimum header
    let truncated = vec![MSG_TYPE_RESPONSE, 0x00];
    let result = handshake.process_response(&truncated);
    assert!(result.is_err(), "truncated frame must be rejected");
}

/// Transport frame has the correct `[1B type][2B BE len][ciphertext]`
/// layout, and the ciphertext is `plaintext_len` + 16 (Poly1305 tag) bytes.
#[test]
fn transport_frame_has_correct_structure() {
    let (mut client, _server) = paired_transports();

    let plaintext = b"structure check";
    let frame = client.encrypt(plaintext).expect("encrypt should succeed");

    // Byte 0: type = 0x04
    assert_eq!(frame[0], MSG_TYPE_TRANSPORT, "type byte should be 0x04");

    // Bytes 1-2: length BE u16
    let declared_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    assert_eq!(
        frame.len(),
        3 + declared_len,
        "frame length should match 3-byte header + declared length"
    );

    // Ciphertext = plaintext + 16-byte Poly1305 tag
    assert_eq!(
        declared_len,
        plaintext.len() + TAG_LEN,
        "ciphertext should be plaintext + 16-byte tag"
    );
}

/// A 4096-byte payload (the maximum) encrypts without error.
#[test]
fn transport_max_payload_accepted() {
    let (mut client, mut server) = paired_transports();

    let plaintext = vec![0xABu8; MAX_FRAME_PAYLOAD];
    let frame = client
        .encrypt(&plaintext)
        .expect("max-size payload should encrypt successfully");

    let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let decrypted = server
        .decrypt(&frame[3..3 + ct_len])
        .expect("max-size payload should decrypt successfully");
    assert_eq!(decrypted, plaintext);
}

/// Empty plaintext round-trips through encrypt/decrypt without error.
#[test]
fn transport_empty_payload_round_trips() {
    let (mut client, mut server) = paired_transports();

    let frame = client
        .encrypt(&[])
        .expect("empty payload should encrypt successfully");

    // Frame should still have header + 16-byte auth tag
    assert_eq!(
        frame.len(),
        3 + TAG_LEN,
        "empty plaintext frame should be header + tag"
    );

    let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    let decrypted = server
        .decrypt(&frame[3..3 + ct_len])
        .expect("empty payload should decrypt successfully");
    assert!(
        decrypted.is_empty(),
        "decrypted empty payload should be empty"
    );
}

// -----------------------------------------------------------------------
// Property tests
// -----------------------------------------------------------------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

    /// Arbitrary byte payloads (0..=4096 bytes) survive an encrypt/decrypt
    /// round-trip through a freshly paired transport session.
    #[test]
    fn transport_payload_round_trips(
        payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=MAX_FRAME_PAYLOAD)
    ) {
        let (mut client, mut server) = paired_transports();

        let frame = client.encrypt(&payload).expect("encrypt should not fail for valid payload");

        assert_eq!(frame[0], MSG_TYPE_TRANSPORT);
        let ct_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let ciphertext = &frame[3..3 + ct_len];

        let decrypted = server.decrypt(ciphertext).expect("decrypt should succeed for client-encrypted payload");
        assert_eq!(decrypted, payload, "decrypted payload must equal original");
    }

    /// Payloads larger than MAX_FRAME_PAYLOAD must be rejected at encrypt time.
    #[test]
    fn transport_oversized_payload_rejected(
        extra in 1usize..=256usize
    ) {
        let (mut client, _server) = paired_transports();
        let oversized = vec![0xFFu8; MAX_FRAME_PAYLOAD + extra];
        let result = client.encrypt(&oversized);
        assert!(result.is_err(), "encrypt must fail for payloads exceeding MAX_FRAME_PAYLOAD");
    }
}

// -----------------------------------------------------------------------
// Config-driven behavior tests
// -----------------------------------------------------------------------

/// A non-default `NoiseConfig` must change observable behavior: tightening
/// `max_frame_payload` rejects a payload that the default would accept.
#[test]
fn noise_config_tightens_frame_payload_limit() {
    use hamma_core::config::NoiseConfig;

    // Size chosen to be well below the default (4 KiB) but above the
    // custom limit, so the same payload passes default and fails custom.
    let custom_limit = 128;
    let plaintext = vec![0xABu8; 256];

    // Baseline: default config accepts 256-byte payload.
    let (mut default_client, _) = paired_transports();
    default_client
        .encrypt(&plaintext)
        .expect("default config should accept 256-byte payload");

    // Custom: build a transport with a tightened limit and prove it rejects
    // the same payload. Re-using the paired_transports helper and then
    // swapping to a custom-config variant via from_snow_with_config keeps
    // the handshake plumbing reused.
    let (client_state, _server_state) = paired_snow_transports();
    let mut custom_cfg = NoiseConfig::default();
    custom_cfg.max_frame_payload = custom_limit;
    let mut custom_client = NoiseTransport::from_snow_with_config(client_state, custom_cfg);
    let result = custom_client.encrypt(&plaintext);
    assert!(
        result.is_err(),
        "custom config with max_frame_payload={custom_limit} must reject {}-byte payload",
        plaintext.len()
    );
}

// -----------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------

/// Helper: perform a full handshake and return paired raw snow transport
/// states. Lets callers wrap with whichever [`NoiseConfig`] they want to
/// exercise.
fn paired_snow_transports() -> (TransportState, TransportState) {
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

    let client_state = initiator
        .into_transport_mode()
        .expect("initiator transport");
    let server_state = responder
        .into_transport_mode()
        .expect("responder transport");

    (client_state, server_state)
}

/// Helper: perform a full handshake and return paired transport states
/// wrapped with default `NoiseConfig`.
fn paired_transports() -> (NoiseTransport, NoiseTransport) {
    let (client_state, server_state) = paired_snow_transports();
    (
        NoiseTransport::from_snow(client_state),
        NoiseTransport::from_snow(server_state),
    )
}
