//! Behavioral configuration for the hamma stack.
//!
//! Every field in [`Config`] is a **tuning knob** — a value that a reasonable
//! operator (or an agent, via aletheia's parameter registry, forkwright/hamma#7)
//! might want to change without recompiling. Values documented here match the
//! current hard-coded defaults; changing the default here changes the default
//! everywhere.
//!
//! # What is NOT here
//!
//! Cryptographic invariants (key lengths, AEAD tag sizes, Noise handshake
//! parameters) and protocol-fixed constants (message type bytes, HTTP upgrade
//! path, wire-format version numbers) are **not** exposed as config. Changing
//! them is a protocol-break, not a tuning operation, so they remain `const`
//! next to the code that relies on their immutability.
//!
//! # Discoverability
//!
//! The doc-comment on each field is the agent-facing description. It should
//! explain:
//! 1. What the value controls,
//! 2. The unit (bytes, count, ms, …),
//! 3. A reasonable range,
//! 4. What symptom would motivate changing it.
//!
//! # Extensibility
//!
//! [`Config`] and its nested sub-configs are marked `#[non_exhaustive]` so
//! adding new knobs is not a breaking change. Construct instances through the
//! `Default` impl (and then mutate fields) or by using [`serde`] to load from
//! a file.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
//
// Named constants so the defaults are inspectable from code and the comments
// double as the canonical rationale.

/// Default cap on HTTP response header block size (8 KiB).
///
/// Large enough for typical `GET /key` and `101 Switching Protocols`
/// responses, small enough to bound memory if the peer misbehaves.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;

/// Default cap on total `/key` response body size, expressed as a multiple
/// of the header cap. 4× the header cap accommodates large JSON responses
/// without permitting unbounded reads.
pub const DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER: usize = 4;

/// Default initial capacity for the header-scan buffer (512 bytes).
///
/// A single-hint allocation; the buffer grows as needed up to the cap.
pub const DEFAULT_HEADER_READ_INITIAL_CAPACITY: usize = 512;

/// Default read chunk size when draining an HTTP response body (4 KiB).
///
/// Matches a common page size and plays well with TLS record sizes.
pub const DEFAULT_RESPONSE_READ_CHUNK_BYTES: usize = 4096;

/// Default cap on a single Noise transport frame payload (4 KiB plaintext).
///
/// This bounds the size of a control-protocol message; larger messages must
/// be split by the caller. Must not exceed `u16::MAX - TAG_LEN` because the
/// wire framing uses a `u16` length.
pub const DEFAULT_MAX_FRAME_PAYLOAD: usize = 4096;

/// Default scratch-buffer size for serialising/deserialising Noise handshake
/// messages (256 bytes).
///
/// An IK `msg1`/`msg2` is ≤ 96 bytes; 256 gives headroom for payload-bearing
/// handshakes without over-allocating.
pub const DEFAULT_HANDSHAKE_SCRATCH_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// WireConfig
// ---------------------------------------------------------------------------

/// Tuning knobs for the wire layer (TCP/TLS/HTTP upgrade I/O).
///
/// Applies to [`dictyon::wire`](../../dictyon/wire/index.html) — the module
/// that owns raw socket I/O and the HTTP upgrade handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WireConfig {
    /// Maximum HTTP response header block we will buffer, in bytes.
    ///
    /// **Controls:** memory bound for header parsing; attacker-resilience.
    /// **Range:** `[1024, 65_536]` — below 1 KiB breaks legitimate control
    /// servers; above 64 KiB is wasted memory per connection.
    /// **Default:** 8 KiB. Raise if a control server sends very large
    /// header blocks (e.g. many cookies); lower to harden against abuse.
    pub max_header_bytes: usize,

    /// Multiplier applied to `max_header_bytes` to cap the total
    /// `/key` endpoint response size.
    ///
    /// **Controls:** upper bound on untrusted JSON body size before parse.
    /// **Range:** `[1, 16]`.
    /// **Default:** 4 (= 32 KiB at default header cap). Raise only if a
    /// control server ships a very large key-discovery JSON body.
    pub key_response_body_multiplier: usize,

    /// Initial capacity hint for the header-scan buffer, in bytes.
    ///
    /// **Controls:** number of allocations during header read on small
    /// responses. Does not cap size — that is `max_header_bytes`.
    /// **Range:** `[64, max_header_bytes]`.
    /// **Default:** 512.
    pub header_read_initial_capacity: usize,

    /// Chunk size for reads while draining an HTTP response body, in bytes.
    ///
    /// **Controls:** syscall/read granularity while collecting body bytes.
    /// **Range:** `[512, 65_536]`.
    /// **Default:** 4 KiB. Increase for high-throughput links; decrease for
    /// memory-constrained environments.
    pub response_read_chunk_bytes: usize,
}

impl Default for WireConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            key_response_body_multiplier: DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER,
            header_read_initial_capacity: DEFAULT_HEADER_READ_INITIAL_CAPACITY,
            response_read_chunk_bytes: DEFAULT_RESPONSE_READ_CHUNK_BYTES,
        }
    }
}

impl WireConfig {
    /// Return the maximum permitted `/key` response body size in bytes.
    ///
    /// Derived as `max_header_bytes * key_response_body_multiplier`.
    #[must_use]
    pub fn key_response_max_bytes(&self) -> usize {
        self.max_header_bytes
            .saturating_mul(self.key_response_body_multiplier)
    }
}

// ---------------------------------------------------------------------------
// NoiseConfig
// ---------------------------------------------------------------------------

/// Tuning knobs for the Noise transport framing layer.
///
/// These are **framing** limits, not cryptographic parameters. The Noise
/// pattern, AEAD tag length, and message-type bytes are protocol invariants
/// and remain `const` inside `dictyon::noise`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NoiseConfig {
    /// Maximum plaintext payload per Noise transport frame, in bytes.
    ///
    /// **Controls:** largest single control-plane message that can be sent
    /// without caller-side chunking.
    /// **Range:** `[256, 65_519]` — the wire format uses a `u16` length;
    /// the 16-byte Poly1305 tag is added on top, so the absolute ceiling is
    /// `u16::MAX - 16 = 65_519`.
    /// **Default:** 4 KiB — matches the reference implementation and most
    /// control-plane message sizes.
    pub max_frame_payload: usize,

    /// Scratch buffer size for Noise IK handshake serialisation, in bytes.
    ///
    /// **Controls:** size of the temporary buffer passed to `snow` during
    /// `write_message`/`read_message`. Must be ≥ the largest handshake
    /// message (≤ 96 bytes for IK without payload).
    /// **Range:** `[128, 4096]`.
    /// **Default:** 256 — leaves headroom for payload-bearing IK variants.
    pub handshake_scratch_bytes: usize,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            max_frame_payload: DEFAULT_MAX_FRAME_PAYLOAD,
            handshake_scratch_bytes: DEFAULT_HANDSHAKE_SCRATCH_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/// Top-level hamma configuration — a flat, persistable snapshot of every
/// behavioral tuning knob across the stack.
///
/// Construct via [`Config::default`] and mutate individual fields, or load
/// from TOML/JSON through [`serde`]. All sub-configs are independently
/// defaulted so partial construction is always valid.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    /// Wire-layer (TCP/TLS/HTTP) tuning knobs.
    pub wire: WireConfig,

    /// Noise transport framing knobs.
    pub noise: NoiseConfig,
}

impl Config {
    /// Construct a new [`Config`] with all defaults.
    ///
    /// Equivalent to [`Config::default`], provided for fluent call sites.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
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
    fn default_values_match_documented_constants() {
        let c = Config::default();
        assert_eq!(c.wire.max_header_bytes, DEFAULT_MAX_HEADER_BYTES);
        assert_eq!(
            c.wire.key_response_body_multiplier,
            DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER
        );
        assert_eq!(
            c.wire.header_read_initial_capacity,
            DEFAULT_HEADER_READ_INITIAL_CAPACITY
        );
        assert_eq!(
            c.wire.response_read_chunk_bytes,
            DEFAULT_RESPONSE_READ_CHUNK_BYTES
        );
        assert_eq!(c.noise.max_frame_payload, DEFAULT_MAX_FRAME_PAYLOAD);
        assert_eq!(
            c.noise.handshake_scratch_bytes,
            DEFAULT_HANDSHAKE_SCRATCH_BYTES
        );
    }

    #[test]
    fn key_response_max_bytes_is_derived() {
        let c = WireConfig::default();
        assert_eq!(
            c.key_response_max_bytes(),
            DEFAULT_MAX_HEADER_BYTES * DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER
        );
    }

    #[test]
    fn key_response_max_bytes_saturates_on_overflow() {
        let c = WireConfig {
            max_header_bytes: usize::MAX,
            key_response_body_multiplier: 4,
            ..Default::default()
        };
        // Saturating multiplication must not panic.
        assert_eq!(c.key_response_max_bytes(), usize::MAX);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let original = Config {
            wire: WireConfig {
                max_header_bytes: 16_384,
                key_response_body_multiplier: 2,
                header_read_initial_capacity: 1024,
                response_read_chunk_bytes: 8192,
            },
            noise: NoiseConfig {
                max_frame_payload: 8192,
                handshake_scratch_bytes: 512,
            },
        };
        let json = serde_json::to_string(&original).expect("serialise");
        let back: Config = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(original, back);
    }

    #[test]
    fn config_deserialises_from_partial_json() {
        // Missing sub-tables and fields fall back to defaults because we
        // use `#[serde(default)]` on Config.
        let partial = r#"{"wire": {"max_header_bytes": 2048,
            "key_response_body_multiplier": 4,
            "header_read_initial_capacity": 512,
            "response_read_chunk_bytes": 4096}}"#;
        let c: Config = serde_json::from_str(partial).expect("partial config");
        assert_eq!(c.wire.max_header_bytes, 2048);
        assert_eq!(c.noise, NoiseConfig::default());
    }

    #[test]
    fn config_rejects_unknown_fields() {
        // Guards against silently-ignored typos in persisted configs.
        let bad = r#"{"wire": {"max_header_bytes": 2048,
            "key_response_body_multiplier": 4,
            "header_read_initial_capacity": 512,
            "response_read_chunk_bytes": 4096,
            "unexpected": 1}}"#;
        let result: Result<Config, _> = serde_json::from_str(bad);
        assert!(result.is_err(), "unknown field must be rejected");
    }
}
