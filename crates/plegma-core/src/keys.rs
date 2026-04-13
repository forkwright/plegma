//! Typed key wrappers for the Tailscale/WireGuard key hierarchy.
//!
//! All keys are Curve25519, 32 bytes. Each key type is a newtype that enforces
//! correct usage: private keys are non-cloneable and zeroized on drop, public
//! keys are freely cloneable and derive the standard traits.
//!
//! Serialization uses Tailscale's typed hex prefixes (`mkey:`, `nodekey:`,
//! `discokey:`, `privkey:`).

use core::fmt;

use rand::rngs::OsRng;
use snafu::Snafu;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing or handling keys.
#[derive(Debug, Snafu)]
pub enum KeyError {
    /// The key string is missing the expected prefix.
    #[snafu(display("key missing prefix '{prefix}': got '{input}'"))]
    MissingPrefix {
        /// The expected prefix.
        prefix: String,
        /// The full input string.
        input: String,
    },

    /// The hex portion of the key is not valid.
    #[snafu(display("invalid hex in key: {message}"))]
    InvalidHex {
        /// Description of the hex error.
        message: String,
    },

    /// The decoded key is not the expected length.
    #[snafu(display("key length wrong: expected {expected}, got {actual}"))]
    WrongLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
}

/// Length of all Curve25519 keys in bytes.
const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Macro for reducing boilerplate across the three key pairs
// ---------------------------------------------------------------------------

macro_rules! key_pair {
    (
        private_name = $Priv:ident,
        public_name  = $Pub:ident,
        private_prefix = $priv_prefix:expr,
        public_prefix  = $pub_prefix:expr,
        doc_private    = $doc_priv:expr,
        doc_public     = $doc_pub:expr,
    ) => {
        #[doc = $doc_priv]
        pub struct $Priv([u8; KEY_LEN]);

        // Manual Debug: redact private key material.
        impl fmt::Debug for $Priv {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($Priv))
                    .field(&"[REDACTED]")
                    .finish()
            }
        }

        // Zeroize on drop for private keys.
        impl Drop for $Priv {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl ZeroizeOnDrop for $Priv {}

        impl $Priv {
            /// Generate a new random private key.
            #[must_use]
            pub fn generate() -> Self {
                let secret = StaticSecret::random_from_rng(OsRng);
                Self(secret.to_bytes())
            }

            /// Create a private key from raw bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Derive the corresponding public key.
            #[must_use]
            pub fn public_key(&self) -> $Pub {
                let secret = StaticSecret::from(self.0);
                let public = PublicKey::from(&secret);
                $Pub(*public.as_bytes())
            }

            /// Serialize to hex with the Tailscale private-key prefix.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let hex = hex_encode(&self.0);
                format!("{}{hex}", $priv_prefix)
            }
        }

        #[doc = $doc_pub]
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $Pub([u8; KEY_LEN]);

        impl fmt::Debug for $Pub {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($Pub))
                    .field(&self.to_hex())
                    .finish()
            }
        }

        impl $Pub {
            /// Create a public key from raw bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Serialize to hex with the Tailscale public-key prefix.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let hex = hex_encode(&self.0);
                format!("{}{hex}", $pub_prefix)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Key pair definitions
// ---------------------------------------------------------------------------

key_pair! {
    private_name   = MachinePrivate,
    public_name    = MachinePublic,
    private_prefix = "privkey:",
    public_prefix  = "mkey:",
    doc_private    = "Machine identity private key -- persisted to disk, never rotates.\n\nUsed for the Noise IK handshake with the control server.",
    doc_public     = "Machine identity public key.\n\nSerialized with the `mkey:` prefix in the Tailscale protocol.",
}

key_pair! {
    private_name   = NodePrivate,
    public_name    = NodePublic,
    private_prefix = "privkey:",
    public_prefix  = "nodekey:",
    doc_private    = "Node identity private key -- `WireGuard` identity. Rotates on expiry.\n\nUsed for `WireGuard` tunnels and DERP communication.",
    doc_public     = "Node identity public key.\n\nSerialized with the `nodekey:` prefix in the Tailscale protocol.",
}

key_pair! {
    private_name   = DiscoPrivate,
    public_name    = DiscoPublic,
    private_prefix = "privkey:",
    public_prefix  = "discokey:",
    doc_private    = "Disco ephemeral private key -- regenerated per process.\n\nUsed for NAT traversal via the disco protocol.",
    doc_public     = "Disco ephemeral public key.\n\nSerialized with the `discokey:` prefix in the Tailscale protocol.",
}

// ---------------------------------------------------------------------------
// MachinePublic: additional parsing support
// ---------------------------------------------------------------------------

impl MachinePublic {
    /// Parse a `MachinePublic` from the Tailscale `"mkey:hexhex..."` format.
    ///
    /// This is used to deserialize the server's public key returned by
    /// `GET /key?v=N`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] if the prefix is missing, the hex is invalid, or
    /// the decoded length is not 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, KeyError> {
        let prefix = "mkey:";
        let hex = s
            .strip_prefix(prefix)
            .ok_or_else(|| KeyError::MissingPrefix {
                prefix: prefix.to_string(),
                input: s.to_string(),
            })?;
        let bytes = hex_decode(hex)?;
        if bytes.len() != KEY_LEN {
            return Err(KeyError::WrongLength {
                expected: KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Hex encoding helper (avoids pulling in the `hex` crate for one function)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, KeyError> {
    if s.len() % 2 != 0 {
        return Err(KeyError::InvalidHex {
            message: "odd number of hex digits".to_string(),
        });
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        // Safety: chunks(2) on a valid UTF-8 str with even length gives ASCII pairs.
        let hi = hex_nibble(chunk[0]).map_err(|e| KeyError::InvalidHex { message: e })?;
        let lo = hex_nibble(chunk[1]).map_err(|e| KeyError::InvalidHex { message: e })?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", b as char)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_machine_key_produces_32_bytes() {
        let key = MachinePrivate::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn public_key_derivation_is_deterministic() {
        let priv_key = MachinePrivate::generate();
        let pub1 = priv_key.public_key();
        let pub2 = priv_key.public_key();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn private_key_debug_redacts() {
        let key = MachinePrivate::generate();
        let debug = format!("{key:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "debug output should redact key material: {debug}"
        );
        // The output should be like `MachinePrivate("[REDACTED]")` --
        // no raw hex bytes or byte arrays leaked.
        assert!(
            !debug.contains("0x"),
            "debug output should not contain raw hex: {debug}"
        );
    }

    #[test]
    fn from_bytes_round_trips() {
        let original = MachinePrivate::generate();
        let bytes = *original.as_bytes();
        let restored = MachinePrivate::from_bytes(bytes);
        assert_eq!(original.as_bytes(), restored.as_bytes());

        let pub_original = original.public_key();
        let pub_bytes = *pub_original.as_bytes();
        let pub_restored = MachinePublic::from_bytes(pub_bytes);
        assert_eq!(pub_original, pub_restored);
    }

    #[test]
    fn to_hex_includes_prefix() {
        let priv_key = MachinePrivate::generate();
        let pub_key = priv_key.public_key();

        let priv_hex = priv_key.to_hex();
        assert!(priv_hex.starts_with("privkey:"), "private hex: {priv_hex}");
        // prefix + 64 hex chars
        assert_eq!(priv_hex.len(), "privkey:".len() + 64);

        let pub_hex = pub_key.to_hex();
        assert!(pub_hex.starts_with("mkey:"), "public hex: {pub_hex}");
        assert_eq!(pub_hex.len(), "mkey:".len() + 64);

        // Node key prefix
        let node_priv = NodePrivate::generate();
        let node_pub = node_priv.public_key();
        assert!(node_pub.to_hex().starts_with("nodekey:"));

        // Disco key prefix
        let disco_priv = DiscoPrivate::generate();
        let disco_pub = disco_priv.public_key();
        assert!(disco_pub.to_hex().starts_with("discokey:"));
    }

    #[test]
    fn different_keys_produce_different_public_keys() {
        let key1 = MachinePrivate::generate();
        let key2 = MachinePrivate::generate();
        assert_ne!(key1.public_key(), key2.public_key());
    }

    #[test]
    fn node_key_round_trips() {
        let priv_key = NodePrivate::generate();
        let bytes = *priv_key.as_bytes();
        let restored = NodePrivate::from_bytes(bytes);
        assert_eq!(priv_key.public_key(), restored.public_key());
    }

    #[test]
    fn disco_key_round_trips() {
        let priv_key = DiscoPrivate::generate();
        let bytes = *priv_key.as_bytes();
        let restored = DiscoPrivate::from_bytes(bytes);
        assert_eq!(priv_key.public_key(), restored.public_key());
    }
}
