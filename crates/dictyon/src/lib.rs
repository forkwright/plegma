//! # Dictyon
//!
//! *δίκτυον — a net, a cast net, a thing woven to catch.*
//!
//! Peer-side client for the plegma mesh networking stack. Speaks
//! wire-compatible Tailscale control protocol to an upstream coordination
//! server (tailscale.com during Phase A, histos when sovereignty is wanted),
//! drives a `WireGuard` data plane via boringtun, traverses NATs through DERP
//! relays, and resolves peer names via `MagicDNS`.
//!
//! ## Status
//!
//! Noise IK handshake and key types implemented. TCP/TLS connection,
//! HTTP upgrade, Noise handshake completion, registration, and map
//! streaming implemented in [`wire`] and the async extension of [`control`].
//!
//! ## Scope
//!
//! - `WireGuard` data plane (via `boringtun`, when wired)
//! - Noise-framed control protocol client
//! - DERP relay client for NAT traversal fallback
//! - `MagicDNS` resolver
//! - Route / exit-node configuration
//!
//! Out of scope: Taildrop, Tailscale SSH, Funnel, app connectors. Those are
//! opinionated product features of tailscale.com and not required for plegma's
//! mesh-networking target.

#![deny(missing_docs)]

pub mod control;
pub mod error;
pub mod noise;
pub mod transport;
pub mod wire;
