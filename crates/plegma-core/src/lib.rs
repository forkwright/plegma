//! # Plegma Core
//!
//! Shared types for the plegma mesh networking stack. Consumed by `dictyon`
//! (client) and, eventually, `histos` (coordination server). Holds the
//! cross-crate vocabulary: Noise framing, `WireGuard` key wrappers, peer
//! identity types, ACL representations, protocol constants.
//!
//! This crate has no network I/O and minimal dependencies. It must compile
//! fast and stay boring — types, not behavior.

#![deny(missing_docs)]

pub mod keys;
