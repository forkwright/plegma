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

/// Placeholder sentinel indicating the crate is reachable from the workspace.
///
/// Removed when the first real type module lands.
#[must_use]
pub const fn scaffold_sentinel() -> &'static str {
    "plegma-core"
}

#[cfg(test)]
mod tests {
    use super::scaffold_sentinel;

    #[test]
    fn sentinel_returns_crate_name() {
        assert_eq!(scaffold_sentinel(), "plegma-core");
    }
}
