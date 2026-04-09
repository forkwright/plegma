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
//! Pre-alpha scaffold. Nothing here works yet. See the project roadmap in
//! kanon/projects/plegma for the phase plan.
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

/// Placeholder sentinel indicating the crate is reachable from the workspace.
///
/// Removed when the first real module lands.
#[must_use]
pub const fn scaffold_sentinel() -> &'static str {
    "dictyon"
}

#[cfg(test)]
mod tests {
    use super::scaffold_sentinel;

    #[test]
    fn sentinel_returns_crate_name() {
        assert_eq!(scaffold_sentinel(), "dictyon");
    }
}
