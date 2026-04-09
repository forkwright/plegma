# Plegma

*πλέγμα  -  a woven thing, a plaited mesh, a net*

A clean-room Rust implementation of a Tailscale-compatible mesh networking stack. Pre-alpha, in design.

## Status

**Pre-alpha.** Design phase. No releases yet, no stable API, no build instructions beyond `cargo check`.

Current workstream: `dictyon`, the peer-side client.

## What this is

Plegma is a Rust-native mesh networking stack  -  the pieces needed to weave a set of devices into a single flat network, speak WireGuard peer-to-peer, traverse NATs via DERP relays, and name each other via MagicDNS. It targets wire-compatibility with Tailscale's existing control plane so that devices running plegma can join the same tailnet as devices running the reference Tailscale client.

**Why it exists.** A production-grade Rust implementation of the Tailscale client/server protocol does not exist. Plegma fills that gap, initially as the networking layer for the [forkwright](https://github.com/forkwright) ecosystem  -  [aletheia](https://github.com/forkwright/aletheia) (cognitive runtime), [akroasis](https://github.com/forkwright/akroasis) (signals intelligence), [harmonia](https://github.com/forkwright/harmonia) (media platform), and [thumos](https://github.com/forkwright/thumos) (sovereign mobile OS)  -  and openly as an option for anyone who wants a memory-safe, auditable mesh client.

## Crates

| Crate | Role | Status |
|---|---|---|
| `dictyon` (δίκτυον, "net") | Peer client: WireGuard data plane (via boringtun), Noise control protocol to the coordination server, DERP relay client, MagicDNS resolver, route configuration | Scaffold |
| `plegma-core` | Shared types: Noise framing, WireGuard key types, peer identity, ACL types, protocol constants | Scaffold |
| `histos` (ἱστός, "loom")  -  **planned** | Coordination server: peer registry, ACL enforcement, preauth keys, DERP coordination. Replaces Headscale/tailscale.com when sovereignty is wanted | Not started |
| `plegma-derp`  -  **planned** | DERP relay server (optional  -  can reuse Tailscale's DERP for Phase A) | Not started |

## Design principles

1. **Clean-room Rust, not a port.** No C, no unsafe beyond what `boringtun` already audits, no vendor blobs. Memory safety end-to-end.
2. **Wire-compatible first.** Phase A targets interop with tailscale.com's control plane so dictyon can be validated against a reference server before histos exists. Protocol extensions are opt-in, layered on top, never break compat.
3. **Small feature target.** Peer WG, MagicDNS, exit nodes, ACLs. Not Taildrop, Tailscale SSH, Funnel, or app connectors. Those can be added later if anyone wants them.
4. **Sovereignty extensions.** Future `histos` will add forkwright-specific extensions: hardware-key-signed admin operations (FIDO2 attestation), tamper-evident peer enrollment, measured-boot attestation hooks. Upstream-incompatible, opt-in.
5. **Kanon standards.** Built against [kanon](https://github.com/forkwright/kanon) linting, formatting, and testing standards. Same quality floor as the rest of forkwright.

## Phases

See [kanon/projects/plegma/](https://github.com/forkwright/kanon/tree/main/projects/plegma) for the full roadmap.

- **Phase A  -  dictyon client against tailscale.com**. Validates the Rust client on a production reference server. No histos scope.
- **Phase B  -  histos coordination server, wire-compatible**. Matches Headscale's feature surface for forkwright self-hosting.
- **Phase C  -  histos sovereignty extensions**. Titan-signed admin ops, attestation hooks, canary integration.
- **Phase D  -  DERP relay**. Optional own-relay for full-stack independence.

## License

[AGPL-3.0-or-later](LICENSE).

**Note for downstream consumers**: AGPL is the forkwright project default. For wider Rust-ecosystem adoption (where permissive licenses are the convention  -  boringtun is BSD-3, hickory-dns is MIT/Apache, tailscale itself is BSD-3), the license may be revisited before the first public release. Open discussion welcome.

## Contributing

Not yet accepting external contributions while the initial architecture stabilizes. Watch the repo for status updates.
