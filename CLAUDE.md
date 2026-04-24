<!--
scope: hamma repo conventions (Tailscale-compatible mesh networking in pure Rust: dictyon, hamma-core, future histos)
defers_to: ~/menos-ops/CLAUDE.md for machine topology; ~/.claude/CLAUDE.md for operator principles; kanon standards for universal engineering policy
tightens: no-unsafe/no-unwrap discipline, boringtun as the only audited unsafe boundary
-->

# CLAUDE.md

Project orientation for AI coding agents working on hamma.

## What hamma is

A clean-room Rust Tailscale-compatible mesh networking stack. Pre-alpha, design-phase. Built as the networking layer for the forkwright ecosystem (aletheia, akroasis, harmonia, thumos) and as an OSS contribution to the Rust networking ecosystem.

See [README.md](README.md) for the public-facing description and [projects/hamma/](https://github.com/forkwright/kanon/tree/main/projects/hamma) in kanon for the full roadmap, phase plans, and decision log.

## Standards

All work must comply with [kanon standards](https://github.com/forkwright/kanon):

- `RUST.md`  -  language-specific rules, dependency policy, banned crates
- `TESTING.md`  -  test naming (`verb_condition`), error path coverage
- `SECURITY.md`  -  secret handling, input validation, unsafe justification
- `WRITING.md`  -  doc comment style, commit message voice
- `ARCHITECTURE.md`  -  crate boundary discipline, dependency direction
- `REPO-SETUP.md`  -  workspace configuration, lints, CI gates

Lint before committing: `kanon lint . --summary`. Gate: `kanon gate`.

## Structure

```
hamma/
├── crates/
│   ├── dictyon/        # peer client (headline crate, ships first)
│   └── hamma-core/    # shared types (Noise framing, keys, ACL, protocol consts)
├── .github/workflows/  # CI gates (installed by kanon init)
├── Cargo.toml          # workspace root
├── deny.toml           # dependency policy
├── clippy.toml         # lint configuration
├── rustfmt.toml        # format configuration
├── flake.nix           # reproducible dev shell
└── LICENSE             # AGPL-3.0-or-later
```

Planned but not yet scaffolded:
- `crates/histos/`  -  coordination server (Phase B)
- `crates/hamma-derp/`  -  DERP relay server (Phase D, optional)

## Commands

```bash
cargo check --workspace          # fast compile check
cargo test --workspace           # run all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                 # dependency audit
kanon lint . --summary           # full kanon lint
```

## Key patterns

- **Error handling**: `snafu` with `.context()` propagation and `Location` tracking. No `anyhow`, no `thiserror`. See the RUST.md error handling section.
- **Async runtime**: `tokio` with the actor-per-component pattern. No shared mutable state across async boundaries. `tokio::sync::Mutex` for async-locked data; `parking_lot::Mutex` for sync-only (never `std::sync::Mutex`  -  it deadlocks held across `.await`).
- **Time**: `std::time::Instant` for monotonic time, `chrono` / `time` crate for wall-clock when displayed to humans. Wall clock is never a dependency of correctness.
- **Networking primitives**: `tokio::net` for TCP/UDP, `boringtun` (Cloudflare) for WireGuard data plane. No raw sockets, no nix crate, no libc. No reimplementation of WireGuard crypto  -  use the audited reference.
- **Identity types**: ed25519 for node identity, Curve25519 for WireGuard tunnel keys, X25519 for Noise handshakes. Wrap each in a newtype to prevent accidental mixing. Types live in `hamma-core`.
- **Configuration**: TOML files parsed via `figment` with env-var override cascade. See TOML.md in kanon standards.
- **Logging**: `tracing` with structured fields. Never `println!` in library code. `tracing-subscriber` for the binary.
- **No `unwrap()`, no `expect()` in library code**. Deny at workspace level. Tests may use `.expect("msg")` for clear assertion.
- **No `unsafe`**. Workspace-wide deny. If a specific crate needs unsafe (unlikely until low-level protocol work), it goes in a clearly named module with per-block `// SAFETY:` comments and an allow attribute.

## Current phase

**Phase A**: dictyon client against tailscale.com control plane. No histos scope yet. Milestone: dictyon can join an existing tailnet, establish peer-to-peer WG tunnels with tailscale.com-managed peers, resolve MagicDNS names, and route via Mullvad exit nodes.

## License reconsideration item

The forkwright project default is AGPL-3.0-or-later. For a low-level networking library intended for ecosystem adoption, this may hurt uptake  -  the Rust networking convention is permissive (boringtun is BSD-3, hickory-dns is MIT/Apache, tokio is MIT, tailscale itself is BSD-3).

**Before the first public release** (tag v0.1.0 or equivalent), revisit the license with Cody:

- Option A: keep AGPL-3.0-or-later (sovereignty maximalism, forkwright-internal use dominates)
- Option B: switch to Apache-2.0 (Rust-ecosystem convention, maximal adoption)
- Option C: dual MIT/Apache-2.0 (idiomatic Rust standard, no patent ambiguity)

Until then the AGPL text is the working placeholder. Do not remove the copyleft without discussion.

## Dependencies on other forkwright projects

- **kanon**: standards, lint engine. Dev-time dependency.
- **koinon** (akroasis-provided shared crate): may become a workspace dep if we need ID types shared with RF intelligence layers.

Hamma does NOT depend on aletheia, thumos, harmonia, or akroasis at runtime. Those projects depend on hamma, not the reverse.

## Before submitting a PR

1. `cargo check --workspace` clean
2. `cargo test --workspace` all passing
3. `cargo clippy --workspace --all-targets -- -D warnings` clean
4. `cargo fmt --all -- --check` clean
5. `cargo deny check` clean
6. `kanon lint .` zero violations (or justified ignores in `.kanon-lint-ignore`)
7. Conventional commit messages
8. No `unwrap()` / `expect()` in library code
9. Public APIs have doc comments with `# Errors` sections for fallible functions

## Git

Conventional commits: `type(scope): description`. Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`, `perf`, `build`. Present tense imperative, first line no longer than 72 chars.

One logical change per commit. Rebase before pushing to keep history linear.

Never commit directly to main once branch protection is set up. Never push to any upstream that isn't `origin`.
