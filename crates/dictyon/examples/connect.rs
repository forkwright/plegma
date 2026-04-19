//! Minimal example: connect to tailscale.com and stream map updates.
//!
//! Reads `TS_AUTHKEY` from the environment (optional). Generates ephemeral
//! keys, connects to the Tailscale control plane, registers the node, and
//! then streams map updates until interrupted.
//!
//! Usage:
//! ```text
//! TS_AUTHKEY=tskey-auth-... cargo run --example connect
//! ```

use dictyon::control::{ControlClient, ControlError, RegisterOutcome};
use dictyon::noise::{NoiseError, NoiseHandshake};
use dictyon::transport::{ControlConnection, TransportError};
use dictyon::wire::{AsyncControlStream, ControlConfig, WireError, connect};
use hamma_core::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use snafu::{ResultExt, Snafu};
use tracing::{info, warn};

const CONTROL_URL: &str = "https://controlplane.tailscale.com";

/// Concrete error type for this example. Each variant identifies the stage
/// that failed so diagnostics stay specific without leaking internal types.
#[derive(Debug, Snafu)]
#[non_exhaustive]
enum ExampleError {
    /// Failed to configure the tracing filter directive.
    #[snafu(display("tracing filter init: {message}"))]
    TracingInit {
        /// Description of the tracing init failure.
        message: String,
    },
    /// Wire-level error (TLS / HTTP upgrade / transport framing).
    #[snafu(display("wire layer: {source}"))]
    Wire {
        /// Underlying wire error.
        source: WireError,
    },
    /// Noise handshake error.
    #[snafu(display("noise handshake: {source}"))]
    Noise {
        /// Underlying Noise error.
        source: NoiseError,
    },
    /// Control-plane protocol error (register / map stream).
    #[snafu(display("control protocol: {source}"))]
    Control {
        /// Underlying control error.
        source: ControlError,
    },
    /// Control-connection transport error.
    #[snafu(display("transport layer: {source}"))]
    Transport {
        /// Underlying transport error.
        source: TransportError,
    },
    /// Failed to build the placeholder Noise responder for the placeholder
    /// `ControlConnection`.
    #[snafu(display("placeholder handshake setup: {message}"))]
    PlaceholderHandshake {
        /// Description of the failure.
        message: String,
    },
}

impl From<WireError> for ExampleError {
    fn from(source: WireError) -> Self {
        Self::Wire { source }
    }
}

impl From<ControlError> for ExampleError {
    fn from(source: ControlError) -> Self {
        Self::Control { source }
    }
}

impl From<NoiseError> for ExampleError {
    fn from(source: NoiseError) -> Self {
        Self::Noise { source }
    }
}

impl From<TransportError> for ExampleError {
    fn from(source: TransportError) -> Self {
        Self::Transport { source }
    }
}

#[tokio::main]
async fn main() -> Result<(), ExampleError> {
    let directive =
        "dictyon=debug"
            .parse()
            .map_err(
                |e: tracing_subscriber::filter::ParseError| ExampleError::TracingInit {
                    message: e.to_string(),
                },
            )?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(directive))
        .init();

    run().await
}

async fn run() -> Result<(), ExampleError> {
    let auth_key = match std::env::var("TS_AUTHKEY") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => {
            warn!("TS_AUTHKEY not set — server will require interactive auth");
            None
        }
        Err(e) => {
            warn!("TS_AUTHKEY unreadable ({e}); treating as absent");
            None
        }
    };

    let machine_key = MachinePrivate::generate();
    let node_key = NodePrivate::generate();
    let disco_key = DiscoPrivate::generate();

    info!("connecting to {CONTROL_URL}");

    let config = ControlConfig {
        control_url: CONTROL_URL.to_string(),
        machine_key: MachinePrivate::from_bytes(*machine_key.as_bytes()),
    };

    let mut stream = connect(&config).await?;
    info!("TLS + Noise handshake complete");

    let client_machine = MachinePrivate::from_bytes(*machine_key.as_bytes());
    let mut client = ControlClient::new(
        build_placeholder_connection()?,
        client_machine,
        node_key,
        disco_key,
    );

    register_node(&mut client, &mut stream, auth_key.as_deref()).await?;
    stream_map(&mut client, &mut stream).await?;
    Ok(())
}

async fn register_node(
    client: &mut ControlClient,
    stream: &mut AsyncControlStream,
    auth_key: Option<&str>,
) -> Result<(), ExampleError> {
    info!("registering…");
    match client.register(stream, auth_key).await? {
        RegisterOutcome::Authorized(resp) => {
            info!(
                authorized = resp.machine_authorized,
                expiry = ?resp.node_key_expiry,
                "node authorized"
            );
        }
        RegisterOutcome::NeedsAuth { auth_url } => {
            info!("visit to authorize: {auth_url}");
            let resp = client.poll_registration(stream, &auth_url).await?;
            info!(authorized = resp.machine_authorized, "auth complete");
        }
        // RegisterOutcome is #[non_exhaustive]; cover future variants.
        _ => {
            warn!("unknown register outcome variant; treating as unsupported");
        }
    }
    Ok(())
}

async fn stream_map(
    client: &mut ControlClient,
    stream: &mut AsyncControlStream,
) -> Result<(), ExampleError> {
    info!("starting map stream…");
    client.start_map_stream(stream).await?;

    loop {
        let is_keepalive = client.recv_map_update(stream).await?;
        if is_keepalive {
            info!("keepalive");
        } else {
            let peers = client.peers();
            info!(peer_count = peers.len(), "map update");
            for peer in peers {
                info!(key = %peer.key, name = %peer.name, "  peer");
            }
        }
    }
}

/// Build a `ControlConnection` using a self-paired Noise handshake.
///
/// The async control methods on [`ControlClient`] route I/O through
/// [`dictyon::wire::AsyncControlStream`] rather than through the embedded
/// transport, so this connection is a placeholder to satisfy the constructor.
fn build_placeholder_connection() -> Result<ControlConnection, ExampleError> {
    let client_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let mut handshake = NoiseHandshake::new(client_key, server_pub);
    let init_msg = handshake.initiation_message()?;

    let params: snow::params::NoiseParams =
        "Noise_IK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e: snow::Error| ExampleError::PlaceholderHandshake {
                message: format!("parse noise params: {e}"),
            })?;
    let prologue = b"Tailscale Control Protocol v1";
    let mut responder = snow::Builder::new(params)
        .local_private_key(server_key.as_bytes())
        .context(PlaceholderHandshakeFromSnowSnafu {
            stage: "local_private_key",
        })?
        .prologue(prologue)
        .context(PlaceholderHandshakeFromSnowSnafu { stage: "prologue" })?
        .build_responder()
        .context(PlaceholderHandshakeFromSnowSnafu {
            stage: "build_responder",
        })?;

    let len_hi = *init_msg
        .get(3)
        .ok_or_else(|| ExampleError::PlaceholderHandshake {
            message: "init_msg too short for length hi byte".to_string(),
        })?;
    let len_lo = *init_msg
        .get(4)
        .ok_or_else(|| ExampleError::PlaceholderHandshake {
            message: "init_msg too short for length lo byte".to_string(),
        })?;
    let payload_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    let noise_init =
        init_msg
            .get(5..5 + payload_len)
            .ok_or_else(|| ExampleError::PlaceholderHandshake {
                message: "init_msg truncated before noise payload".to_string(),
            })?;

    let mut payload_buf = vec![0u8; 256];
    responder
        .read_message(noise_init, &mut payload_buf)
        .context(PlaceholderHandshakeFromSnowSnafu {
            stage: "responder read_message",
        })?;

    let mut resp_buf = vec![0u8; 256];
    let resp_len =
        responder
            .write_message(&[], &mut resp_buf)
            .context(PlaceholderHandshakeFromSnowSnafu {
                stage: "responder write_message",
            })?;

    let len_u16 = u16::try_from(resp_len).map_err(|_| ExampleError::PlaceholderHandshake {
        message: "resp_len exceeds u16".to_string(),
    })?;
    let mut framed_resp = vec![0x02u8];
    framed_resp.extend_from_slice(&len_u16.to_be_bytes());
    let resp_slice =
        resp_buf
            .get(..resp_len)
            .ok_or_else(|| ExampleError::PlaceholderHandshake {
                message: "resp_buf truncated".to_string(),
            })?;
    framed_resp.extend_from_slice(resp_slice);

    Ok(ControlConnection::complete_handshake(
        handshake,
        &framed_resp,
    )?)
}

/// Adapter from raw `snow::Error` through [`ExampleError::PlaceholderHandshake`].
#[derive(Debug, Snafu)]
#[snafu(display("snow library failure during {stage}: {source}"))]
struct PlaceholderHandshakeFromSnow {
    stage: &'static str,
    source: snow::Error,
}

impl From<PlaceholderHandshakeFromSnow> for ExampleError {
    fn from(err: PlaceholderHandshakeFromSnow) -> Self {
        Self::PlaceholderHandshake {
            message: err.to_string(),
        }
    }
}
