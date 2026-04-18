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

use dictyon::control::{ControlClient, RegisterOutcome};
use dictyon::noise::NoiseHandshake;
use dictyon::transport::ControlConnection;
use dictyon::wire::{AsyncControlStream, ControlConfig, connect};
use hamma_core::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use tracing::{info, warn};

const CONTROL_URL: &str = "https://controlplane.tailscale.com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("dictyon=debug".parse()?),
        )
        .init();

    run().await
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = std::env::var("TS_AUTHKEY").ok();
    if auth_key.is_none() {
        warn!("TS_AUTHKEY not set — server will require interactive auth");
    }

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
        build_dummy_connection()?,
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
) -> Result<(), Box<dyn std::error::Error>> {
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
    }
    Ok(())
}

async fn stream_map(
    client: &mut ControlClient,
    stream: &mut AsyncControlStream,
) -> Result<(), Box<dyn std::error::Error>> {
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
fn build_dummy_connection() -> Result<ControlConnection, Box<dyn std::error::Error>> {
    let client_key = MachinePrivate::generate();
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let mut handshake = NoiseHandshake::new(client_key, server_pub);
    let init_msg = handshake.initiation_message()?;

    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
    let prologue = b"Tailscale Control Protocol v1";
    let mut responder = snow::Builder::new(params)
        .local_private_key(server_key.as_bytes())?
        .prologue(prologue)?
        .build_responder()?;

    let payload_len = u16::from_be_bytes([init_msg[3], init_msg[4]]) as usize;
    let noise_init = &init_msg[5..5 + payload_len];

    let mut payload_buf = vec![0u8; 256];
    responder.read_message(noise_init, &mut payload_buf)?;

    let mut resp_buf = vec![0u8; 256];
    let resp_len = responder.write_message(&[], &mut resp_buf)?;

    let len_u16 = u16::try_from(resp_len)?;
    let mut framed_resp = vec![0x02u8];
    framed_resp.extend_from_slice(&len_u16.to_be_bytes());
    framed_resp.extend_from_slice(&resp_buf[..resp_len]);

    Ok(ControlConnection::complete_handshake(
        handshake,
        &framed_resp,
    )?)
}
