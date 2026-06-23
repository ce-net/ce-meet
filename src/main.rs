//! `ce-meet` — real-time WebRTC signaling over the CE mesh.
//!
//! A thin CLI over the [`ce_meet`] library and the CE SDK (`ce-rs`). The signaling plane is
//! pubsub + capability-gated admission; the media plane is browser WebRTC + TURN (documented in
//! [`ce_meet::turn`]). Commands:
//!
//! - `ce-meet create-room`     — mint a fresh room id and print its topic (open or gated).
//! - `ce-meet join <room>`     — subscribe, announce presence, and stream the live roster.
//! - `ce-meet signal <room> <peer> <kind> <sdp>` — publish one SDP/ICE signal to a peer.

use anyhow::{Context, Result};
use ce_meet::admit::Admitter;
use ce_meet::caps::{Gate, parse_node_id};
use ce_meet::client::{MeetClient, new_room_id, now_secs};
use ce_meet::proto::{AdmitReq, Signal, TOPIC_ADMIT, room_topic};
use ce_meet::{ABILITY_JOIN, caps};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ce-meet",
    version,
    about = "Real-time WebRTC signaling over CE — rooms as pubsub topics, capability-gated.",
    long_about = None
)]
struct Cli {
    /// CE node HTTP API base URL.
    #[arg(long, default_value = ce_rs::DEFAULT_BASE_URL, global = true)]
    api: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mint a fresh room id and print it plus its pubsub topic. Share the room id with invitees.
    CreateRoom {
        /// Mark the room gated (capability required to join). Default is open.
        #[arg(long)]
        gated: bool,
    },
    /// Join a room: subscribe to its topic, announce presence, then print roster changes live.
    Join {
        /// The room id to join.
        room: String,
        /// Optional display name to register in the roster.
        #[arg(long)]
        name: Option<String>,
        /// For a gated room: the host NodeId to request admission from.
        #[arg(long)]
        host: Option<String>,
        /// Capability chain (hex) to present; overrides $CE_MEET_CAPS / config file.
        #[arg(long)]
        caps: Option<String>,
        /// Poll interval (ms) for draining the signaling inbox.
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        /// Stop after this many poll cycles (0 = run until interrupted).
        #[arg(long, default_value_t = 0)]
        cycles: u64,
    },
    /// Publish one directed SDP/ICE signal to a peer in a room (browser drives the actual WebRTC).
    Signal {
        /// The room id.
        room: String,
        /// The recipient peer NodeId (hex).
        peer: String,
        /// Signal kind: offer | answer | ice.
        kind: String,
        /// The SDP blob (for offer/answer) or candidate line (for ice).
        body: String,
    },
    /// Host a gated room: serve admission requests, authorizing each joiner's capability chain (and
    /// honoring resume tokens for reconnects) before admitting them. Runs until interrupted.
    Host {
        /// The room id to host admission for.
        room: String,
        /// Mark the room open (admit anyone, no capability). Default is gated.
        #[arg(long)]
        open: bool,
        /// Additional accepted org/CA root NodeId(s) (hex) whose chains this host honors.
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Poll interval (ms) for draining the admission inbox.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
        /// Stop after this many poll cycles (0 = run until interrupted).
        #[arg(long, default_value_t = 0)]
        cycles: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_meet=info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let ce = CeClient::new(&cli.api);

    match cli.cmd {
        Cmd::CreateRoom { gated } => create_room(&ce, gated).await,
        Cmd::Join { room, name, host, caps, poll_ms, cycles } => {
            join(ce, &room, name, host, caps.as_deref(), poll_ms, cycles).await
        }
        Cmd::Signal { room, peer, kind, body } => signal(ce, &room, &peer, &kind, body).await,
        Cmd::Host { room, open, roots, poll_ms, cycles } => {
            host(ce, &room, open, roots, poll_ms, cycles).await
        }
    }
}

async fn create_room(ce: &CeClient, gated: bool) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let room_id = new_room_id(&me, now_secs(), now_secs());
    println!("room id:   {room_id}");
    println!("topic:     {}", room_topic(&room_id));
    println!("host:      {me}");
    println!("access:    {}", if gated { "gated (capability required)" } else { "open" });
    if gated {
        println!();
        println!("Grant a participant join access with a meet:join capability rooted at this host,");
        println!("then have them join with --host {me} --caps <chain-hex>.");
    }
    Ok(())
}

async fn join(
    ce: CeClient,
    room: &str,
    name: Option<String>,
    host: Option<String>,
    caps_flag: Option<&str>,
    poll_ms: u64,
    cycles: u64,
) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let mut client = MeetClient::new(ce, room, &me);

    // Gated room: request admission from the host first.
    if let Some(host) = host {
        let chain = caps::resolve(caps_flag);
        let resp = client
            .request_admission(&host, &chain, name.clone(), 30_000)
            .await
            .context("request admission from host")?;
        if !resp.admitted {
            anyhow::bail!("admission denied: {}", resp.reason.unwrap_or_else(|| "no reason".into()));
        }
        println!("admitted to {room}");
        if !resp.ice_servers.is_empty() {
            println!("ice servers: {}", serde_json::to_string(&resp.ice_servers)?);
        }
    }

    client.subscribe().await.context("subscribe to room topic")?;
    client.announce_join(name).await.context("announce join")?;
    println!("joined {room} as {me}");
    println!("watching roster (Ctrl-C to leave)...");

    let mut n = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        // Keep our presence fresh so peers do not prune us.
        let _ = client.keepalive().await;
        match client.poll().await {
            Ok(effects) => {
                for eff in effects {
                    println!("{}", render_effect(&eff));
                }
            }
            Err(e) => tracing::warn!("poll error: {e}"),
        }
        n += 1;
        if cycles != 0 && n >= cycles {
            break;
        }
    }

    client.announce_leave().await.ok();
    println!("left {room}");
    Ok(())
}

fn render_effect(eff: &ce_meet::Effect) -> String {
    use ce_meet::Effect;
    match eff {
        Effect::Joined(n) => format!("+ {n} joined"),
        Effect::Left(n) => format!("- {n} left"),
        Effect::Refreshed(n) => format!(". {n} present"),
        Effect::Directed(env) => {
            format!("> {} -> {} ({})", env.from, env.to.as_deref().unwrap_or("?"), env.signal.tag())
        }
        Effect::NoChange => String::new(),
    }
}

async fn signal(ce: CeClient, room: &str, peer: &str, kind: &str, body: String) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let mut client = MeetClient::new(ce, room, &me);
    let signal = match kind {
        "offer" => Signal::Offer { sdp: body },
        "answer" => Signal::Answer { sdp: body },
        "ice" => Signal::IceCandidate { candidate: body, sdp_mid: None, sdp_m_line_index: None },
        other => anyhow::bail!("unknown signal kind '{other}' (use offer | answer | ice)"),
    };
    client.subscribe().await.context("subscribe to room topic")?;
    client.signal_peer(peer, signal).await.context("publish signal")?;
    println!("sent {kind} to {peer} in {room}");
    let _ = ABILITY_JOIN; // referenced to keep the symbol in scope for docs/help builds
    Ok(())
}

/// Run the host-side admission loop for a gated (or open) room: drain admission requests off the
/// `meet:admit` channel, run the [`Admitter`] (capability gate + resume-by-identity), and reply.
async fn host(
    ce: CeClient,
    room: &str,
    open: bool,
    roots: Vec<String>,
    poll_ms: u64,
    cycles: u64,
) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let host_id = parse_node_id(&me).context("parse host node id")?;
    let accepted_roots: Vec<_> = roots
        .iter()
        .map(|r| parse_node_id(r).with_context(|| format!("parse accepted root {r}")))
        .collect::<Result<_>>()?;

    let gate = if open { Gate::open(host_id) } else { Gate::gated(host_id, accepted_roots) };
    // Pull the current on-chain revocation set so revoked chains are denied.
    let revoked = ce.revoked().await.unwrap_or_default();
    let gate = gate.with_revoked(revoked);

    // The host's resume-token MAC secret: derived locally from its node id so it is stable across
    // restarts but never leaves the host. (A production host would persist a dedicated secret.)
    let mac_secret = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ce-meet:host-resume-secret:v1");
        h.update(me.as_bytes());
        h.finalize().to_vec()
    };
    let admitter = Admitter::new(room, gate, mac_secret);

    println!("hosting {} room {room} as {me}", if open { "open" } else { "gated" });
    println!("serving admission requests on '{TOPIC_ADMIT}' (Ctrl-C to stop)...");

    let mut n = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        match ce.messages().await {
            Ok(msgs) => {
                for m in msgs {
                    if m.topic != TOPIC_ADMIT {
                        continue;
                    }
                    let Some(token) = m.reply_token else { continue };
                    let bytes = match m.payload() {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let req: AdmitReq = match serde_json::from_slice(&bytes) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let resp = admitter.admit(&m.from, &req, &[], now_secs());
                    println!(
                        "{} {} for {}",
                        if resp.admitted { "admit" } else { "deny" },
                        req.room_id,
                        m.from
                    );
                    let payload = serde_json::to_vec(&resp).unwrap_or_default();
                    if let Err(e) = ce.reply(token, &payload).await {
                        tracing::warn!("reply failed: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("admission poll error: {e}"),
        }
        n += 1;
        if cycles != 0 && n >= cycles {
            break;
        }
    }
    Ok(())
}
