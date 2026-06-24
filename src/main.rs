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
use ce_meet::admit::{AdmitRateLimiter, Admitter};
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
        /// Use the real-time SSE push stream instead of timer polling (recommended for WebRTC).
        #[arg(long)]
        stream: bool,
        /// Poll interval (ms) for draining the signaling inbox (poll mode only).
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        /// Stop after this many poll cycles (0 = run until interrupted; poll mode only).
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
    /// Publish one in-call control signal (mute/camera/share/hand/react/chat/record) to the room.
    Control {
        /// The room id.
        room: String,
        #[command(subcommand)]
        action: ControlAction,
    },
    /// Host/moderator action against a participant: kick, force-mute, or end the room for all.
    Moderate {
        /// The room id.
        room: String,
        #[command(subcommand)]
        action: ModerateAction,
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

/// In-call control signals broadcast to the whole room.
#[derive(Subcommand)]
enum ControlAction {
    /// Set mic/camera mute state (e.g. `mute --audio --video` mutes both).
    Mute {
        /// Mute the microphone.
        #[arg(long)]
        audio: bool,
        /// Turn off the camera.
        #[arg(long)]
        video: bool,
    },
    /// Start or stop screen-sharing.
    Share {
        /// Stop sharing instead of starting.
        #[arg(long)]
        off: bool,
    },
    /// Raise or lower your hand.
    Hand {
        /// Lower the hand instead of raising it.
        #[arg(long)]
        down: bool,
    },
    /// Flash a reaction emoji to the room.
    React {
        /// The reaction token (emoji or short name).
        emoji: String,
    },
    /// Send an in-call chat line.
    Chat {
        /// The chat message body.
        body: String,
    },
    /// Announce recording started/stopped (consent notice; ce-meet records nothing itself).
    Record {
        /// Announce recording stopped instead of started.
        #[arg(long)]
        stop: bool,
    },
}

/// Host/moderator actions (the room host's gate authorizes these via capability).
#[derive(Subcommand)]
enum ModerateAction {
    /// Remove a participant from the room (directed at their NodeId).
    Kick {
        /// The target participant NodeId (hex).
        peer: String,
        /// Optional reason shown to the removed participant.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Force-mute (or request unmute of) a participant's audio (directed).
    Mute {
        /// The target participant NodeId (hex).
        peer: String,
        /// Allow the participant to unmute instead of force-muting.
        #[arg(long)]
        unmute: bool,
    },
    /// End the room for everyone (broadcast).
    End {
        /// Optional reason shown to all participants.
        #[arg(long)]
        reason: Option<String>,
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
        Cmd::Join { room, name, host, caps, stream, poll_ms, cycles } => {
            join(ce, &room, name, host, caps.as_deref(), stream, poll_ms, cycles).await
        }
        Cmd::Signal { room, peer, kind, body } => signal(ce, &room, &peer, &kind, body).await,
        Cmd::Control { room, action } => control(ce, &room, action).await,
        Cmd::Moderate { room, action } => moderate(ce, &room, action).await,
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

#[allow(clippy::too_many_arguments)]
async fn join(
    ce: CeClient,
    room: &str,
    name: Option<String>,
    host: Option<String>,
    caps_flag: Option<&str>,
    stream: bool,
    poll_ms: u64,
    cycles: u64,
) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let mut client = MeetClient::new(ce, room, &me).with_freshness(ce_meet::client::DEFAULT_FRESHNESS_SECS);

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

    if stream {
        // Real-time: drive the roster off the SSE push stream. Sub-second latency, the loop a real
        // WebRTC client uses. A keepalive task runs alongside so peers do not prune us.
        println!("streaming roster (Ctrl-C to leave)...");
        run_streamed(&mut client).await;
    } else {
        println!("watching roster (poll every {poll_ms}ms; Ctrl-C to leave)...");
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
    }

    client.announce_leave().await.ok();
    println!("left {room}");
    Ok(())
}

/// Drive the client from the SSE stream until the stream ends, the room is ended, or Ctrl-C. A
/// background ticker keeps our presence fresh. Effects are printed as they arrive.
async fn run_streamed(client: &mut MeetClient) {
    // The event loop borrows the client mutably; print effects directly from its callback.
    let loop_fut = client.event_loop(|eff| {
        let line = render_effect(eff);
        if !line.is_empty() {
            println!("{line}");
        }
    });
    tokio::select! {
        res = loop_fut => {
            if let Err(e) = res {
                tracing::warn!("event stream ended with error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("interrupted");
        }
    }
}

fn render_effect(eff: &ce_meet::Effect) -> String {
    use ce_meet::Effect;
    match eff {
        Effect::Joined(n) => format!("+ {n} joined"),
        Effect::Left(n) => format!("- {n} left"),
        Effect::Refreshed(n) => format!(". {n} present"),
        Effect::MediaChanged(n) => format!("~ {n} media changed"),
        Effect::Reaction { from, emoji } => format!("* {from} reacted {emoji}"),
        Effect::Chat { from, body } => format!("[chat] {from}: {body}"),
        Effect::Recording { from, active } => {
            format!("! {from} {} recording", if *active { "started" } else { "stopped" })
        }
        Effect::RoomEnded { by, reason } => {
            format!("# room ended by {by}{}", reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())
        }
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

/// Publish one in-call control signal (media-state, chat, reaction, recording-consent) to the room.
async fn control(ce: CeClient, room: &str, action: ControlAction) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let mut client = MeetClient::new(ce, room, &me);
    client.subscribe().await.context("subscribe to room topic")?;
    let what = match action {
        ControlAction::Mute { audio, video } => {
            client.set_media(audio, video).await?;
            format!("media (audio_muted={audio}, video_muted={video})")
        }
        ControlAction::Share { off } => {
            client.set_screen_share(!off).await?;
            format!("screen-share {}", if off { "stopped" } else { "started" })
        }
        ControlAction::Hand { down } => {
            client.raise_hand(!down).await?;
            format!("hand {}", if down { "lowered" } else { "raised" })
        }
        ControlAction::React { emoji } => {
            client.react(emoji.clone()).await?;
            format!("reaction {emoji}")
        }
        ControlAction::Chat { body } => {
            client.chat(body).await?;
            "chat".to_string()
        }
        ControlAction::Record { stop } => {
            client.announce_recording(!stop).await?;
            format!("recording {}", if stop { "stopped" } else { "started" })
        }
    };
    println!("sent {what} to {room}");
    Ok(())
}

/// Publish one host/moderator action. The target's own gate authorizes it via the sender's
/// capability; this command only emits the signal.
async fn moderate(ce: CeClient, room: &str, action: ModerateAction) -> Result<()> {
    let me = ce.status().await.context("query node status")?.node_id;
    let mut client = MeetClient::new(ce, room, &me);
    client.subscribe().await.context("subscribe to room topic")?;
    let what = match action {
        ModerateAction::Kick { peer, reason } => {
            client.kick(&peer, reason).await?;
            format!("kick -> {peer}")
        }
        ModerateAction::Mute { peer, unmute } => {
            client.force_mute(&peer, !unmute).await?;
            format!("{} -> {peer}", if unmute { "request-unmute" } else { "force-mute" })
        }
        ModerateAction::End { reason } => {
            client.end_room(reason).await?;
            "end-room".to_string()
        }
    };
    println!("sent {what} in {room}");
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
    // Bound how much host CPU a flood of admit requests can burn on ce-cap verification.
    let mut limiter = AdmitRateLimiter::default();

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
                    // Rate-limit BEFORE the expensive capability verification.
                    if !limiter.check(&m.from, now_secs()) {
                        tracing::warn!("rate-limited admit flood from {}", m.from);
                        continue;
                    }
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
                    // Serialize the response; on the (impossible) error send an explicit denial the
                    // joiner can parse, rather than an empty body that surfaces as a transport error.
                    let payload = serde_json::to_vec(&resp).unwrap_or_else(|_| {
                        serde_json::to_vec(&ce_meet::AdmitResp {
                            admitted: false,
                            reason: Some("host failed to encode response".into()),
                            ..Default::default()
                        })
                        .unwrap_or_default()
                    });
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
