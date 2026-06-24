//! # ce-meet — real-time WebRTC signaling over the CE mesh
//!
//! ce-meet is a Meet-like **signaling** layer built entirely on CE primitives. A room is a CE
//! pubsub topic; participants exchange SDP offers/answers and ICE candidates over it so their
//! browsers can establish direct WebRTC media. The **media plane** (audio/video) is browser WebRTC,
//! flowing peer-to-peer or via a paid TURN relay — it never passes through any CE node, so no node
//! ever sees the call.
//!
//! ## What this crate is
//!
//! - [`proto`] — the wire protocol: [`proto::SignalEnvelope`] (addressed, sequence-numbered) wrapping
//!   a [`proto::Signal`]. The signal set covers call setup (join/leave/keepalive/offer/answer/ICE),
//!   **in-call media-control state** (mic/camera mute, screen-share, raise-hand), **chat/reactions**,
//!   **recording-consent**, and **host moderation** (kick / force-mute / end-room) — plus the
//!   gated-room admission request/response and the opaque capability abilities. Every
//!   attacker-controlled field is length-bounded and validated on receipt (DoS hardening).
//! - [`room`] — the [`room::Room`] roster state machine: a per-member last-writer-wins register keyed
//!   by NodeId and ordered by the sender's own monotonic `seq`, so membership and per-member media
//!   state **converge** under the unordered, lossy, duplicating delivery pubsub gives — order of
//!   arrival does not matter. A bounded member cap stops roster-exhaustion DoS. Adds
//!   [`room::RoomSnapshot`] for **persistent room state** (snapshot/restore/merge, **atomic** disk
//!   persistence) and resume-by-identity sequence recovery.
//! - [`caps`] — capability resolution and the host-side [`caps::Gate`] that authorizes a signed
//!   `ce-cap` chain before admitting a joiner or honoring a moderation action in a gated room.
//! - [`admit`] — the host-side [`admit::Admitter`]: the full gated-room admission flow over the gate,
//!   plus participant **reconnection** via an HMAC-SHA256'd, identity-bound [`proto::ResumeToken`].
//! - [`order`] — [`order::OrderedInbox`] / [`order::SignalRouter`]: per-peer reorder buffers giving
//!   the in-order, de-duplicated SDP/ICE delivery a WebRTC negotiation needs (**ordering guarantees**).
//! - [`client`] — [`client::MeetClient`], the participant-facing signaling client over [`ce_rs`],
//!   including a **real-time SSE-driven event loop** ([`client::MeetClient::event_loop`]) and a
//!   configurable directed-signal **freshness window**.
//! - [`turn`] — STUN/TURN config types, channel-bound ephemeral [`turn::TurnCredential`] derivation
//!   (HMAC-SHA256, constant-time verify), and relay **selection** ([`turn::select_relay`]) for the
//!   media plane.
//!
//! ## What CE provides (composed, not reinvented)
//!
//! Mesh pubsub (rooms/signaling) + directed app messaging (admission) + `ce-cap` (room gating) +
//! identity (every published envelope is signed, so `from` is unforgeable). Money for the TURN/SFU
//! media tiers is integer base units settled over CE payment channels, exactly like every other CE
//! service. No new node endpoints; this is an app over the SDK.
//!
//! ## Implemented vs planned (the honest boundary)
//!
//! **Implemented (real code, tested):** the entire signaling/roster/admission/ordering state machine;
//! all media-control, chat, reaction, recording-consent and moderation *signals* and their roster
//! effects; bounds/DoS guards; HMAC resume tokens and TURN credentials; relay-candidate ranking;
//! atomic snapshot persistence; the SSE event loop. The *media plane itself* (audio/video RTP) is
//! browser WebRTC and is intentionally not in this crate.
//!
//! **Planned (config/selection here, live wiring deferred to the host/relay):** the `coturn`-class
//! TURN sidecar on relay nodes and the channel-bound credential-issuance endpoint that
//! [`turn::TurnCredential`] derives for; the live `find_service(`[`turn::SERVICE_TURN`]`)` discovery
//! that feeds [`turn::select_relay`]; and the SFU cell image for large rooms (the signaling layer is
//! already SFU-ready because an SFU joins as an ordinary roster member). See [`turn`] for detail.
//!
//! ```no_run
//! use ce_meet::{client::{MeetClient, new_room_id, now_secs}, proto::Signal};
//! use ce_rs::CeClient;
//! # async fn demo() -> anyhow::Result<()> {
//! let ce = CeClient::local();
//! let me = ce.status().await?.node_id;
//! let room_id = new_room_id(&me, 1, now_secs());
//! let mut client = MeetClient::new(ce, room_id, me);
//! client.subscribe().await?;
//! client.announce_join(Some("Leif".into())).await?;
//! // ... later, after a browser produces an offer for `peer`:
//! client.signal_peer("peer_node_id_hex", Signal::Offer { sdp: "v=0...".into() }).await?;
//! # Ok(()) }
//! ```

pub mod admit;
pub mod caps;
pub mod client;
pub mod order;
pub mod proto;
pub mod room;
pub mod turn;

pub use admit::Admitter;
pub use caps::Gate;
pub use client::{MeetClient, new_room_id, now_secs};
pub use order::{OrderedInbox, SignalRouter};
pub use proto::{
    ABILITY_HOST, ABILITY_JOIN, ABILITY_MODERATE, AdmitReq, AdmitResp, MAX_CANDIDATE_LEN,
    MAX_CHAT_LEN, MAX_ENVELOPE_BYTES, MAX_NAME_LEN, MAX_REACTION_LEN, MAX_SDP_LEN, ResumeToken,
    Signal, SignalEnvelope, room_topic,
};
pub use room::{Effect, Member, Room, RoomSnapshot, DEFAULT_MAX_MEMBERS};
pub use turn::{IceServer, RelayCandidate, SERVICE_TURN, TurnCredential, select_relay};
