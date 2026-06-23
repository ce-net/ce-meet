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
//!   a [`proto::Signal`] (join/leave/keepalive/offer/answer/ICE), plus the gated-room admission
//!   request/response and the opaque capability abilities.
//! - [`room`] — the [`room::Room`] roster state machine: a per-member last-writer-wins register keyed
//!   by NodeId and ordered by the sender's own monotonic `seq`, so membership **converges** under the
//!   unordered, lossy, duplicating delivery that pubsub gives — order of arrival does not matter.
//! - [`caps`] — capability resolution and the host-side [`caps::Gate`] that authorizes a signed
//!   `ce-cap` chain before admitting a joiner to a gated room.
//! - [`client`] — [`client::MeetClient`], the participant-facing signaling client over [`ce_rs`].
//! - [`turn`] — STUN/TURN config types and the documented **TURN-via-relay** (paid, channel-bound)
//!   and SFU-cell plan for the media plane.
//!
//! ## What CE provides (composed, not reinvented)
//!
//! Mesh pubsub (rooms/signaling) + directed app messaging (admission) + `ce-cap` (room gating) +
//! identity (every published envelope is signed, so `from` is unforgeable). Money for the TURN/SFU
//! media tiers is integer base units settled over CE payment channels, exactly like every other CE
//! service. No new node endpoints; this is an app over the SDK.
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

pub mod caps;
pub mod client;
pub mod proto;
pub mod room;
pub mod turn;

pub use caps::Gate;
pub use client::{MeetClient, new_room_id, now_secs};
pub use proto::{
    AdmitReq, AdmitResp, Signal, SignalEnvelope, ABILITY_HOST, ABILITY_JOIN, ABILITY_MODERATE,
    room_topic,
};
pub use room::{Effect, Member, Room};
pub use turn::{IceServer, TurnCredential};
