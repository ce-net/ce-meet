//! ce-meet wire protocol: the typed messages exchanged over the CE mesh for WebRTC signaling.
//!
//! A **room** is a CE pubsub topic. Every participant subscribes to the room topic and publishes
//! signaling envelopes onto it; the node signs each publish with the participant's identity, so
//! every received envelope carries a cryptographically authenticated `from` NodeId. ce-meet is the
//! *signaling* plane only — it carries SDP offers/answers and ICE candidates between peers so their
//! browsers can establish a direct WebRTC connection. The **media** plane never touches CE: audio
//! and video flow peer-to-peer (or via a TURN relay; see [`crate::turn`]), end-to-end, so no node
//! ever sees the call.
//!
//! ## Message shape
//!
//! Every message on a room topic is a [`SignalEnvelope`]: an addressed, sequence-numbered wrapper
//! around a [`Signal`] payload. The envelope gives us:
//! - **addressing**: `to` is `None` for a room broadcast (join/leave/roster) or `Some(node)` for a
//!   directed offer/answer/candidate aimed at one peer (everyone else ignores it);
//! - **ordering**: a per-sender monotonic `seq` lets a receiver detect drops and reorder the
//!   out-of-order SDP/ICE flow that pubsub does not guarantee;
//! - **freshness**: `sent_at` (unix seconds) lets receivers discard stale candidates.
//!
//! Payloads are JSON, hex-encoded by the SDK's `publish`/`request` transport. The room id is mixed
//! into the topic, never trusted from the body — a peer cannot forge membership of another room.
//!
//! ## Abilities (capability-gated rooms)
//!
//! A room may be **open** (anyone may join) or **gated** (a host admits peers). Gating is enforced
//! by a room host that authorizes a presented `ce-cap` chain against these opaque abilities before
//! admitting the joiner or honoring a moderation action. CE assigns the strings no meaning; the
//! host's [`crate::caps`] gate does.

use serde::{Deserialize, Serialize};

/// Topic prefix for all ce-meet room topics. The full topic is `meet/room/<room_id>`.
pub const TOPIC_PREFIX: &str = "meet/room/";

/// The directed app-message topic a host listens on for admission requests to gated rooms.
/// (Used with the SDK `request`/`reply` transport, not the broadcast room topic.)
pub const TOPIC_ADMIT: &str = "meet/admit";

/// Ability: join (be admitted to) a gated room.
pub const ABILITY_JOIN: &str = "meet:join";
/// Ability: host/own a room — admit and remove participants, end the room.
pub const ABILITY_HOST: &str = "meet:host";
/// Ability: moderate — remove (kick) a participant without owning the room.
pub const ABILITY_MODERATE: &str = "meet:moderate";

/// The pubsub topic for a room. Deterministic from the room id; both the joiner and the host derive
/// the same string, so no out-of-band topic exchange is needed.
pub fn room_topic(room_id: &str) -> String {
    format!("{TOPIC_PREFIX}{room_id}")
}

/// The inverse of [`room_topic`]: extract the room id from a topic string, if it is a room topic.
pub fn room_id_of(topic: &str) -> Option<&str> {
    topic.strip_prefix(TOPIC_PREFIX)
}

/// The signaling payload — what one participant tells another (or the room) to advance call setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Signal {
    /// A participant announces it has joined the room. Broadcast (`to == None`). Carries an optional
    /// human display name (never trusted for identity — the authenticated `from` NodeId is identity).
    Join {
        /// Optional human-facing display name.
        #[serde(default)]
        display_name: Option<String>,
    },
    /// A participant announces it is leaving the room. Broadcast.
    Leave,
    /// A periodic liveness ping so peers can prune participants that vanished without a `Leave`.
    /// Broadcast.
    Keepalive,
    /// A WebRTC SDP offer, directed at one peer (`to == Some(peer)`). `sdp` is the opaque
    /// session-description blob the receiving browser feeds to `setRemoteDescription`.
    Offer { sdp: String },
    /// A WebRTC SDP answer, directed at the peer whose offer this answers.
    Answer { sdp: String },
    /// A single ICE candidate, directed at one peer. Trickle-ICE: candidates stream as they are
    /// gathered. `candidate` is the SDP candidate line; `sdp_mid` / `sdp_m_line_index` locate it.
    IceCandidate {
        candidate: String,
        #[serde(default)]
        sdp_mid: Option<String>,
        #[serde(default)]
        sdp_m_line_index: Option<u32>,
    },
    /// End-of-candidates marker for a media section (an empty trickle-ICE candidate). Directed.
    IceEnd,
}

impl Signal {
    /// Is this a room-wide broadcast (membership/liveness) rather than a directed peer message?
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Signal::Join { .. } | Signal::Leave | Signal::Keepalive)
    }

    /// A short tag for logging/metrics.
    pub fn tag(&self) -> &'static str {
        match self {
            Signal::Join { .. } => "join",
            Signal::Leave => "leave",
            Signal::Keepalive => "keepalive",
            Signal::Offer { .. } => "offer",
            Signal::Answer { .. } => "answer",
            Signal::IceCandidate { .. } => "ice",
            Signal::IceEnd => "ice_end",
        }
    }
}

/// An addressed, sequence-numbered signaling envelope published onto a room topic.
///
/// `from` is **not** filled in by the sender: the receiver overwrites it with the cryptographically
/// authenticated NodeId the CE node reports for the publish, so a peer can never spoof another's
/// `from`. On the wire the sender leaves it empty; [`SignalEnvelope::with_sender`] stamps it on
/// receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// The room this envelope belongs to. Cross-checked against the topic on receipt.
    pub room_id: String,
    /// Authenticated sender NodeId (hex). Empty on the wire; stamped from the transport on receipt.
    #[serde(default)]
    pub from: String,
    /// Directed recipient NodeId (hex), or `None` for a room broadcast.
    #[serde(default)]
    pub to: Option<String>,
    /// Per-sender monotonic sequence number — lets receivers order and detect dropped messages.
    pub seq: u64,
    /// Unix seconds when the sender emitted this (freshness; discard stale candidates).
    pub sent_at: u64,
    /// The signaling payload.
    pub signal: Signal,
}

impl SignalEnvelope {
    /// Build an envelope to broadcast to the whole room.
    pub fn broadcast(room_id: impl Into<String>, seq: u64, sent_at: u64, signal: Signal) -> Self {
        SignalEnvelope { room_id: room_id.into(), from: String::new(), to: None, seq, sent_at, signal }
    }

    /// Build an envelope directed at a single peer.
    pub fn directed(
        room_id: impl Into<String>,
        to: impl Into<String>,
        seq: u64,
        sent_at: u64,
        signal: Signal,
    ) -> Self {
        SignalEnvelope {
            room_id: room_id.into(),
            from: String::new(),
            to: Some(to.into()),
            seq,
            sent_at,
            signal,
        }
    }

    /// Serialize to JSON bytes for the pubsub transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Infallible for these plain types; fall back to an empty object on the impossible error.
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Parse an envelope from JSON bytes received off a room topic. Rejects malformed input with a
    /// descriptive error (never panics).
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("malformed ce-meet signal envelope: {e}"))
    }

    /// Return a copy with `from` stamped to the authenticated sender the transport reported.
    pub fn with_sender(mut self, from: impl Into<String>) -> Self {
        self.from = from.into();
        self
    }

    /// Is this envelope addressed to `me` — either a broadcast or a direct message to `me`?
    pub fn addressed_to(&self, me: &str) -> bool {
        match &self.to {
            None => true,
            Some(t) => t == me,
        }
    }
}

/// Admission request sent (via the SDK `request`/`reply` transport) by a joiner to a gated room's
/// host. The host authorizes `caps` against [`ABILITY_JOIN`] before replying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmitReq {
    /// The room being joined.
    pub room_id: String,
    /// Hex-encoded `ce-cap` capability chain granting `meet:join` on the host.
    pub caps: String,
    /// Optional human display name to register in the roster.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// The host's reply to an [`AdmitReq`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmitResp {
    /// Whether the joiner was admitted.
    pub admitted: bool,
    /// Human-readable reason when `admitted == false` (e.g. the capability error).
    #[serde(default)]
    pub reason: Option<String>,
    /// The ICE servers (STUN/TURN) the joiner should configure on its WebRTC PeerConnection. Empty
    /// for a pure peer-to-peer room with no relay. See [`crate::turn`].
    #[serde(default)]
    pub ice_servers: Vec<crate::turn::IceServer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_topic_roundtrips() {
        let t = room_topic("abc123");
        assert_eq!(t, "meet/room/abc123");
        assert_eq!(room_id_of(&t), Some("abc123"));
        assert_eq!(room_id_of("other/topic"), None);
    }

    #[test]
    fn signal_classification() {
        assert!(Signal::Join { display_name: None }.is_broadcast());
        assert!(Signal::Leave.is_broadcast());
        assert!(Signal::Keepalive.is_broadcast());
        assert!(!Signal::Offer { sdp: "v=0".into() }.is_broadcast());
        assert!(!Signal::Answer { sdp: "v=0".into() }.is_broadcast());
        assert_eq!(Signal::IceEnd.tag(), "ice_end");
    }

    #[test]
    fn envelope_broadcast_has_no_recipient() {
        let e = SignalEnvelope::broadcast("r", 1, 100, Signal::Leave);
        assert!(e.to.is_none());
        assert!(e.addressed_to("anyone"));
    }

    #[test]
    fn envelope_directed_addresses_only_target() {
        let e = SignalEnvelope::directed("r", "peerB", 2, 100, Signal::Offer { sdp: "x".into() });
        assert!(e.addressed_to("peerB"));
        assert!(!e.addressed_to("peerC"));
    }

    #[test]
    fn envelope_bytes_roundtrip() {
        let e = SignalEnvelope::directed(
            "room",
            "peer",
            7,
            12345,
            Signal::IceCandidate {
                candidate: "candidate:1 1 UDP".into(),
                sdp_mid: Some("0".into()),
                sdp_m_line_index: Some(0),
            },
        );
        let bytes = e.to_bytes();
        let back = SignalEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(SignalEnvelope::from_bytes(b"not json").is_err());
        assert!(SignalEnvelope::from_bytes(b"{}").is_err()); // missing required fields
    }

    #[test]
    fn with_sender_stamps_from() {
        let e = SignalEnvelope::broadcast("r", 1, 0, Signal::Keepalive).with_sender("nodeX");
        assert_eq!(e.from, "nodeX");
    }

    #[test]
    fn sdp_offer_answer_roundtrip() {
        let offer = Signal::Offer { sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n".into() };
        let j = serde_json::to_string(&offer).unwrap();
        let back: Signal = serde_json::from_str(&j).unwrap();
        assert_eq!(offer, back);
        assert!(j.contains("\"kind\":\"offer\""));
    }
}
