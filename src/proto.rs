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
/// Ability: moderate — remove (kick) a participant or force-mute them without owning the room.
pub const ABILITY_MODERATE: &str = "meet:moderate";

// ---- Wire safety bounds (DoS hardening) ----------------------------------------------------
//
// Every length below caps an externally-supplied, attacker-controlled string so a peer cannot
// publish a multi-megabyte blob and exhaust memory across the whole room. The numbers are generous
// relative to real WebRTC traffic (a full SDP for a many-track call is a few kilobytes; a single ICE
// candidate line is well under 256 bytes; a display name or chat line is a short human string) yet
// small enough that the worst case is bounded. [`Signal::validate`] enforces them and
// [`SignalEnvelope::from_bytes`] rejects an over-cap raw frame before it is even parsed.

/// Maximum accepted size, in bytes, of a single serialized [`SignalEnvelope`] frame off the wire.
/// A full multi-track SDP plus envelope overhead fits comfortably; anything larger is rejected.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Maximum length of an SDP blob (offer/answer body).
pub const MAX_SDP_LEN: usize = 32 * 1024;
/// Maximum length of a single ICE candidate line.
pub const MAX_CANDIDATE_LEN: usize = 1024;
/// Maximum length of an `sdp_mid` media-stream identifier.
pub const MAX_MID_LEN: usize = 256;
/// Maximum length of a human display name.
pub const MAX_NAME_LEN: usize = 128;
/// Maximum length of an in-call chat message body.
pub const MAX_CHAT_LEN: usize = 4 * 1024;
/// Maximum length of a reaction token (an emoji or short symbolic name, e.g. `thumbsup`).
pub const MAX_REACTION_LEN: usize = 64;
/// Maximum length of a moderation/leave reason string.
pub const MAX_REASON_LEN: usize = 512;

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

    // ---- In-call media-control signaling (broadcast; mirror Google Meet's per-tile state) ----
    /// A participant's live audio/video mute state. Broadcast so every roster tile shows whether the
    /// member is muted and whether their camera is on. The *state* is signaled here; the actual media
    /// stop/start happens in the browser's WebRTC stack.
    Media {
        /// True when the microphone is muted (no audio sent).
        audio_muted: bool,
        /// True when the camera is off (no video sent).
        video_muted: bool,
    },
    /// A participant started or stopped sharing their screen. Broadcast. Meet shows a "presenting"
    /// badge; consumers light it up from this.
    ScreenShare {
        /// True when actively presenting a screen/window.
        active: bool,
    },
    /// A participant raised or lowered their hand. Broadcast.
    RaiseHand {
        /// True = hand raised, false = lowered.
        raised: bool,
    },
    /// A transient reaction (emoji/symbol) to flash on screen. Broadcast; not retained in the roster.
    Reaction {
        /// A short reaction token — an emoji or a symbolic name like `thumbsup`. Bounded length.
        emoji: String,
    },
    /// An in-call text chat line. Broadcast to the whole room (Meet's chat panel). Not retained as
    /// roster state; the caller appends it to its own transcript.
    Chat {
        /// The chat message body. Bounded length; never trusted as anything but display text.
        body: String,
    },

    // ---- Recording-consent signaling (broadcast) ----
    /// Someone began (or stopped) recording the call. Broadcast so every participant is informed and
    /// can consent or leave — ce-meet performs no recording itself; this is the consent/notice signal.
    Recording {
        /// True = recording started, false = recording stopped.
        active: bool,
    },

    // ---- Host/moderator control (directed at the affected participant; broadcast for EndRoom) ----
    /// A host/moderator removes a participant from the room. Directed at the kicked NodeId. The
    /// affected client leaves; other clients prune the member on the matching `Leave`/liveness. The
    /// sender must hold [`ABILITY_HOST`] or [`ABILITY_MODERATE`] (enforced by the host's gate).
    Kick {
        /// Optional human-readable reason, surfaced to the removed participant. Bounded length.
        #[serde(default)]
        reason: Option<String>,
    },
    /// A host/moderator force-mutes a participant's audio (the "mute everyone"/"mute participant"
    /// control). Directed at the target NodeId, which should mute locally and broadcast its `Media`
    /// state. Requires [`ABILITY_HOST`] or [`ABILITY_MODERATE`].
    ForceMute {
        /// True = force-mute audio, false = allow unmute (request the participant to unmute).
        audio_muted: bool,
    },
    /// The host ends the room for everyone. Broadcast. Clients tear down and leave on receipt.
    /// Requires [`ABILITY_HOST`].
    EndRoom {
        /// Optional reason shown to all participants. Bounded length.
        #[serde(default)]
        reason: Option<String>,
    },
}

impl Signal {
    /// Is this a room-wide broadcast (membership/liveness/media-state/chat) rather than a directed
    /// peer message? Directed signals carry a `to` recipient; broadcasts do not.
    pub fn is_broadcast(&self) -> bool {
        matches!(
            self,
            Signal::Join { .. }
                | Signal::Leave
                | Signal::Keepalive
                | Signal::Media { .. }
                | Signal::ScreenShare { .. }
                | Signal::RaiseHand { .. }
                | Signal::Reaction { .. }
                | Signal::Chat { .. }
                | Signal::Recording { .. }
                | Signal::EndRoom { .. }
        )
    }

    /// Is this a host/moderator control action whose sender must be authorized (kick / force-mute /
    /// end-room)? The host gate enforces the capability before the action is honored.
    pub fn is_moderation(&self) -> bool {
        matches!(
            self,
            Signal::Kick { .. } | Signal::ForceMute { .. } | Signal::EndRoom { .. }
        )
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
            Signal::Media { .. } => "media",
            Signal::ScreenShare { .. } => "screenshare",
            Signal::RaiseHand { .. } => "raisehand",
            Signal::Reaction { .. } => "reaction",
            Signal::Chat { .. } => "chat",
            Signal::Recording { .. } => "recording",
            Signal::Kick { .. } => "kick",
            Signal::ForceMute { .. } => "forcemute",
            Signal::EndRoom { .. } => "endroom",
        }
    }

    /// Validate that all attacker-controlled string fields are within their wire bounds (see the
    /// `MAX_*` constants). Returns `Ok(())` for a well-formed signal, `Err(reason)` (safe to log)
    /// when any field exceeds its cap. Called on every received signal before it touches room state,
    /// so an oversized blob can never be forwarded to a WebRTC stack or retained in a roster.
    pub fn validate(&self) -> Result<(), String> {
        fn check(field: &str, s: &str, max: usize) -> Result<(), String> {
            if s.len() > max {
                Err(format!("{field} exceeds {max} bytes ({} bytes)", s.len()))
            } else {
                Ok(())
            }
        }
        match self {
            Signal::Join { display_name } => {
                if let Some(n) = display_name {
                    check("display_name", n, MAX_NAME_LEN)?;
                }
            }
            Signal::Offer { sdp } | Signal::Answer { sdp } => check("sdp", sdp, MAX_SDP_LEN)?,
            Signal::IceCandidate { candidate, sdp_mid, .. } => {
                check("candidate", candidate, MAX_CANDIDATE_LEN)?;
                if let Some(m) = sdp_mid {
                    check("sdp_mid", m, MAX_MID_LEN)?;
                }
            }
            Signal::Reaction { emoji } => check("reaction", emoji, MAX_REACTION_LEN)?,
            Signal::Chat { body } => check("chat", body, MAX_CHAT_LEN)?,
            Signal::Kick { reason } | Signal::EndRoom { reason } => {
                if let Some(r) = reason {
                    check("reason", r, MAX_REASON_LEN)?;
                }
            }
            // Variants with no unbounded string fields are always valid.
            Signal::Leave
            | Signal::Keepalive
            | Signal::IceEnd
            | Signal::Media { .. }
            | Signal::ScreenShare { .. }
            | Signal::RaiseHand { .. }
            | Signal::Recording { .. }
            | Signal::ForceMute { .. } => {}
        }
        Ok(())
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

    /// Serialize to JSON bytes for the pubsub transport. Infallible in practice for these plain
    /// `Serialize` types, but the error is surfaced rather than masked so a future non-trivial field
    /// that breaks serialization is caught instead of silently emitting an empty frame.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow::anyhow!("serialize ce-meet envelope: {e}"))
    }

    /// Parse an envelope from JSON bytes received off a room topic and validate its bounds. Rejects:
    /// a frame larger than [`MAX_ENVELOPE_BYTES`] (before parsing, so a giant blob is cheap to drop),
    /// malformed JSON, and any signal whose fields exceed their `MAX_*` caps. Never panics.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            anyhow::bail!(
                "ce-meet envelope too large: {} bytes (max {MAX_ENVELOPE_BYTES})",
                bytes.len()
            );
        }
        let env: SignalEnvelope = serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("malformed ce-meet signal envelope: {e}"))?;
        env.signal
            .validate()
            .map_err(|reason| anyhow::anyhow!("invalid ce-meet signal: {reason}"))?;
        Ok(env)
    }

    /// Is this envelope fresh enough to act on, given the receiver's clock `now` (unix seconds) and a
    /// `max_age_secs` window? Returns true when `sent_at` is within `[now - max_age_secs, now +
    /// CLOCK_SKEW_SLACK]`. A `max_age_secs` of 0 disables the check (always fresh). Stale directed
    /// candidates (a far-future or long-past `sent_at`) are dropped by callers that enforce freshness;
    /// see [`crate::client::MeetClient`]. This makes the `sent_at` field load-bearing rather than
    /// merely documented.
    pub fn is_fresh(&self, now: u64, max_age_secs: u64) -> bool {
        if max_age_secs == 0 {
            return true;
        }
        // Reject envelopes claiming to be from too far in the future (clock skew or forgery).
        const CLOCK_SKEW_SLACK: u64 = 120;
        if self.sent_at > now.saturating_add(CLOCK_SKEW_SLACK) {
            return false;
        }
        now.saturating_sub(self.sent_at) <= max_age_secs
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmitReq {
    /// The room being joined.
    pub room_id: String,
    /// Hex-encoded `ce-cap` capability chain granting `meet:join` on the host.
    pub caps: String,
    /// Optional human display name to register in the roster.
    #[serde(default)]
    pub display_name: Option<String>,
    /// A resume token from a prior admission, presented to skip the capability handshake on a
    /// reconnect. When present and valid for the authenticated sender, the host re-admits by identity.
    #[serde(default)]
    pub resume: Option<ResumeToken>,
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
    /// A short-lived resume token the joiner presents to skip re-authorization on reconnect. `None`
    /// when not admitted. The joiner stores it and, after a drop, re-attaches with it instead of
    /// re-running the full capability handshake. See [`ResumeToken`].
    #[serde(default)]
    pub resume: Option<ResumeToken>,
}

/// A capability-gate resume token. After a participant is admitted to a gated room, the host issues
/// one of these keyed to the participant's identity; on a later reconnect the participant presents it
/// (in [`AdmitReq::resume`]) to be re-admitted **by identity** without re-presenting the full
/// capability chain — as long as it has not expired and the participant is the same node.
///
/// It is not a bearer secret to a third party: the host re-derives and re-checks it against the
/// authenticated reconnecting NodeId, so a stolen token used by a different node is rejected. The
/// `seq_floor` carries the participant's last-known outbound sequence so the resumed session never
/// re-uses a `seq` a peer would drop (see [`crate::room::Room::resume_outbound_from`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeToken {
    /// The room this token is valid for.
    pub room_id: String,
    /// The NodeId (hex) the token was issued to — must equal the authenticated reconnecting sender.
    pub node_id: String,
    /// Unix seconds after which the token no longer resumes (the joiner must re-handshake).
    pub expires_at: u64,
    /// The participant's last-known outbound `seq` floor, restored on resume to preserve monotonicity.
    #[serde(default)]
    pub seq_floor: u64,
    /// Host-derived MAC over `(room_id, node_id, expires_at, seq_floor)` so the host verifies a token
    /// it issued without storing per-participant state. Hex-encoded.
    pub mac: String,
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
        let bytes = e.to_bytes().unwrap();
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

    #[test]
    fn admit_req_round_trips_with_and_without_resume() {
        let req = AdmitReq {
            room_id: "r".into(),
            caps: "abcd".into(),
            display_name: Some("Leif".into()),
            resume: None,
        };
        let back: AdmitReq = serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert_eq!(back.room_id, "r");
        assert!(back.resume.is_none());

        let tok = ResumeToken {
            room_id: "r".into(),
            node_id: "ab".repeat(32),
            expires_at: 5000,
            seq_floor: 9,
            mac: "deadbeef".into(),
        };
        let req2 = AdmitReq { resume: Some(tok.clone()), ..Default::default() };
        let back2: AdmitReq = serde_json::from_slice(&serde_json::to_vec(&req2).unwrap()).unwrap();
        assert_eq!(back2.resume, Some(tok));
    }

    #[test]
    fn admit_resp_round_trips_with_resume_and_ice() {
        let resp = AdmitResp {
            admitted: true,
            reason: None,
            ice_servers: vec![crate::turn::IceServer::stun("stun:x:3478")],
            resume: Some(ResumeToken {
                room_id: "r".into(),
                node_id: "ff".repeat(32),
                expires_at: 1000,
                seq_floor: 0,
                mac: "aa".into(),
            }),
        };
        let back: AdmitResp = serde_json::from_slice(&serde_json::to_vec(&resp).unwrap()).unwrap();
        assert!(back.admitted);
        assert_eq!(back.ice_servers.len(), 1);
        assert!(back.resume.is_some());
    }

    #[test]
    fn admit_resp_default_is_denied_with_no_resume() {
        let resp = AdmitResp::default();
        assert!(!resp.admitted);
        assert!(resp.resume.is_none());
        assert!(resp.ice_servers.is_empty());
    }

    // ---- new media-control / moderation signals ----

    #[test]
    fn media_control_signals_classify_as_broadcast() {
        assert!(Signal::Media { audio_muted: true, video_muted: false }.is_broadcast());
        assert!(Signal::ScreenShare { active: true }.is_broadcast());
        assert!(Signal::RaiseHand { raised: true }.is_broadcast());
        assert!(Signal::Reaction { emoji: "👍".into() }.is_broadcast());
        assert!(Signal::Chat { body: "hi".into() }.is_broadcast());
        assert!(Signal::Recording { active: true }.is_broadcast());
        assert!(Signal::EndRoom { reason: None }.is_broadcast());
    }

    #[test]
    fn directed_moderation_signals_are_not_broadcast() {
        assert!(!Signal::Kick { reason: None }.is_broadcast());
        assert!(!Signal::ForceMute { audio_muted: true }.is_broadcast());
    }

    #[test]
    fn moderation_classification() {
        assert!(Signal::Kick { reason: None }.is_moderation());
        assert!(Signal::ForceMute { audio_muted: true }.is_moderation());
        assert!(Signal::EndRoom { reason: None }.is_moderation());
        assert!(!Signal::Chat { body: "x".into() }.is_moderation());
        assert!(!Signal::Media { audio_muted: false, video_muted: false }.is_moderation());
    }

    #[test]
    fn new_signal_tags_are_stable() {
        assert_eq!(Signal::Media { audio_muted: true, video_muted: true }.tag(), "media");
        assert_eq!(Signal::ScreenShare { active: false }.tag(), "screenshare");
        assert_eq!(Signal::RaiseHand { raised: false }.tag(), "raisehand");
        assert_eq!(Signal::Reaction { emoji: "x".into() }.tag(), "reaction");
        assert_eq!(Signal::Chat { body: "x".into() }.tag(), "chat");
        assert_eq!(Signal::Recording { active: true }.tag(), "recording");
        assert_eq!(Signal::Kick { reason: None }.tag(), "kick");
        assert_eq!(Signal::ForceMute { audio_muted: true }.tag(), "forcemute");
        assert_eq!(Signal::EndRoom { reason: None }.tag(), "endroom");
    }

    #[test]
    fn new_signals_json_round_trip() {
        for sig in [
            Signal::Media { audio_muted: true, video_muted: false },
            Signal::ScreenShare { active: true },
            Signal::RaiseHand { raised: true },
            Signal::Reaction { emoji: "tada".into() },
            Signal::Chat { body: "hello world".into() },
            Signal::Recording { active: false },
            Signal::Kick { reason: Some("spam".into()) },
            Signal::ForceMute { audio_muted: true },
            Signal::EndRoom { reason: Some("done".into()) },
        ] {
            let j = serde_json::to_vec(&sig).unwrap();
            let back: Signal = serde_json::from_slice(&j).unwrap();
            assert_eq!(sig, back);
        }
    }

    // ---- bounds / validation ----

    #[test]
    fn validate_accepts_in_bounds_signals() {
        assert!(Signal::Offer { sdp: "v=0".repeat(10) }.validate().is_ok());
        assert!(Signal::Chat { body: "x".repeat(MAX_CHAT_LEN) }.validate().is_ok());
        assert!(Signal::Join { display_name: Some("Leif".into()) }.validate().is_ok());
        assert!(Signal::Reaction { emoji: "👍".into() }.validate().is_ok());
    }

    #[test]
    fn validate_rejects_oversized_sdp() {
        let big = Signal::Offer { sdp: "a".repeat(MAX_SDP_LEN + 1) };
        let err = big.validate().unwrap_err();
        assert!(err.contains("sdp"), "{err}");
    }

    #[test]
    fn validate_rejects_oversized_candidate_and_name_and_chat() {
        assert!(
            Signal::IceCandidate {
                candidate: "c".repeat(MAX_CANDIDATE_LEN + 1),
                sdp_mid: None,
                sdp_m_line_index: None,
            }
            .validate()
            .is_err()
        );
        assert!(Signal::Join { display_name: Some("n".repeat(MAX_NAME_LEN + 1)) }.validate().is_err());
        assert!(Signal::Chat { body: "c".repeat(MAX_CHAT_LEN + 1) }.validate().is_err());
        assert!(Signal::Reaction { emoji: "e".repeat(MAX_REACTION_LEN + 1) }.validate().is_err());
        assert!(Signal::Kick { reason: Some("r".repeat(MAX_REASON_LEN + 1)) }.validate().is_err());
    }

    #[test]
    fn from_bytes_rejects_oversized_frame_cheaply() {
        // A frame larger than the cap is rejected without trusting/parsing its contents.
        let huge = vec![b'x'; MAX_ENVELOPE_BYTES + 1];
        let err = SignalEnvelope::from_bytes(&huge).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn from_bytes_rejects_oversized_sdp_payload() {
        // A well-formed envelope whose SDP exceeds MAX_SDP_LEN is rejected at parse time.
        let env = SignalEnvelope::directed(
            "r",
            "peer",
            0,
            0,
            Signal::Offer { sdp: "a".repeat(MAX_SDP_LEN + 10) },
        );
        let bytes = env.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_ENVELOPE_BYTES, "frame itself is within the hard cap");
        let err = SignalEnvelope::from_bytes(&bytes).unwrap_err().to_string();
        assert!(err.contains("invalid ce-meet signal"), "{err}");
    }

    // ---- freshness ----

    #[test]
    fn freshness_window_disabled_is_always_fresh() {
        let e = SignalEnvelope::broadcast("r", 0, 1_000, Signal::Keepalive);
        assert!(e.is_fresh(9_999_999, 0));
    }

    #[test]
    fn freshness_rejects_stale_and_future() {
        let e = SignalEnvelope::broadcast("r", 0, 1_000, Signal::Keepalive);
        // within window
        assert!(e.is_fresh(1_030, 60));
        // too old
        assert!(!e.is_fresh(2_000, 60));
        // far future sent_at (skew/forgery) -> not fresh
        let future = SignalEnvelope::broadcast("r", 0, 10_000, Signal::Keepalive);
        assert!(!future.is_fresh(1_000, 60));
        // small future within skew slack is allowed
        let slight = SignalEnvelope::broadcast("r", 0, 1_050, Signal::Keepalive);
        assert!(slight.is_fresh(1_000, 60));
    }
}
