//! [`MeetClient`]: the participant-facing signaling client over the CE SDK.
//!
//! Wraps a [`ce_rs::CeClient`] with ce-meet semantics: derive/create a room id, subscribe to the
//! room topic, publish join/leave/keepalive and directed SDP/ICE envelopes, and drain received
//! envelopes into roster [`Effect`]s. All transport is CE pubsub + directed app messaging — there is
//! no ce-meet server. The host of a gated room runs the [`crate::caps::Gate`] over the `request`/
//! `reply` admission channel; this client presents its capability chain there.

use crate::proto::{AdmitReq, AdmitResp, Signal, SignalEnvelope, TOPIC_ADMIT, room_topic};
use crate::room::{Effect, Room};
use anyhow::{Result, anyhow};
use ce_rs::CeClient;
use sha2::{Digest, Sha256};

/// Generate a fresh, unguessable room id: `sha256(creator || nonce || now)` truncated to 32 hex
/// chars. Deterministic topic derivation ([`room_topic`]) means no central registry is needed.
pub fn new_room_id(creator_hex: &str, nonce: u64, now: u64) -> String {
    let mut h = Sha256::new();
    h.update(creator_hex.as_bytes());
    h.update(nonce.to_le_bytes());
    h.update(now.to_le_bytes());
    let full = hex::encode(h.finalize());
    full[..32].to_string()
}

/// Current unix seconds, or 0 if the clock is before the epoch (never in practice).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A participant's signaling client for one room.
pub struct MeetClient {
    ce: CeClient,
    room: Room,
}

impl MeetClient {
    /// Build a client bound to a local CE node and a room, for participant `me` (NodeId hex). Get
    /// `me` from `ce.status().await?.node_id`.
    pub fn new(ce: CeClient, room_id: impl Into<String>, me: impl Into<String>) -> Self {
        let room_id = room_id.into();
        let me = me.into();
        MeetClient { ce, room: Room::new(room_id, me) }
    }

    /// The room id this client is bound to.
    pub fn room_id(&self) -> &str {
        self.room.room_id()
    }

    /// A read-only view of the local roster state.
    pub fn room(&self) -> &Room {
        &self.room
    }

    /// Subscribe to the room's pubsub topic so this node receives signaling envelopes. Idempotent.
    pub async fn subscribe(&self) -> Result<()> {
        self.ce.subscribe(&room_topic(self.room.room_id())).await
    }

    /// Publish a `Join` to the room (announce presence). `display_name` is cosmetic only.
    pub async fn announce_join(&mut self, display_name: Option<String>) -> Result<()> {
        let seq = self.room.next_outbound_seq();
        let env = SignalEnvelope::broadcast(
            self.room.room_id(),
            seq,
            now_secs(),
            Signal::Join { display_name },
        );
        self.publish(&env).await
    }

    /// Publish a `Leave` to the room.
    pub async fn announce_leave(&mut self) -> Result<()> {
        let seq = self.room.next_outbound_seq();
        let env = SignalEnvelope::broadcast(self.room.room_id(), seq, now_secs(), Signal::Leave);
        self.publish(&env).await
    }

    /// Publish a `Keepalive` to the room (liveness; keeps peers from pruning us).
    pub async fn keepalive(&mut self) -> Result<()> {
        let seq = self.room.next_outbound_seq();
        let env = SignalEnvelope::broadcast(self.room.room_id(), seq, now_secs(), Signal::Keepalive);
        self.publish(&env).await
    }

    /// Send a directed [`Signal`] (SDP offer/answer, ICE candidate) to a specific peer. The envelope
    /// rides the room topic; only the addressed peer acts on it.
    pub async fn signal_peer(&mut self, to: &str, signal: Signal) -> Result<()> {
        let seq = self.room.next_outbound_seq();
        let env = SignalEnvelope::directed(self.room.room_id(), to, seq, now_secs(), signal);
        self.publish(&env).await
    }

    /// Low-level publish of a pre-built envelope onto the room topic.
    pub async fn publish(&self, env: &SignalEnvelope) -> Result<()> {
        self.ce.publish(&room_topic(self.room.room_id()), &env.to_bytes()).await
    }

    /// Poll the node's app-message inbox, decode every envelope on this room's topic, stamp it with
    /// its authenticated sender, apply it to the roster, and return the resulting effects (skipping
    /// our own echoes and `NoChange`). This is the pull-based loop a CLI runs on a timer; a real-time
    /// app would instead drive [`apply_message`] from the SSE message stream.
    pub async fn poll(&mut self) -> Result<Vec<Effect>> {
        let msgs = self.ce.messages().await?;
        let topic = room_topic(self.room.room_id());
        let me = self.room.me().to_string();
        let mut effects = Vec::new();
        for m in msgs {
            if m.topic != topic {
                continue;
            }
            if m.from == me {
                continue; // ignore our own published echoes
            }
            let bytes = match m.payload() {
                Ok(b) => b,
                Err(_) => continue, // malformed payload hex — skip, never panic
            };
            if let Some(eff) = self.apply_message(&m.from, &bytes) {
                effects.push(eff);
            }
        }
        Ok(effects)
    }

    /// Apply one raw received message (authenticated `from` + payload bytes) to the roster. Returns
    /// `Some(effect)` for a meaningful change, `None` for malformed input or no-ops. Pure-ish: it
    /// mutates the local roster but does no I/O — usable directly from an SSE stream handler.
    pub fn apply_message(&mut self, from: &str, payload: &[u8]) -> Option<Effect> {
        let env = SignalEnvelope::from_bytes(payload).ok()?.with_sender(from);
        match self.room.apply(&env) {
            Effect::NoChange => None,
            eff => Some(eff),
        }
    }

    /// Request admission to a **gated** room from its `host` (NodeId hex), presenting `caps_hex`.
    /// Uses the SDK `request`/`reply` transport on [`TOPIC_ADMIT`]. Returns the host's
    /// [`AdmitResp`] (including the ICE servers to configure). `timeout_ms` bounds the wait.
    pub async fn request_admission(
        &self,
        host: &str,
        caps_hex: &str,
        display_name: Option<String>,
        timeout_ms: u64,
    ) -> Result<AdmitResp> {
        let req = AdmitReq {
            room_id: self.room.room_id().to_string(),
            caps: caps_hex.to_string(),
            display_name,
        };
        let payload = serde_json::to_vec(&req)?;
        let reply = self.ce.request(host, TOPIC_ADMIT, &payload, timeout_ms).await?;
        serde_json::from_slice(&reply).map_err(|e| anyhow!("malformed admit reply: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_id_is_deterministic_and_short() {
        let a = new_room_id("creator", 1, 1000);
        let b = new_room_id("creator", 1, 1000);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn room_id_varies_with_inputs() {
        assert_ne!(new_room_id("creator", 1, 1000), new_room_id("creator", 2, 1000));
        assert_ne!(new_room_id("a", 1, 1000), new_room_id("b", 1, 1000));
    }

    #[test]
    fn apply_message_updates_roster() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let env = SignalEnvelope::broadcast("room", 0, now_secs(), Signal::Join { display_name: None });
        let eff = client.apply_message("peerA", &env.to_bytes());
        assert_eq!(eff, Some(Effect::Joined("peerA".into())));
        assert_eq!(client.room().present(), vec!["peerA"]);
    }

    #[test]
    fn apply_message_rejects_garbage_without_panic() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        assert_eq!(client.apply_message("peerA", b"not json"), None);
        assert_eq!(client.apply_message("peerA", b"{}"), None);
    }

    #[test]
    fn apply_message_ignores_other_room() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let env = SignalEnvelope::broadcast("OTHER", 0, 1, Signal::Join { display_name: None });
        assert_eq!(client.apply_message("peerA", &env.to_bytes()), None);
    }

    #[test]
    fn apply_message_directed_surfaces_envelope() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let env =
            SignalEnvelope::directed("room", "me", 0, 1, Signal::Offer { sdp: "v=0".into() });
        match client.apply_message("peerA", &env.to_bytes()) {
            Some(Effect::Directed(e)) => assert_eq!(e.from, "peerA"),
            other => panic!("expected Directed, got {other:?}"),
        }
    }
}
