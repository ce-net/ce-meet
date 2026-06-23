//! [`MeetClient`]: the participant-facing signaling client over the CE SDK.
//!
//! Wraps a [`ce_rs::CeClient`] with ce-meet semantics: derive/create a room id, subscribe to the
//! room topic, publish join/leave/keepalive and directed SDP/ICE envelopes, and drain received
//! envelopes into roster [`Effect`]s. All transport is CE pubsub + directed app messaging — there is
//! no ce-meet server. The host of a gated room runs the [`crate::caps::Gate`] over the `request`/
//! `reply` admission channel; this client presents its capability chain there.

use crate::order::SignalRouter;
use crate::proto::{
    AdmitReq, AdmitResp, ResumeToken, Signal, SignalEnvelope, TOPIC_ADMIT, room_topic,
};
use crate::room::{Effect, Room, RoomSnapshot};
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
    /// Per-peer reorder buffer for directed SDP/ICE signals (in-order, de-duplicated delivery).
    router: SignalRouter,
}

impl MeetClient {
    /// Build a client bound to a local CE node and a room, for participant `me` (NodeId hex). Get
    /// `me` from `ce.status().await?.node_id`.
    pub fn new(ce: CeClient, room_id: impl Into<String>, me: impl Into<String>) -> Self {
        let room_id = room_id.into();
        let me = me.into();
        MeetClient { ce, room: Room::new(room_id, me), router: SignalRouter::new() }
    }

    /// Rebuild a client from a persisted [`RoomSnapshot`] (host or participant resuming after a
    /// crash). The roster, member LWW state, and outbound `seq` are restored intact; the directed-
    /// signal reorder buffer starts fresh (per-peer ordering re-anchors on the next directed signal).
    pub fn restore(ce: CeClient, snapshot: RoomSnapshot) -> Self {
        MeetClient { ce, room: Room::restore(snapshot), router: SignalRouter::new() }
    }

    /// The room id this client is bound to.
    pub fn room_id(&self) -> &str {
        self.room.room_id()
    }

    /// A read-only view of the local roster state.
    pub fn room(&self) -> &Room {
        &self.room
    }

    /// Capture the local roster state for persistence (see [`Room::snapshot`]).
    pub fn snapshot(&self) -> RoomSnapshot {
        self.room.snapshot()
    }

    /// Restore this client's outbound sequence floor on reconnect, so a resumed session never re-uses
    /// a `seq` peers would drop. Pass the `seq_floor` from a [`ResumeToken`] (or a persisted
    /// snapshot's `next_seq`). Returns the new outbound seq. See [`Room::resume_outbound_from`].
    pub fn resume_outbound_from(&mut self, floor: u64) -> u64 {
        self.room.resume_outbound_from(floor)
    }

    /// Adopt the `seq_floor` carried by a host's [`ResumeToken`] after a successful reconnect, so the
    /// resumed session continues its monotonic outbound sequence. Convenience over
    /// [`MeetClient::resume_outbound_from`].
    pub fn adopt_resume(&mut self, tok: &ResumeToken) -> u64 {
        self.room.resume_outbound_from(tok.seq_floor)
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

    /// Apply one raw received message and, if it is a **directed signal addressed to us**, feed it
    /// through the per-peer reorder buffer — returning the directed signals that are now deliverable
    /// to our WebRTC stack **in the sender's `seq` order**, de-duplicated. Membership (join/leave/
    /// keepalive) is still applied to the roster as a side effect (drop the returned [`Effect`] if you
    /// only want the ordered signals). Directed signals not addressed to us, and malformed input,
    /// yield an empty vec.
    ///
    /// This is the ordering guarantee the SDP/ICE flow needs: pubsub delivers unordered, but a browser
    /// must apply an offer before its trickled candidates. Use this from the SSE message handler to
    /// drive `RTCPeerConnection` deterministically.
    pub fn ingest_ordered(&mut self, from: &str, payload: &[u8]) -> Vec<SignalEnvelope> {
        let env = match SignalEnvelope::from_bytes(payload) {
            Ok(e) => e.with_sender(from),
            Err(_) => return Vec::new(),
        };
        match self.room.apply(&env) {
            Effect::Directed(boxed) => {
                if boxed.addressed_to(self.room.me()) {
                    self.router.offer(*boxed)
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Skip a peer's directed-signal reorder buffer past a presumed-lost `seq` (e.g. an offer the
    /// caller will renegotiate). Returns the now-deliverable run. See [`SignalRouter::skip_peer_to`].
    pub fn skip_peer_to(&mut self, peer: &str, seq: u64) -> Vec<SignalEnvelope> {
        self.router.skip_peer_to(peer, seq)
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
            resume: None,
        };
        self.send_admit(host, &req, timeout_ms).await
    }

    /// Reconnect to a gated room by presenting a prior [`ResumeToken`] instead of the full capability
    /// chain. On success the host re-admits by identity (no chain re-check) and returns a fresh
    /// token; the caller should [`MeetClient::adopt_resume`] it to keep its outbound `seq` monotonic.
    pub async fn request_resume(
        &self,
        host: &str,
        resume: ResumeToken,
        display_name: Option<String>,
        timeout_ms: u64,
    ) -> Result<AdmitResp> {
        let req = AdmitReq {
            room_id: self.room.room_id().to_string(),
            caps: String::new(),
            display_name,
            resume: Some(resume),
        };
        self.send_admit(host, &req, timeout_ms).await
    }

    /// Encode and send an [`AdmitReq`] to `host` over the admission request/reply channel.
    async fn send_admit(
        &self,
        host: &str,
        req: &AdmitReq,
        timeout_ms: u64,
    ) -> Result<AdmitResp> {
        let payload = serde_json::to_vec(req)?;
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

    #[test]
    fn restore_rebuilds_roster_and_outbound_seq() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        client.apply_message("peerA", &SignalEnvelope::broadcast("room", 0, 1, Signal::Join { display_name: None }).to_bytes());
        client.room.next_outbound_seq(); // advance my own counter
        let snap = client.snapshot();

        let ce2 = CeClient::with_token("http://127.0.0.1:8844", None);
        let restored = MeetClient::restore(ce2, snap);
        assert_eq!(restored.room().present(), vec!["peerA"]);
        assert_eq!(restored.room().outbound_seq(), client.room().outbound_seq());
    }

    #[test]
    fn adopt_resume_advances_outbound_floor() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let tok = ResumeToken {
            room_id: "room".into(),
            node_id: "me".into(),
            expires_at: 9999,
            seq_floor: 7,
            mac: "x".into(),
        };
        assert_eq!(client.adopt_resume(&tok), 7);
        assert_eq!(client.room().outbound_seq(), 7);
    }

    #[test]
    fn ingest_ordered_delivers_directed_signals_in_seq_order() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        // offer(seq0), then ice(seq2) arrives before ice(seq1) -> buffered, released in order
        let offer = SignalEnvelope::directed("room", "me", 0, 1, Signal::Offer { sdp: "o".into() });
        let ice2 = SignalEnvelope::directed("room", "me", 2, 3, Signal::IceCandidate {
            candidate: "c2".into(), sdp_mid: None, sdp_m_line_index: None });
        let ice1 = SignalEnvelope::directed("room", "me", 1, 2, Signal::IceCandidate {
            candidate: "c1".into(), sdp_mid: None, sdp_m_line_index: None });

        let r0 = client.ingest_ordered("peerA", &offer.to_bytes());
        assert_eq!(r0.len(), 1);
        assert_eq!(r0[0].seq, 0);
        assert!(client.ingest_ordered("peerA", &ice2.to_bytes()).is_empty(), "gap buffers");
        let run = client.ingest_ordered("peerA", &ice1.to_bytes());
        assert_eq!(run.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn ingest_ordered_ignores_signals_for_other_peers() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        // directed at someone else -> not surfaced to us
        let env = SignalEnvelope::directed("room", "OTHER", 0, 1, Signal::Offer { sdp: "x".into() });
        assert!(client.ingest_ordered("peerA", &env.to_bytes()).is_empty());
    }

    #[test]
    fn ingest_ordered_ignores_malformed_and_broadcast() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        assert!(client.ingest_ordered("peerA", b"not json").is_empty());
        // a broadcast join still updates the roster but yields no directed signals
        let join = SignalEnvelope::broadcast("room", 0, 1, Signal::Join { display_name: None });
        assert!(client.ingest_ordered("peerA", &join.to_bytes()).is_empty());
        assert_eq!(client.room().present(), vec!["peerA"]);
    }
}
