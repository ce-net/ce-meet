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

/// The default freshness window (seconds) for directed signals when freshness enforcement is on.
/// A trickled ICE candidate older than this (by its `sent_at`) is dropped rather than fed to the
/// WebRTC stack — a stale candidate can stall renegotiation. 0 elsewhere means "disabled".
pub const DEFAULT_FRESHNESS_SECS: u64 = 30;

/// A participant's signaling client for one room.
pub struct MeetClient {
    ce: CeClient,
    room: Room,
    /// Per-peer reorder buffer for directed SDP/ICE signals (in-order, de-duplicated delivery).
    router: SignalRouter,
    /// When non-zero, directed signals whose `sent_at` is older than this many seconds (or implausibly
    /// far in the future) are discarded by [`MeetClient::ingest_ordered`]. 0 = no freshness check.
    freshness_secs: u64,
}

impl MeetClient {
    /// Build a client bound to a local CE node and a room, for participant `me` (NodeId hex). Get
    /// `me` from `ce.status().await?.node_id`. Freshness enforcement starts disabled; enable it with
    /// [`MeetClient::with_freshness`].
    pub fn new(ce: CeClient, room_id: impl Into<String>, me: impl Into<String>) -> Self {
        let room_id = room_id.into();
        let me = me.into();
        MeetClient {
            ce,
            room: Room::new(room_id, me),
            router: SignalRouter::new(),
            freshness_secs: 0,
        }
    }

    /// Enable (or change) the directed-signal freshness window in seconds. With it set, an SDP/ICE
    /// signal whose `sent_at` is older than `secs` (or implausibly future) is dropped by
    /// [`MeetClient::ingest_ordered`] before reaching the WebRTC stack. Pass 0 to disable. A typical
    /// value is [`DEFAULT_FRESHNESS_SECS`].
    pub fn with_freshness(mut self, secs: u64) -> Self {
        self.freshness_secs = secs;
        self
    }

    /// The configured directed-signal freshness window (0 = disabled).
    pub fn freshness_secs(&self) -> u64 {
        self.freshness_secs
    }

    /// Rebuild a client from a persisted [`RoomSnapshot`] (host or participant resuming after a
    /// crash). The roster, member LWW state, and outbound `seq` are restored intact; the directed-
    /// signal reorder buffer starts fresh (per-peer ordering re-anchors on the next directed signal).
    pub fn restore(ce: CeClient, snapshot: RoomSnapshot) -> Self {
        MeetClient {
            ce,
            room: Room::restore(snapshot),
            router: SignalRouter::new(),
            freshness_secs: 0,
        }
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

    /// Broadcast any [`Signal`] to the whole room (allocating the next outbound seq). The building
    /// block for the media-control / chat / reaction helpers below.
    pub async fn broadcast(&mut self, signal: Signal) -> Result<()> {
        let seq = self.room.next_outbound_seq();
        let env = SignalEnvelope::broadcast(self.room.room_id(), seq, now_secs(), signal);
        self.publish(&env).await
    }

    /// Send a directed control [`Signal`] (a moderation action such as `Kick`/`ForceMute`) to one
    /// peer. Whether the recipient honors it is decided by *its* host gate — the sender's authority is
    /// a capability the recipient verifies, never asserted here.
    pub async fn signal_directed(&mut self, to: &str, signal: Signal) -> Result<()> {
        self.signal_peer(to, signal).await
    }

    /// Broadcast this participant's live mic/camera mute state (Meet's per-tile mute indicators).
    pub async fn set_media(&mut self, audio_muted: bool, video_muted: bool) -> Result<()> {
        self.broadcast(Signal::Media { audio_muted, video_muted }).await
    }

    /// Broadcast that this participant started or stopped sharing their screen.
    pub async fn set_screen_share(&mut self, active: bool) -> Result<()> {
        self.broadcast(Signal::ScreenShare { active }).await
    }

    /// Broadcast raising or lowering this participant's hand.
    pub async fn raise_hand(&mut self, raised: bool) -> Result<()> {
        self.broadcast(Signal::RaiseHand { raised }).await
    }

    /// Broadcast a transient reaction (an emoji/symbol). The body is bounds-validated on publish.
    pub async fn react(&mut self, emoji: impl Into<String>) -> Result<()> {
        self.broadcast(Signal::Reaction { emoji: emoji.into() }).await
    }

    /// Broadcast an in-call chat line. Bounds-validated on publish.
    pub async fn chat(&mut self, body: impl Into<String>) -> Result<()> {
        self.broadcast(Signal::Chat { body: body.into() }).await
    }

    /// Announce that the call is being recorded (`true`) or recording stopped (`false`). ce-meet does
    /// no recording itself; this is the consent/notice broadcast every participant sees.
    pub async fn announce_recording(&mut self, active: bool) -> Result<()> {
        self.broadcast(Signal::Recording { active }).await
    }

    /// Host/moderator: remove a participant from the room (directed at the target NodeId). The target
    /// honors it only if the sender holds [`crate::proto::ABILITY_HOST`]/`ABILITY_MODERATE` per the
    /// target's gate.
    pub async fn kick(&mut self, target: &str, reason: Option<String>) -> Result<()> {
        self.signal_directed(target, Signal::Kick { reason }).await
    }

    /// Host/moderator: force-mute (or request-unmute) a participant's audio (directed).
    pub async fn force_mute(&mut self, target: &str, audio_muted: bool) -> Result<()> {
        self.signal_directed(target, Signal::ForceMute { audio_muted }).await
    }

    /// Host: end the room for everyone (broadcast). Other clients tear down on receipt.
    pub async fn end_room(&mut self, reason: Option<String>) -> Result<()> {
        self.broadcast(Signal::EndRoom { reason }).await
    }

    /// Low-level publish of a pre-built envelope onto the room topic. Validates the envelope's bounds
    /// before publishing so this node never emits an over-cap frame a peer would reject.
    pub async fn publish(&self, env: &SignalEnvelope) -> Result<()> {
        env.signal.validate().map_err(|e| anyhow!("refusing to publish invalid signal: {e}"))?;
        let bytes = env.to_bytes()?;
        self.ce.publish(&room_topic(self.room.room_id()), &bytes).await
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

    /// Drive the roster in **real time** from the node's SSE app-message push stream, invoking
    /// `on_effect` for every meaningful roster change as it arrives (sub-second, unlike the
    /// timer-based [`MeetClient::poll`]). This is the loop a real WebRTC client runs: the moment a peer
    /// publishes an offer/candidate or a membership change, it is applied and surfaced.
    ///
    /// Filters to this room's topic, ignores our own echoes, and skips malformed frames (never
    /// panics). Returns when the stream ends (node closed it) or an `EndRoom` is observed. Errors from
    /// individual stream items are logged and skipped so a transient decode hiccup does not kill the
    /// call. `on_effect` is a synchronous callback (render/log); do async work by sending on a channel.
    pub async fn event_loop<F>(&mut self, mut on_effect: F) -> Result<()>
    where
        F: FnMut(&Effect),
    {
        use futures_util::StreamExt;
        let topic = room_topic(self.room.room_id());
        let me = self.room.me().to_string();
        // Open the stream on a second client targeting the same node, so the long-lived stream borrow
        // does not conflict with the `&mut self` we need to apply each message. The token is
        // re-discovered from the environment exactly as for the primary client.
        let ce = CeClient::new(self.ce.base_url());
        let stream = ce.messages_stream().await?;
        futures_util::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let m = match item {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("meet event stream item error: {e}");
                    continue;
                }
            };
            if m.topic != topic || m.from == me {
                continue;
            }
            let bytes = match m.payload() {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Some(eff) = self.apply_message(&m.from, &bytes) {
                on_effect(&eff);
                if matches!(eff, Effect::RoomEnded { .. }) {
                    break;
                }
            }
        }
        Ok(())
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
        // Freshness: drop a stale (or implausibly future) directed signal before it can stall the
        // WebRTC stack. Applies only when enforcement is enabled (freshness_secs != 0).
        if self.freshness_secs != 0
            && !env.signal.is_broadcast()
            && !env.is_fresh(now_secs(), self.freshness_secs)
        {
            return Vec::new();
        }
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
        let eff = client.apply_message("peerA", &env.to_bytes().unwrap());
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
        assert_eq!(client.apply_message("peerA", &env.to_bytes().unwrap()), None);
    }

    #[test]
    fn apply_message_directed_surfaces_envelope() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let env =
            SignalEnvelope::directed("room", "me", 0, 1, Signal::Offer { sdp: "v=0".into() });
        match client.apply_message("peerA", &env.to_bytes().unwrap()) {
            Some(Effect::Directed(e)) => assert_eq!(e.from, "peerA"),
            other => panic!("expected Directed, got {other:?}"),
        }
    }

    #[test]
    fn restore_rebuilds_roster_and_outbound_seq() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        client.apply_message("peerA", &SignalEnvelope::broadcast("room", 0, 1, Signal::Join { display_name: None }).to_bytes().unwrap());
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

        let r0 = client.ingest_ordered("peerA", &offer.to_bytes().unwrap());
        assert_eq!(r0.len(), 1);
        assert_eq!(r0[0].seq, 0);
        assert!(client.ingest_ordered("peerA", &ice2.to_bytes().unwrap()).is_empty(), "gap buffers");
        let run = client.ingest_ordered("peerA", &ice1.to_bytes().unwrap());
        assert_eq!(run.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn ingest_ordered_ignores_signals_for_other_peers() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        // directed at someone else -> not surfaced to us
        let env = SignalEnvelope::directed("room", "OTHER", 0, 1, Signal::Offer { sdp: "x".into() });
        assert!(client.ingest_ordered("peerA", &env.to_bytes().unwrap()).is_empty());
    }

    #[test]
    fn ingest_ordered_ignores_malformed_and_broadcast() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        assert!(client.ingest_ordered("peerA", b"not json").is_empty());
        // a broadcast join still updates the roster but yields no directed signals
        let join = SignalEnvelope::broadcast("room", 0, 1, Signal::Join { display_name: None });
        assert!(client.ingest_ordered("peerA", &join.to_bytes().unwrap()).is_empty());
        assert_eq!(client.room().present(), vec!["peerA"]);
    }

    #[test]
    fn apply_message_surfaces_media_and_chat() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        client.apply_message(
            "peerA",
            &SignalEnvelope::broadcast("room", 0, 1, Signal::Join { display_name: None })
                .to_bytes()
                .unwrap(),
        );
        let media = SignalEnvelope::broadcast(
            "room",
            1,
            2,
            Signal::Media { audio_muted: true, video_muted: false },
        );
        assert_eq!(
            client.apply_message("peerA", &media.to_bytes().unwrap()),
            Some(Effect::MediaChanged("peerA".into()))
        );
        assert!(client.room().member("peerA").unwrap().audio_muted);

        let chat = SignalEnvelope::broadcast("room", 2, 3, Signal::Chat { body: "hi".into() });
        assert_eq!(
            client.apply_message("peerA", &chat.to_bytes().unwrap()),
            Some(Effect::Chat { from: "peerA".into(), body: "hi".into() })
        );
    }

    #[test]
    fn freshness_drops_stale_directed_signal() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        // freshness window of 30s; an offer with sent_at far in the past is dropped.
        let mut client = MeetClient::new(ce, "room", "me").with_freshness(30);
        assert_eq!(client.freshness_secs(), 30);
        let stale = SignalEnvelope::directed("room", "me", 0, 1, Signal::Offer { sdp: "o".into() });
        // sent_at = 1 is ancient relative to wall-clock now -> dropped.
        assert!(client.ingest_ordered("peerA", &stale.to_bytes().unwrap()).is_empty());
    }

    #[test]
    fn freshness_disabled_delivers_old_signal() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        // freshness disabled (default) -> even an old sent_at is delivered.
        let mut client = MeetClient::new(ce, "room", "me");
        let old = SignalEnvelope::directed("room", "me", 0, 1, Signal::Offer { sdp: "o".into() });
        let out = client.ingest_ordered("peerA", &old.to_bytes().unwrap());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn end_room_effect_is_observed() {
        let ce = CeClient::with_token("http://127.0.0.1:8844", None);
        let mut client = MeetClient::new(ce, "room", "me");
        let end = SignalEnvelope::broadcast("room", 0, 1, Signal::EndRoom { reason: None });
        assert_eq!(
            client.apply_message("host", &end.to_bytes().unwrap()),
            Some(Effect::RoomEnded { by: "host".into(), reason: None })
        );
        assert!(client.room().is_ended());
    }
}
