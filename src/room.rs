//! Room state: the roster and the per-sender ordering machine.
//!
//! A [`Room`] is the *local view* a participant keeps of who is in the room. Pubsub gives at-most-
//! once, unordered, possibly-duplicated delivery, so the roster must converge to the same membership
//! at every participant regardless of message order or drops. The convergence rule is a small CRDT:
//!
//! > Each participant's presence is a last-writer-wins register keyed by NodeId, ordered by the
//! > sender's own monotonic `seq`. A `Join`/`Keepalive` with a higher `seq` than we've seen marks
//! > the member present; a `Leave` with a higher `seq` marks them absent. Equal-or-lower `seq` is
//! > ignored (duplicate/reorder). Because every member only ever *increments* its own `seq`, and the
//! > last action (present vs absent) wins by that total order, all replicas that have seen the same
//! > set of envelopes agree — and order of arrival does not matter.
//!
//! This is a standard LWW-element-set keyed per member, with the member's own sequence as the
//! timestamp (no wall clocks, so no clock-skew hazards). [`Room::apply`] is the single mutator and
//! is commutative, idempotent, and convergent — the properties the tests assert.

use crate::proto::{Signal, SignalEnvelope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One member's presence in the local roster view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The member's authenticated NodeId (hex).
    pub node_id: String,
    /// Optional display name from the member's most recent `Join`.
    pub display_name: Option<String>,
    /// Whether the member is currently present (true) or has left (false).
    pub present: bool,
    /// The highest `seq` we have observed from this member — the LWW timestamp.
    pub last_seq: u64,
    /// `sent_at` of the last applied envelope from this member (freshness for liveness pruning).
    pub last_seen: u64,
}

/// The outcome of applying one envelope to a [`Room`] — what changed, for the caller to react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A member became (or was first seen as) present.
    Joined(String),
    /// A member became absent.
    Left(String),
    /// A directed signal (offer/answer/ICE) for `to`; the caller routes it to its WebRTC stack if
    /// `to` is itself. Carries the full envelope so the caller has the SDP/candidate.
    Directed(Box<SignalEnvelope>),
    /// A liveness ping refreshed a present member; no membership change.
    Refreshed(String),
    /// The envelope was a duplicate/reorder/older than known state and changed nothing.
    NoChange,
}

/// A participant's local view of one room.
#[derive(Debug, Clone)]
pub struct Room {
    room_id: String,
    /// This participant's own NodeId (hex) — used to recognise self-directed signals.
    me: String,
    members: HashMap<String, Member>,
    /// This participant's own outbound sequence counter (monotonic).
    next_seq: u64,
}

impl Room {
    /// Create a fresh local view of `room_id` for participant `me` (NodeId hex).
    pub fn new(room_id: impl Into<String>, me: impl Into<String>) -> Self {
        Room { room_id: room_id.into(), me: me.into(), members: HashMap::new(), next_seq: 0 }
    }

    /// The room id.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// This participant's NodeId hex.
    pub fn me(&self) -> &str {
        &self.me
    }

    /// Allocate the next outbound sequence number for a message *this* participant sends. Monotonic;
    /// every call increments. Use the returned value when building an outbound [`SignalEnvelope`].
    pub fn next_outbound_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    /// The set of NodeIds currently present (sorted, deterministic — good for display and tests).
    pub fn present(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.members.values().filter(|m| m.present).map(|m| m.node_id.clone()).collect();
        v.sort();
        v
    }

    /// Number of present members.
    pub fn present_count(&self) -> usize {
        self.members.values().filter(|m| m.present).count()
    }

    /// Look up a member's full state.
    pub fn member(&self, node_id: &str) -> Option<&Member> {
        self.members.get(node_id)
    }

    /// Apply a received (sender-stamped) envelope to the roster, returning what changed.
    ///
    /// The envelope **must** already carry an authenticated `from` (via
    /// [`SignalEnvelope::with_sender`]). Envelopes for a different room, or with an empty sender, are
    /// rejected as [`Effect::NoChange`] — they never mutate state. Directed signals do not touch the
    /// roster; they are surfaced as [`Effect::Directed`] for the caller to route to WebRTC.
    pub fn apply(&mut self, env: &SignalEnvelope) -> Effect {
        // Defensive: wrong room or unauthenticated sender changes nothing.
        if env.room_id != self.room_id || env.from.is_empty() {
            return Effect::NoChange;
        }

        match &env.signal {
            Signal::Offer { .. }
            | Signal::Answer { .. }
            | Signal::IceCandidate { .. }
            | Signal::IceEnd => {
                // Directed peer signaling — surface it; the caller decides if it is addressed to us.
                Effect::Directed(Box::new(env.clone()))
            }
            Signal::Join { display_name } => {
                self.lww(&env.from, env.seq, env.sent_at, true, display_name.clone())
            }
            Signal::Leave => self.lww(&env.from, env.seq, env.sent_at, false, None),
            Signal::Keepalive => {
                // A keepalive is a "still present" assertion: it can (re)mark present but its main job
                // is to refresh liveness. Treat it as a present-assertion at this seq.
                match self.lww(&env.from, env.seq, env.sent_at, true, None) {
                    Effect::Joined(n) => Effect::Joined(n),
                    Effect::NoChange => {
                        // seq not advanced, but if they are already present refresh last_seen.
                        if let Some(m) = self.members.get_mut(&env.from)
                            && m.present
                            && env.sent_at > m.last_seen
                        {
                            m.last_seen = env.sent_at;
                        }
                        Effect::Refreshed(env.from.clone())
                    }
                    other => other,
                }
            }
        }
    }

    /// The LWW register update keyed by member, ordered by `seq`. Returns the membership effect.
    ///
    /// Ordering rule (a convergent, order-independent CRDT):
    /// - a strictly **higher** `seq` always wins (the member's own seq is monotonic, so this is the
    ///   normal case);
    /// - a strictly **lower** `seq` is ignored (duplicate / reorder);
    /// - on an **equal** `seq` with a conflicting presence, **absent (`Leave`) wins over present
    ///   (`Join`)** — a deterministic remove-bias tie-break so two replicas that saw the same events
    ///   in different orders still converge. (A well-behaved sender never emits two different actions
    ///   at the same seq; this only guards the adversarial/buggy case.)
    fn lww(
        &mut self,
        node_id: &str,
        seq: u64,
        sent_at: u64,
        present: bool,
        display_name: Option<String>,
    ) -> Effect {
        match self.members.get_mut(node_id) {
            Some(m) => {
                if seq < m.last_seq {
                    return Effect::NoChange; // strictly older — ignore
                }
                if seq == m.last_seq {
                    // Equal seq: only an absent-assertion may override a present one (remove-bias).
                    // Refresh display name / last_seen opportunistically, but do not flip to present.
                    if let Some(dn) = display_name {
                        m.display_name = Some(dn);
                    }
                    m.last_seen = sent_at.max(m.last_seen);
                    if !present && m.present {
                        m.present = false;
                        return Effect::Left(node_id.to_string());
                    }
                    return Effect::NoChange;
                }
                // Strictly newer seq wins outright.
                let was_present = m.present;
                m.last_seq = seq;
                m.last_seen = sent_at.max(m.last_seen);
                m.present = present;
                if let Some(dn) = display_name {
                    m.display_name = Some(dn);
                }
                match (was_present, present) {
                    (false, true) => Effect::Joined(node_id.to_string()),
                    (true, false) => Effect::Left(node_id.to_string()),
                    _ => Effect::NoChange,
                }
            }
            None => {
                self.members.insert(
                    node_id.to_string(),
                    Member {
                        node_id: node_id.to_string(),
                        display_name,
                        present,
                        last_seq: seq,
                        last_seen: sent_at,
                    },
                );
                if present {
                    Effect::Joined(node_id.to_string())
                } else {
                    // First time we hear of someone is via their Leave: record absent, no "left" event.
                    Effect::NoChange
                }
            }
        }
    }

    /// Prune members that are present but whose last liveness is older than `now - stale_secs`.
    /// Returns the NodeIds pruned (marked absent). A participant that crashed without a `Leave` is
    /// eventually removed this way. Pruning advances no `seq`, so a later real message from the same
    /// member (higher seq) correctly re-adds them.
    pub fn prune_stale(&mut self, now: u64, stale_secs: u64) -> Vec<String> {
        let mut pruned = Vec::new();
        for m in self.members.values_mut() {
            if m.present && now.saturating_sub(m.last_seen) > stale_secs {
                m.present = false;
                pruned.push(m.node_id.clone());
            }
        }
        pruned.sort();
        pruned
    }

    // ---- Persistent room state -------------------------------------------------------------

    /// Capture the full convergent state of this room as a [`RoomSnapshot`] — the room id, every
    /// member's LWW register (`last_seq`/presence/`last_seen`/name) and this participant's own
    /// outbound `next_seq`. A host (or a participant resuming after a crash) persists this and later
    /// restores it with [`Room::restore`], picking up exactly where it left off without replaying the
    /// whole signaling history. Because the state is a per-member LWW set, a restored snapshot that is
    /// then fed newer envelopes converges to the same membership as one that never crashed.
    pub fn snapshot(&self) -> RoomSnapshot {
        let mut members: Vec<Member> = self.members.values().cloned().collect();
        members.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        RoomSnapshot {
            room_id: self.room_id.clone(),
            me: self.me.clone(),
            next_seq: self.next_seq,
            members,
        }
    }

    /// Rebuild a [`Room`] from a persisted [`RoomSnapshot`]. The inverse of [`Room::snapshot`].
    pub fn restore(snap: RoomSnapshot) -> Self {
        let members =
            snap.members.into_iter().map(|m| (m.node_id.clone(), m)).collect::<HashMap<_, _>>();
        Room { room_id: snap.room_id, me: snap.me, members, next_seq: snap.next_seq }
    }

    /// A deterministic, order-independent digest of the convergent roster state: for every member,
    /// `(node_id, present, last_seq)` sorted by node id. Two replicas that have applied the same set
    /// of envelopes (in any order, with any duplicates) produce the **same** digest — so a host can
    /// cheaply assert convergence, or a reconnecting peer can detect it is behind. Display names and
    /// `last_seen` are intentionally excluded: they are cosmetic/liveness, not membership identity.
    pub fn digest(&self) -> Vec<(String, bool, u64)> {
        let mut d: Vec<(String, bool, u64)> =
            self.members.values().map(|m| (m.node_id.clone(), m.present, m.last_seq)).collect();
        d.sort();
        d
    }

    /// Merge another replica's [`RoomSnapshot`] of the **same** room into this one, applying the LWW
    /// rule per member: a higher `last_seq` wins; on an equal `last_seq` a conflicting presence
    /// resolves absent-wins (the same remove-bias tie-break [`Room::apply`] uses), so the merge is
    /// commutative and convergent. Snapshots for a different room are ignored. Returns the node ids
    /// whose presence changed locally. This is how a host that took over a room (or two hosts that
    /// reconcile) converge their persisted state without replaying every envelope.
    pub fn merge_snapshot(&mut self, other: &RoomSnapshot) -> Vec<String> {
        if other.room_id != self.room_id {
            return Vec::new();
        }
        let mut changed = Vec::new();
        for om in &other.members {
            match self.members.get_mut(&om.node_id) {
                Some(m) => {
                    if om.last_seq > m.last_seq {
                        if m.present != om.present {
                            changed.push(m.node_id.clone());
                        }
                        m.last_seq = om.last_seq;
                        m.present = om.present;
                        m.last_seen = om.last_seen.max(m.last_seen);
                        if om.display_name.is_some() {
                            m.display_name = om.display_name.clone();
                        }
                    } else if om.last_seq == m.last_seq {
                        // Equal seq: absent wins; refresh last_seen/name opportunistically.
                        m.last_seen = om.last_seen.max(m.last_seen);
                        if om.display_name.is_some() && m.display_name.is_none() {
                            m.display_name = om.display_name.clone();
                        }
                        if !om.present && m.present {
                            m.present = false;
                            changed.push(m.node_id.clone());
                        }
                    }
                    // strictly older: ignore.
                }
                None => {
                    if om.present {
                        changed.push(om.node_id.clone());
                    }
                    self.members.insert(om.node_id.clone(), om.clone());
                }
            }
        }
        changed.sort();
        changed
    }

    // ---- Participant reconnection (resume by identity) -------------------------------------

    /// Restore this participant's outbound sequence floor after a reconnection, so a resumed session
    /// never re-uses a `seq` it already published (which a peer's LWW register would silently drop as
    /// a duplicate/reorder). Pass the highest `seq` the participant is known to have sent — typically
    /// from a persisted [`RoomSnapshot::next_seq`] or a [`crate::client::ResumeToken`]. The outbound
    /// counter advances to `max(current, floor)`; it never goes backwards. Returns the new next seq.
    pub fn resume_outbound_from(&mut self, floor: u64) -> u64 {
        self.next_seq = self.next_seq.max(floor);
        self.next_seq
    }

    /// The current outbound sequence counter (the value the *next* [`Room::next_outbound_seq`] call
    /// will return). Persist this in a resume token so a reconnecting participant keeps monotonicity.
    pub fn outbound_seq(&self) -> u64 {
        self.next_seq
    }
}

/// A persisted, restorable snapshot of a [`Room`]'s convergent state. Serializable so a host can
/// write it to disk (or a blob) and reload it, and so two replicas can reconcile via
/// [`Room::merge_snapshot`]. See [`Room::snapshot`] / [`Room::restore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomSnapshot {
    /// The room this snapshot belongs to.
    pub room_id: String,
    /// The participant whose local view this is.
    pub me: String,
    /// The participant's own next outbound sequence number (monotonic; preserved across restore).
    pub next_seq: u64,
    /// Every member's LWW register, sorted by node id for a deterministic encoding.
    pub members: Vec<Member>,
}

impl RoomSnapshot {
    /// Serialize to JSON bytes for persistence (disk, blob store, or a resume payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Parse a snapshot from JSON bytes. Rejects malformed input with a descriptive error.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("malformed ce-meet room snapshot: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(from: &str, seq: u64, at: u64) -> SignalEnvelope {
        SignalEnvelope::broadcast("r", seq, at, Signal::Join { display_name: None }).with_sender(from)
    }
    fn leave(from: &str, seq: u64, at: u64) -> SignalEnvelope {
        SignalEnvelope::broadcast("r", seq, at, Signal::Leave).with_sender(from)
    }

    #[test]
    fn join_then_leave_converges() {
        let mut room = Room::new("r", "me");
        assert_eq!(room.apply(&join("a", 0, 10)), Effect::Joined("a".into()));
        assert_eq!(room.present(), vec!["a"]);
        assert_eq!(room.apply(&leave("a", 1, 11)), Effect::Left("a".into()));
        assert!(room.present().is_empty());
    }

    #[test]
    fn duplicate_join_is_idempotent() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 5, 10));
        // same seq again -> no change
        assert_eq!(room.apply(&join("a", 5, 10)), Effect::NoChange);
        assert_eq!(room.present_count(), 1);
    }

    #[test]
    fn out_of_order_leave_before_join_does_not_resurrect() {
        let mut room = Room::new("r", "me");
        // We receive the leave (seq 1) first, then the older join (seq 0).
        room.apply(&leave("a", 1, 20));
        let eff = room.apply(&join("a", 0, 10)); // older seq -> ignored
        assert_eq!(eff, Effect::NoChange);
        assert!(room.present().is_empty(), "stale join must not resurrect a left member");
    }

    #[test]
    fn rejoin_with_higher_seq_works() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        room.apply(&leave("a", 1, 11));
        assert_eq!(room.apply(&join("a", 2, 12)), Effect::Joined("a".into()));
        assert_eq!(room.present(), vec!["a"]);
    }

    #[test]
    fn wrong_room_is_ignored() {
        let mut room = Room::new("r", "me");
        let mut e = join("a", 0, 10);
        e.room_id = "other".into();
        assert_eq!(room.apply(&e), Effect::NoChange);
    }

    #[test]
    fn unauthenticated_sender_is_ignored() {
        let mut room = Room::new("r", "me");
        let e = SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: None }); // from empty
        assert_eq!(room.apply(&e), Effect::NoChange);
        assert_eq!(room.present_count(), 0);
    }

    #[test]
    fn directed_signal_does_not_touch_roster() {
        let mut room = Room::new("r", "me");
        let off = SignalEnvelope::directed("r", "me", 0, 10, Signal::Offer { sdp: "v=0".into() })
            .with_sender("a");
        match room.apply(&off) {
            Effect::Directed(env) => assert_eq!(env.from, "a"),
            other => panic!("expected Directed, got {other:?}"),
        }
        assert_eq!(room.present_count(), 0);
    }

    #[test]
    fn keepalive_refreshes_present_member() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        let ka = SignalEnvelope::broadcast("r", 1, 30, Signal::Keepalive).with_sender("a");
        assert_eq!(room.apply(&ka), Effect::Refreshed("a".into()));
        assert_eq!(room.member("a").unwrap().last_seen, 30);
    }

    #[test]
    fn prune_removes_stale_members() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 100));
        room.apply(&join("b", 0, 100));
        // b refreshes at t=200
        let ka = SignalEnvelope::broadcast("r", 1, 200, Signal::Keepalive).with_sender("b");
        room.apply(&ka);
        // prune at t=250 with stale window 60: a (last seen 100) goes, b (200) stays
        let pruned = room.prune_stale(250, 60);
        assert_eq!(pruned, vec!["a"]);
        assert_eq!(room.present(), vec!["b"]);
    }

    #[test]
    fn outbound_seq_is_monotonic() {
        let mut room = Room::new("r", "me");
        assert_eq!(room.next_outbound_seq(), 0);
        assert_eq!(room.next_outbound_seq(), 1);
        assert_eq!(room.next_outbound_seq(), 2);
    }

    #[test]
    fn leave_first_seen_records_absent_without_left_event() {
        let mut room = Room::new("r", "me");
        // First we ever hear of "a" is a Leave -> no Left event, but recorded absent.
        assert_eq!(room.apply(&leave("a", 3, 10)), Effect::NoChange);
        assert!(!room.member("a").unwrap().present);
        // A later (lower seq) join is ignored; convergence holds.
        assert_eq!(room.apply(&join("a", 1, 5)), Effect::NoChange);
        assert!(room.present().is_empty());
    }

    // ---- persistent room state ----

    #[test]
    fn snapshot_restore_round_trip_preserves_state() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        room.apply(&join("b", 0, 11));
        room.apply(&leave("b", 1, 12));
        room.next_outbound_seq(); // bump my own counter to 1
        let snap = room.snapshot();
        let restored = Room::restore(snap.clone());
        assert_eq!(restored.present(), room.present());
        assert_eq!(restored.outbound_seq(), room.outbound_seq());
        assert_eq!(restored.snapshot(), snap);
    }

    #[test]
    fn snapshot_bytes_round_trip() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 2, 10));
        let snap = room.snapshot();
        let bytes = snap.to_bytes();
        let back = RoomSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn snapshot_from_bytes_rejects_garbage() {
        assert!(RoomSnapshot::from_bytes(b"not json").is_err());
        assert!(RoomSnapshot::from_bytes(b"{}").is_err());
    }

    #[test]
    fn restored_room_converges_with_later_events() {
        // A host snapshots, "crashes", restores, then applies a newer event: it must end in the same
        // state as a host that never crashed and saw every event.
        let mut live = Room::new("r", "me");
        live.apply(&join("a", 0, 10));
        let snap = live.snapshot();

        let mut crashed = Room::restore(snap);
        // newer event arrives only at the restored replica
        crashed.apply(&leave("a", 1, 20));
        // the live one also sees it
        live.apply(&leave("a", 1, 20));

        assert_eq!(crashed.present(), live.present());
        assert_eq!(crashed.digest(), live.digest());
    }

    #[test]
    fn digest_is_order_independent() {
        let mut r1 = Room::new("r", "me");
        let mut r2 = Room::new("r", "me");
        r1.apply(&join("a", 0, 10));
        r1.apply(&join("b", 0, 11));
        r1.apply(&leave("a", 1, 12));
        // r2 sees the same events reversed, with a duplicate
        r2.apply(&leave("a", 1, 12));
        r2.apply(&join("b", 0, 11));
        r2.apply(&join("a", 0, 10));
        r2.apply(&join("b", 0, 11));
        assert_eq!(r1.digest(), r2.digest());
    }

    #[test]
    fn merge_snapshot_converges_two_replicas() {
        // Replica 1 saw a-join; replica 2 saw b-join and a-leave(seq1). Merging 2 into 1 must yield
        // the union LWW state: a absent (seq 1 wins), b present.
        let mut r1 = Room::new("r", "me");
        r1.apply(&join("a", 0, 10));

        let mut r2 = Room::new("r", "me");
        r2.apply(&join("b", 0, 11));
        r2.apply(&leave("a", 1, 20)); // r2 only ever saw a's leave at seq 1

        let changed = r1.merge_snapshot(&r2.snapshot());
        // a flips present->absent, b is newly added present
        assert!(changed.contains(&"b".to_string()));
        assert!(changed.contains(&"a".to_string()));
        assert_eq!(r1.present(), vec!["b"]);

        // Merge is symmetric in outcome: merging r1 into r2 yields the same present-set.
        let mut r1b = Room::new("r", "me");
        r1b.apply(&join("a", 0, 10));
        let mut r2b = Room::new("r", "me");
        r2b.apply(&join("b", 0, 11));
        r2b.apply(&leave("a", 1, 20));
        r2b.merge_snapshot(&r1b.snapshot());
        assert_eq!(r2b.present(), r1.present());
    }

    #[test]
    fn merge_snapshot_ignores_other_room() {
        let mut r1 = Room::new("r", "me");
        r1.apply(&join("a", 0, 10));
        let mut other = Room::new("OTHER", "me");
        other.apply(&join("z", 0, 99));
        let changed = r1.merge_snapshot(&other.snapshot());
        assert!(changed.is_empty());
        assert_eq!(r1.present(), vec!["a"]);
    }

    #[test]
    fn merge_snapshot_older_seq_does_not_override() {
        let mut r1 = Room::new("r", "me");
        r1.apply(&join("a", 5, 10)); // a present at seq 5
        let mut stale = Room::new("r", "me");
        stale.apply(&leave("a", 2, 5)); // a absent at seq 2 (older)
        let changed = r1.merge_snapshot(&stale.snapshot());
        assert!(changed.is_empty(), "older snapshot must not flip newer state");
        assert_eq!(r1.present(), vec!["a"]);
    }

    // ---- reconnection / resume ----

    #[test]
    fn resume_outbound_never_goes_backwards() {
        let mut room = Room::new("r", "me");
        room.next_outbound_seq(); // 0
        room.next_outbound_seq(); // 1, next is 2
        assert_eq!(room.outbound_seq(), 2);
        // resuming from a lower floor keeps the higher counter
        assert_eq!(room.resume_outbound_from(1), 2);
        // resuming from a higher floor advances it
        assert_eq!(room.resume_outbound_from(10), 10);
        // and the next allocated seq respects the floor (no reuse)
        assert_eq!(room.next_outbound_seq(), 10);
    }

    #[test]
    fn resume_prevents_seq_reuse_so_peer_accepts_post_reconnect_messages() {
        // A participant publishes join(seq0); a peer records it. The participant crashes, restores
        // from a token carrying next_seq=1, and publishes leave. Without resume it would reuse seq0
        // and the peer would drop the leave as a duplicate; with resume the leave gets seq1 and wins.
        let mut peer_view = Room::new("r", "peer");
        peer_view.apply(&join("p", 0, 10));
        assert_eq!(peer_view.present(), vec!["p"]);

        let mut resumed = Room::new("r", "p");
        resumed.resume_outbound_from(1); // token said we already used seq 0
        let next = resumed.next_outbound_seq();
        assert_eq!(next, 1);
        let leave_env =
            SignalEnvelope::broadcast("r", next, 20, Signal::Leave).with_sender("p");
        assert_eq!(peer_view.apply(&leave_env), Effect::Left("p".into()));
        assert!(peer_view.present().is_empty());
    }
}
