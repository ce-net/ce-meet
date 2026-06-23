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
use std::collections::HashMap;

/// One member's presence in the local roster view.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
