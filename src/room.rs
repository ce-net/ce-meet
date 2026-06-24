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

/// One member's presence and live media state in the local roster view.
///
/// Presence (`present`) is the LWW register described in the module docs. The media-control fields
/// (`audio_muted`, `video_muted`, `sharing`, `hand_raised`) mirror Google Meet's per-tile state; they
/// are last-writer-wins by the same per-member `seq`, so they converge under reordering exactly like
/// presence does. They are cosmetic call state, excluded from the membership [`Room::digest`].
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
    /// Live microphone-muted state (from the member's most recent `Media` signal). Defaults false.
    #[serde(default)]
    pub audio_muted: bool,
    /// Live camera-off state (from the member's most recent `Media` signal). Defaults false.
    #[serde(default)]
    pub video_muted: bool,
    /// Whether the member is currently presenting a screen (from `ScreenShare`). Defaults false.
    #[serde(default)]
    pub sharing: bool,
    /// Whether the member has a raised hand (from `RaiseHand`). Defaults false.
    #[serde(default)]
    pub hand_raised: bool,
    /// Per-attribute LWW floors for the three independent media dimensions `(media/av, screen-share,
    /// raise-hand)`, each holding the **next-acceptable** seq for that attribute (0 = none applied
    /// yet). Independent floors mean an out-of-order update to one dimension (e.g. a later raise-hand)
    /// never blocks an earlier, separately-sent update to another (e.g. a mute), which a single shared
    /// seq register would. Excluded from `digest` (cosmetic call state, not membership identity).
    #[serde(default)]
    pub media_seq: u64,
    #[serde(default)]
    pub share_seq: u64,
    #[serde(default)]
    pub hand_seq: u64,
}

/// A media-control state update applied to a [`Member`] by [`Room::media_lww`]. Each variant targets
/// one independent media dimension with its own LWW sequence floor.
enum MediaUpdate {
    /// Set audio/video mute state (from a `Media` signal).
    Av { audio_muted: bool, video_muted: bool },
    /// Set screen-share state (from a `ScreenShare` signal).
    Sharing(bool),
    /// Set raised-hand state (from a `RaiseHand` signal).
    Hand(bool),
}

impl MediaUpdate {
    /// The current per-attribute seq floor for this dimension on `m`.
    fn seq_floor(&self, m: &Member) -> u64 {
        match self {
            MediaUpdate::Av { .. } => m.media_seq,
            MediaUpdate::Sharing(_) => m.share_seq,
            MediaUpdate::Hand(_) => m.hand_seq,
        }
    }

    /// Apply this update to `m` and advance the matching per-attribute floor to `seq + 1` (the
    /// next-acceptable seq), so a duplicate of `seq` is then rejected.
    fn apply_to(&self, m: &mut Member, seq: u64) {
        let next = seq.saturating_add(1);
        match *self {
            MediaUpdate::Av { audio_muted, video_muted } => {
                m.audio_muted = audio_muted;
                m.video_muted = video_muted;
                m.media_seq = next;
            }
            MediaUpdate::Sharing(active) => {
                m.sharing = active;
                m.share_seq = next;
            }
            MediaUpdate::Hand(raised) => {
                m.hand_raised = raised;
                m.hand_seq = next;
            }
        }
    }
}

/// The outcome of applying one envelope to a [`Room`] — what changed, for the caller to react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A member became (or was first seen as) present.
    Joined(String),
    /// A member became absent.
    Left(String),
    /// A directed signal (offer/answer/ICE, or a directed moderation action like kick/force-mute)
    /// for `to`; the caller routes it to its WebRTC stack / control handler if `to` is itself.
    /// Carries the full envelope so the caller has the SDP/candidate/reason.
    Directed(Box<SignalEnvelope>),
    /// A liveness ping refreshed a present member; no membership change.
    Refreshed(String),
    /// A member's media state (mic/cam mute, screen-share, or raised-hand) changed. Carries the
    /// affected NodeId; read the new state from [`Room::member`].
    MediaChanged(String),
    /// A transient broadcast reaction from a member (emoji). Not retained as roster state.
    Reaction { from: String, emoji: String },
    /// A broadcast in-call chat line from a member. Not retained as roster state.
    Chat { from: String, body: String },
    /// A member announced the call is being recorded (`true`) or recording stopped (`false`). Carries
    /// the announcing NodeId so a UI can show a consent banner.
    Recording { from: String, active: bool },
    /// The host ended the room for everyone. The caller should tear down and leave.
    RoomEnded { by: String, reason: Option<String> },
    /// The envelope was a duplicate/reorder/older than known state and changed nothing.
    NoChange,
}

/// The default cap on the number of distinct members a [`Room`] will track. A peer cannot grow a
/// receiver's roster past this by publishing `Join` envelopes from many forged-looking NodeIds — once
/// the cap is reached, a *new* (previously unseen) member's join is rejected, bounding memory. Updates
/// to members already in the roster are always accepted (so a real participant is never starved out).
/// 1024 is far above any realistic call yet bounds the worst-case allocation.
pub const DEFAULT_MAX_MEMBERS: usize = 1024;

/// A participant's local view of one room: the convergent roster (presence + per-member media state)
/// plus this participant's own outbound sequence counter.
///
/// ```
/// use ce_meet::room::{Room, Effect};
/// use ce_meet::proto::{Signal, SignalEnvelope};
///
/// let mut room = Room::new("r", "me");
/// // A peer's Join arrives (sender-stamped with its authenticated NodeId).
/// let join = SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: Some("Bob".into()) })
///     .with_sender("bob");
/// assert_eq!(room.apply(&join), Effect::Joined("bob".into()));
/// assert_eq!(room.present(), vec!["bob".to_string()]);
///
/// // Bob mutes his mic; the roster reflects it as last-writer-wins media state.
/// let mute = SignalEnvelope::broadcast("r", 1, 11, Signal::Media { audio_muted: true, video_muted: false })
///     .with_sender("bob");
/// assert_eq!(room.apply(&mute), Effect::MediaChanged("bob".into()));
/// assert!(room.member("bob").unwrap().audio_muted);
/// ```
#[derive(Debug, Clone)]
pub struct Room {
    room_id: String,
    /// This participant's own NodeId (hex) — used to recognise self-directed signals.
    me: String,
    members: HashMap<String, Member>,
    /// This participant's own outbound sequence counter (monotonic).
    next_seq: u64,
    /// Upper bound on the number of distinct members tracked (DoS guard). See [`DEFAULT_MAX_MEMBERS`].
    max_members: usize,
    /// Set once an `EndRoom` is observed, so the caller can stop processing.
    ended: bool,
}

impl Room {
    /// Create a fresh local view of `room_id` for participant `me` (NodeId hex), with the default
    /// member cap ([`DEFAULT_MAX_MEMBERS`]).
    pub fn new(room_id: impl Into<String>, me: impl Into<String>) -> Self {
        Room {
            room_id: room_id.into(),
            me: me.into(),
            members: HashMap::new(),
            next_seq: 0,
            max_members: DEFAULT_MAX_MEMBERS,
            ended: false,
        }
    }

    /// Override the maximum number of distinct members this room will track (DoS guard). A value of 0
    /// is treated as 1. See [`DEFAULT_MAX_MEMBERS`].
    pub fn with_max_members(mut self, max: usize) -> Self {
        self.max_members = max.max(1);
        self
    }

    /// The configured maximum number of distinct members.
    pub fn max_members(&self) -> usize {
        self.max_members
    }

    /// Number of distinct members tracked (present or absent).
    pub fn known_count(&self) -> usize {
        self.members.len()
    }

    /// Whether an `EndRoom` has been observed for this room.
    pub fn is_ended(&self) -> bool {
        self.ended
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
            | Signal::IceEnd
            | Signal::Kick { .. }
            | Signal::ForceMute { .. } => {
                // Directed peer signaling / directed moderation — surface it; the caller decides if
                // it is addressed to us. (Authorization of moderation is the host gate's job, not the
                // roster machine's; the room only routes.)
                Effect::Directed(Box::new(env.clone()))
            }
            Signal::Reaction { emoji } => {
                // Transient broadcast — not retained, but refresh liveness if the member is present.
                if let Some(m) = self.members.get_mut(&env.from)
                    && env.sent_at > m.last_seen
                {
                    m.last_seen = env.sent_at;
                }
                Effect::Reaction { from: env.from.clone(), emoji: emoji.clone() }
            }
            Signal::Chat { body } => {
                if let Some(m) = self.members.get_mut(&env.from)
                    && env.sent_at > m.last_seen
                {
                    m.last_seen = env.sent_at;
                }
                Effect::Chat { from: env.from.clone(), body: body.clone() }
            }
            Signal::Recording { active } => {
                Effect::Recording { from: env.from.clone(), active: *active }
            }
            Signal::EndRoom { reason } => {
                self.ended = true;
                Effect::RoomEnded { by: env.from.clone(), reason: reason.clone() }
            }
            Signal::Media { audio_muted, video_muted } => self.media_lww(
                &env.from,
                env.seq,
                env.sent_at,
                MediaUpdate::Av { audio_muted: *audio_muted, video_muted: *video_muted },
            ),
            Signal::ScreenShare { active } => {
                self.media_lww(&env.from, env.seq, env.sent_at, MediaUpdate::Sharing(*active))
            }
            Signal::RaiseHand { raised } => {
                self.media_lww(&env.from, env.seq, env.sent_at, MediaUpdate::Hand(*raised))
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
                // DoS guard: refuse to allocate a slot for a brand-new member once the cap is hit.
                // Existing members (the `Some` arm above) are always updatable, so a real participant
                // is never starved; only the unbounded growth from forged-NodeId joins is stopped.
                if self.members.len() >= self.max_members {
                    return Effect::NoChange;
                }
                self.members.insert(
                    node_id.to_string(),
                    Member {
                        node_id: node_id.to_string(),
                        display_name,
                        present,
                        last_seq: seq,
                        last_seen: sent_at,
                        audio_muted: false,
                        video_muted: false,
                        sharing: false,
                        hand_raised: false,
                        media_seq: 0,
                        share_seq: 0,
                        hand_seq: 0,
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

    /// LWW update for a member's media-control state (mute / screen-share / raised-hand). Each of the
    /// three media dimensions has its **own** per-attribute seq floor, so it is keyed by the sender's
    /// monotonic `seq` *per dimension*: a strictly higher seq for that attribute applies the update and
    /// advances its floor; an equal or older seq is ignored (duplicate/reorder). Using independent
    /// floors is essential — a later raise-hand must not block an earlier, separately-sent mute, which
    /// a single shared register would. A media signal from an unknown member creates an absent
    /// placeholder so the state is retained when their (possibly reordered) `Join` arrives — subject to
    /// the member cap. Presence (`last_seq`) is untouched: media is not a presence assertion.
    fn media_lww(&mut self, node_id: &str, seq: u64, sent_at: u64, update: MediaUpdate) -> Effect {
        match self.members.get_mut(node_id) {
            Some(m) => {
                // `floor` is the next-acceptable seq for this attribute (0 = nothing applied yet).
                // Apply when `seq >= floor`; an older or duplicate seq is ignored.
                let floor = update.seq_floor(m);
                if seq < floor {
                    m.last_seen = sent_at.max(m.last_seen);
                    return Effect::NoChange;
                }
                m.last_seen = sent_at.max(m.last_seen);
                update.apply_to(m, seq);
                Effect::MediaChanged(node_id.to_string())
            }
            None => {
                if self.members.len() >= self.max_members {
                    return Effect::NoChange;
                }
                let mut m = Member {
                    node_id: node_id.to_string(),
                    display_name: None,
                    present: false, // not a presence assertion; await their Join
                    last_seq: 0,
                    last_seen: sent_at,
                    audio_muted: false,
                    video_muted: false,
                    sharing: false,
                    hand_raised: false,
                    media_seq: 0,
                    share_seq: 0,
                    hand_seq: 0,
                };
                update.apply_to(&mut m, seq);
                self.members.insert(node_id.to_string(), m);
                Effect::MediaChanged(node_id.to_string())
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

    /// Rebuild a [`Room`] from a persisted [`RoomSnapshot`]. The inverse of [`Room::snapshot`]. The
    /// member cap resets to [`DEFAULT_MAX_MEMBERS`] (it is a local DoS-policy knob, not persisted
    /// state); re-apply [`Room::with_max_members`] if a non-default cap is wanted.
    pub fn restore(snap: RoomSnapshot) -> Self {
        let members =
            snap.members.into_iter().map(|m| (m.node_id.clone(), m)).collect::<HashMap<_, _>>();
        Room {
            room_id: snap.room_id,
            me: snap.me,
            members,
            next_seq: snap.next_seq,
            max_members: DEFAULT_MAX_MEMBERS,
            ended: false,
        }
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
    /// Serialize to JSON bytes for persistence (disk, blob store, or a resume payload). The
    /// serialization error is surfaced rather than masked behind an empty object.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow::anyhow!("serialize room snapshot: {e}"))
    }

    /// Parse a snapshot from JSON bytes. Rejects malformed input with a descriptive error.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("malformed ce-meet room snapshot: {e}"))
    }

    /// Persist this snapshot to `path` **atomically**: write to a sibling temp file, fsync it, then
    /// rename over the destination (and fsync the parent directory on Unix). A crash mid-write can
    /// never leave a half-written, unparseable snapshot — the destination is either the old contents
    /// or the new ones, never a torn mix. Used by a host that persists room state across restarts.
    pub fn save_atomic(&self, path: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let path = path.as_ref();
        let bytes = self.to_bytes()?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        // Unique temp name in the same directory so the rename is atomic (same filesystem).
        let tmp = parent.join(format!(
            ".ce-meet-snap-{}-{}.tmp",
            std::process::id(),
            self.next_seq
        ));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all(); // best-effort directory durability
        }
        Ok(())
    }

    /// Load a snapshot previously written by [`RoomSnapshot::save_atomic`].
    pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        Self::from_bytes(&bytes)
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
    fn bc(from: &str, seq: u64, at: u64, sig: Signal) -> SignalEnvelope {
        SignalEnvelope::broadcast("r", seq, at, sig).with_sender(from)
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
        let bytes = snap.to_bytes().unwrap();
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

    // ---- media-control state ----

    #[test]
    fn media_signal_updates_member_state() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        let eff = room.apply(&bc("a", 1, 11, Signal::Media { audio_muted: true, video_muted: true }));
        assert_eq!(eff, Effect::MediaChanged("a".into()));
        let m = room.member("a").unwrap();
        assert!(m.audio_muted && m.video_muted);
        // unmute audio, keep video off
        room.apply(&bc("a", 2, 12, Signal::Media { audio_muted: false, video_muted: true }));
        let m = room.member("a").unwrap();
        assert!(!m.audio_muted && m.video_muted);
    }

    #[test]
    fn media_state_is_lww_ordered_and_ignores_stale() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        room.apply(&bc("a", 5, 50, Signal::Media { audio_muted: true, video_muted: false }));
        // a stale (lower seq) media update must not override
        assert_eq!(
            room.apply(&bc("a", 3, 30, Signal::Media { audio_muted: false, video_muted: true })),
            Effect::NoChange
        );
        assert!(room.member("a").unwrap().audio_muted);
        assert!(!room.member("a").unwrap().video_muted);
    }

    #[test]
    fn screen_share_and_raise_hand_track() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        room.apply(&bc("a", 1, 11, Signal::ScreenShare { active: true }));
        assert!(room.member("a").unwrap().sharing);
        room.apply(&bc("a", 2, 12, Signal::RaiseHand { raised: true }));
        assert!(room.member("a").unwrap().hand_raised);
        room.apply(&bc("a", 3, 13, Signal::ScreenShare { active: false }));
        assert!(!room.member("a").unwrap().sharing);
        assert!(room.member("a").unwrap().hand_raised, "raised hand persists across unrelated update");
    }

    #[test]
    fn media_before_join_creates_absent_placeholder_then_join_converges() {
        // A reordered Media arrives before the Join; the state is retained, the member absent until
        // the Join (higher seq? no — Join has lower seq). Verify state survives and presence resolves.
        let mut room = Room::new("r", "me");
        // Media at seq 2 arrives first
        room.apply(&bc("a", 2, 20, Signal::Media { audio_muted: true, video_muted: false }));
        assert!(!room.member("a").unwrap().present, "media is not a presence assertion");
        assert!(room.member("a").unwrap().audio_muted);
        // Join at seq 0 is older -> ignored for presence (seq < last_seq), member stays absent.
        assert_eq!(room.apply(&join("a", 0, 10)), Effect::NoChange);
        // A newer Join (seq 3) marks present and keeps the media state.
        assert_eq!(room.apply(&join("a", 3, 30)), Effect::Joined("a".into()));
        assert!(room.member("a").unwrap().audio_muted);
        assert!(room.member("a").unwrap().present);
    }

    #[test]
    fn media_state_excluded_from_digest() {
        let mut r1 = Room::new("r", "me");
        let mut r2 = Room::new("r", "me");
        r1.apply(&join("a", 0, 10));
        r2.apply(&join("a", 0, 10));
        // r1 sees a mute (advances seq), r2 does not. digest excludes media but DOES include last_seq,
        // so to compare membership identity alone we compare present-sets.
        r1.apply(&bc("a", 1, 11, Signal::Media { audio_muted: true, video_muted: false }));
        assert_eq!(r1.present(), r2.present());
        assert!(r1.member("a").unwrap().audio_muted);
        assert!(!r2.member("a").unwrap().audio_muted);
    }

    // ---- transient broadcasts: reaction / chat / recording / end-room ----

    #[test]
    fn reaction_and_chat_surface_without_roster_change() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        let before = room.digest();
        let eff = room.apply(&bc("a", 1, 11, Signal::Reaction { emoji: "👍".into() }));
        assert_eq!(eff, Effect::Reaction { from: "a".into(), emoji: "👍".into() });
        let eff = room.apply(&bc("a", 2, 12, Signal::Chat { body: "hi".into() }));
        assert_eq!(eff, Effect::Chat { from: "a".into(), body: "hi".into() });
        // reactions/chat do not advance the LWW seq register (they are not membership)
        assert_eq!(room.digest(), before, "transient broadcasts leave membership identity unchanged");
        assert_eq!(room.present(), vec!["a"]);
    }

    #[test]
    fn recording_consent_surfaces() {
        let mut room = Room::new("r", "me");
        room.apply(&join("host", 0, 10));
        let eff = room.apply(&bc("host", 1, 11, Signal::Recording { active: true }));
        assert_eq!(eff, Effect::Recording { from: "host".into(), active: true });
    }

    #[test]
    fn end_room_sets_ended_and_surfaces() {
        let mut room = Room::new("r", "me");
        room.apply(&join("host", 0, 10));
        assert!(!room.is_ended());
        let eff = room.apply(&bc("host", 1, 11, Signal::EndRoom { reason: Some("done".into()) }));
        assert_eq!(eff, Effect::RoomEnded { by: "host".into(), reason: Some("done".into()) });
        assert!(room.is_ended());
    }

    #[test]
    fn directed_moderation_surfaces_as_directed() {
        let mut room = Room::new("r", "me");
        let kick = SignalEnvelope::directed("r", "me", 0, 10, Signal::Kick { reason: None })
            .with_sender("host");
        match room.apply(&kick) {
            Effect::Directed(e) => assert_eq!(e.signal.tag(), "kick"),
            other => panic!("expected Directed kick, got {other:?}"),
        }
        let fm = SignalEnvelope::directed("r", "me", 1, 11, Signal::ForceMute { audio_muted: true })
            .with_sender("host");
        match room.apply(&fm) {
            Effect::Directed(e) => assert_eq!(e.signal.tag(), "forcemute"),
            other => panic!("expected Directed force-mute, got {other:?}"),
        }
        // directed moderation never alters the roster
        assert_eq!(room.present_count(), 0);
    }

    // ---- member cap (DoS guard) ----

    #[test]
    fn member_cap_rejects_new_members_beyond_limit() {
        let mut room = Room::new("r", "me").with_max_members(3);
        assert_eq!(room.max_members(), 3);
        for i in 0..3 {
            assert_eq!(room.apply(&join(&format!("m{i}"), 0, 10)), Effect::Joined(format!("m{i}")));
        }
        assert_eq!(room.known_count(), 3);
        // a 4th distinct member is refused (no allocation)
        assert_eq!(room.apply(&join("overflow", 0, 10)), Effect::NoChange);
        assert_eq!(room.known_count(), 3);
        assert!(!room.present().contains(&"overflow".to_string()));
    }

    #[test]
    fn member_cap_still_allows_updates_to_known_members() {
        let mut room = Room::new("r", "me").with_max_members(2);
        room.apply(&join("a", 0, 10));
        room.apply(&join("b", 0, 10));
        // cap reached; but an existing member can still leave/rejoin
        assert_eq!(room.apply(&leave("a", 1, 11)), Effect::Left("a".into()));
        assert_eq!(room.apply(&join("a", 2, 12)), Effect::Joined("a".into()));
        // and media updates to a known member are accepted
        assert_eq!(
            room.apply(&bc("b", 1, 11, Signal::Media { audio_muted: true, video_muted: false })),
            Effect::MediaChanged("b".into())
        );
    }

    #[test]
    fn member_cap_zero_is_clamped_to_one() {
        let room = Room::new("r", "me").with_max_members(0);
        assert_eq!(room.max_members(), 1);
    }

    #[test]
    fn media_signal_respects_member_cap() {
        let mut room = Room::new("r", "me").with_max_members(1);
        room.apply(&join("a", 0, 10));
        // a media signal from a NEW member beyond the cap is dropped
        assert_eq!(
            room.apply(&bc("b", 0, 10, Signal::ScreenShare { active: true })),
            Effect::NoChange
        );
        assert_eq!(room.known_count(), 1);
    }

    // ---- atomic persistence ----

    #[test]
    fn save_atomic_then_load_round_trips() {
        let mut room = Room::new("r", "me");
        room.apply(&join("a", 0, 10));
        room.apply(&bc("a", 1, 11, Signal::Media { audio_muted: true, video_muted: false }));
        let snap = room.snapshot();
        let dir = std::env::temp_dir().join(format!("ce-meet-snap-{}", std::process::id()));
        let path = dir.join("room.json");
        snap.save_atomic(&path).unwrap();
        let back = RoomSnapshot::load(&path).unwrap();
        assert_eq!(snap, back);
        // overwrite atomically with a newer snapshot
        room.apply(&leave("a", 2, 12));
        let snap2 = room.snapshot();
        snap2.save_atomic(&path).unwrap();
        let back2 = RoomSnapshot::load(&path).unwrap();
        assert_eq!(snap2, back2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
