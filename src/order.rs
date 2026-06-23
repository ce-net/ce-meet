//! SDP/ICE message ordering: a per-peer reorder buffer that turns pubsub's unordered, lossy,
//! duplicating delivery into the in-order signaling stream a WebRTC negotiation needs.
//!
//! ## Why ordering matters for signaling
//!
//! The roster ([`crate::room`]) is a CRDT and does not care about delivery order. The *directed*
//! SDP/ICE flow between two peers is different: a browser's `RTCPeerConnection` must see the SDP
//! **offer** before any trickled ICE candidate for that offer, and applying candidates out of order
//! (or replaying a duplicate) can stall negotiation. Pubsub gives no ordering, so the receiving side
//! must reorder by the sender's monotonic `seq` before handing signals to its WebRTC stack.
//!
//! ## What this buffer guarantees
//!
//! For each remote peer, [`OrderedInbox`] keeps a small reorder window keyed by the sender's `seq`:
//!
//! - **in-order delivery**: [`OrderedInbox::offer`] returns the signals that are now contiguous from
//!   the next expected `seq`, in `seq` order — never a later signal before an earlier one;
//! - **duplicate suppression**: a `seq` at or below what was already delivered is dropped;
//! - **gap tolerance**: an out-of-order future `seq` is buffered until the gap fills, then released
//!   as a run. A bounded window means a permanently lost message does not wedge the stream forever —
//!   [`OrderedInbox::skip_to`] (or the window cap) lets the consumer step past a hole.
//!
//! The buffer is per-`(peer)` because each sender's `seq` is its own monotonic counter; two peers'
//! sequences are independent. [`SignalRouter`] multiplexes one buffer per peer for the common case of
//! a room with several remote participants.

use crate::proto::SignalEnvelope;
use std::collections::HashMap;

/// The default reorder window: how many out-of-order future envelopes a peer's [`OrderedInbox`] will
/// hold before it force-advances past a presumed-lost `seq`. Signaling messages are tiny and a call
/// rarely reorders by more than a handful, so a small window bounds memory while tolerating jitter.
pub const DEFAULT_WINDOW: u64 = 64;

/// A per-peer in-order delivery buffer over the sender's monotonic `seq`.
///
/// Feed every received [`SignalEnvelope`] from one peer into [`OrderedInbox::offer`]; it returns the
/// envelopes that are now deliverable in `seq` order (possibly empty, possibly a run that a buffered
/// gap just unblocked). Duplicates and already-delivered seqs are dropped.
#[derive(Debug, Clone)]
pub struct OrderedInbox {
    /// The next `seq` we expect to deliver. Starts at 0 (the first seq any sender emits).
    next: u64,
    /// Whether anything has been delivered yet (so seq 0 is handled correctly).
    started: bool,
    /// Out-of-order future envelopes, keyed by their `seq`, awaiting the gap before them to fill.
    buffer: HashMap<u64, SignalEnvelope>,
    /// Max future envelopes to hold before force-advancing past a lost seq.
    window: u64,
}

impl Default for OrderedInbox {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderedInbox {
    /// A fresh inbox with the default reorder window, expecting the peer's first message at `seq 0`.
    pub fn new() -> Self {
        OrderedInbox { next: 0, started: false, buffer: HashMap::new(), window: DEFAULT_WINDOW }
    }

    /// A fresh inbox with an explicit reorder window. A window of 0 is treated as 1 (deliver-or-drop,
    /// no buffering) so the buffer can never be wedged by a single hole.
    pub fn with_window(window: u64) -> Self {
        OrderedInbox { next: 0, started: false, buffer: HashMap::new(), window: window.max(1) }
    }

    /// The `seq` the inbox is currently waiting to deliver next.
    pub fn next_expected(&self) -> u64 {
        self.next
    }

    /// How many out-of-order envelopes are currently buffered awaiting a gap to fill.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Offer one received envelope. Returns the envelopes now deliverable, in strictly ascending
    /// `seq` order:
    /// - the envelope itself plus any buffered run it unblocks, if it is the next expected `seq`;
    /// - an empty vec if it is a duplicate/old (`seq < next`) or a future `seq` (buffered for later);
    /// - if buffering the future `seq` would exceed the window, the buffer force-advances to the
    ///   lowest buffered `seq`, releasing what it can (a lost message never wedges the stream).
    pub fn offer(&mut self, env: SignalEnvelope) -> Vec<SignalEnvelope> {
        let seq = env.seq;

        // Duplicate or already-delivered: drop.
        if self.started && seq < self.next {
            return Vec::new();
        }
        if self.started && seq == self.next {
            // exactly expected -> deliver it and drain the contiguous run after it.
        } else if !self.started && seq > self.next {
            // First message we ever saw from this peer is ahead of seq 0: buffer it, but anchor the
            // window so we are not stuck waiting for seqs that predate our subscription forever.
            self.buffer.insert(seq, env);
            self.enforce_window();
            return self.drain();
        } else if self.started && seq > self.next {
            // future gap -> buffer.
            self.buffer.insert(seq, env);
            self.enforce_window();
            return self.drain();
        }

        // Deliver `env` now (it is the next expected, or our very first at seq 0..=next).
        self.buffer.insert(seq, env);
        if !self.started {
            // First-ever delivery: anchor `next` at this seq so a peer that starts above 0 still
            // delivers in order from where it began.
            self.next = seq;
            self.started = true;
        }
        self.drain()
    }

    /// Force the buffer to skip ahead to `seq`, abandoning any unfilled gap below it. Returns the
    /// envelopes that become deliverable as a result. A consumer calls this when it decides a lost
    /// message will never arrive (e.g. an offer it can renegotiate without).
    pub fn skip_to(&mut self, seq: u64) -> Vec<SignalEnvelope> {
        if seq > self.next || !self.started {
            self.next = seq;
            self.started = true;
            // drop anything strictly below the new floor
            self.buffer.retain(|&k, _| k >= seq);
        }
        self.drain()
    }

    /// Drain the contiguous run of buffered envelopes starting at `self.next`, advancing `next` past
    /// each delivered seq. Stops at the first gap.
    fn drain(&mut self) -> Vec<SignalEnvelope> {
        let mut out = Vec::new();
        while let Some(env) = self.buffer.remove(&self.next) {
            out.push(env);
            self.next = self.next.saturating_add(1);
            self.started = true;
        }
        out
    }

    /// If the buffer holds at least `window` future envelopes, advance `next` to the lowest buffered
    /// seq so the stream can make progress past a presumed-lost message. `window` is the maximum number
    /// of out-of-order envelopes held before the buffer gives up on the gap below them.
    fn enforce_window(&mut self) {
        if self.buffer.len() as u64 >= self.window
            && let Some(&min) = self.buffer.keys().min()
            && min > self.next
        {
            self.next = min;
            self.started = true;
        }
    }
}

/// Multiplexes one [`OrderedInbox`] per remote peer. A participant feeds every directed
/// [`SignalEnvelope`] it receives (keyed by the authenticated `from`) and gets back the in-order,
/// de-duplicated run for that peer — ready to drive its WebRTC stack one peer at a time.
#[derive(Debug, Clone, Default)]
pub struct SignalRouter {
    inboxes: HashMap<String, OrderedInbox>,
    window: u64,
}

impl SignalRouter {
    /// A router whose per-peer inboxes use the default reorder window.
    pub fn new() -> Self {
        SignalRouter { inboxes: HashMap::new(), window: DEFAULT_WINDOW }
    }

    /// A router whose per-peer inboxes use an explicit reorder window.
    pub fn with_window(window: u64) -> Self {
        SignalRouter { inboxes: HashMap::new(), window: window.max(1) }
    }

    /// Offer a received directed envelope. It is routed to the inbox for `env.from`; returns that
    /// peer's now-deliverable, in-order run. Envelopes with an empty `from` (unauthenticated) are
    /// dropped — ordering requires a known sender.
    pub fn offer(&mut self, env: SignalEnvelope) -> Vec<SignalEnvelope> {
        if env.from.is_empty() {
            return Vec::new();
        }
        let window = self.window;
        let inbox = self
            .inboxes
            .entry(env.from.clone())
            .or_insert_with(|| OrderedInbox::with_window(window));
        inbox.offer(env)
    }

    /// The number of peers this router is tracking.
    pub fn peer_count(&self) -> usize {
        self.inboxes.len()
    }

    /// Skip a single peer's inbox ahead past a presumed-lost `seq` (see [`OrderedInbox::skip_to`]).
    pub fn skip_peer_to(&mut self, peer: &str, seq: u64) -> Vec<SignalEnvelope> {
        match self.inboxes.get_mut(peer) {
            Some(inbox) => inbox.skip_to(seq),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Signal;

    fn cand(seq: u64, body: &str) -> SignalEnvelope {
        SignalEnvelope::directed(
            "r",
            "me",
            seq,
            seq,
            Signal::IceCandidate {
                candidate: body.into(),
                sdp_mid: None,
                sdp_m_line_index: None,
            },
        )
        .with_sender("peer")
    }

    fn bodies(envs: &[SignalEnvelope]) -> Vec<String> {
        envs.iter()
            .map(|e| match &e.signal {
                Signal::IceCandidate { candidate, .. } => candidate.clone(),
                other => other.tag().to_string(),
            })
            .collect()
    }

    #[test]
    fn in_order_delivers_immediately() {
        let mut ib = OrderedInbox::new();
        assert_eq!(bodies(&ib.offer(cand(0, "a"))), vec!["a"]);
        assert_eq!(bodies(&ib.offer(cand(1, "b"))), vec!["b"]);
        assert_eq!(bodies(&ib.offer(cand(2, "c"))), vec!["c"]);
        assert_eq!(ib.next_expected(), 3);
    }

    #[test]
    fn reorders_a_gap_then_releases_the_run() {
        let mut ib = OrderedInbox::new();
        assert_eq!(bodies(&ib.offer(cand(0, "a"))), vec!["a"]);
        // seq 2 arrives before seq 1 -> buffered, nothing released
        assert!(ib.offer(cand(2, "c")).is_empty());
        assert_eq!(ib.buffered(), 1);
        // seq 1 fills the gap -> 1 then 2 released in order
        assert_eq!(bodies(&ib.offer(cand(1, "b"))), vec!["b", "c"]);
        assert_eq!(ib.buffered(), 0);
        assert_eq!(ib.next_expected(), 3);
    }

    #[test]
    fn duplicates_are_dropped() {
        let mut ib = OrderedInbox::new();
        assert_eq!(bodies(&ib.offer(cand(0, "a"))), vec!["a"]);
        assert_eq!(bodies(&ib.offer(cand(1, "b"))), vec!["b"]);
        // replay older seqs -> nothing
        assert!(ib.offer(cand(0, "a")).is_empty());
        assert!(ib.offer(cand(1, "b")).is_empty());
        assert_eq!(ib.next_expected(), 2);
    }

    #[test]
    fn first_message_above_zero_anchors_in_order() {
        // A late joiner whose first observed envelope is seq 5 should deliver from 5 onward, not stall
        // forever waiting for 0..4 it will never see.
        let mut ib = OrderedInbox::new();
        // seq 5 first: buffered (we do not yet know we will never see 0..4)
        assert!(ib.offer(cand(5, "f")).is_empty());
        // seq 6 buffered too
        assert!(ib.offer(cand(6, "g")).is_empty());
        // consumer decides to skip to 5 -> releases 5,6 in order
        assert_eq!(bodies(&ib.skip_to(5)), vec!["f", "g"]);
        assert_eq!(ib.next_expected(), 7);
    }

    #[test]
    fn window_force_advances_past_a_lost_message() {
        // window = max out-of-order envelopes held before the gap below them is abandoned.
        let mut ib = OrderedInbox::with_window(3);
        // seq 0 delivered
        assert_eq!(bodies(&ib.offer(cand(0, "a"))), vec!["a"]);
        // seq 1 is lost forever; buffer 2,3 (len < window) -> nothing released yet
        assert!(ib.offer(cand(2, "c")).is_empty());
        assert!(ib.offer(cand(3, "d")).is_empty());
        // the 3rd buffered future env reaches the window: next advances to lowest buffered (2),
        // then the contiguous run 2,3,4 is released.
        let released = ib.offer(cand(4, "e"));
        assert_eq!(bodies(&released), vec!["c", "d", "e"]);
        assert_eq!(ib.next_expected(), 5);
    }

    #[test]
    fn skip_to_drops_lower_and_releases_higher() {
        let mut ib = OrderedInbox::new();
        ib.offer(cand(0, "a"));
        // buffer 3,4 with a gap at 1,2
        ib.offer(cand(3, "d"));
        ib.offer(cand(4, "e"));
        // give up on 1,2 -> skip to 3 releases 3,4
        assert_eq!(bodies(&ib.skip_to(3)), vec!["d", "e"]);
        assert_eq!(ib.next_expected(), 5);
    }

    #[test]
    fn skip_to_in_the_past_is_a_noop() {
        let mut ib = OrderedInbox::new();
        ib.offer(cand(0, "a"));
        ib.offer(cand(1, "b"));
        // we are at next=2; skipping to 1 must not rewind
        assert!(ib.skip_to(1).is_empty());
        assert_eq!(ib.next_expected(), 2);
    }

    #[test]
    fn router_keeps_peers_independent() {
        let mut r = SignalRouter::new();
        let a0 = cand(0, "a0"); // from "peer"
        let mut b0 = cand(0, "b0");
        b0.from = "other".into();
        assert_eq!(bodies(&r.offer(a0)), vec!["a0"]);
        assert_eq!(bodies(&r.offer(b0)), vec!["b0"]);
        assert_eq!(r.peer_count(), 2);
        // each peer's seq space is independent: peer's seq1 still flows
        assert_eq!(bodies(&r.offer(cand(1, "a1"))), vec!["a1"]);
    }

    #[test]
    fn router_drops_unauthenticated_sender() {
        let mut r = SignalRouter::new();
        let mut anon = cand(0, "x");
        anon.from = String::new();
        assert!(r.offer(anon).is_empty());
        assert_eq!(r.peer_count(), 0);
    }

    #[test]
    fn router_skip_peer_to_unknown_peer_is_empty() {
        let mut r = SignalRouter::new();
        assert!(r.skip_peer_to("nobody", 5).is_empty());
    }

    #[test]
    fn offer_with_window_zero_never_buffers() {
        // window 0 -> treated as 1: a single buffered future env immediately trips the window
        // (len 1 >= 1), so a hole never wedges the stream — the future seq is released at once.
        let mut ib = OrderedInbox::with_window(0);
        assert_eq!(bodies(&ib.offer(cand(0, "a"))), vec!["a"]);
        // seq 2 (gap at 1): buffer len 1 >= window 1 -> force-advance to 2 and release immediately.
        assert_eq!(bodies(&ib.offer(cand(2, "c"))), vec!["c"]);
        assert_eq!(ib.next_expected(), 3);
    }
}
