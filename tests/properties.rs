//! Property tests for ce-meet's load-bearing logic:
//!  - envelope serialization round-trips for arbitrary signals;
//!  - roster convergence: applying the same set of membership events in ANY order (with duplicates)
//!    yields the same present-set (the CRDT property);
//!  - LWW correctness: the highest-seq action per member always wins;
//!  - TURN credential derive/verify is sound (and tamper/expiry are rejected).
//!
//! These validate the invariants the foundation rests on, not just example cases.

use ce_meet::order::OrderedInbox;
use ce_meet::proto::{MAX_SDP_LEN, Signal, SignalEnvelope};
use ce_meet::room::Room;
use ce_meet::turn::{RelayCandidate, TurnCredential, select_relay};
use proptest::prelude::*;
use std::collections::BTreeSet;

/// An arbitrary, in-bounds Signal (string fields kept within the wire `MAX_*` caps so the envelope
/// survives the bounds-checking `from_bytes`). Covers every signal variant including the media-control
/// and moderation additions.
fn any_signal() -> impl Strategy<Value = Signal> {
    // A short display name (<= MAX_NAME_LEN).
    let name = "[a-zA-Z0-9 ]{0,32}";
    prop_oneof![
        proptest::option::of(name).prop_map(|d| Signal::Join { display_name: d }),
        Just(Signal::Leave),
        Just(Signal::Keepalive),
        "[ -~]{0,256}".prop_map(|s| Signal::Offer { sdp: s }),
        "[ -~]{0,256}".prop_map(|s| Signal::Answer { sdp: s }),
        ("[ -~]{0,128}", proptest::option::of("[a-z0-9]{0,8}"), any::<Option<u32>>()).prop_map(
            |(c, m, i)| { Signal::IceCandidate { candidate: c, sdp_mid: m, sdp_m_line_index: i } }
        ),
        Just(Signal::IceEnd),
        (any::<bool>(), any::<bool>())
            .prop_map(|(a, v)| Signal::Media { audio_muted: a, video_muted: v }),
        any::<bool>().prop_map(|a| Signal::ScreenShare { active: a }),
        any::<bool>().prop_map(|r| Signal::RaiseHand { raised: r }),
        "[a-z]{0,16}".prop_map(|e| Signal::Reaction { emoji: e }),
        "[ -~]{0,256}".prop_map(|b| Signal::Chat { body: b }),
        any::<bool>().prop_map(|a| Signal::Recording { active: a }),
        proptest::option::of("[ -~]{0,64}").prop_map(|r| Signal::Kick { reason: r }),
        any::<bool>().prop_map(|a| Signal::ForceMute { audio_muted: a }),
        proptest::option::of("[ -~]{0,64}").prop_map(|r| Signal::EndRoom { reason: r }),
    ]
}

/// An arbitrary envelope.
fn any_envelope() -> impl Strategy<Value = SignalEnvelope> {
    ("[a-z0-9]{1,16}", any::<Option<String>>(), any::<u64>(), any::<u64>(), any_signal()).prop_map(
        |(room_id, to, seq, sent_at, signal)| SignalEnvelope {
            room_id,
            from: String::new(),
            to,
            seq,
            sent_at,
            signal,
        },
    )
}

proptest! {
    #[test]
    fn envelope_json_round_trips(env in any_envelope()) {
        let bytes = env.to_bytes().unwrap();
        let back = SignalEnvelope::from_bytes(&bytes).unwrap();
        prop_assert_eq!(env, back);
    }

    /// Convergence: a fixed multiset of (member, seq, present) membership events, applied in any
    /// permutation (and duplicated), always yields the same present-set.
    #[test]
    fn roster_converges_regardless_of_order(
        // up to 8 events: (member 0..4, seq 0..6, present)
        events in proptest::collection::vec((0u8..4, 0u64..6, any::<bool>()), 1..8),
        // a permutation seed
        shuffle in any::<u64>(),
    ) {
        let to_env = |(m, seq, present): &(u8, u64, bool)| {
            let from = format!("m{m}");
            let signal = if *present { Signal::Join { display_name: None } } else { Signal::Leave };
            (from, SignalEnvelope::broadcast("r", *seq, 0, signal))
        };

        // Reference order.
        let mut a = Room::new("r", "me");
        for ev in &events {
            let (from, env) = to_env(ev);
            a.apply(&env.with_sender(&from));
        }

        // A different order: rotate by a seed-derived amount, and duplicate the first event.
        let mut shuffled = events.clone();
        let n = shuffled.len();
        let rot = (shuffle as usize) % n;
        shuffled.rotate_left(rot);
        if let Some(first) = events.first().copied() {
            shuffled.push(first); // duplicate delivery
        }

        let mut b = Room::new("r", "me");
        for ev in &shuffled {
            let (from, env) = to_env(ev);
            b.apply(&env.with_sender(&from));
        }

        prop_assert_eq!(a.present(), b.present());
    }

    /// LWW: for a single member, the action with the highest seq determines presence.
    #[test]
    fn highest_seq_action_wins(
        actions in proptest::collection::vec((0u64..100, any::<bool>()), 1..20),
    ) {
        let mut room = Room::new("r", "me");
        for (seq, present) in &actions {
            let signal = if *present { Signal::Join { display_name: None } } else { Signal::Leave };
            room.apply(&SignalEnvelope::broadcast("r", *seq, 0, signal).with_sender("m"));
        }
        // Expected outcome: among all actions sharing the MAX seq, absent (Leave) wins over present
        // (Join) by the remove-bias tie-break — so the member is present only if EVERY max-seq action
        // asserts present.
        let max_seq = actions.iter().map(|(seq, _)| *seq).max().unwrap();
        let expected_present = actions.iter().filter(|(seq, _)| *seq == max_seq).all(|(_, p)| *p);
        prop_assert_eq!(room.present().contains(&"m".to_string()), expected_present);
    }

    /// A directed signal never changes membership, for any sender/recipient/seq.
    #[test]
    fn directed_signals_never_change_roster(
        sender in "[a-z]{1,8}",
        recipient in "[a-z]{1,8}",
        seq in any::<u64>(),
        sdp in ".*",
    ) {
        let mut room = Room::new("r", "me");
        let env = SignalEnvelope::directed("r", recipient, seq, 0, Signal::Offer { sdp })
            .with_sender(&sender);
        room.apply(&env);
        prop_assert_eq!(room.present_count(), 0);
    }

    /// TURN credentials verify iff derived from the same secret and not expired.
    #[test]
    fn turn_credential_soundness(
        channel in "[a-f0-9]{1,16}",
        secret in proptest::collection::vec(any::<u8>(), 1..32),
        now in 0u64..1_000_000,
        ttl in 1u64..100_000,
        check_offset in 0u64..200_000,
    ) {
        let cred = TurnCredential::derive(&channel, &secret, now, ttl);
        let check_at = now.saturating_add(check_offset);
        let expected = check_at <= cred.expires_at;
        prop_assert_eq!(cred.verify(&secret, check_at), expected);
        // A different secret never verifies.
        let mut other = secret.clone();
        other.push(0xff);
        prop_assert!(!cred.verify(&other, now));
    }

    /// Malformed bytes never panic the parser (graceful error, never a crash).
    #[test]
    fn parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = SignalEnvelope::from_bytes(&bytes); // must not panic; Ok or Err both fine
    }

    /// Snapshot/restore is a no-op on convergent state: a room snapshotted mid-stream, restored, and
    /// fed the remaining events ends in the SAME present-set as a room that processed every event
    /// without interruption. (Persistent-state correctness under concurrent updates.)
    #[test]
    fn snapshot_restore_preserves_convergence(
        events in proptest::collection::vec((0u8..4, 0u64..6, any::<bool>()), 1..10),
        split in 0usize..10,
    ) {
        let to_env = |(m, seq, present): &(u8, u64, bool)| {
            let from = format!("m{m}");
            let signal = if *present { Signal::Join { display_name: None } } else { Signal::Leave };
            (from, SignalEnvelope::broadcast("r", *seq, 0, signal))
        };

        // Uninterrupted reference.
        let mut reference = Room::new("r", "me");
        for ev in &events {
            let (from, env) = to_env(ev);
            reference.apply(&env.with_sender(&from));
        }

        // Snapshot after `split` events, restore, then apply the rest.
        let cut = split.min(events.len());
        let mut a = Room::new("r", "me");
        for ev in &events[..cut] {
            let (from, env) = to_env(ev);
            a.apply(&env.with_sender(&from));
        }
        let snap = Room::restore(Room::restore(a.snapshot()).snapshot()); // double round-trip
        let mut restored = snap;
        for ev in &events[cut..] {
            let (from, env) = to_env(ev);
            restored.apply(&env.with_sender(&from));
        }

        prop_assert_eq!(restored.present(), reference.present());
        prop_assert_eq!(restored.digest(), reference.digest());
    }

    /// Merging two replicas' snapshots converges: replica A applies a subset, replica B applies the
    /// rest, then each merges the other's snapshot — both end at the same present-set as a replica
    /// that applied everything. Merge is commutative and convergent (the CRDT law).
    #[test]
    fn merge_snapshots_converge(
        events in proptest::collection::vec((0u8..4, 0u64..6, any::<bool>()), 1..10),
        split in 0usize..10,
    ) {
        let to_env = |(m, seq, present): &(u8, u64, bool)| {
            let from = format!("m{m}");
            let signal = if *present { Signal::Join { display_name: None } } else { Signal::Leave };
            (from, SignalEnvelope::broadcast("r", *seq, 0, signal))
        };

        let mut reference = Room::new("r", "me");
        for ev in &events { let (f, e) = to_env(ev); reference.apply(&e.with_sender(&f)); }

        let cut = split.min(events.len());
        let mut a = Room::new("r", "me");
        for ev in &events[..cut] { let (f, e) = to_env(ev); a.apply(&e.with_sender(&f)); }
        let mut b = Room::new("r", "me");
        for ev in &events[cut..] { let (f, e) = to_env(ev); b.apply(&e.with_sender(&f)); }

        let sa = a.snapshot();
        let sb = b.snapshot();
        a.merge_snapshot(&sb);
        b.merge_snapshot(&sa);

        prop_assert_eq!(a.present(), reference.present());
        prop_assert_eq!(b.present(), a.present());
    }

    /// SDP/ICE ordering: a contiguous run of seqs 0..n, delivered in ANY permutation with duplicates,
    /// is released by the reorder buffer in strictly ascending seq order, exactly once each.
    #[test]
    fn ordered_inbox_delivers_in_order_under_any_permutation(
        n in 1u64..12,
        perm_seed in any::<u64>(),
        dup_seed in any::<u64>(),
    ) {
        // Build envelopes for seqs 0..n.
        let mk = |seq: u64| SignalEnvelope::directed("r", "me", seq, seq, Signal::IceCandidate {
            candidate: format!("c{seq}"), sdp_mid: None, sdp_m_line_index: None,
        }).with_sender("peer");

        // Deterministic shuffle: rotate then swap a pair, and duplicate one element.
        let mut order: Vec<u64> = (0..n).collect();
        let rot = (perm_seed as usize) % (n as usize);
        order.rotate_left(rot);
        if n >= 2 {
            let i = (perm_seed as usize) % (n as usize);
            let j = (dup_seed as usize) % (n as usize);
            order.swap(i, j);
        }
        let dup = order[(dup_seed as usize) % order.len()];
        order.push(dup); // a duplicate arrival

        // Window must cover the whole run so a legitimate reorder is never force-skipped.
        let mut inbox = OrderedInbox::with_window(n + 4);
        let mut delivered: Vec<u64> = Vec::new();
        for seq in order {
            for out in inbox.offer(mk(seq)) {
                delivered.push(out.seq);
            }
        }
        // Every seq delivered exactly once, in strictly ascending order.
        let expected: Vec<u64> = (0..n).collect();
        prop_assert_eq!(&delivered, &expected);
        // (cross-check: no duplicates, full set)
        let as_set: BTreeSet<u64> = delivered.iter().copied().collect();
        prop_assert_eq!(as_set.len(), n as usize);
    }

    /// The reorder buffer never emits a seq lower than one it already emitted (monotonic output),
    /// for arbitrary arrival sequences (including gaps it may force-skip past). No resurrection of an
    /// already-delivered or skipped seq.
    #[test]
    fn ordered_inbox_output_is_monotonic(
        arrivals in proptest::collection::vec(0u64..20, 0..40),
    ) {
        let mk = |seq: u64| SignalEnvelope::directed("r", "me", seq, seq, Signal::IceEnd)
            .with_sender("peer");
        let mut inbox = OrderedInbox::with_window(8);
        let mut last: Option<u64> = None;
        for seq in arrivals {
            for out in inbox.offer(mk(seq)) {
                if let Some(prev) = last {
                    prop_assert!(out.seq > prev, "output must strictly increase: {} after {}", out.seq, prev);
                }
                last = Some(out.seq);
            }
        }
    }

    /// Bounds: any signal whose strings are within the documented caps validates; pushing the
    /// largest bounded field one byte over the cap always fails. (No oversized blob slips through.)
    #[test]
    fn validate_is_exact_at_the_sdp_boundary(extra in 0usize..4) {
        let at_cap = Signal::Offer { sdp: "a".repeat(MAX_SDP_LEN) };
        prop_assert!(at_cap.validate().is_ok());
        let over = Signal::Offer { sdp: "a".repeat(MAX_SDP_LEN + 1 + extra) };
        prop_assert!(over.validate().is_err());
    }

    /// Media-control state converges: a member's join plus an arbitrary permutation (with a duplicate)
    /// of mute/share/hand toggles yields the same final per-member media state regardless of order.
    /// Each toggle gets a unique, strictly-increasing seq (the well-behaved-sender contract: a sender
    /// never emits two different values at the same seq), so the per-attribute LWW has a clear winner.
    #[test]
    fn media_state_converges_under_permutation(
        kinds in proptest::collection::vec((0u8..3, any::<bool>()), 1..8),
        rot in any::<u64>(),
    ) {
        // Assign a unique seq per toggle by index (1-based; 0 is the join).
        let toggles: Vec<(u64, u8, bool)> =
            kinds.iter().enumerate().map(|(i, (k, v))| (i as u64 + 1, *k, *v)).collect();

        let to_sig = |(_, kind, val): &(u64, u8, bool)| match kind {
            0 => Signal::Media { audio_muted: *val, video_muted: false },
            1 => Signal::ScreenShare { active: *val },
            _ => Signal::RaiseHand { raised: *val },
        };

        let mut reference = Room::new("r", "me");
        reference.apply(&SignalEnvelope::broadcast("r", 0, 0, Signal::Join { display_name: None }).with_sender("m"));
        for t in &toggles {
            reference.apply(&SignalEnvelope::broadcast("r", t.0, t.0, to_sig(t)).with_sender("m"));
        }

        let mut shuffled = toggles.clone();
        let n = shuffled.len();
        shuffled.rotate_left((rot as usize) % n);
        if let Some(first) = toggles.first().copied() { shuffled.push(first); } // duplicate delivery

        let mut other = Room::new("r", "me");
        other.apply(&SignalEnvelope::broadcast("r", 0, 0, Signal::Join { display_name: None }).with_sender("m"));
        for t in &shuffled {
            other.apply(&SignalEnvelope::broadcast("r", t.0, t.0, to_sig(t)).with_sender("m"));
        }

        let a = reference.member("m").unwrap();
        let b = other.member("m").unwrap();
        prop_assert_eq!((a.audio_muted, a.sharing, a.hand_raised),
                        (b.audio_muted, b.sharing, b.hand_raised));
    }

    /// The member cap is never exceeded for any flood of distinct senders.
    #[test]
    fn member_cap_is_never_exceeded(
        cap in 1usize..32,
        senders in 1usize..200,
    ) {
        let mut room = Room::new("r", "me").with_max_members(cap);
        for i in 0..senders {
            let from = format!("s{i}");
            room.apply(&SignalEnvelope::broadcast("r", 0, 0, Signal::Join { display_name: None }).with_sender(&from));
        }
        prop_assert!(room.known_count() <= cap);
    }

    /// OrderedInbox near u64::MAX: contiguous seqs starting just below the wraparound boundary deliver
    /// in order without panicking (saturating arithmetic guards the edge). The buffer never wraps to a
    /// lower seq.
    #[test]
    fn ordered_inbox_handles_high_seqs(
        base_off in 0u64..5,
        len in 1u64..6,
    ) {
        let base = u64::MAX - 6 + base_off;
        let mk = |seq: u64| SignalEnvelope::directed("r", "me", seq, 0, Signal::IceEnd).with_sender("peer");
        let mut inbox = OrderedInbox::with_window(16);
        let mut delivered: Vec<u64> = Vec::new();
        // anchor at `base`, then deliver base..base+len (saturating at u64::MAX)
        for k in 0..len {
            let seq = base.saturating_add(k);
            for out in inbox.offer(mk(seq)) {
                delivered.push(out.seq);
            }
        }
        // output is monotonic and within [base, u64::MAX]
        for w in delivered.windows(2) {
            prop_assert!(w[1] > w[0]);
        }
        prop_assert!(delivered.iter().all(|&s| s >= base));
    }

    /// select_relay output is a stable, score-ordered permutation of its input (same multiset, sorted
    /// best-first), for arbitrary candidate sets. Never drops or invents a candidate.
    #[test]
    fn select_relay_is_a_stable_permutation(
        cands in proptest::collection::vec((0u32..500, 0.0f32..1.0), 0..16),
    ) {
        let input: Vec<RelayCandidate> = cands.iter().enumerate().map(|(i, (rtt, rep))| {
            let mut c = RelayCandidate::new(format!("node{i:04}"), format!("turn:r{i}:3478"));
            c.rtt_ms = *rtt;
            c.reputation = *rep;
            c
        }).collect();
        let ranked = select_relay(input.clone());
        // same set of node ids
        let in_ids: BTreeSet<_> = input.iter().map(|c| c.node_id.clone()).collect();
        let out_ids: BTreeSet<_> = ranked.iter().map(|c| c.node_id.clone()).collect();
        prop_assert_eq!(in_ids, out_ids);
        // sorted best-first (non-decreasing score)
        for w in ranked.windows(2) {
            prop_assert!(w[0].score() <= w[1].score());
        }
    }
}
