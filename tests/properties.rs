//! Property tests for ce-meet's load-bearing logic:
//!  - envelope serialization round-trips for arbitrary signals;
//!  - roster convergence: applying the same set of membership events in ANY order (with duplicates)
//!    yields the same present-set (the CRDT property);
//!  - LWW correctness: the highest-seq action per member always wins;
//!  - TURN credential derive/verify is sound (and tamper/expiry are rejected).
//!
//! These validate the invariants the foundation rests on, not just example cases.

use ce_meet::order::OrderedInbox;
use ce_meet::proto::{Signal, SignalEnvelope};
use ce_meet::room::Room;
use ce_meet::turn::TurnCredential;
use proptest::prelude::*;
use std::collections::BTreeSet;

/// An arbitrary Signal.
fn any_signal() -> impl Strategy<Value = Signal> {
    prop_oneof![
        any::<Option<String>>().prop_map(|d| Signal::Join { display_name: d }),
        Just(Signal::Leave),
        Just(Signal::Keepalive),
        ".*".prop_map(|s| Signal::Offer { sdp: s }),
        ".*".prop_map(|s| Signal::Answer { sdp: s }),
        (".*", any::<Option<String>>(), any::<Option<u32>>()).prop_map(|(c, m, i)| {
            Signal::IceCandidate { candidate: c, sdp_mid: m, sdp_m_line_index: i }
        }),
        Just(Signal::IceEnd),
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
        let bytes = env.to_bytes();
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
}
