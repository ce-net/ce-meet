//! Property tests for ce-meet's load-bearing logic:
//!  - envelope serialization round-trips for arbitrary signals;
//!  - roster convergence: applying the same set of membership events in ANY order (with duplicates)
//!    yields the same present-set (the CRDT property);
//!  - LWW correctness: the highest-seq action per member always wins;
//!  - TURN credential derive/verify is sound (and tamper/expiry are rejected).
//!
//! These validate the invariants the foundation rests on, not just example cases.

use ce_meet::proto::{Signal, SignalEnvelope};
use ce_meet::room::Room;
use ce_meet::turn::TurnCredential;
use proptest::prelude::*;

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
}
