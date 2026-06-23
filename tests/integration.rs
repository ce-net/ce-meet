//! Integration tests for ce-meet: full SDP/ICE round-trips through the envelope+roster pipeline,
//! roster join/leave convergence across independent replicas, the capability gate end-to-end, and
//! failure injection (dropped peer, malformed input, duplicate/reordered delivery).
//!
//! These exercise the library against in-memory state only (no running node) — the signaling logic
//! is pure and deterministic, so it is fully testable without the mesh. Live-mesh behavior is the
//! province of the SDK transport (already tested in ce-rs); here we validate the protocol + state
//! machine that rides it.

use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
use ce_identity::Identity;
use ce_meet::caps::Gate;
use ce_meet::proto::{ABILITY_JOIN, Signal, SignalEnvelope};
use ce_meet::room::{Effect, Room};
use std::sync::atomic::{AtomicU64, Ordering};

fn id(tag: &str) -> Identity {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-meet-it-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

/// Deliver an envelope (as it would arrive off pubsub) to a replica: serialize, "transport",
/// deserialize, stamp the authenticated sender, apply.
fn deliver(room: &mut Room, from: &str, env: &SignalEnvelope) -> Effect {
    let bytes = env.to_bytes();
    let received = SignalEnvelope::from_bytes(&bytes).unwrap().with_sender(from);
    room.apply(&received)
}

#[test]
fn sdp_offer_answer_ice_round_trip() {
    // A sends an offer to B; B answers; both trickle ICE. The roster machine surfaces each as a
    // Directed effect carrying the exact SDP/candidate, addressed to the right peer.
    let mut b_view = Room::new("call", "B");

    let offer = SignalEnvelope::directed(
        "call",
        "B",
        0,
        100,
        Signal::Offer { sdp: "v=0\r\no=A 1 1 IN IP4 0.0.0.0\r\n".into() },
    );
    match deliver(&mut b_view, "A", &offer) {
        Effect::Directed(e) => {
            assert!(e.addressed_to("B"));
            assert_eq!(e.signal, Signal::Offer { sdp: "v=0\r\no=A 1 1 IN IP4 0.0.0.0\r\n".into() });
        }
        other => panic!("expected offer Directed, got {other:?}"),
    }

    // B's answer back to A — validated through A's view.
    let mut a_view = Room::new("call", "A");
    let answer =
        SignalEnvelope::directed("call", "A", 0, 101, Signal::Answer { sdp: "v=0\r\nanswer\r\n".into() });
    match deliver(&mut a_view, "B", &answer) {
        Effect::Directed(e) => assert!(e.addressed_to("A")),
        other => panic!("expected answer Directed, got {other:?}"),
    }

    // Trickle ICE both ways.
    let cand = SignalEnvelope::directed(
        "call",
        "B",
        1,
        102,
        Signal::IceCandidate {
            candidate: "candidate:1 1 UDP 2122260223 192.168.1.2 50000 typ host".into(),
            sdp_mid: Some("0".into()),
            sdp_m_line_index: Some(0),
        },
    );
    match deliver(&mut b_view, "A", &cand) {
        Effect::Directed(e) => assert_eq!(e.signal.tag(), "ice"),
        other => panic!("expected ICE Directed, got {other:?}"),
    }
    // Directed signaling never alters the roster.
    assert_eq!(b_view.present_count(), 0);
}

#[test]
fn two_replicas_converge_on_membership() {
    // Two participants each keep their own Room view; both observe the same join/leave events in
    // DIFFERENT orders and must converge to the same present-set.
    let mut v1 = Room::new("r", "v1");
    let mut v2 = Room::new("r", "v2");

    let a_join = SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: Some("Alice".into()) });
    let b_join = SignalEnvelope::broadcast("r", 0, 11, Signal::Join { display_name: Some("Bob".into()) });
    let a_leave = SignalEnvelope::broadcast("r", 1, 20, Signal::Leave);

    // v1 sees: a_join, b_join, a_leave
    deliver(&mut v1, "A", &a_join);
    deliver(&mut v1, "B", &b_join);
    deliver(&mut v1, "A", &a_leave);

    // v2 sees a totally different order, with a duplicate: b_join, a_leave, a_join, b_join
    deliver(&mut v2, "B", &b_join);
    deliver(&mut v2, "A", &a_leave);
    deliver(&mut v2, "A", &a_join);
    deliver(&mut v2, "B", &b_join);

    assert_eq!(v1.present(), vec!["B"]);
    assert_eq!(v2.present(), v1.present(), "replicas must converge regardless of order");
}

#[test]
fn dropped_peer_is_pruned_by_liveness() {
    // A peer joins, never sends Leave, and goes silent. Liveness pruning removes it; a later real
    // message (higher seq) correctly re-adds it.
    let mut room = Room::new("r", "me");
    deliver(&mut room, "ghost", &SignalEnvelope::broadcast("r", 0, 100, Signal::Join { display_name: None }));
    deliver(&mut room, "live", &SignalEnvelope::broadcast("r", 0, 100, Signal::Join { display_name: None }));
    // live refreshes at t=300; ghost stays silent
    deliver(&mut room, "live", &SignalEnvelope::broadcast("r", 1, 300, Signal::Keepalive));

    let pruned = room.prune_stale(400, 120);
    assert_eq!(pruned, vec!["ghost"]);
    assert_eq!(room.present(), vec!["live"]);

    // ghost comes back with a higher seq -> re-added
    deliver(&mut room, "ghost", &SignalEnvelope::broadcast("r", 1, 410, Signal::Join { display_name: None }));
    assert!(room.present().contains(&"ghost".to_string()));
}

#[test]
fn duplicate_and_reordered_delivery_is_safe() {
    let mut room = Room::new("r", "me");
    let join = SignalEnvelope::broadcast("r", 5, 10, Signal::Join { display_name: None });
    let leave = SignalEnvelope::broadcast("r", 6, 11, Signal::Leave);

    // Apply leave (newer) before join (older), then a duplicate join.
    deliver(&mut room, "x", &leave);
    deliver(&mut room, "x", &join);
    deliver(&mut room, "x", &join);
    // The leave (seq 6) wins; the older join (seq 5) never resurrects.
    assert!(room.present().is_empty());
}

#[test]
fn capability_gate_admits_then_revokes() {
    // End-to-end gate: host issues meet:join; the joiner is admitted; after revocation it is denied.
    let host = id("host");
    let joiner = id("joiner");
    let cap = SignedCapability::issue(
        &host,
        joiner.node_id(),
        vec![ABILITY_JOIN.to_string()],
        Resource::Any,
        Caveats::default(),
        7,
        None,
    );
    let chain = encode_chain(&[cap]);

    let gate = Gate::gated(host.node_id(), vec![]);
    assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000).is_ok());

    let revoked_gate =
        Gate::gated(host.node_id(), vec![]).with_revoked([(host.node_id_hex(), 7u64)]);
    assert!(revoked_gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000).is_err());
}

#[test]
fn capability_gate_rejects_forged_and_malformed() {
    let host = id("host");
    let stranger = id("stranger");
    let joiner = id("joiner");

    // forged: rooted at a stranger, not the host
    let forged = SignedCapability::issue(
        &stranger,
        joiner.node_id(),
        vec![ABILITY_JOIN.to_string()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let gate = Gate::gated(host.node_id(), vec![]);
    assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &encode_chain(&[forged]), &[], 1000).is_err());

    // malformed hex
    assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, "nothex", &[], 1000).is_err());
    // empty chain
    assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, "", &[], 1000).is_err());
}

#[test]
fn open_room_admits_anyone() {
    let host = id("host");
    let gate = Gate::open(host.node_id());
    // anyone, no caps
    for who in ["a", "b", "c"] {
        let nid = id(who).node_id_hex();
        assert!(gate.check(&nid, ABILITY_JOIN, "", &[], 1000).is_ok());
    }
}

#[test]
fn ordering_is_observable_via_seq() {
    // The roster machine uses seq to break ties; an integration consumer can also use seq on
    // Directed envelopes to order an out-of-order ICE flow. Verify seq survives the round trip.
    let mut room = Room::new("r", "me");
    let e1 = SignalEnvelope::directed("r", "me", 41, 10, Signal::IceCandidate {
        candidate: "c1".into(),
        sdp_mid: None,
        sdp_m_line_index: None,
    });
    let e2 = SignalEnvelope::directed("r", "me", 42, 11, Signal::IceCandidate {
        candidate: "c2".into(),
        sdp_mid: None,
        sdp_m_line_index: None,
    });
    let mut seqs = Vec::new();
    for e in [&e2, &e1] {
        if let Effect::Directed(env) = deliver(&mut room, "peer", e) {
            seqs.push(env.seq);
        }
    }
    // Consumer can sort by seq to recover send order even when delivered reversed.
    seqs.sort();
    assert_eq!(seqs, vec![41, 42]);
}
