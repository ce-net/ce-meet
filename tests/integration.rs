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
use ce_meet::admit::{AdmitRateLimiter, Admitter};
use ce_meet::caps::Gate;
use ce_meet::order::{OrderedInbox, SignalRouter};
use ce_meet::proto::{
    ABILITY_HOST, ABILITY_JOIN, ABILITY_MODERATE, AdmitReq, MAX_SDP_LEN, Signal, SignalEnvelope,
};
use ce_meet::room::{Effect, Room};
use ce_meet::turn::{RelayCandidate, select_relay};
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
    let bytes = env.to_bytes().unwrap();
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

// ---- persistent room state: snapshot/restore convergence under concurrent updates ----

#[test]
fn persisted_host_converges_with_live_host_across_concurrent_updates() {
    // A host maintains the authoritative roster, snapshots it (persists), then "crashes" and
    // restores. Meanwhile concurrent joins/leaves stream in. The restored host, fed the same later
    // events, must converge to the exact same membership as a host that never crashed.
    let events: Vec<(&str, u64, bool, u64)> = vec![
        ("a", 0, true, 10),
        ("b", 0, true, 11),
        ("c", 0, true, 12),
        ("a", 1, false, 20), // a leaves
        ("b", 1, true, 21),  // b keepalive-ish re-assert
        ("c", 1, false, 22), // c leaves
        ("a", 2, true, 30),  // a rejoins
    ];
    let to_env = |(_who, seq, present, at): &(&str, u64, bool, u64)| {
        let sig = if *present { Signal::Join { display_name: None } } else { Signal::Leave };
        SignalEnvelope::broadcast("r", *seq, *at, sig)
    };

    // Live host sees all events in order.
    let mut live = Room::new("r", "host");
    for ev in &events {
        deliver(&mut live, ev.0, &to_env(ev));
    }

    // Crashing host: apply the first 3, snapshot, restore, then apply the rest in a DIFFERENT order.
    let mut crashing = Room::new("r", "host");
    for ev in &events[..3] {
        deliver(&mut crashing, ev.0, &to_env(ev));
    }
    let snap = crashing.snapshot();
    let bytes = snap.to_bytes().unwrap(); // round-trip through persistence
    let restored_snap = ce_meet::room::RoomSnapshot::from_bytes(&bytes).unwrap();
    let mut restored = Room::restore(restored_snap);
    // apply remaining events reversed + a duplicate
    let mut rest: Vec<_> = events[3..].to_vec();
    rest.reverse();
    rest.push(events[3]); // duplicate delivery
    for ev in &rest {
        deliver(&mut restored, ev.0, &to_env(ev));
    }

    assert_eq!(restored.present(), live.present(), "restored host converges with live host");
    assert_eq!(restored.digest(), live.digest());
}

#[test]
fn two_persisted_replicas_reconcile_via_merge() {
    // Two hosts each saw a disjoint slice of events, persist, then reconcile by merging snapshots.
    // Both must end at the same convergent membership.
    let mut h1 = Room::new("r", "h1");
    deliver(&mut h1, "a", &SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: None }));
    deliver(&mut h1, "b", &SignalEnvelope::broadcast("r", 0, 11, Signal::Join { display_name: None }));

    let mut h2 = Room::new("r", "h2");
    deliver(&mut h2, "a", &SignalEnvelope::broadcast("r", 1, 20, Signal::Leave)); // a left (seq1)
    deliver(&mut h2, "c", &SignalEnvelope::broadcast("r", 0, 21, Signal::Join { display_name: None }));

    let s1 = h1.snapshot();
    let s2 = h2.snapshot();
    h1.merge_snapshot(&s2);
    h2.merge_snapshot(&s1);

    // Convergent outcome: a absent (seq1 leave wins), b present, c present.
    assert_eq!(h1.present(), vec!["b", "c"]);
    assert_eq!(h1.present(), h2.present(), "merged replicas converge");
    assert_eq!(h1.digest(), h2.digest());
}

// ---- participant reconnection: resume by identity ----

#[test]
fn reconnection_resume_admits_by_identity_and_preserves_seq() {
    // First join via a real capability chain; the host issues a resume token. The participant drops,
    // reconnects presenting ONLY the token, and is re-admitted by identity without the chain. The
    // token's seq_floor lets the resumed session keep a monotonic outbound seq that peers accept.
    let host = id("host");
    let joiner = id("joiner");
    let cap = SignedCapability::issue(
        &host,
        joiner.node_id(),
        vec![ABILITY_JOIN.to_string()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let chain = encode_chain(&[cap]);
    let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"host-secret".to_vec());

    // First admission with the chain.
    let first = adm.admit(
        &joiner.node_id_hex(),
        &AdmitReq { room_id: "r".into(), caps: chain, display_name: None, resume: None },
        &[],
        1000,
    );
    assert!(first.admitted);
    assert!(first.resume.is_some());
    // Pretend the participant published up to seq 4 before dropping; the host re-issues a token
    // carrying that seq floor (in practice the joiner reports it; here we mint it directly).
    let tok = adm.issue_resume(&joiner.node_id_hex(), 5, 1000);

    // Reconnect with ONLY the token, no chain.
    let again = adm.admit(
        &joiner.node_id_hex(),
        &AdmitReq { room_id: "r".into(), caps: String::new(), display_name: None, resume: Some(tok) },
        &[],
        1500,
    );
    assert!(again.admitted, "valid token resumes by identity without a chain");
    let resumed_tok = again.resume.unwrap();
    assert_eq!(resumed_tok.seq_floor, 5, "seq floor carried across reconnect");

    // The resumed participant restores its outbound seq so a peer accepts its next message.
    let joiner_hex = joiner.node_id_hex();
    let mut peer_view = Room::new("r", "peer");
    deliver(&mut peer_view, &joiner_hex,
        &SignalEnvelope::broadcast("r", 4, 10, Signal::Join { display_name: None }));
    let mut resumed = Room::new("r", joiner_hex.as_str());
    resumed.resume_outbound_from(resumed_tok.seq_floor);
    let next = resumed.next_outbound_seq();
    assert_eq!(next, 5);
    let leave = SignalEnvelope::broadcast("r", next, 20, Signal::Leave).with_sender(joiner_hex.as_str());
    assert_eq!(peer_view.apply(&leave), Effect::Left(joiner_hex.clone()));
}

#[test]
fn reconnection_with_stolen_token_is_denied() {
    let host = id("host");
    let joiner = id("joiner");
    let thief = id("thief");
    let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"host-secret".to_vec());
    let tok = adm.issue_resume(&joiner.node_id_hex(), 3, 1000);
    // Thief replays the joiner's token (and has no valid chain) -> denied.
    let resp = adm.admit(
        &thief.node_id_hex(),
        &AdmitReq { room_id: "r".into(), caps: String::new(), display_name: None, resume: Some(tok) },
        &[],
        1100,
    );
    assert!(!resp.admitted, "a token bound to another identity must not admit a thief");
}

// ---- capability-gated private rooms via the Admitter (deny/allow) ----

#[test]
fn private_room_admitter_denies_without_cap_allows_with() {
    let host = id("host");
    let joiner = id("joiner");
    let adm = Admitter::new("priv", Gate::gated(host.node_id(), vec![]), b"s".to_vec());

    // No capability -> denied.
    let denied = adm.admit(
        &joiner.node_id_hex(),
        &AdmitReq { room_id: "priv".into(), caps: String::new(), display_name: None, resume: None },
        &[],
        1000,
    );
    assert!(!denied.admitted);
    assert!(denied.resume.is_none());

    // With a valid host-issued cap -> allowed.
    let cap = SignedCapability::issue(
        &host,
        joiner.node_id(),
        vec![ABILITY_JOIN.to_string()],
        Resource::Any,
        Caveats::default(),
        9,
        None,
    );
    let chain = encode_chain(&[cap]);
    let allowed = adm.admit(
        &joiner.node_id_hex(),
        &AdmitReq { room_id: "priv".into(), caps: chain, display_name: None, resume: None },
        &[],
        1000,
    );
    assert!(allowed.admitted);
    assert!(allowed.resume.is_some());
}

// ---- SDP/ICE message ordering guarantees ----

#[test]
fn ice_flow_delivered_in_order_through_reorder_buffer() {
    // A peer sends offer(0), ice(1), ice(2), ice(3); pubsub delivers them shuffled with a duplicate.
    // The reorder buffer must hand them to the WebRTC stack in strict seq order, exactly once each.
    let mut inbox = OrderedInbox::new();
    let mk = |seq: u64, body: &str| {
        SignalEnvelope::directed("r", "me", seq, seq, Signal::IceCandidate {
            candidate: body.into(), sdp_mid: None, sdp_m_line_index: None,
        }).with_sender("peer")
    };
    let offer = SignalEnvelope::directed("r", "me", 0, 0, Signal::Offer { sdp: "o".into() })
        .with_sender("peer");

    let mut delivered: Vec<u64> = Vec::new();
    // shuffled arrival: 2, offer(0), 3, 1, dup(2)
    for env in [mk(2, "c2"), offer, mk(3, "c3"), mk(1, "c1"), mk(2, "c2-dup")] {
        for out in inbox.offer(env) {
            delivered.push(out.seq);
        }
    }
    assert_eq!(delivered, vec![0, 1, 2, 3], "strict in-order, exactly once");
}

#[test]
fn router_orders_each_peer_independently() {
    // Two peers interleave their directed flows; each peer's stream is ordered by its own seq space.
    let mut router = SignalRouter::new();
    let mk = |from: &str, seq: u64| {
        SignalEnvelope::directed("r", "me", seq, seq, Signal::IceCandidate {
            candidate: format!("{from}-{seq}"), sdp_mid: None, sdp_m_line_index: None,
        }).with_sender(from)
    };

    let mut got_a: Vec<u64> = Vec::new();
    let mut got_b: Vec<u64> = Vec::new();
    // interleaved, each out of order within its own space
    let stream = [
        mk("A", 1), // A: buffer (waiting for 0)
        mk("B", 0), // B: deliver 0
        mk("A", 0), // A: deliver 0,1
        mk("B", 2), // B: buffer
        mk("B", 1), // B: deliver 1,2
    ];
    for env in stream {
        let from = env.from.clone();
        for out in router.offer(env) {
            if from == "A" { got_a.push(out.seq) } else { got_b.push(out.seq) }
        }
    }
    assert_eq!(got_a, vec![0, 1]);
    assert_eq!(got_b, vec![0, 1, 2]);
    assert_eq!(router.peer_count(), 2);
}

// ---- in-call media-control state converges like presence ----

#[test]
fn media_state_converges_across_replicas_under_reorder() {
    // Two replicas observe a member's join + a sequence of media toggles in different orders; the
    // member's final media state must match (LWW by the member's own seq).
    let toggles = [
        (0u64, Signal::Join { display_name: None }),
        (1, Signal::Media { audio_muted: true, video_muted: false }),
        (2, Signal::ScreenShare { active: true }),
        (3, Signal::Media { audio_muted: false, video_muted: true }),
        (4, Signal::RaiseHand { raised: true }),
    ];

    let mut v1 = Room::new("call", "v1");
    for (seq, sig) in toggles.iter() {
        deliver(&mut v1, "m", &SignalEnvelope::broadcast("call", *seq, *seq, sig.clone()));
    }

    // v2 sees them shuffled + a duplicate
    let mut v2 = Room::new("call", "v2");
    let order = [4usize, 1, 0, 3, 2, 1];
    for i in order {
        let (seq, sig) = &toggles[i];
        deliver(&mut v2, "m", &SignalEnvelope::broadcast("call", *seq, *seq, sig.clone()));
    }

    let m1 = v1.member("m").unwrap();
    let m2 = v2.member("m").unwrap();
    assert_eq!((m1.audio_muted, m1.video_muted, m1.sharing, m1.hand_raised),
               (false, true, true, true));
    assert_eq!((m1.audio_muted, m1.video_muted, m1.sharing, m1.hand_raised),
               (m2.audio_muted, m2.video_muted, m2.sharing, m2.hand_raised),
               "media state converges regardless of order");
}

// ---- moderation actions are routed but authorized by the host gate ----

#[test]
fn kick_is_directed_and_does_not_touch_roster() {
    let mut victim = Room::new("r", "victim");
    let kick = SignalEnvelope::directed("r", "victim", 0, 10, Signal::Kick { reason: Some("bye".into()) });
    match deliver(&mut victim, "host", &kick) {
        Effect::Directed(e) => {
            assert!(e.addressed_to("victim"));
            assert_eq!(e.signal.tag(), "kick");
        }
        other => panic!("expected directed kick, got {other:?}"),
    }
    assert_eq!(victim.present_count(), 0);
}

#[test]
fn end_room_marks_room_ended_for_all() {
    let mut r = Room::new("r", "p");
    r.apply(&SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: None }).with_sender("host"));
    let end = SignalEnvelope::broadcast("r", 1, 11, Signal::EndRoom { reason: None }).with_sender("host");
    match r.apply(&end) {
        Effect::RoomEnded { by, .. } => assert_eq!(by, "host"),
        other => panic!("expected RoomEnded, got {other:?}"),
    }
    assert!(r.is_ended());
}

#[test]
fn moderate_ability_gates_kick_authorization() {
    // A moderator with meet:moderate is authorized for a kick; a stranger is not. (The room machine
    // routes the signal; the host gate is what decides whether to honor it.)
    let host = id("host");
    let mod_user = id("mod");
    let stranger = id("stranger");
    let cap = SignedCapability::issue(
        &host,
        mod_user.node_id(),
        vec![ABILITY_MODERATE.to_string()],
        Resource::Any,
        Caveats::default(),
        1,
        None,
    );
    let chain = encode_chain(&[cap]);
    let gate = Gate::gated(host.node_id(), vec![]);
    assert!(gate.check(&mod_user.node_id_hex(), ABILITY_MODERATE, &chain, &[], 1000).is_ok());
    assert!(gate.check(&stranger.node_id_hex(), ABILITY_MODERATE, "", &[], 1000).is_err());
    // host ability is separate from moderate
    assert!(gate.check(&mod_user.node_id_hex(), ABILITY_HOST, &chain, &[], 1000).is_err());
}

// ---- DoS guards ----

#[test]
fn roster_member_cap_resists_a_flood_of_distinct_senders() {
    // Simulate a flood: many forged-looking NodeIds publish joins. The roster must not grow past the
    // cap, bounding memory.
    let mut room = Room::new("r", "me").with_max_members(50);
    for i in 0..500u32 {
        let from = format!("flood-{i}");
        deliver(&mut room, &from, &SignalEnvelope::broadcast("r", 0, 10, Signal::Join { display_name: None }));
    }
    assert_eq!(room.known_count(), 50, "member cap bounds the roster under a sender flood");
    assert!(room.present_count() <= 50);
}

#[test]
fn oversized_sdp_is_rejected_at_parse_and_never_reaches_roster() {
    let room = Room::new("r", "me");
    let env = SignalEnvelope::directed("r", "me", 0, 10, Signal::Offer { sdp: "x".repeat(MAX_SDP_LEN + 1) });
    // The frame is built locally but a receiver parses with from_bytes, which rejects it.
    let bytes = env.to_bytes().unwrap();
    assert!(SignalEnvelope::from_bytes(&bytes).is_err(), "oversized SDP rejected on receive");
    // The roster is untouched.
    assert_eq!(room.present_count(), 0);
}

#[test]
fn admit_flood_is_rate_limited_before_verification() {
    // An attacker floods admit requests from one identity; only `capacity` per window get through to
    // the (expensive) gate, the rest are dropped cheaply.
    let host = id("host");
    let attacker = id("attacker");
    let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec());
    let mut limiter = AdmitRateLimiter::new(5, 10, 1024);
    let req = AdmitReq { room_id: "r".into(), caps: String::new(), display_name: None, resume: None };

    let mut verified = 0;
    let mut dropped = 0;
    for _ in 0..100 {
        if limiter.check(&attacker.node_id_hex(), 1000) {
            // would run the gate
            let _ = adm.admit(&attacker.node_id_hex(), &req, &[], 1000);
            verified += 1;
        } else {
            dropped += 1;
        }
    }
    assert_eq!(verified, 5, "only capacity requests reach verification per window");
    assert_eq!(dropped, 95);
}

// ---- relay selection (media tier) ----

#[test]
fn relay_selection_prefers_nearest_then_most_reputable() {
    let mut far = RelayCandidate::new("aa".repeat(32), "turn:far:3478");
    far.rtt_ms = 200;
    far.reputation = 1.0;
    let mut near = RelayCandidate::new("bb".repeat(32), "turn:near:3478");
    near.rtt_ms = 20;
    near.reputation = 0.0;
    let mut mid = RelayCandidate::new("cc".repeat(32), "turn:mid:3478");
    mid.rtt_ms = 25;
    mid.reputation = 1.0;
    let ranked = select_relay(vec![far, near.clone(), mid]);
    assert_eq!(ranked[0].node_id, near.node_id, "the closest relay is selected");
    assert_eq!(ranked.len(), 3);
}
