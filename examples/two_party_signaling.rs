//! A self-contained, node-free walkthrough of a two-party ce-meet call: the full signaling handshake
//! (admission -> roster join -> SDP offer/answer -> trickle ICE) plus the in-call controls
//! (mute / screen-share / chat / reactions) and host moderation (kick / end-room), exercised purely
//! against the in-memory state machine so it runs anywhere with no mesh.
//!
//! Run with:  `cargo run --example two_party_signaling`
//!
//! In a real deployment each `Room` lives in a different process on a different machine; the
//! [`SignalEnvelope`]s shown here travel between them over CE pubsub (`MeetClient::publish` /
//! `poll` / `event_loop`). The convergence and ordering properties demonstrated below hold under the
//! unordered, lossy, duplicating delivery pubsub gives — which is the whole point of the design.

use ce_meet::admit::Admitter;
use ce_meet::caps::Gate;
use ce_meet::order::OrderedInbox;
use ce_meet::proto::{AdmitReq, Signal, SignalEnvelope};
use ce_meet::room::{Effect, Room};

/// A tiny stand-in for "publish this envelope onto the room topic, where the other party receives it
/// and stamps the authenticated sender." Returns the sender-stamped envelope the receiver applies.
fn transmit(from: &str, env: &SignalEnvelope) -> SignalEnvelope {
    let bytes = env.to_bytes().expect("serialize");
    SignalEnvelope::from_bytes(&bytes).expect("parse").with_sender(from)
}

fn main() {
    println!("== ce-meet two-party signaling walkthrough ==\n");

    let room_id = "demo-room";

    // ---- 1. Host runs an OPEN room and admits Bob (a gated room would require a ce-cap chain) ----
    let host_id = [7u8; 32];
    let admitter = Admitter::new(room_id, Gate::open(host_id), b"host-mac-secret".to_vec());
    let bob_hex = "bb".repeat(32);
    let resp = admitter.admit(
        &bob_hex,
        &AdmitReq { room_id: room_id.into(), caps: String::new(), display_name: Some("Bob".into()), resume: None },
        &[],
        1_000,
    );
    println!("[admit] Bob admitted: {} (resume token issued: {})", resp.admitted, resp.resume.is_some());
    assert!(resp.admitted);

    // ---- 2. Two local roster views (in reality, two machines) ----
    let alice_hex = "aa".repeat(32);
    let mut alice = Room::new(room_id, &alice_hex);
    let mut bob = Room::new(room_id, &bob_hex);

    // Each announces presence; the other applies it.
    let a_join = SignalEnvelope::broadcast(room_id, alice.next_outbound_seq(), 100, Signal::Join { display_name: Some("Alice".into()) });
    let b_join = SignalEnvelope::broadcast(room_id, bob.next_outbound_seq(), 101, Signal::Join { display_name: Some("Bob".into()) });
    bob.apply(&transmit(&alice_hex, &a_join));
    alice.apply(&transmit(&bob_hex, &b_join));
    println!("[roster] Alice sees present: {:?}", alice.present().len());
    println!("[roster] Bob sees present:   {:?}", bob.present().len());

    // ---- 3. SDP offer/answer, then trickle ICE, ordered through a reorder buffer ----
    let offer = SignalEnvelope::directed(room_id, &bob_hex, alice.next_outbound_seq(), 102,
        Signal::Offer { sdp: "v=0\r\no=alice 1 1 IN IP4 0.0.0.0\r\n".into() });
    if let Effect::Directed(e) = bob.apply(&transmit(&alice_hex, &offer)) {
        println!("[sdp] Bob received {} from Alice", e.signal.tag());
    }
    let answer = SignalEnvelope::directed(room_id, &alice_hex, bob.next_outbound_seq(), 103,
        Signal::Answer { sdp: "v=0\r\nanswer\r\n".into() });
    if let Effect::Directed(e) = alice.apply(&transmit(&bob_hex, &answer)) {
        println!("[sdp] Alice received {} from Bob", e.signal.tag());
    }

    // Trickle ICE arrives out of order; the reorder buffer hands them to WebRTC in seq order.
    let mut inbox = OrderedInbox::new();
    let c0 = SignalEnvelope::directed(room_id, &bob_hex, 0, 200, Signal::IceCandidate { candidate: "cand-0".into(), sdp_mid: None, sdp_m_line_index: None }).with_sender(&alice_hex);
    let c2 = SignalEnvelope::directed(room_id, &bob_hex, 2, 202, Signal::IceCandidate { candidate: "cand-2".into(), sdp_mid: None, sdp_m_line_index: None }).with_sender(&alice_hex);
    let c1 = SignalEnvelope::directed(room_id, &bob_hex, 1, 201, Signal::IceCandidate { candidate: "cand-1".into(), sdp_mid: None, sdp_m_line_index: None }).with_sender(&alice_hex);
    let mut ordered = Vec::new();
    for env in [c0, c2, c1] {
        for out in inbox.offer(env) {
            if let Signal::IceCandidate { candidate, .. } = &out.signal {
                ordered.push(candidate.clone());
            }
        }
    }
    println!("[ice] candidates delivered in order: {ordered:?}");
    assert_eq!(ordered, vec!["cand-0", "cand-1", "cand-2"]);

    // ---- 4. In-call controls: mute, screen-share, raise hand, chat, reaction ----
    let media = SignalEnvelope::broadcast(room_id, alice.next_outbound_seq(), 300, Signal::Media { audio_muted: true, video_muted: false });
    bob.apply(&transmit(&alice_hex, &media));
    println!("[media] Bob sees Alice audio_muted = {}", bob.member(&alice_hex).map(|m| m.audio_muted).unwrap_or(false));

    let share = SignalEnvelope::broadcast(room_id, alice.next_outbound_seq(), 301, Signal::ScreenShare { active: true });
    bob.apply(&transmit(&alice_hex, &share));
    println!("[media] Bob sees Alice sharing = {}", bob.member(&alice_hex).map(|m| m.sharing).unwrap_or(false));

    let chat = SignalEnvelope::broadcast(room_id, bob.next_outbound_seq(), 302, Signal::Chat { body: "hi Alice!".into() });
    if let Effect::Chat { from, body } = alice.apply(&transmit(&bob_hex, &chat)) {
        println!("[chat] Alice received from {}: {}", &from[..4], body);
    }

    let react = SignalEnvelope::broadcast(room_id, bob.next_outbound_seq(), 303, Signal::Reaction { emoji: "thumbsup".into() });
    if let Effect::Reaction { emoji, .. } = alice.apply(&transmit(&bob_hex, &react)) {
        println!("[reaction] Alice saw reaction: {emoji}");
    }

    // ---- 5. Host moderation: end the room for everyone ----
    let end = SignalEnvelope::broadcast(room_id, 9999, 400, Signal::EndRoom { reason: Some("call over".into()) });
    let host_hex = hex::encode(host_id);
    if let Effect::RoomEnded { reason, .. } = alice.apply(&transmit(&host_hex, &end)) {
        println!("[moderation] room ended: {}", reason.unwrap_or_default());
    }
    bob.apply(&transmit(&host_hex, &end));
    assert!(alice.is_ended() && bob.is_ended());

    println!("\n== done: handshake, ordering, media controls, and moderation all converged ==");
}
