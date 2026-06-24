# ce-meet architecture & sequence

This document traces the control flow of a ce-meet call across the crate's modules, so a reader does
not have to reconstruct it from four files. ce-meet is the **signaling plane only**; the media plane
(audio/video RTP) is browser WebRTC and never touches a CE node.

## Components

| Module | Type | Responsibility |
|---|---|---|
| `proto` | `SignalEnvelope`, `Signal`, `AdmitReq/Resp`, `ResumeToken` | wire format, signal set, bounds validation, freshness |
| `room` | `Room`, `Member`, `Effect`, `RoomSnapshot` | roster + media-state CRDT, member cap, persistence |
| `caps` | `Gate`, `resolve` | capability-chain authorization (`ce-cap`) for gated rooms |
| `admit` | `Admitter`, `AdmitRateLimiter` | host admission flow, HMAC resume tokens, rate limiting |
| `order` | `OrderedInbox`, `SignalRouter` | per-peer SDP/ICE reorder buffers |
| `client` | `MeetClient` | the participant-facing client over the `ce-rs` SDK |
| `turn` | `IceServer`, `TurnCredential`, `RelayCandidate`, `select_relay` | media-tier config + relay selection |

## The join handshake (gated room)

A gated-room join spans `client` → `admit` → `caps` → `proto` → back to `client`:

```
Joiner (MeetClient)                 Host (Admitter + Gate)
───────────────────                 ──────────────────────
request_admission(host, caps_hex)
  │  AdmitReq{room,caps,name}
  ├───────── ce.request ──────────► admit(requester, req, now)
  │  (directed app message,            │ 1. room match?
  │   TOPIC_ADMIT)                      │ 2. resume token? -> verify_resume (HMAC, identity, expiry)
  │                                     │ 3. else Gate::check(requester, meet:join, caps_hex)
  │                                     │      └─ ce-cap::authorize(chain rooted at host/org root)
  │                                     │ 4. on allow: issue_resume + ICE servers
  │  AdmitResp{admitted,ice,resume} ◄───┤
  ◄──────── ce.reply ─────────────────  │
  │
  ├─ subscribe(room_topic)                (both sides on the pubsub topic now)
  ├─ announce_join(name)  ── publish ──►  Room::apply -> Effect::Joined
  │
  └─ (browser produces SDP) signal_peer(peer, Offer) ── publish ──► ordered delivery
```

The host runs `AdmitRateLimiter::check` **before** the (expensive) `Gate::check`, so an admit flood
is dropped cheaply. The `ResumeToken` MAC is HMAC-SHA256 over `(room, node, expiry, seq_floor)`; on
reconnect the host re-derives it and compares in constant time against the **authenticated**
reconnecting NodeId, so a stolen token does not admit a different node.

## The SDP/ICE flow (ordering)

Pubsub delivers unordered, but a browser must apply an offer before its trickled candidates:

```
peer publishes:  Offer(seq0)  Ice(seq1)  Ice(seq2) ...
pubsub delivers: seq2, seq0, seq1, seq2(dup), ...   (any order, drops, dups)

MeetClient::ingest_ordered(from, bytes)
  ├─ from_bytes  -> bounds-validate (reject over-cap SDP/candidate)
  ├─ freshness   -> drop stale directed signals (sent_at outside window)
  ├─ room.apply  -> Effect::Directed(env)  (if addressed to us)
  └─ SignalRouter -> OrderedInbox(per peer).offer(env)
         └─ returns the now-contiguous run in strict seq order, de-duplicated
            (bounded window; skip_to steps past a permanently-lost seq)
```

## Roster convergence (CRDT)

Membership and per-member media state are last-writer-wins registers keyed by NodeId and ordered by
that member's own monotonic `seq` (no wall clocks, so no clock-skew hazards):

- a strictly higher `seq` wins;
- a strictly lower `seq` is ignored (duplicate / reorder);
- on an equal `seq` with conflicting presence, **absent (`Leave`) wins** (deterministic remove-bias).

So every replica that has applied the same set of envelopes converges to the same roster, regardless
of arrival order, drops, or duplicates. `digest()` exposes the membership identity for a cheap
convergence assertion; `merge_snapshot()` reconciles two replicas with the same LWW rule.

## Real-time loop vs poll

`MeetClient::event_loop` drains the node's SSE app-message push stream (`messages_stream`) and applies
each frame as it arrives (sub-second), the loop a real WebRTC client uses. `poll()` is the timer-based
fallback for environments without the stream. Both funnel through `apply_message` / `ingest_ordered`,
so behavior is identical apart from latency.

## DoS / robustness boundaries

- **Payload caps** (`proto::MAX_*`): `from_bytes` rejects an over-cap frame before parsing and any
  signal whose fields exceed their caps — no multi-megabyte SDP/candidate/chat blob is forwarded.
- **Member cap** (`Room::with_max_members`): a flood of forged-NodeId joins cannot grow the roster
  past the cap; existing members remain updatable so a real participant is never starved.
- **Admit rate limit** (`AdmitRateLimiter`): bounded per-sender token bucket with a bounded tracked-
  sender map, so neither a request flood nor a spoofed-sender flood exhausts host CPU or memory.
- **Atomic persistence** (`RoomSnapshot::save_atomic`): temp-file + fsync + rename, so a crash mid-
  write never leaves a torn snapshot.

## Media tier (the seam to WebRTC)

`turn` defines what a host hands a joiner in `AdmitResp::ice_servers`. `select_relay` ranks discovered
relay candidates (latency-dominant, reputation tie-break). `TurnCredential` derives a channel-bound
ephemeral credential (HMAC-SHA256, constant-time verify). The live `find_service("meet:turn")`
discovery, the coturn sidecar, the credential-issuance endpoint, and the SFU cell image are the
documented-but-deferred parts of the media tier (see the README's Implemented-vs-Planned table).
