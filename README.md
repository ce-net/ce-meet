# ce-meet

Real-time (Google-Meet-like) **WebRTC signaling over the CE mesh**. Rooms are CE pubsub topics;
participants exchange SDP offers/answers and ICE candidates over them so their browsers can establish
direct WebRTC media. Rooms can be open or **capability-gated** with `ce-cap`.

ce-meet is an **application built on CE primitives** (the `ce-rs` SDK + `ce-cap`), not part of the
node. It adds no node endpoints: everything rides mesh pubsub, directed app messaging, and signed
capability chains.

> **Signaling here, media in the browser.** ce-meet carries *only* the signaling plane (rooms,
> roster, SDP/ICE). The audio/video **media plane** is browser WebRTC, flowing peer-to-peer (or via a
> paid TURN relay) — it never passes through any CE node, so **no node ever sees your call**.

## What CE provides (composed, not reinvented)

| Need | CE primitive |
|---|---|
| Rooms / signaling fan-out | mesh **Gossipsub pubsub** (`subscribe`/`publish`) — a room is a topic |
| Gated-room admission | directed **app messaging** (`request`/`reply`) + **`ce-cap`** chain authorization |
| Unforgeable identity | node **identity** — every published envelope is signed, so `from` is authenticated |
| TURN/SFU media tiers | **payment channels** (metered, paid relay/SFU) + **discovery** (find relays) + **jobs** (deploy an SFU cell) |

## Architecture

- **Room = pubsub topic** `meet/room/<room_id>`. Everyone subscribes; everyone publishes
  [`SignalEnvelope`]s onto it.
- **SignalEnvelope** — an addressed, **sequence-numbered** wrapper around a `Signal`. The signal set
  covers: call setup (`Join`/`Leave`/`Keepalive`/`Offer`/`Answer`/`IceCandidate`/`IceEnd`),
  **in-call media-control state** (`Media{audio,video}` / `ScreenShare` / `RaiseHand`),
  **chat & reactions** (`Chat` / `Reaction`), **recording-consent** (`Recording`), and **host
  moderation** (`Kick` / `ForceMute` / `EndRoom`). `to == None` is a room broadcast; `to == Some(peer)`
  is a directed peer signal. The per-sender monotonic `seq` lets receivers order and de-duplicate.
  Every attacker-controlled string field is **length-bounded and validated on receipt** (`from_bytes`
  rejects an over-cap frame before parsing and any signal whose fields exceed their `MAX_*` caps).
- **Roster = a small CRDT.** Each member's presence **and live media state** (mic/cam mute,
  screen-share, raised-hand) is a last-writer-wins register keyed by NodeId and ordered by that
  member's own `seq` (no wall clocks). Higher seq wins; on an equal seq a remove (`Leave`) wins
  (remove-bias tie-break). Result: **every replica that has seen the same set of envelopes converges
  to the same membership and media state, regardless of delivery order, drops, or duplicates.** A
  liveness sweep prunes peers that vanished without a `Leave`. A configurable **member cap**
  (`with_max_members`, default 1024) bounds the roster so a flood of forged-NodeId joins cannot
  exhaust memory.
- **Gating.** An open room admits anyone. A gated room's host runs a `Gate` that authorizes a
  presented `ce-cap` chain (rooted at the host's own key or a configured org root) against the opaque
  abilities `meet:join` / `meet:host` / `meet:moderate` before admitting a joiner — offline,
  attenuating, revocation-aware. The host-side **`Admitter`** wraps the gate into the full admission
  flow: it answers an `AdmitReq` with an `AdmitResp` (allow/deny + ICE servers) and mints a
  reconnect token on success.
- **In-call controls & moderation.** Broadcast `Media`/`ScreenShare`/`RaiseHand` drive the per-tile
  mute/camera/presenting/hand indicators; `Chat`/`Reaction` are transient broadcasts surfaced as
  effects (not retained as state); `Recording` is the consent notice (ce-meet records nothing itself).
  `Kick`/`ForceMute` are **directed** moderation actions and `EndRoom` is a broadcast one — the
  recipient honors them only when the sender holds `meet:host`/`meet:moderate` per the recipient's
  own gate (authority is a verified capability, never asserted).
- **Real-time SSE event loop.** `MeetClient::event_loop` drives the roster off the node's SSE
  app-message push stream (sub-second), the loop a real WebRTC client uses — versus the timer-based
  `poll()` fallback. A configurable **freshness window** (`with_freshness`) drops stale directed
  signals so a long-delayed ICE candidate cannot stall renegotiation (makes `sent_at` load-bearing).
- **Persistent room state.** A host (or a participant resuming after a crash) can `snapshot()` the
  convergent roster to a `RoomSnapshot` and `restore()` it later, picking up exactly where it left off
  without replaying signaling history. `save_atomic()` persists it **durably** (temp-file + fsync +
  rename, so a crash mid-write never leaves a torn snapshot). Two hosts that took divergent slices of
  the stream reconcile with `merge_snapshot()` — an order-independent LWW merge — and a `digest()`
  lets any replica cheaply assert convergence.
- **Reconnection (resume by identity).** On first admission the host issues a `ResumeToken` keyed to
  the joiner's NodeId and **HMAC-SHA256'd** with the host's secret. On a later reconnect the
  participant presents the token instead of re-running the capability handshake; the host re-derives
  and re-checks it (in constant time) against the **authenticated** reconnecting NodeId, so a stolen
  token used by another node is rejected and an expired one forces a fresh handshake. The token
  carries the participant's `seq` floor so the resumed session never re-uses a sequence number a peer
  would silently drop. Admission is **rate-limited** per sender (`AdmitRateLimiter`, a bounded
  token-bucket) so a flood of admit requests cannot burn host CPU on capability verification.
- **SDP/ICE ordering guarantees.** Pubsub delivers unordered, but a browser must apply an SDP offer
  before its trickled ICE candidates. The per-peer **`OrderedInbox`** (multiplexed by `SignalRouter`)
  reorders each sender's directed signals by `seq` into strictly ascending, de-duplicated delivery,
  with a bounded window so a permanently lost message never wedges the stream (`skip_to` steps past a
  hole). `MeetClient::ingest_ordered` drives a WebRTC stack deterministically from the message stream.

## Library

```rust
use ce_meet::{client::{MeetClient, new_room_id, now_secs}, proto::Signal};
use ce_rs::CeClient;

# async fn demo() -> anyhow::Result<()> {
let ce = CeClient::local();
let me = ce.status().await?.node_id;

// Create + join a room.
let room_id = new_room_id(&me, 1, now_secs());
let mut client = MeetClient::new(ce, room_id, me);
client.subscribe().await?;
client.announce_join(Some("Leif".into())).await?;

// Browser produces an SDP offer for `peer` -> signal it over the mesh.
client.signal_peer("peer_node_id_hex", Signal::Offer { sdp: "v=0...".into() }).await?;

// Drain the inbox; react to roster + directed signals.
for effect in client.poll().await? {
    println!("{effect:?}");
}
# Ok(()) }
```

Modules: `proto` (wire format + all signals + bounds validation + admission/resume messages), `room`
(roster + media-state CRDT, member cap, snapshot/restore/merge + atomic persistence), `caps`
(resolution + host `Gate`), `admit` (host-side `Admitter`: gate + HMAC resume-by-identity +
`AdmitRateLimiter`), `order` (`OrderedInbox`/`SignalRouter` SDP/ICE reordering), `client`
(`MeetClient`: publish helpers, `poll`, real-time `event_loop`, freshness), `turn` (STUN/TURN config,
HMAC channel-bound credentials, relay selection + the relay/SFU plan).

## CLI

```bash
# Mint a room (open by default; --gated for capability-gated).
ce-meet create-room
ce-meet create-room --gated

# Join: subscribe, announce presence, watch the live roster.
ce-meet join <room-id> --name "Leif"            # timer-poll loop
ce-meet join <room-id> --name "Leif" --stream   # real-time SSE push loop (recommended)
# Gated room: request admission from the host with a capability chain.
ce-meet join <room-id> --host <host-node-id> --caps <chain-hex>

# Host a gated room: serve (rate-limited) admission requests, authorizing each joiner's capability
# chain (and honoring resume tokens on reconnect). --open admits anyone; --root adds accepted roots.
ce-meet host <room-id>
ce-meet host <room-id> --open
ce-meet host <room-id> --root <org-node-id>

# Publish one directed signal (the browser drives the actual WebRTC session).
ce-meet signal <room-id> <peer-node-id> offer  "v=0..."
ce-meet signal <room-id> <peer-node-id> answer "v=0..."
ce-meet signal <room-id> <peer-node-id> ice    "candidate:1 1 UDP ..."

# In-call controls (broadcast to the room):
ce-meet control <room-id> mute --audio --video    # set mic/camera mute state
ce-meet control <room-id> share                   # start screen-share (--off to stop)
ce-meet control <room-id> hand                    # raise hand (--down to lower)
ce-meet control <room-id> react thumbsup          # flash a reaction
ce-meet control <room-id> chat "hello everyone"   # in-call chat line
ce-meet control <room-id> record                  # announce recording (--stop to end)

# Host/moderator actions (the target's gate authorizes via your capability):
ce-meet moderate <room-id> kick <peer-node-id> --reason "spam"
ce-meet moderate <room-id> mute <peer-node-id>    # force-mute (--unmute to request unmute)
ce-meet moderate <room-id> end --reason "done"    # end the room for everyone
```

Capability chain resolution order: `--caps <hex>` flag → `$CE_MEET_CAPS` → `<config>/ce-meet/caps`.

A runnable, node-free walkthrough of the full handshake + controls + moderation:

```bash
cargo run --example two_party_signaling
```

## The media plane: TURN-via-relay (planned) and SFU

The browser handles media; ce-meet only tells it *where* to relay via the `ice_servers` it returns
in an admission reply. Three tiers, cheapest first (see `src/turn.rs` for the full plan):

1. **Direct P2P** — most calls connect peer-to-peer via STUN (the same NAT conditions CE's own DCUtR
   hole-punching already works under). Zero relayed bytes.
2. **TURN relay (symmetric-NAT fallback)** — a CE relay node also runs a `coturn`-class TURN server,
   discovered via `find_service("meet:turn")` and ranked best-first by **`turn::select_relay`** (atlas
   + `/history` reputation + RTT). Access is **metered and paid over a CE payment channel**: the relay
   issues a short-lived, channel-bound ephemeral TURN credential (`TurnCredential`, the standard
   TURN-REST convention, here an **HMAC-SHA256** keyed digest verified in constant time) that cannot
   outlive its channel. TURN becomes a paid CE service, not a free-rider subsidy — the same economic
   model as every other CE primitive (money is integer base units, decimal strings on the wire, settled
   over channels). *Built here: the `IceServer`/`TurnCredential` types, credential derive/verify, and
   the `select_relay` ranking. Planned: the coturn sidecar + the live `find_service` discovery wiring
   + the channel-bound issuance endpoint on relay nodes.*
3. **SFU cell (large rooms)** — full-mesh calls are O(n²) uplink. For large rooms the host deploys an
   **SFU as a CE job/cell** (`ce-rs::mesh_deploy`) on a paid node; the SFU joins the room as a normal
   roster participant, so the signaling layer here is already SFU-ready. *The SFU cell image is future
   work.*

## Implemented vs planned

| Capability | Status |
|---|---|
| Signaling: rooms, roster CRDT, SDP/ICE exchange, ordering | **Implemented** |
| In-call media-control state (mute / camera / screen-share / raise-hand) | **Implemented** |
| Chat, reactions, recording-consent signaling | **Implemented** |
| Host moderation: kick / force-mute / end-room (capability-gated) | **Implemented** |
| Bounds/DoS guards: payload caps, member cap, admit rate-limiter | **Implemented** |
| HMAC resume tokens & TURN credentials, constant-time verify | **Implemented** |
| Real-time SSE event loop, directed-signal freshness window | **Implemented** |
| Atomic snapshot persistence; snapshot merge/digest; resume-by-identity | **Implemented** |
| Relay-candidate ranking (`select_relay`) | **Implemented** |
| Media plane (audio/video RTP) | **Out of scope** (browser WebRTC) |
| Live `find_service("meet:turn")` discovery wiring | **Planned** |
| `coturn` sidecar + channel-bound TURN credential issuance endpoint | **Planned** |
| SFU cell image for large rooms | **Planned** |

## Tests

`cargo test` — unit tests on every public fn (happy + error paths), integration tests (full
SDP/ICE round-trips and in-order reorder-buffer delivery, two-replica roster convergence,
persisted-host snapshot/restore convergence under concurrent updates, two-replica snapshot merge
reconciliation, reconnection-resume by identity + stolen/expired-token rejection, the capability
gate and `Admitter` deny/allow end-to-end, dropped-peer pruning, duplicate/reordered delivery), and
property tests (envelope serialization round-trips, CRDT convergence under arbitrary order +
duplicates, snapshot-restore and snapshot-merge convergence, in-order reorder-buffer delivery under
any permutation + monotonic output, LWW correctness, TURN credential soundness,
parser-never-panics on arbitrary bytes).

## License

MIT.
