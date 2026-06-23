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
- **SignalEnvelope** — an addressed, **sequence-numbered** wrapper around a `Signal`
  (`Join`/`Leave`/`Keepalive`/`Offer`/`Answer`/`IceCandidate`/`IceEnd`). `to == None` is a room
  broadcast (membership); `to == Some(peer)` is a directed peer signal. The per-sender monotonic
  `seq` lets receivers order and de-duplicate the out-of-order flow pubsub gives.
- **Roster = a small CRDT.** Each member's presence is a last-writer-wins register keyed by NodeId
  and ordered by that member's own `seq` (no wall clocks). Higher seq wins; on an equal seq a
  remove (`Leave`) wins (remove-bias tie-break). Result: **every replica that has seen the same set
  of envelopes converges to the same membership, regardless of delivery order, drops, or duplicates.**
  A liveness sweep prunes peers that vanished without a `Leave`.
- **Gating.** An open room admits anyone. A gated room's host runs a `Gate` that authorizes a
  presented `ce-cap` chain (rooted at the host's own key or a configured org root) against the opaque
  abilities `meet:join` / `meet:host` / `meet:moderate` before admitting a joiner — offline,
  attenuating, revocation-aware.

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

Modules: `proto` (wire format), `room` (roster CRDT), `caps` (resolution + host `Gate`),
`client` (`MeetClient`), `turn` (STUN/TURN config + the relay/SFU plan).

## CLI

```bash
# Mint a room (open by default; --gated for capability-gated).
ce-meet create-room
ce-meet create-room --gated

# Join: subscribe, announce presence, stream the live roster.
ce-meet join <room-id> --name "Leif"
# Gated room: request admission from the host with a capability chain.
ce-meet join <room-id> --host <host-node-id> --caps <chain-hex>

# Publish one directed signal (the browser drives the actual WebRTC session).
ce-meet signal <room-id> <peer-node-id> offer  "v=0..."
ce-meet signal <room-id> <peer-node-id> answer "v=0..."
ce-meet signal <room-id> <peer-node-id> ice    "candidate:1 1 UDP ..."
```

Capability chain resolution order: `--caps <hex>` flag → `$CE_MEET_CAPS` → `<config>/ce-meet/caps`.

## The media plane: TURN-via-relay (planned) and SFU

The browser handles media; ce-meet only tells it *where* to relay via the `ice_servers` it returns
in an admission reply. Three tiers, cheapest first (see `src/turn.rs` for the full plan):

1. **Direct P2P** — most calls connect peer-to-peer via STUN (the same NAT conditions CE's own DCUtR
   hole-punching already works under). Zero relayed bytes.
2. **TURN relay (symmetric-NAT fallback)** — a CE relay node also runs a `coturn`-class TURN server,
   discovered via `find_service("meet:turn")`, ranked by atlas + `/history` reputation + RTT. Access
   is **metered and paid over a CE payment channel**: the relay issues a short-lived,
   channel-bound ephemeral TURN credential (`TurnCredential`, the standard TURN-REST convention) that
   cannot outlive its channel. TURN becomes a paid CE service, not a free-rider subsidy — the same
   economic model as every other CE primitive (money is integer base units, decimal strings on the
   wire, settled over channels). *Built here: the credential derive/verify + ICE-server types.
   Planned: the coturn sidecar + the channel-bound issuance endpoint on relay nodes.*
3. **SFU cell (large rooms)** — full-mesh calls are O(n²) uplink. For large rooms the host deploys an
   **SFU as a CE job/cell** (`ce-rs::mesh_deploy`) on a paid node; the SFU joins the room as a normal
   roster participant, so the signaling layer here is already SFU-ready. *The SFU cell image is future
   work.*

## Tests

`cargo test` — unit tests on every public fn (happy + error paths), integration tests (full
SDP/ICE round-trips, two-replica roster convergence, the capability gate end-to-end, dropped-peer
pruning, duplicate/reordered delivery), and property tests (envelope serialization round-trips, CRDT
convergence under arbitrary order + duplicates, LWW correctness, TURN credential soundness,
parser-never-panics on arbitrary bytes).

## License

MIT.
