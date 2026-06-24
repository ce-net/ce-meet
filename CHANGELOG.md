# Changelog

All notable changes to ce-meet are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); ce-meet is pre-1.0, so minor versions may break.

## [Unreleased]

### Added
- **In-call media-control signaling**: `Media{audio_muted,video_muted}`, `ScreenShare`, `RaiseHand`,
  threaded into `Member` as last-writer-wins state and surfaced as `Effect::MediaChanged`.
- **Chat, reactions, recording-consent**: `Chat`, `Reaction`, `Recording` broadcast signals with
  matching `Effect`s (transient; not retained as roster state).
- **Host moderation**: `Kick`, `ForceMute` (directed) and `EndRoom` (broadcast), gated by the
  recipient's own `meet:host`/`meet:moderate` capability check. `Room` tracks `is_ended()`.
- **Real-time SSE event loop**: `MeetClient::event_loop` drives the roster off the node's
  app-message push stream; `ce-meet join --stream` uses it. Timer `poll()` remains as a fallback.
- **Directed-signal freshness window** (`MeetClient::with_freshness`): drops stale/implausibly-future
  directed signals, making `SignalEnvelope::sent_at` load-bearing (`is_fresh`).
- **Bounds/DoS guards**: per-field payload caps (`proto::MAX_*`), envelope size cap enforced in
  `from_bytes`, `Signal::validate`, a `Room` member cap (`with_max_members`), and a per-sender
  admission rate limiter (`AdmitRateLimiter`).
- **Atomic snapshot persistence**: `RoomSnapshot::save_atomic` / `load` (temp-file + fsync + rename).
- **Relay selection**: `turn::RelayCandidate` + `select_relay` (latency-dominant, reputation
  tie-break) and `default_stun_servers`.
- New CLI commands: `ce-meet control` (mute/share/hand/react/chat/record) and `ce-meet moderate`
  (kick/mute/end). `examples/two_party_signaling.rs`; `docs/architecture.md`.

### Changed
- Resume-token MAC and TURN-credential digest are now **HMAC-SHA256** (were `sha256(secret||...)`);
  `TurnCredential::verify` uses constant-time comparison.
- `SignalEnvelope::to_bytes` / `RoomSnapshot::to_bytes` now return `Result` instead of silently
  emitting an empty object on the (impossible) serialization error.

### Notes
- The CLI poll loop is unsuitable for real WebRTC timing; use `--stream` (SSE) for live calls.
- Media plane (audio/video) remains intentionally out of scope (browser WebRTC). The coturn sidecar,
  live `find_service` discovery, channel-bound credential issuance, and the SFU cell are deferred —
  see the README "Implemented vs planned" table.
