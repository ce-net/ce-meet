//! The media plane: STUN/TURN config and the **TURN-via-relay** plan.
//!
//! ce-meet builds only the *signaling* plane (rooms, roster, SDP/ICE exchange). The *media* plane —
//! the actual audio/video RTP flow — is browser WebRTC. This module is the seam between the two: it
//! defines the [`IceServer`] list a host hands a joiner (in [`crate::proto::AdmitResp`]), which the
//! browser feeds straight into `new RTCPeerConnection({ iceServers })`.
//!
//! ## How media flows (three tiers, cheapest first)
//!
//! 1. **Direct P2P (no relay).** Most calls connect peer-to-peer once ICE finds a working candidate
//!    pair. STUN (a public reflexive-address probe) is enough; CE itself already runs DCUtR hole-
//!    punching for its own mesh, so the network conditions CE works under are exactly the ones
//!    WebRTC's ICE works under. Cost: zero relayed bytes.
//!
//! 2. **TURN relay (symmetric-NAT fallback).** When both peers are behind symmetric NATs, ICE needs
//!    a TURN relay to forward the encrypted RTP. This is the ~10-15% of calls Google serves from its
//!    own global TURN fleet. CE's answer is a **market of paid relays**, not one fleet:
//!    - The CE relay node (the Hetzner box today, any node tomorrow) also runs a `coturn`-class TURN
//!      server. A room host discovers willing relays via the SDK `find_service("meet:turn")` DHT
//!      lookup (relays `advertise_service("meet:turn")`), ranks them by the atlas + `/history`
//!      reputation substrate + RTT, and selects the topology-nearest one.
//!    - Access is **metered and paid over a CE payment channel**, exactly like `ce-pin` rent and the
//!      existing `relay/pay` mechanism: the host opens a channel to the relay and the relay issues a
//!      short-lived TURN credential ([`TurnCredential`]) bound to that channel. The browser uses the
//!      credential; the relay meters relayed bytes and redeems channel receipts. This makes TURN a
//!      paid CE service rather than a free-rider subsidy — the same economic model as every other CE
//!      primitive (money is integer base units, decimal strings on the wire, settled over channels).
//!    - The TURN long-term-credential username/password are derived from the channel id + an expiry,
//!      so a leaked credential cannot outlive the channel or be reused on another relay.
//!
//! 3. **SFU cell (large rooms).** Mesh (full-P2P) calls are O(n^2) in uplink and stop scaling past a
//!    handful of participants. For large rooms the host deploys an **SFU (Selective Forwarding Unit)
//!    as a CE job/cell** (`ce-rs::mesh_deploy`) on a paid mesh node: every participant sends one
//!    upstream to the SFU, which fans out. The SFU's signaling still flows over this same room topic
//!    (the SFU is just another participant in the roster). Building the SFU cell itself is future
//!    work; the signaling layer here is already SFU-ready because the SFU joins as a normal peer.
//!
//! ## What is built here vs. planned
//!
//! Built: the [`IceServer`] / [`TurnCredential`] config types, the relay-discovery service string,
//! and credential derivation/expiry helpers — everything the *signaling* layer needs to tell a
//! browser where to relay. Planned (documented, not coded here): the coturn sidecar on relay nodes,
//! the channel-bound TURN REST credential issuance endpoint, and the SFU cell image.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Constant-time byte-slice equality (length-aware) so credential verification does not leak the
/// password via timing. Returns false immediately on a length mismatch (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The keyed digest backing a [`TurnCredential`] password: `hex(HMAC-SHA256(secret, username))`.
/// A real keyed MAC rather than `sha256(secret||username)`.
fn turn_password(shared_secret: &[u8], username: &str) -> String {
    let mut mac = match HmacSha256::new_from_slice(shared_secret) {
        Ok(m) => m,
        Err(_) => return String::new(), // impossible for HMAC; an empty password never verifies.
    };
    mac.update(username.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The DHT service string a node advertises when it is willing to act as a paid TURN relay. A room
/// host discovers relays via `ce_rs::CeClient::find_service(SERVICE_TURN)`.
pub const SERVICE_TURN: &str = "meet:turn";

/// A single ICE server entry, shaped exactly like the browser's `RTCIceServer` dictionary so it can
/// be handed to `new RTCPeerConnection({ iceServers: [...] })` with no translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    /// One or more URLs, e.g. `stun:stun.l.example:3478` or `turn:relay.ce-net.com:3478?transport=udp`.
    pub urls: Vec<String>,
    /// TURN long-term-credential username (omitted for plain STUN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// TURN long-term-credential password (omitted for plain STUN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl IceServer {
    /// A plain STUN server (no credentials) — the zero-cost reflexive-address probe.
    pub fn stun(url: impl Into<String>) -> Self {
        IceServer { urls: vec![url.into()], username: None, credential: None }
    }

    /// A TURN server with long-term credentials.
    pub fn turn(url: impl Into<String>, username: impl Into<String>, credential: impl Into<String>) -> Self {
        IceServer {
            urls: vec![url.into()],
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    /// Is this a TURN entry (carries credentials) rather than plain STUN?
    pub fn is_turn(&self) -> bool {
        self.username.is_some() && self.credential.is_some()
    }
}

/// A short-lived TURN credential bound to a CE payment channel. The relay issues it after a channel
/// is opened; the browser uses `username`/`password` for the TURN long-term-credential mechanism.
///
/// The credential follows the widely-deployed "TURN REST API" ephemeral-credential convention:
/// `username = "<expiry_unix>:<channel_id>"` and `password = hex(HMAC-SHA256(shared_secret,
/// username))` — a real keyed MAC, deterministic so the relay can re-derive and verify it statelessly,
/// expiring so a leak is bounded. Verification uses a constant-time compare to avoid a timing leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCredential {
    /// TURN username: `"<expiry_unix>:<channel_id>"`.
    pub username: String,
    /// TURN password: the derived digest, hex-encoded.
    pub password: String,
    /// Unix seconds after which this credential is invalid.
    pub expires_at: u64,
    /// The payment channel this credential meters against.
    pub channel_id: String,
}

impl TurnCredential {
    /// Derive a channel-bound ephemeral credential. `shared_secret` is known to the relay (its
    /// per-deployment TURN static-auth-secret); both sides re-derive the same password from it, so
    /// the relay verifies statelessly. `now`/`ttl_secs` set the expiry.
    pub fn derive(channel_id: &str, shared_secret: &[u8], now: u64, ttl_secs: u64) -> Self {
        let expires_at = now.saturating_add(ttl_secs);
        let username = format!("{expires_at}:{channel_id}");
        let password = turn_password(shared_secret, &username);
        TurnCredential { username, password, expires_at, channel_id: channel_id.to_string() }
    }

    /// Re-derive and check a presented credential against the relay's secret. Returns true only if the
    /// username is well-formed for `(expires_at, channel_id)`, the HMAC password re-derives (compared
    /// in constant time), and the credential is unexpired at `now`. The relay calls this to authorize a
    /// TURN allocation without storing per-client state.
    pub fn verify(&self, shared_secret: &[u8], now: u64) -> bool {
        if now > self.expires_at {
            return false;
        }
        // The username must be exactly the one the password is bound to (no substitution).
        let expected_username = format!("{}:{}", self.expires_at, self.channel_id);
        if !ct_eq(expected_username.as_bytes(), self.username.as_bytes()) {
            return false;
        }
        let expected = turn_password(shared_secret, &self.username);
        ct_eq(expected.as_bytes(), self.password.as_bytes())
    }

    /// Render this credential as an [`IceServer`] for a given TURN URL, ready to hand to a browser.
    pub fn ice_server(&self, turn_url: impl Into<String>) -> IceServer {
        IceServer::turn(turn_url, self.username.clone(), self.password.clone())
    }
}

/// A discovered TURN relay candidate, as ranked for host selection. A room host obtains the raw
/// provider NodeIds from `ce_rs::CeClient::find_service(`[`SERVICE_TURN`]`)`, then enriches each with a
/// reputation/latency score (from the atlas + `/history`) and ranks them with [`select_relay`].
#[derive(Debug, Clone, PartialEq)]
pub struct RelayCandidate {
    /// The relay's NodeId (hex), from the discovery lookup.
    pub node_id: String,
    /// The relay's advertised TURN URL (e.g. `turn:relay.ce-net.com:3478?transport=udp`).
    pub turn_url: String,
    /// Round-trip latency estimate in milliseconds (lower is better); `u32::MAX` if unknown.
    pub rtt_ms: u32,
    /// A reputation score in `0.0..=1.0` derived by the host from the `/history` substrate (higher is
    /// better). A brand-new relay defaults low so a proven one is preferred under equal latency.
    pub reputation: f32,
}

impl RelayCandidate {
    /// Build a candidate with an unknown RTT and zero reputation — the floor a host starts from before
    /// enriching with atlas/history data.
    pub fn new(node_id: impl Into<String>, turn_url: impl Into<String>) -> Self {
        RelayCandidate {
            node_id: node_id.into(),
            turn_url: turn_url.into(),
            rtt_ms: u32::MAX,
            reputation: 0.0,
        }
    }

    /// A composite selection score: lower is better. Latency dominates (a far relay relays media
    /// badly) but a higher reputation breaks ties and discounts latency slightly, so a proven nearby
    /// relay beats an unknown one at the same RTT. Pure and deterministic for a stable ranking.
    pub fn score(&self) -> f64 {
        // Normalize reputation into a [0,1] discount; clamp defensively against bad inputs.
        let rep = self.reputation.clamp(0.0, 1.0) as f64;
        // A relay with unknown RTT is treated as far (but still selectable if it's the only one).
        let rtt = self.rtt_ms as f64;
        // Discount up to 20% of latency for a perfect reputation.
        rtt * (1.0 - 0.2 * rep)
    }
}

/// Rank discovered relay candidates and return them best-first (lowest [`RelayCandidate::score`]).
/// Deterministic: ties break by NodeId so the selection is stable across hosts. Returns an empty vec
/// for no candidates (the room then runs pure-P2P with STUN only). This is the *selection* logic of
/// the media tier; the live `find_service` lookup and the channel-bound credential issuance that feed
/// it are wired by the host (see the crate README's "Implemented vs planned" boundary).
///
/// ```
/// use ce_meet::turn::{RelayCandidate, select_relay};
/// let mut near = RelayCandidate::new("bb", "turn:near:3478");
/// near.rtt_ms = 20;
/// let mut far = RelayCandidate::new("aa", "turn:far:3478");
/// far.rtt_ms = 200;
/// far.reputation = 1.0;
/// let ranked = select_relay(vec![far, near]);
/// assert_eq!(ranked[0].turn_url, "turn:near:3478"); // latency dominates reputation
/// ```
pub fn select_relay(mut candidates: Vec<RelayCandidate>) -> Vec<RelayCandidate> {
    candidates.sort_by(|a, b| {
        a.score()
            .partial_cmp(&b.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    candidates
}

/// The standard set of public-ish STUN servers a room offers for the zero-cost reflexive probe when
/// no paid relay is selected. A host may override this; it exists so an open room is usable with no
/// configuration. (STUN only — no credentials, no relayed bytes, no cost.)
pub fn default_stun_servers() -> Vec<IceServer> {
    vec![IceServer::stun("stun:stun.l.google.com:19302")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_has_no_credentials() {
        let s = IceServer::stun("stun:stun.l.example:3478");
        assert!(!s.is_turn());
        assert!(s.username.is_none());
    }

    #[test]
    fn turn_carries_credentials() {
        let t = IceServer::turn("turn:relay:3478", "user", "pass");
        assert!(t.is_turn());
    }

    #[test]
    fn stun_serializes_without_credential_keys() {
        let s = IceServer::stun("stun:x:3478");
        let j = serde_json::to_string(&s).unwrap();
        assert!(!j.contains("username"));
        assert!(!j.contains("credential"));
    }

    #[test]
    fn credential_derive_then_verify() {
        let secret = b"relay-static-auth-secret";
        let cred = TurnCredential::derive("chan123", secret, 1000, 3600);
        assert_eq!(cred.expires_at, 4600);
        assert!(cred.username.starts_with("4600:"));
        // valid before expiry
        assert!(cred.verify(secret, 2000));
        // expired
        assert!(!cred.verify(secret, 5000));
        // wrong secret fails
        assert!(!cred.verify(b"other-secret", 2000));
    }

    #[test]
    fn credential_tamper_is_rejected() {
        let secret = b"s";
        let mut cred = TurnCredential::derive("c", secret, 0, 100);
        cred.password = "deadbeef".into();
        assert!(!cred.verify(secret, 10));
    }

    #[test]
    fn credential_username_tamper_is_rejected() {
        let secret = b"s";
        let mut cred = TurnCredential::derive("c", secret, 0, 100);
        cred.username = "999:other".into();
        assert!(!cred.verify(secret, 10));
    }

    #[test]
    fn credential_to_ice_server() {
        let cred = TurnCredential::derive("c", b"s", 0, 100);
        let ice = cred.ice_server("turn:relay:3478");
        assert!(ice.is_turn());
        assert_eq!(ice.username.as_deref(), Some(cred.username.as_str()));
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // length mismatch
    }

    #[test]
    fn password_is_hmac_not_plain_sha256() {
        // The password must equal HMAC-SHA256(secret, username), not sha256(secret||username).
        use hmac::Mac;
        let secret = b"relay-secret";
        let cred = TurnCredential::derive("chan", secret, 1000, 60);
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(cred.username.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(cred.password, expected);
        // A plain sha256(secret||username) would differ.
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(secret);
        h.update(cred.username.as_bytes());
        assert_ne!(cred.password, hex::encode(h.finalize()));
    }

    #[test]
    fn select_relay_ranks_by_latency_then_reputation() {
        let mut near = RelayCandidate::new("aa".repeat(32), "turn:near:3478");
        near.rtt_ms = 20;
        near.reputation = 0.1;
        let mut far = RelayCandidate::new("bb".repeat(32), "turn:far:3478");
        far.rtt_ms = 100;
        far.reputation = 1.0;
        let ranked = select_relay(vec![far.clone(), near.clone()]);
        assert_eq!(ranked[0].node_id, near.node_id, "the nearer relay wins despite lower reputation");
    }

    #[test]
    fn select_relay_reputation_breaks_latency_tie() {
        let mut a = RelayCandidate::new("11".repeat(32), "turn:a:3478");
        a.rtt_ms = 50;
        a.reputation = 0.0;
        let mut b = RelayCandidate::new("22".repeat(32), "turn:b:3478");
        b.rtt_ms = 50;
        b.reputation = 1.0;
        let ranked = select_relay(vec![a.clone(), b.clone()]);
        assert_eq!(ranked[0].node_id, b.node_id, "equal RTT -> higher reputation wins");
    }

    #[test]
    fn select_relay_empty_is_empty() {
        assert!(select_relay(vec![]).is_empty());
    }

    #[test]
    fn select_relay_is_deterministic_for_identical_scores() {
        let a = RelayCandidate::new("ff".repeat(32), "turn:a:3478");
        let b = RelayCandidate::new("00".repeat(32), "turn:b:3478");
        let r1 = select_relay(vec![a.clone(), b.clone()]);
        let r2 = select_relay(vec![b, a]);
        assert_eq!(r1, r2, "tie-break by node_id is stable regardless of input order");
        assert_eq!(r1[0].node_id, "00".repeat(32));
    }

    #[test]
    fn default_stun_is_stun_only() {
        let s = default_stun_servers();
        assert!(!s.is_empty());
        assert!(s.iter().all(|i| !i.is_turn()));
    }
}
