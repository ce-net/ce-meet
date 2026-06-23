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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
/// `username = "<expiry_unix>:<channel_id>"` and `password = base64(HMAC-ish digest)`. Here the
/// digest is `sha256(shared_secret || username)` — deterministic so the relay can re-derive and
/// verify it statelessly, expiring so a leak is bounded.
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
        let mut h = Sha256::new();
        h.update(shared_secret);
        h.update(username.as_bytes());
        let password = hex::encode(h.finalize());
        TurnCredential { username, password, expires_at, channel_id: channel_id.to_string() }
    }

    /// Re-derive and constant-purpose-check a presented credential against the relay's secret.
    /// Returns true only if the password matches the derivation and the credential is unexpired at
    /// `now`. The relay calls this to authorize a TURN allocation without storing per-client state.
    pub fn verify(&self, shared_secret: &[u8], now: u64) -> bool {
        if now > self.expires_at {
            return false;
        }
        let expected = Self::derive(&self.channel_id, shared_secret, self.expires_at.saturating_sub(0), 0);
        // derive() with ttl 0 and now==expires_at reproduces the same username+password.
        let recomputed = {
            let username = format!("{}:{}", self.expires_at, self.channel_id);
            if username != self.username {
                return false;
            }
            let mut h = Sha256::new();
            h.update(shared_secret);
            h.update(username.as_bytes());
            hex::encode(h.finalize())
        };
        let _ = expected; // keep the symmetry obvious; recomputed is the authoritative check
        recomputed == self.password
    }

    /// Render this credential as an [`IceServer`] for a given TURN URL, ready to hand to a browser.
    pub fn ice_server(&self, turn_url: impl Into<String>) -> IceServer {
        IceServer::turn(turn_url, self.username.clone(), self.password.clone())
    }
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
}
