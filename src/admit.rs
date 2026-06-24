//! Host-side admission for capability-gated private rooms, plus reconnection-by-identity.
//!
//! [`crate::caps::Gate`] answers the narrow question "may this NodeId perform this action with this
//! capability chain?". [`Admitter`] is the host's full admission *flow* around it: it takes an
//! [`AdmitReq`] off the `meet:admit` request channel and produces an [`AdmitResp`] — running the gate
//! for a first join, **or** validating a [`ResumeToken`] for a reconnect, and (on success) minting a
//! fresh resume token bound to the joiner's identity and current sequence floor.
//!
//! ## Two admission paths
//!
//! 1. **First join (capability handshake).** A gated room runs the [`Gate`] over the presented chain.
//!    Open rooms admit unconditionally. On admit, the host returns a [`ResumeToken`] keyed to the
//!    joiner's NodeId so a later reconnect is cheap.
//! 2. **Reconnect (resume by identity).** A returning participant presents the token it was given.
//!    The host re-derives the token MAC over `(room, node, expiry, seq_floor)` with its own secret and
//!    checks it against the **authenticated reconnecting NodeId** — so a token stolen by another node
//!    does not admit them, and an expired token forces a fresh handshake. No capability re-check is
//!    needed: the original admission already authorized this identity, and identity is unforgeable.
//!
//! The MAC secret is the host's per-room (or per-deployment) static auth secret — never sent to a
//! joiner — exactly like the TURN static-auth-secret in [`crate::turn`]. The token therefore needs no
//! server-side state: the host verifies a token it issued purely by re-derivation.

use crate::caps::Gate;
use crate::proto::{ABILITY_JOIN, AdmitReq, AdmitResp, ResumeToken};
use crate::turn::IceServer;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default lifetime of a minted [`ResumeToken`], in seconds (one hour). A reconnect within this
/// window skips the capability handshake; after it, the participant re-authorizes.
pub const DEFAULT_RESUME_TTL: u64 = 3600;

/// The host-side admission handler for one gated (or open) room.
///
/// Owns the room id, the [`Gate`], the ICE servers to hand admitted joiners, the MAC secret used to
/// issue/verify [`ResumeToken`]s, and the resume TTL. [`Admitter::admit`] is the single entry point a
/// host's `meet:admit` reply loop calls per request; it never panics and returns a safe
/// [`AdmitResp`].
#[derive(Clone)]
pub struct Admitter {
    room_id: String,
    gate: Gate,
    ice_servers: Vec<IceServer>,
    mac_secret: Vec<u8>,
    resume_ttl: u64,
}

impl Admitter {
    /// Build an admitter for `room_id` with the given [`Gate`] and the host's MAC secret (used to
    /// mint/verify resume tokens — keep it private to the host).
    pub fn new(room_id: impl Into<String>, gate: Gate, mac_secret: impl Into<Vec<u8>>) -> Self {
        Admitter {
            room_id: room_id.into(),
            gate,
            ice_servers: Vec::new(),
            mac_secret: mac_secret.into(),
            resume_ttl: DEFAULT_RESUME_TTL,
        }
    }

    /// Attach the ICE servers (STUN/TURN) handed to every admitted joiner.
    pub fn with_ice_servers(mut self, ice: Vec<IceServer>) -> Self {
        self.ice_servers = ice;
        self
    }

    /// Override the resume-token lifetime (seconds).
    pub fn with_resume_ttl(mut self, ttl: u64) -> Self {
        self.resume_ttl = ttl;
        self
    }

    /// The room this admitter serves.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// Handle one admission request from `requester` (the **authenticated** sender NodeId hex the
    /// transport reported — never trusted from the request body). `host_tags` are the host's
    /// capability self-tags; `now` is unix seconds.
    ///
    /// Resolution order:
    /// - request is for a different room -> deny;
    /// - request carries a resume token -> validate it against `requester` and admit on success
    ///   (else fall through to a fresh handshake);
    /// - otherwise run the gate over the presented capability chain.
    ///
    /// On admit, mints a fresh [`ResumeToken`] (carrying `seq_floor`) and returns the ICE servers.
    pub fn admit(
        &self,
        requester: &str,
        req: &AdmitReq,
        host_tags: &[String],
        now: u64,
    ) -> AdmitResp {
        if req.room_id != self.room_id {
            return AdmitResp {
                admitted: false,
                reason: Some("admission request is for a different room".into()),
                ..Default::default()
            };
        }

        // Reconnect path: a presented, valid token for this same identity short-circuits the gate.
        if let Some(tok) = &req.resume {
            match self.verify_resume(requester, tok, now) {
                Ok(()) => return self.grant(requester, tok.seq_floor, now),
                Err(_reason) => {
                    // Token invalid/expired/forged: fall through to a fresh capability handshake
                    // rather than hard-denying, so a stale token degrades gracefully.
                }
            }
        }

        // First-join path: the capability gate decides.
        match self.gate.check(requester, ABILITY_JOIN, &req.caps, host_tags, now) {
            Ok(()) => self.grant(requester, 0, now),
            Err(reason) => AdmitResp { admitted: false, reason: Some(reason), ..Default::default() },
        }
    }

    /// Build a successful response: admitted, with ICE servers and a freshly minted resume token.
    fn grant(&self, requester: &str, seq_floor: u64, now: u64) -> AdmitResp {
        let resume = self.issue_resume(requester, seq_floor, now);
        AdmitResp {
            admitted: true,
            reason: None,
            ice_servers: self.ice_servers.clone(),
            resume: Some(resume),
        }
    }

    /// Mint a resume token bound to `node_id`, valid for `resume_ttl` from `now`, carrying `seq_floor`.
    pub fn issue_resume(&self, node_id: &str, seq_floor: u64, now: u64) -> ResumeToken {
        let expires_at = now.saturating_add(self.resume_ttl);
        let mac = self.resume_mac(node_id, expires_at, seq_floor);
        ResumeToken {
            room_id: self.room_id.clone(),
            node_id: node_id.to_string(),
            expires_at,
            seq_floor,
            mac,
        }
    }

    /// Verify a presented resume token against the authenticated `requester`. Checks, in order: the
    /// room matches, the token was issued to this same identity, it has not expired, and the MAC
    /// re-derives. Returns `Ok(())` if the token resumes, `Err(reason)` otherwise.
    pub fn verify_resume(
        &self,
        requester: &str,
        tok: &ResumeToken,
        now: u64,
    ) -> Result<(), String> {
        if tok.room_id != self.room_id {
            return Err("resume token is for a different room".into());
        }
        if tok.node_id != requester {
            return Err("resume token was issued to a different identity".into());
        }
        if now > tok.expires_at {
            return Err("resume token has expired".into());
        }
        let expected = self.resume_mac(&tok.node_id, tok.expires_at, tok.seq_floor);
        if !ct_eq(expected.as_bytes(), tok.mac.as_bytes()) {
            return Err("resume token signature invalid".into());
        }
        Ok(())
    }

    /// Derive the token MAC as `hex(HMAC-SHA256(secret, domain || room || 0 || node || 0 || expiry ||
    /// floor))`. A real keyed MAC (not a hand-rolled `sha256(secret||...)`), so it is not vulnerable to
    /// length-extension regardless of field layout. Domain-separated by a version tag and the room id,
    /// with NUL separators between the variable-length string fields so distinct `(room, node)` pairs
    /// can never collide into the same preimage.
    fn resume_mac(&self, node_id: &str, expires_at: u64, seq_floor: u64) -> String {
        // `new_from_slice` accepts a key of any length (HMAC pads/hashes as needed); it is infallible
        // for `Hmac`, but handle the Result without unwrap to honor the no-unwrap rule on prod paths.
        let mut mac = match HmacSha256::new_from_slice(&self.mac_secret) {
            Ok(m) => m,
            Err(_) => return String::new(), // impossible for HMAC; an empty MAC never verifies.
        };
        mac.update(b"ce-meet:resume:v1");
        mac.update(self.room_id.as_bytes());
        mac.update(&[0u8]);
        mac.update(node_id.as_bytes());
        mac.update(&[0u8]);
        mac.update(&expires_at.to_le_bytes());
        mac.update(&seq_floor.to_le_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// A per-sender admission-request rate limiter (a fixed-window token bucket) that bounds how much
/// host CPU a flood of `meet:admit` requests can burn on full `ce-cap` signature verification.
///
/// Each distinct requester NodeId gets `capacity` admit attempts per `window_secs`; further attempts
/// in the same window are dropped *before* the expensive gate runs. The bucket count is itself bounded
/// (`max_tracked`) so the limiter cannot be turned into a memory-exhaustion vector by spoofed senders:
/// once full, an unseen sender is rate-limited by default until a window rolls over and stale buckets
/// are evicted. Cheap, allocation-light, and fully deterministic for testing (the clock is injected).
#[derive(Debug, Clone)]
pub struct AdmitRateLimiter {
    capacity: u32,
    window_secs: u64,
    max_tracked: usize,
    buckets: std::collections::HashMap<String, (u64, u32)>, // node -> (window_start, count)
}

/// Default admit attempts allowed per sender per window.
pub const DEFAULT_ADMIT_CAPACITY: u32 = 10;
/// Default rate-limit window, seconds.
pub const DEFAULT_ADMIT_WINDOW_SECS: u64 = 10;
/// Default cap on the number of distinct senders tracked at once (memory bound).
pub const DEFAULT_ADMIT_MAX_TRACKED: usize = 4096;

impl Default for AdmitRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_ADMIT_CAPACITY, DEFAULT_ADMIT_WINDOW_SECS, DEFAULT_ADMIT_MAX_TRACKED)
    }
}

impl AdmitRateLimiter {
    /// Build a limiter allowing `capacity` attempts per `window_secs` per sender, tracking at most
    /// `max_tracked` distinct senders. Zero values are clamped to 1 so it never divides by zero or
    /// degenerates into an unbounded map.
    pub fn new(capacity: u32, window_secs: u64, max_tracked: usize) -> Self {
        AdmitRateLimiter {
            capacity: capacity.max(1),
            window_secs: window_secs.max(1),
            max_tracked: max_tracked.max(1),
            buckets: std::collections::HashMap::new(),
        }
    }

    /// Record an attempt by `node` at `now` (unix seconds). Returns `true` if the attempt is allowed
    /// (under the per-window cap) or `false` if it should be dropped. Rolls the window per sender and
    /// evicts buckets older than one window when the tracked-sender cap is hit.
    pub fn check(&mut self, node: &str, now: u64) -> bool {
        // Roll/evict before inserting a brand-new sender so the map stays bounded.
        if !self.buckets.contains_key(node) && self.buckets.len() >= self.max_tracked {
            let window = self.window_secs;
            self.buckets.retain(|_, (start, _)| now.saturating_sub(*start) < window);
            if self.buckets.len() >= self.max_tracked {
                // Still full of fresh buckets: refuse the unseen sender this window (fail-closed).
                return false;
            }
        }
        let window = self.window_secs;
        let entry = self.buckets.entry(node.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= window {
            *entry = (now, 0); // new window
        }
        if entry.1 >= self.capacity {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Number of senders currently tracked (for tests/metrics).
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

/// Constant-time byte-slice equality (length-aware) so token verification does not leak the MAC via
/// timing. Returns false immediately on a length mismatch (length is not secret).
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

#[cfg(test)]
mod tests {
    use super::*;
    use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
    use ce_identity::Identity;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ce-meet-admit-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    fn join_chain(host: &Identity, joiner: &Identity, nonce: u64) -> String {
        let cap = SignedCapability::issue(
            host,
            joiner.node_id(),
            vec![ABILITY_JOIN.to_string()],
            Resource::Any,
            Caveats::default(),
            nonce,
            None,
        );
        encode_chain(&[cap])
    }

    fn req(room: &str, caps: &str) -> AdmitReq {
        AdmitReq { room_id: room.into(), caps: caps.into(), display_name: None, resume: None }
    }

    #[test]
    fn open_room_admits_and_issues_resume() {
        let host = id("host");
        let joiner = id("joiner");
        let adm = Admitter::new("r", Gate::open(host.node_id()), b"secret".to_vec());
        let resp = adm.admit(&joiner.node_id_hex(), &req("r", ""), &[], 1000);
        assert!(resp.admitted);
        let tok = resp.resume.expect("resume token issued on admit");
        assert_eq!(tok.node_id, joiner.node_id_hex());
        assert_eq!(tok.room_id, "r");
        assert_eq!(tok.expires_at, 1000 + DEFAULT_RESUME_TTL);
    }

    #[test]
    fn gated_room_admits_valid_chain_denies_empty() {
        let host = id("host");
        let joiner = id("joiner");
        let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec());
        let chain = join_chain(&host, &joiner, 1);
        assert!(adm.admit(&joiner.node_id_hex(), &req("r", &chain), &[], 1000).admitted);

        let denied = adm.admit(&joiner.node_id_hex(), &req("r", ""), &[], 1000);
        assert!(!denied.admitted);
        assert!(denied.reason.is_some());
        assert!(denied.resume.is_none());
    }

    #[test]
    fn wrong_room_request_is_denied() {
        let host = id("host");
        let adm = Admitter::new("r", Gate::open(host.node_id()), b"s".to_vec());
        let resp = adm.admit(&id("j").node_id_hex(), &req("OTHER", ""), &[], 1000);
        assert!(!resp.admitted);
        assert!(resp.reason.unwrap().contains("different room"));
    }

    #[test]
    fn resume_token_round_trip_admits_same_identity() {
        let host = id("host");
        let joiner = id("joiner");
        let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec());
        // first join with a real chain
        let chain = join_chain(&host, &joiner, 1);
        let first = adm.admit(&joiner.node_id_hex(), &req("r", &chain), &[], 1000);
        let tok = first.resume.unwrap();

        // reconnect: present ONLY the token, no chain
        let reconnect = AdmitReq {
            room_id: "r".into(),
            caps: String::new(),
            display_name: None,
            resume: Some(tok),
        };
        let resp = adm.admit(&joiner.node_id_hex(), &reconnect, &[], 1500);
        assert!(resp.admitted, "valid token resumes without a chain");
        assert!(resp.resume.is_some(), "a fresh token is minted on resume");
    }

    #[test]
    fn resume_token_rejected_for_different_identity() {
        let host = id("host");
        let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec());
        let tok = adm.issue_resume("aa".repeat(32).as_str(), 3, 1000);
        // a different node presents the stolen token AND no valid chain -> denied
        let thief = id("thief");
        let reconnect = AdmitReq {
            room_id: "r".into(),
            caps: String::new(),
            display_name: None,
            resume: Some(tok),
        };
        let resp = adm.admit(&thief.node_id_hex(), &reconnect, &[], 1100);
        assert!(!resp.admitted, "a token bound to another identity must not admit a thief");
    }

    #[test]
    fn expired_resume_token_falls_through_to_handshake() {
        let host = id("host");
        let joiner = id("joiner");
        let adm =
            Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec()).with_resume_ttl(10);
        let tok = adm.issue_resume(&joiner.node_id_hex(), 0, 1000); // expires at 1010
        // present an expired token but ALSO a valid chain -> falls through, still admitted
        let chain = join_chain(&host, &joiner, 1);
        let reconnect = AdmitReq {
            room_id: "r".into(),
            caps: chain,
            display_name: None,
            resume: Some(tok.clone()),
        };
        let resp = adm.admit(&joiner.node_id_hex(), &reconnect, &[], 5000);
        assert!(resp.admitted, "expired token falls through to a successful chain handshake");

        // and an expired token with NO chain is denied
        let bare = AdmitReq { room_id: "r".into(), resume: Some(tok), ..Default::default() };
        assert!(!adm.admit(&joiner.node_id_hex(), &bare, &[], 5000).admitted);
    }

    #[test]
    fn tampered_resume_mac_is_rejected() {
        let host = id("host");
        let joiner = id("joiner");
        let adm = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"s".to_vec());
        let mut tok = adm.issue_resume(&joiner.node_id_hex(), 0, 1000);
        assert!(adm.verify_resume(&joiner.node_id_hex(), &tok, 1100).is_ok());
        tok.mac = "deadbeef".into();
        assert!(adm.verify_resume(&joiner.node_id_hex(), &tok, 1100).is_err());
        // tampering with seq_floor also breaks the MAC
        let mut tok2 = adm.issue_resume(&joiner.node_id_hex(), 0, 1000);
        tok2.seq_floor = 999;
        assert!(adm.verify_resume(&joiner.node_id_hex(), &tok2, 1100).is_err());
    }

    #[test]
    fn resume_token_from_a_different_host_secret_is_rejected() {
        let host = id("host");
        let joiner = id("joiner");
        let issuer = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"secret-A".to_vec());
        let tok = issuer.issue_resume(&joiner.node_id_hex(), 0, 1000);
        // a host with a different secret cannot verify the token
        let other = Admitter::new("r", Gate::gated(host.node_id(), vec![]), b"secret-B".to_vec());
        assert!(other.verify_resume(&joiner.node_id_hex(), &tok, 1100).is_err());
    }

    #[test]
    fn resume_carries_seq_floor_for_monotonic_reconnect() {
        let host = id("host");
        let joiner = id("joiner");
        let adm = Admitter::new("r", Gate::open(host.node_id()), b"s".to_vec());
        let tok = adm.issue_resume(&joiner.node_id_hex(), 42, 1000);
        assert_eq!(tok.seq_floor, 42);
        assert!(adm.verify_resume(&joiner.node_id_hex(), &tok, 1100).is_ok());
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn resume_mac_is_hmac_not_plain_sha256() {
        // The MAC must equal HMAC-SHA256(secret, domain||room||0||node||0||expiry||floor),
        // not a hand-rolled sha256(secret||...). Reproduce the HMAC and compare.
        let adm = Admitter::new("room", Gate::open([0u8; 32]), b"k".to_vec());
        let tok = adm.issue_resume("nodehex", 7, 1000);
        let mut h = HmacSha256::new_from_slice(b"k").unwrap();
        h.update(b"ce-meet:resume:v1");
        h.update(b"room");
        h.update(&[0u8]);
        h.update(b"nodehex");
        h.update(&[0u8]);
        h.update(&tok.expires_at.to_le_bytes());
        h.update(&7u64.to_le_bytes());
        assert_eq!(tok.mac, hex::encode(h.finalize().into_bytes()));
        // A plain sha256(secret||...) would differ.
        use sha2::Digest;
        let mut sh = Sha256::new();
        sh.update(b"k");
        sh.update(&tok.expires_at.to_le_bytes());
        assert_ne!(tok.mac, hex::encode(sh.finalize()));
    }

    // ---- rate limiter ----

    #[test]
    fn rate_limiter_allows_up_to_capacity_then_blocks() {
        let mut rl = AdmitRateLimiter::new(3, 10, 100);
        assert!(rl.check("a", 1000));
        assert!(rl.check("a", 1000));
        assert!(rl.check("a", 1000));
        // 4th in the same window is blocked
        assert!(!rl.check("a", 1000));
        // a different sender has its own budget
        assert!(rl.check("b", 1000));
    }

    #[test]
    fn rate_limiter_rolls_window() {
        let mut rl = AdmitRateLimiter::new(2, 10, 100);
        assert!(rl.check("a", 1000));
        assert!(rl.check("a", 1005));
        assert!(!rl.check("a", 1008)); // still in window [1000,1010)
        // window rolls at 1010
        assert!(rl.check("a", 1010));
    }

    #[test]
    fn rate_limiter_bounds_tracked_senders() {
        // Cap tracked senders at 2; a flood of distinct senders cannot grow the map without bound.
        let mut rl = AdmitRateLimiter::new(5, 10, 2);
        assert!(rl.check("a", 1000));
        assert!(rl.check("b", 1000));
        // 3rd distinct sender within the same window: map full of fresh buckets -> fail-closed.
        assert!(!rl.check("c", 1000));
        assert!(rl.tracked() <= 2);
        // after the window, stale buckets evict and a new sender is admitted again.
        assert!(rl.check("c", 1020));
        assert!(rl.tracked() <= 2);
    }

    #[test]
    fn rate_limiter_clamps_degenerate_params() {
        let mut rl = AdmitRateLimiter::new(0, 0, 0);
        // capacity clamped to 1: first allowed, second blocked within the (1s) window.
        assert!(rl.check("a", 0));
        assert!(!rl.check("a", 0));
    }

    #[test]
    fn force_mute_chain_authorizes_via_moderate_ability() {
        // A moderator holding meet:moderate is authorized by the host gate for a moderation action.
        use crate::proto::ABILITY_MODERATE;
        let host = id("host");
        let mod_user = id("mod");
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
        // a join-only chain does NOT grant moderate
        let join_cap = SignedCapability::issue(
            &host,
            mod_user.node_id(),
            vec![ABILITY_JOIN.to_string()],
            Resource::Any,
            Caveats::default(),
            2,
            None,
        );
        let join_chain = encode_chain(&[join_cap]);
        assert!(gate.check(&mod_user.node_id_hex(), ABILITY_MODERATE, &join_chain, &[], 1000).is_err());
    }
}
