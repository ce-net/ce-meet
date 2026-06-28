//! Capability handling for ce-meet: client-side chain resolution and the host-side admission gate.
//!
//! ce-meet mints no trust. A **gated** room's host authorizes a presented, signed, attenuating
//! `ce-cap` chain (rooted at the host's own key or a configured org root) before admitting a joiner
//! or honoring a moderation action. Abilities are opaque app-chosen strings (`meet:join`,
//! `meet:host`, `meet:moderate`); the `ce-cap` verifier assigns them no meaning — this module does.
//!
//! Client side: [`resolve`] loads the hex chain to present, from (in precedence order) an explicit
//! flag, the `$CE_MEET_CAPS` env var, or `<config dir>/ce-meet/caps`.
//!
//! Host side: [`Gate`] wraps the `ce-cap::authorize` call with ce-meet's room semantics, including
//! the **open-room** shortcut (no capability required) and on-chain revocation lookup.

use anyhow::{Result, anyhow};
use ce_iam_core::{SignedCapability, authorize, decode_chain};
use ce_identity::NodeId;
use std::collections::HashSet;
use std::path::PathBuf;

/// Resolve the capability-chain hex a client should present when joining a gated room. `explicit`
/// is the `--caps` flag. Returns an empty string when nothing is configured (the host's gate then
/// returns a clear "denied" rather than the client guessing).
pub fn resolve(explicit: Option<&str>) -> String {
    if let Some(c) = explicit.map(str::trim).filter(|c| !c.is_empty()) {
        return c.to_string();
    }
    if let Ok(c) = std::env::var("CE_MEET_CAPS") {
        let c = c.trim().to_string();
        if !c.is_empty() {
            return c;
        }
    }
    if let Some(p) = caps_file()
        && let Ok(c) = std::fs::read_to_string(&p)
    {
        let c = c.trim().to_string();
        if !c.is_empty() {
            return c;
        }
    }
    String::new()
}

fn caps_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("CE_MEET_DIR") {
        return Some(PathBuf::from(d).join("caps"));
    }
    directories::ProjectDirs::from("", "", "ce-meet").map(|p| p.config_dir().join("caps"))
}

/// Parse a NodeId hex string into a [`NodeId`] (`[u8; 32]`).
pub fn parse_node_id(hex_str: &str) -> Result<NodeId> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| anyhow!("node id is not valid hex"))?;
    bytes.try_into().map_err(|_| anyhow!("node id must be 32 bytes (64 hex chars)"))
}

/// The host-side admission gate for one room.
///
/// A room is either **open** (anyone may join — no capability needed) or **gated** (a chain granting
/// the requested ability, rooted at an accepted root, is required). The gate owns the host's
/// identity, its accepted org roots, and the current on-chain revocation set.
#[derive(Debug, Clone)]
pub struct Gate {
    /// The host's own NodeId — always an implicit accepted root for chains it issued itself.
    host_id: NodeId,
    /// Additional accepted org/CA root keys (the SSH `TrustedUserCAKeys` analog).
    accepted_roots: Vec<NodeId>,
    /// Whether the room is open (no capability required).
    open: bool,
    /// Revoked `(issuer_hex, nonce)` pairs from the chain (`CeClient::revoked`).
    revoked: HashSet<(String, u64)>,
}

impl Gate {
    /// A gate for an **open** room — every join is admitted, no capability needed.
    pub fn open(host_id: NodeId) -> Self {
        Gate { host_id, accepted_roots: Vec::new(), open: true, revoked: HashSet::new() }
    }

    /// A gate for a **gated** room — joiners must present a chain granting the action.
    pub fn gated(host_id: NodeId, accepted_roots: Vec<NodeId>) -> Self {
        Gate { host_id, accepted_roots, open: false, revoked: HashSet::new() }
    }

    /// Load the on-chain revocation set (from `CeClient::revoked`) so the gate denies revoked chains.
    pub fn with_revoked(mut self, revoked: impl IntoIterator<Item = (String, u64)>) -> Self {
        self.revoked = revoked.into_iter().collect();
        self
    }

    /// Is this an open room?
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Decide whether `requester` (NodeId hex) may perform `action` in this room, presenting the
    /// hex-encoded capability chain `caps_hex`. `now` is unix seconds; `host_tags` are the host's
    /// capability self-tags (matched by `Resource::Tag`).
    ///
    /// Open rooms admit unconditionally. Gated rooms require a non-empty chain that
    /// `ce-cap::authorize` accepts: rooted at an accepted root, every link signed/valid/unrevoked,
    /// attenuating, the leaf held by `requester` and granting `action`.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` (safe to surface) otherwise — never panics.
    pub fn check(
        &self,
        requester_hex: &str,
        action: &str,
        caps_hex: &str,
        host_tags: &[String],
        now: u64,
    ) -> Result<(), String> {
        if self.open && action == crate::proto::ABILITY_JOIN {
            return Ok(());
        }
        let requester = parse_node_id(requester_hex).map_err(|e: anyhow::Error| e.to_string())?;
        let chain: Vec<SignedCapability> =
            decode_chain(caps_hex).map_err(|_| "no valid capability presented".to_string())?;
        let revoked = &self.revoked;
        let is_revoked = |issuer: &NodeId, nonce: u64| -> bool {
            revoked.contains(&(hex::encode(issuer), nonce))
        };
        authorize(
            &self.host_id,
            &self.accepted_roots,
            host_tags,
            now,
            &requester,
            action,
            &chain,
            &is_revoked,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ABILITY_HOST, ABILITY_JOIN};
    use ce_iam_core::{Caveats, Resource, SignedCapability, encode_chain};
    use ce_identity::Identity;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ce-meet-cap-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    #[test]
    fn resolve_explicit_takes_precedence() {
        assert_eq!(resolve(Some("deadbeef")), "deadbeef");
        assert_eq!(resolve(Some("  abc  ")), "abc");
    }

    #[test]
    fn resolve_empty_falls_through_to_none() {
        unsafe {
            std::env::remove_var("CE_MEET_CAPS");
            std::env::set_var("CE_MEET_DIR", "/nonexistent-ce-meet-dir-xyz");
        }
        assert_eq!(resolve(Some("  ")), "");
        unsafe {
            std::env::remove_var("CE_MEET_DIR");
        }
    }

    #[test]
    fn parse_node_id_rejects_bad_input() {
        assert!(parse_node_id("nothex").is_err());
        assert!(parse_node_id("aa").is_err()); // too short
        assert!(parse_node_id(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn open_room_admits_without_caps() {
        let host = id("host");
        let gate = Gate::open(host.node_id());
        assert!(gate.is_open());
        assert!(gate.check(&id("joiner").node_id_hex(), ABILITY_JOIN, "", &[], 1000).is_ok());
    }

    #[test]
    fn gated_room_denies_empty_chain() {
        let host = id("host");
        let gate = Gate::gated(host.node_id(), vec![]);
        let r = gate.check(&id("joiner").node_id_hex(), ABILITY_JOIN, "", &[], 1000);
        assert!(r.is_err());
    }

    #[test]
    fn gated_room_admits_valid_self_issued_chain() {
        let host = id("host");
        let joiner = id("joiner");
        // host self-issues meet:join to the joiner.
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
        let gate = Gate::gated(host.node_id(), vec![]);
        assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000).is_ok());
    }

    #[test]
    fn gated_room_denies_wrong_ability() {
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
        let gate = Gate::gated(host.node_id(), vec![]);
        // chain grants join, not host
        assert!(gate.check(&joiner.node_id_hex(), ABILITY_HOST, &chain, &[], 1000).is_err());
    }

    #[test]
    fn gated_room_denies_revoked_chain() {
        let host = id("host");
        let joiner = id("joiner");
        let cap = SignedCapability::issue(
            &host,
            joiner.node_id(),
            vec![ABILITY_JOIN.to_string()],
            Resource::Any,
            Caveats::default(),
            42,
            None,
        );
        let chain = encode_chain(&[cap]);
        let gate = Gate::gated(host.node_id(), vec![])
            .with_revoked([(host.node_id_hex(), 42u64)]);
        let r = gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000);
        assert!(r.unwrap_err().contains("revoked"));
    }

    #[test]
    fn gated_room_denies_chain_from_stranger_root() {
        let host = id("host");
        let stranger = id("stranger");
        let joiner = id("joiner");
        // chain rooted at a stranger, not the host or an accepted root
        let cap = SignedCapability::issue(
            &stranger,
            joiner.node_id(),
            vec![ABILITY_JOIN.to_string()],
            Resource::Any,
            Caveats::default(),
            1,
            None,
        );
        let chain = encode_chain(&[cap]);
        let gate = Gate::gated(host.node_id(), vec![]);
        assert!(gate.check(&joiner.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000).is_err());
    }

    #[test]
    fn gated_room_accepts_org_root() {
        let host = id("host");
        let org = id("org");
        let employee = id("employee");
        let cap = SignedCapability::issue(
            &org,
            employee.node_id(),
            vec![ABILITY_JOIN.to_string()],
            Resource::Any,
            Caveats::default(),
            1,
            None,
        );
        let chain = encode_chain(&[cap]);
        let gate = Gate::gated(host.node_id(), vec![org.node_id()]);
        assert!(gate.check(&employee.node_id_hex(), ABILITY_JOIN, &chain, &[], 1000).is_ok());
    }

    #[test]
    fn gated_room_denies_malformed_caps_hex() {
        let host = id("host");
        let gate = Gate::gated(host.node_id(), vec![]);
        let r = gate.check(&id("j").node_id_hex(), ABILITY_JOIN, "zzzz-not-hex", &[], 1000);
        assert!(r.is_err());
    }
}
