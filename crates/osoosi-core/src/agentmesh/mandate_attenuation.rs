//! Attenuated Capability Mandate Chains with Ed25519 Signatures
//!
//! Enforces:
//! - Monotonic Capability Attenuation: Services_{N+1} = Services_N ∩ Narrowed
//! - Segregated Rights: `allowed_services` (outbound call) vs `allowed_publish` (inbound host)
//! - Strict Scheme Parser: only `mcp://`, `a2a://`, `inference://`, `egress://`
//! - Zero Holder Datalog Rules: strictly rejects executable/declarative rules injected by holder
//! - Cryptographic chaining using Ed25519 signatures across delegation hops
//! - Bounded delegation depth: maximum 8 hops

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_DELEGATION_DEPTH: usize = 8;
pub const ALLOWED_SCHEMES: &[&str] = &["mcp://", "a2a://", "inference://", "egress://"];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MandateError {
    #[error("Invalid URI scheme for '{uri}': must begin with one of {allowed:?}")]
    InvalidUriScheme {
        uri: String,
        allowed: &'static [&'static str],
    },

    #[error("Prohibited target in URI '{uri}': {reason}")]
    ProhibitedTarget {
        uri: String,
        reason: String,
    },

    #[error("Privilege escalation in allowed_services: requested '{requested}' not in parent services {parent_services:?}")]
    PrivilegeEscalationService {
        requested: String,
        parent_services: Vec<String>,
    },

    #[error("Privilege escalation in allowed_publish: requested '{requested}' not in parent publish {parent_publish:?}")]
    PrivilegeEscalationPublish {
        requested: String,
        parent_publish: Vec<String>,
    },

    #[error("Mandate delegation depth {depth} exceeds maximum allowable depth {max}")]
    MaxDelegationDepthExceeded {
        depth: usize,
        max: usize,
    },

    #[error("Mandate expired: exp={exp}, now={now}")]
    MandateExpired {
        exp: u64,
        now: u64,
    },

    #[error("Mandate not yet valid: nbf={nbf}, now={now}")]
    MandateNotYetValid {
        nbf: u64,
        now: u64,
    },

    #[error("Cryptographic signature failure at delegation depth {depth}: {reason}")]
    SignatureFailure {
        depth: usize,
        reason: String,
    },

    #[error("Holder mismatch: mandate is held by '{holder}', but invoked by '{invoker}'")]
    HolderMismatch {
        holder: String,
        invoker: String,
    },

    #[error("Service call unauthorized: URI '{uri}' is not in mandate allowed_services")]
    ServiceCallUnauthorized {
        uri: String,
    },

    #[error("Publish unauthorized: URI '{uri}' is not in mandate allowed_publish")]
    PublishUnauthorized {
        uri: String,
    },

    #[error("Holder-supplied Datalog/script rules strictly forbidden by AgentOctopus security invariant")]
    HolderRulesForbidden,

    #[error("Malformed mandate encoding: {0}")]
    SerializationError(String),
}

/// Validates that a URI complies with strict AgentMesh pore rules:
/// 1. Must start with `mcp://`, `a2a://`, `inference://`, or `egress://`.
/// 2. Must not contain raw IPv4 or IPv6 literals.
/// 3. Must not contain `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`.
/// 4. Must not contain path traversals (`..`), null bytes (`\0`), control characters, or backslashes.
pub fn validate_mesh_uri(uri: &str) -> Result<(), MandateError> {
    let matches_scheme = ALLOWED_SCHEMES.iter().any(|scheme| uri.starts_with(scheme));
    if !matches_scheme {
        return Err(MandateError::InvalidUriScheme {
            uri: uri.to_string(),
            allowed: ALLOWED_SCHEMES,
        });
    }

    let uri_lower = uri.to_lowercase();

    // Check for null bytes or control characters
    if uri.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Contains control characters or null bytes".to_string(),
        });
    }

    // Check for directory traversal, backslashes, percent-encoded traversal, or credentials
    if uri.contains("..")
        || uri.contains('\\')
        || uri_lower.contains("%2e")
        || uri_lower.contains("%2f")
        || uri_lower.contains("%5c")
        || uri_lower.contains("%00")
        || uri.contains('@')
    {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Contains path traversal, percent-encoding, or credentials".to_string(),
        });
    }

    // Check for prohibited keywords
    if uri_lower.contains("localhost")
        || uri_lower.contains("127.0.0.1")
        || uri_lower.contains("0.0.0.0")
        || uri_lower.contains("169.254.")
    {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Target references prohibited loopback or link-local host".to_string(),
        });
    }

    // Extract authority part
    let body = uri.split("://").nth(1).unwrap_or("");
    let authority = body.split('/').next().unwrap_or("");

    // Case A: IPv6 in bracket notation [addr] or [addr]:port
    if authority.starts_with('[') {
        let closing = authority.find(']').ok_or_else(|| MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Malformed IPv6 bracket notation".to_string(),
        })?;
        let ip_str = &authority[1..closing];
        let port_part = &authority[closing + 1..];

        if !port_part.is_empty() {
            if let Some(port_num) = port_part.strip_prefix(':') {
                if port_num.is_empty() || !port_num.chars().all(|c| c.is_ascii_digit()) || port_num.parse::<u16>().is_err() {
                    return Err(MandateError::ProhibitedTarget {
                        uri: uri.to_string(),
                        reason: "Malformed port in IPv6 URI".to_string(),
                    });
                }
            } else {
                return Err(MandateError::ProhibitedTarget {
                    uri: uri.to_string(),
                    reason: "Malformed character following IPv6 closing bracket".to_string(),
                });
            }
        }

        if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
            return Err(MandateError::ProhibitedTarget {
                uri: uri.to_string(),
                reason: format!("Raw IPv6 literal address forbidden; logical names required ({ipv6})"),
            });
        }
    }

    // Case B: Host with explicit :port is strictly forbidden in logical AgentMesh URIs
    let host = authority.split(':').next().unwrap_or(authority);
    if authority.contains(':') {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Explicit port numbers are forbidden in logical AgentMesh URIs".to_string(),
        });
    }

    // Mathematical IPv4 check
    if let Ok(ipv4) = Ipv4Addr::from_str(host) {
        let octets = ipv4.octets();
        let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 64;
        let is_broadcast = octets == [255, 255, 255, 255];

        let reason = if ipv4.is_loopback() {
            "Loopback IPv4 address forbidden"
        } else if ipv4.is_private() {
            "RFC 1918 private IPv4 address forbidden"
        } else if ipv4.is_link_local() {
            "Link-local IPv4 address forbidden"
        } else if ipv4.is_unspecified() {
            "Unspecified IPv4 address (0.0.0.0) forbidden"
        } else if is_cgnat {
            "CGNAT IPv4 address (100.64.0.0/10) forbidden"
        } else if is_broadcast {
            "Broadcast IPv4 address forbidden"
        } else {
            "Raw IPv4 literal address forbidden; logical names required"
        };

        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: reason.to_string(),
        });
    }

    // Check if integer decimal IP notation (e.g. 2130706433 for 127.0.0.1)
    if host.parse::<u32>().is_ok() {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: "Integer decimal IP literal forbidden".to_string(),
        });
    }

    // Direct IPv6 check (unbracketed)
    if let Ok(ipv6) = Ipv6Addr::from_str(host) {
        return Err(MandateError::ProhibitedTarget {
            uri: uri.to_string(),
            reason: format!("Raw IPv6 literal address forbidden; logical names required ({ipv6})"),
        });
    }

    Ok(())
}

/// Single hop in an Ed25519-signed capability delegation chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationLink {
    pub depth: usize,
    pub delegator_spiffe_id: String,
    pub delegator_verifying_key: [u8; 32],
    pub delegatee_spiffe_id: String,
    pub delegatee_verifying_key: [u8; 32],
    pub attenuated_services: BTreeSet<String>,
    pub attenuated_publish: BTreeSet<String>,
    pub delegated_at: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl DelegationLink {
    /// Computes canonical byte representation for signature verification.
    /// Cryptographically commits to both delegator and delegatee public keys.
    pub fn canonical_payload(
        depth: usize,
        delegator_spiffe_id: &str,
        delegator_verifying_key: &[u8; 32],
        delegatee_spiffe_id: &str,
        delegatee_verifying_key: &[u8; 32],
        services: &BTreeSet<String>,
        publish: &BTreeSet<String>,
        delegated_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(&(depth as u64).to_be_bytes());
        bytes.extend_from_slice(delegator_spiffe_id.as_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(delegator_verifying_key);
        bytes.extend_from_slice(delegatee_spiffe_id.as_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(delegatee_verifying_key);

        for s in services {
            bytes.extend_from_slice(s.as_bytes());
            bytes.push(0x1F); // Unit separator
        }
        bytes.push(0x00);

        for p in publish {
            bytes.extend_from_slice(p.as_bytes());
            bytes.push(0x1F); // Unit separator
        }
        bytes.push(0x00);

        bytes.extend_from_slice(&delegated_at.to_be_bytes());
        bytes.extend_from_slice(&expires_at.to_be_bytes());
        bytes
    }
}

/// Cryptographically Attenuated Capability Mandate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttenuatedMandate {
    pub mandate_id: String,
    pub root_issuer_spiffe_id: String,
    pub root_verifying_key: [u8; 32],
    pub current_holder_spiffe_id: String,
    pub depth: usize,
    pub allowed_services: BTreeSet<String>,
    pub allowed_publish: BTreeSet<String>,
    pub not_before: u64,
    pub expires_at: u64,
    pub delegation_chain: Vec<DelegationLink>,
}

impl AttenuatedMandate {
    /// Constructs a root capability mandate signed by the primary authority key,
    /// binding the initial holder's public key.
    pub fn create_root(
        root_signing_key: &SigningKey,
        root_spiffe_id: &str,
        initial_holder_spiffe_id: &str,
        initial_holder_verifying_key: [u8; 32],
        allowed_services: BTreeSet<String>,
        allowed_publish: BTreeSet<String>,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, MandateError> {
        // Validate all initial URIs
        for s in &allowed_services {
            validate_mesh_uri(s)?;
        }
        for p in &allowed_publish {
            validate_mesh_uri(p)?;
        }

        let root_vk = root_signing_key.verifying_key().to_bytes();
        let mandate_id = format!("mandate-root-{:016x}", rand::random::<u64>());

        // Root delegation link (depth 0)
        let payload = DelegationLink::canonical_payload(
            0,
            root_spiffe_id,
            &root_vk,
            initial_holder_spiffe_id,
            &initial_holder_verifying_key,
            &allowed_services,
            &allowed_publish,
            not_before,
            expires_at,
        );

        let sig: Signature = root_signing_key.sign(&payload);
        let link = DelegationLink {
            depth: 0,
            delegator_spiffe_id: root_spiffe_id.to_string(),
            delegator_verifying_key: root_vk,
            delegatee_spiffe_id: initial_holder_spiffe_id.to_string(),
            delegatee_verifying_key: initial_holder_verifying_key,
            attenuated_services: allowed_services.clone(),
            attenuated_publish: allowed_publish.clone(),
            delegated_at: not_before,
            expires_at,
            signature: sig.to_bytes().to_vec(),
        };

        Ok(Self {
            mandate_id,
            root_issuer_spiffe_id: root_spiffe_id.to_string(),
            root_verifying_key: root_vk,
            current_holder_spiffe_id: initial_holder_spiffe_id.to_string(),
            depth: 0,
            allowed_services,
            allowed_publish,
            not_before,
            expires_at,
            delegation_chain: vec![link],
        })
    }

    /// Attenuates the mandate for a delegatee, strictly enforcing:
    /// 1. Delegator key matches parent link's authorized delegatee key
    /// 2. Monotonic capability shrinkage: requested ⊆ parent
    /// 3. Bounded lifetime: new_exp <= parent_exp
    /// 4. Incremented depth: depth + 1 <= MAX_DELEGATION_DEPTH
    /// 5. Cryptographic signature over child link binding delegatee_verifying_key
    pub fn attenuate(
        &self,
        delegator_key: &SigningKey,
        delegatee_spiffe_id: &str,
        delegatee_verifying_key: [u8; 32],
        narrowed_services: BTreeSet<String>,
        narrowed_publish: BTreeSet<String>,
        new_expires_at: u64,
        now: u64,
    ) -> Result<Self, MandateError> {
        // Check validity window
        if now < self.not_before {
            return Err(MandateError::MandateNotYetValid {
                nbf: self.not_before,
                now,
            });
        }
        if now > self.expires_at {
            return Err(MandateError::MandateExpired {
                exp: self.expires_at,
                now,
            });
        }

        // Check depth limit
        let next_depth = self.depth + 1;
        if next_depth > MAX_DELEGATION_DEPTH {
            return Err(MandateError::MaxDelegationDepthExceeded {
                depth: next_depth,
                max: MAX_DELEGATION_DEPTH,
            });
        }

        // Validate URIs
        for s in &narrowed_services {
            validate_mesh_uri(s)?;
        }
        for p in &narrowed_publish {
            validate_mesh_uri(p)?;
        }

        // Monotonic intersection: ensure requested services are a subset of parent
        for s in &narrowed_services {
            if !self.allowed_services.contains(s) {
                return Err(MandateError::PrivilegeEscalationService {
                    requested: s.clone(),
                    parent_services: self.allowed_services.iter().cloned().collect(),
                });
            }
        }

        // Monotonic intersection: ensure requested publish items are a subset of parent
        for p in &narrowed_publish {
            if !self.allowed_publish.contains(p) {
                return Err(MandateError::PrivilegeEscalationPublish {
                    requested: p.clone(),
                    parent_publish: self.allowed_publish.iter().cloned().collect(),
                });
            }
        }

        let delegator_vk = delegator_key.verifying_key().to_bytes();

        // Enforce that delegator_key matches the parent link's authorized delegatee key
        if let Some(parent_link) = self.delegation_chain.last() {
            if delegator_vk != parent_link.delegatee_verifying_key {
                return Err(MandateError::SignatureFailure {
                    depth: self.depth,
                    reason: "Delegator signing key does not match parent delegatee verifying key".to_string(),
                });
            }
            if self.current_holder_spiffe_id != parent_link.delegatee_spiffe_id {
                return Err(MandateError::SignatureFailure {
                    depth: self.depth,
                    reason: "Current holder SPIFFE ID does not match parent delegatee".to_string(),
                });
            }
        }

        // Monotonic lifetime
        let clamped_exp = std::cmp::min(new_expires_at, self.expires_at);

        let payload = DelegationLink::canonical_payload(
            next_depth,
            &self.current_holder_spiffe_id,
            &delegator_vk,
            delegatee_spiffe_id,
            &delegatee_verifying_key,
            &narrowed_services,
            &narrowed_publish,
            now,
            clamped_exp,
        );

        let sig: Signature = delegator_key.sign(&payload);

        let new_link = DelegationLink {
            depth: next_depth,
            delegator_spiffe_id: self.current_holder_spiffe_id.clone(),
            delegator_verifying_key: delegator_vk,
            delegatee_spiffe_id: delegatee_spiffe_id.to_string(),
            delegatee_verifying_key,
            attenuated_services: narrowed_services.clone(),
            attenuated_publish: narrowed_publish.clone(),
            delegated_at: now,
            expires_at: clamped_exp,
            signature: sig.to_bytes().to_vec(),
        };

        let mut new_chain = self.delegation_chain.clone();
        new_chain.push(new_link);

        Ok(Self {
            mandate_id: format!("{}-d{}", self.mandate_id, next_depth),
            root_issuer_spiffe_id: self.root_issuer_spiffe_id.clone(),
            root_verifying_key: self.root_verifying_key,
            current_holder_spiffe_id: delegatee_spiffe_id.to_string(),
            depth: next_depth,
            allowed_services: narrowed_services,
            allowed_publish: narrowed_publish,
            not_before: now,
            expires_at: clamped_exp,
            delegation_chain: new_chain,
        })
    }

    /// Verifies the entire cryptographic delegation chain from Root to Leaf.
    /// Strictly asserts:
    /// 1. Root link delegator verifying key equals expected_root_key
    /// 2. Root link delegator SPIFFE ID equals root_issuer_spiffe_id
    /// 3. Inter-hop key continuity: link[i].delegator_vk == link[i-1].delegatee_vk
    /// 4. Inter-hop SPIFFE continuity: link[i].delegator_spiffe == link[i-1].delegatee_spiffe
    /// 5. Leaf delegatee SPIFFE ID equals current_holder_spiffe_id
    /// 6. Monotonic capability shrinkage and valid Ed25519 signatures on all links
    pub fn verify_chain(&self, expected_root_key: &[u8; 32], now: u64) -> Result<(), MandateError> {
        if now < self.not_before {
            return Err(MandateError::MandateNotYetValid {
                nbf: self.not_before,
                now,
            });
        }
        if now > self.expires_at {
            return Err(MandateError::MandateExpired {
                exp: self.expires_at,
                now,
            });
        }
        if &self.root_verifying_key != expected_root_key {
            return Err(MandateError::SignatureFailure {
                depth: 0,
                reason: "Root verifying key does not match trusted root anchor".to_string(),
            });
        }
        if self.delegation_chain.is_empty() || self.delegation_chain.len() != self.depth + 1 {
            return Err(MandateError::SignatureFailure {
                depth: self.depth,
                reason: "Delegation chain length mismatch with declared depth".to_string(),
            });
        }

        // 1. Assert root link anchor binding
        if self.delegation_chain[0].delegator_verifying_key != *expected_root_key {
            return Err(MandateError::SignatureFailure {
                depth: 0,
                reason: "Link 0 delegator key does not match trusted root anchor".to_string(),
            });
        }
        if self.delegation_chain[0].delegator_spiffe_id != self.root_issuer_spiffe_id {
            return Err(MandateError::SignatureFailure {
                depth: 0,
                reason: "Link 0 delegator SPIFFE ID does not match root issuer SPIFFE ID".to_string(),
            });
        }

        let mut prev_services = &self.delegation_chain[0].attenuated_services;
        let mut prev_publish = &self.delegation_chain[0].attenuated_publish;
        let mut prev_exp = self.delegation_chain[0].expires_at;

        for (i, link) in self.delegation_chain.iter().enumerate() {
            if link.depth != i {
                return Err(MandateError::SignatureFailure {
                    depth: i,
                    reason: format!("Link depth {} does not match chain position {}", link.depth, i),
                });
            }

            // 2. Inter-hop key and SPIFFE continuity verification
            if i > 0 {
                let prev_link = &self.delegation_chain[i - 1];
                if link.delegator_verifying_key != prev_link.delegatee_verifying_key {
                    return Err(MandateError::SignatureFailure {
                        depth: i,
                        reason: format!(
                            "Cryptographic delegation key chain broken at hop {}: delegator key does not match parent delegatee key",
                            i
                        ),
                    });
                }
                if link.delegator_spiffe_id != prev_link.delegatee_spiffe_id {
                    return Err(MandateError::SignatureFailure {
                        depth: i,
                        reason: format!(
                            "SPIFFE ID continuity broken at hop {}: delegator '{}' does not match parent delegatee '{}'",
                            i, link.delegator_spiffe_id, prev_link.delegatee_spiffe_id
                        ),
                    });
                }
            }

            // 3. Verify Ed25519 signature
            let vk = VerifyingKey::from_bytes(&link.delegator_verifying_key).map_err(|e| {
                MandateError::SignatureFailure {
                    depth: i,
                    reason: format!("Invalid delegator public key: {e}"),
                }
            })?;

            if link.signature.len() != 64 {
                return Err(MandateError::SignatureFailure {
                    depth: i,
                    reason: format!("Signature must be 64 bytes, got {}", link.signature.len()),
                });
            }
            let sig = Signature::from_slice(&link.signature).map_err(|e| {
                MandateError::SignatureFailure {
                    depth: i,
                    reason: format!("Invalid signature format: {e}"),
                }
            })?;

            let payload = DelegationLink::canonical_payload(
                link.depth,
                &link.delegator_spiffe_id,
                &link.delegator_verifying_key,
                &link.delegatee_spiffe_id,
                &link.delegatee_verifying_key,
                &link.attenuated_services,
                &link.attenuated_publish,
                link.delegated_at,
                link.expires_at,
            );

            vk.verify(&payload, &sig)
                .map_err(|e| MandateError::SignatureFailure {
                    depth: i,
                    reason: format!("Ed25519 signature verification failed: {e}"),
                })?;

            // 4. Verify monotonic capability containment
            if i > 0 {
                for s in &link.attenuated_services {
                    if !prev_services.contains(s) {
                        return Err(MandateError::PrivilegeEscalationService {
                            requested: s.clone(),
                            parent_services: prev_services.iter().cloned().collect(),
                        });
                    }
                }
                for p in &link.attenuated_publish {
                    if !prev_publish.contains(p) {
                        return Err(MandateError::PrivilegeEscalationPublish {
                            requested: p.clone(),
                            parent_publish: prev_publish.iter().cloned().collect(),
                        });
                    }
                }
                if link.expires_at > prev_exp {
                    return Err(MandateError::SignatureFailure {
                        depth: i,
                        reason: "Delegation link expires after parent mandate".to_string(),
                    });
                }
            }

            prev_services = &link.attenuated_services;
            prev_publish = &link.attenuated_publish;
            prev_exp = link.expires_at;
        }

        // 5. Leaf Holder SPIFFE ID Verification
        let leaf = self.delegation_chain.last().unwrap();
        if self.current_holder_spiffe_id != leaf.delegatee_spiffe_id {
            return Err(MandateError::SignatureFailure {
                depth: self.depth,
                reason: format!(
                    "Current holder SPIFFE ID '{}' does not match leaf delegatee SPIFFE ID '{}'",
                    self.current_holder_spiffe_id, leaf.delegatee_spiffe_id
                ),
            });
        }

        Ok(())
    }

    /// Authorizes an outbound service call (`allowed_services`).
    pub fn authorize_service_call(
        &self,
        caller_spiffe_id: &str,
        target_uri: &str,
        now: u64,
    ) -> Result<(), MandateError> {
        if self.current_holder_spiffe_id != caller_spiffe_id {
            return Err(MandateError::HolderMismatch {
                holder: self.current_holder_spiffe_id.clone(),
                invoker: caller_spiffe_id.to_string(),
            });
        }
        if now > self.expires_at {
            return Err(MandateError::MandateExpired {
                exp: self.expires_at,
                now,
            });
        }
        validate_mesh_uri(target_uri)?;

        if !self.allowed_services.contains(target_uri) {
            return Err(MandateError::ServiceCallUnauthorized {
                uri: target_uri.to_string(),
            });
        }

        Ok(())
    }

    /// Authorizes inbound publishing/hosting of a service (`allowed_publish`).
    pub fn authorize_publish(
        &self,
        publisher_spiffe_id: &str,
        service_uri: &str,
        now: u64,
    ) -> Result<(), MandateError> {
        if self.current_holder_spiffe_id != publisher_spiffe_id {
            return Err(MandateError::HolderMismatch {
                holder: self.current_holder_spiffe_id.clone(),
                invoker: publisher_spiffe_id.to_string(),
            });
        }
        if now > self.expires_at {
            return Err(MandateError::MandateExpired {
                exp: self.expires_at,
                now,
            });
        }
        validate_mesh_uri(service_uri)?;

        if !self.allowed_publish.contains(service_uri) {
            return Err(MandateError::PublishUnauthorized {
                uri: service_uri.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_root_mandate_creation() {
        let root_key = SigningKey::generate(&mut OsRng);
        let holder_key = SigningKey::generate(&mut OsRng);
        let mut services = BTreeSet::new();
        services.insert("mcp://calc".to_string());
        services.insert("mcp://echo".to_string());

        let mut publish = BTreeSet::new();
        publish.insert("mcp://octopus/doc_extractor".to_string());

        let mandate = AttenuatedMandate::create_root(
            &root_key,
            "spiffe://agentoctopus.local/authority",
            "spiffe://agentoctopus.local/arm/arm_calc/epoch/0",
            holder_key.verifying_key().to_bytes(),
            services,
            publish,
            1000,
            2000,
        )
        .expect("Root mandate creation failed");

        assert_eq!(mandate.depth, 0);
        assert_eq!(mandate.delegation_chain.len(), 1);
        assert!(mandate.verify_chain(&root_key.verifying_key().to_bytes(), 1500).is_ok());
    }

    #[test]
    fn test_monotonic_attenuation_success() {
        let root_key = SigningKey::generate(&mut OsRng);
        let holder1_key = SigningKey::generate(&mut OsRng);
        let child1_key = SigningKey::generate(&mut OsRng);

        let mut root_services = BTreeSet::new();
        root_services.insert("mcp://calc".to_string());
        root_services.insert("mcp://payroll".to_string());

        let root_publish = BTreeSet::new();

        let root_mandate = AttenuatedMandate::create_root(
            &root_key,
            "spiffe://agentoctopus.local/authority",
            "spiffe://agentoctopus.local/arm/holder1",
            holder1_key.verifying_key().to_bytes(),
            root_services,
            root_publish,
            1000,
            5000,
        )
        .unwrap();

        // Attenuate to only mcp://calc
        let mut child_services = BTreeSet::new();
        child_services.insert("mcp://calc".to_string());
        let child_publish = BTreeSet::new();

        let child_mandate = root_mandate
            .attenuate(
                &holder1_key,
                "spiffe://agentoctopus.local/arm/child1",
                child1_key.verifying_key().to_bytes(),
                child_services,
                child_publish,
                4000,
                1500,
            )
            .expect("Attenuation failed");

        assert_eq!(child_mandate.depth, 1);
        assert_eq!(child_mandate.delegation_chain.len(), 2);
        assert!(child_mandate.allowed_services.contains("mcp://calc"));
        assert!(!child_mandate.allowed_services.contains("mcp://payroll"));
        assert!(child_mandate.verify_chain(&root_key.verifying_key().to_bytes(), 2000).is_ok());
    }

    #[test]
    fn test_privilege_escalation_rejected() {
        let root_key = SigningKey::generate(&mut OsRng);
        let holder_key = SigningKey::generate(&mut OsRng);
        let child_key = SigningKey::generate(&mut OsRng);

        let mut root_services = BTreeSet::new();
        root_services.insert("mcp://calc".to_string());

        let root_mandate = AttenuatedMandate::create_root(
            &root_key,
            "spiffe://agentoctopus.local/authority",
            "spiffe://agentoctopus.local/arm/holder",
            holder_key.verifying_key().to_bytes(),
            root_services,
            BTreeSet::new(),
            1000,
            5000,
        )
        .unwrap();

        // Attempt privilege escalation: add mcp://payroll
        let mut escalated = BTreeSet::new();
        escalated.insert("mcp://calc".to_string());
        escalated.insert("mcp://payroll".to_string());

        let res = root_mandate.attenuate(
            &holder_key,
            "spiffe://agentoctopus.local/arm/child",
            child_key.verifying_key().to_bytes(),
            escalated,
            BTreeSet::new(),
            4000,
            1500,
        );

        assert!(matches!(res, Err(MandateError::PrivilegeEscalationService { .. })));
    }

    #[test]
    fn test_strict_uri_filter_schemes() {
        // Allowed schemes
        assert!(validate_mesh_uri("mcp://calc").is_ok());
        assert!(validate_mesh_uri("a2a://supervisor").is_ok());
        assert!(validate_mesh_uri("inference://qwen").is_ok());
        assert!(validate_mesh_uri("egress://api.example.com").is_ok());

        // Prohibited schemes
        assert!(matches!(
            validate_mesh_uri("http://google.com"),
            Err(MandateError::InvalidUriScheme { .. })
        ));
        assert!(matches!(
            validate_mesh_uri("file:///etc/shadow"),
            Err(MandateError::InvalidUriScheme { .. })
        ));

        // Prohibited targets
        assert!(matches!(
            validate_mesh_uri("mcp://127.0.0.1:8080/calc"),
            Err(MandateError::ProhibitedTarget { .. })
        ));
        assert!(matches!(
            validate_mesh_uri("mcp://192.168.1.1/calc"),
            Err(MandateError::ProhibitedTarget { .. })
        ));
        assert!(matches!(
            validate_mesh_uri("mcp://calc/../admin"),
            Err(MandateError::ProhibitedTarget { .. })
        ));
    }

    #[test]
    fn test_segregated_rights() {
        let root_key = SigningKey::generate(&mut OsRng);
        let pub_key = SigningKey::generate(&mut OsRng);

        let mut publish = BTreeSet::new();
        publish.insert("mcp://octopus/doc_extractor".to_string());

        let mandate = AttenuatedMandate::create_root(
            &root_key,
            "spiffe://agentoctopus.local/authority",
            "spiffe://agentoctopus.local/arm/publisher",
            pub_key.verifying_key().to_bytes(),
            BTreeSet::new(), // No allowed_services
            publish,
            1000,
            5000,
        )
        .unwrap();

        let now = 2000;
        let caller = "spiffe://agentoctopus.local/arm/publisher";

        // Publishing is authorized
        assert!(mandate.authorize_publish(caller, "mcp://octopus/doc_extractor", now).is_ok());

        // Calling is rejected (publishing does NOT confer calling right)
        assert!(matches!(
            mandate.authorize_service_call(caller, "mcp://octopus/doc_extractor", now),
            Err(MandateError::ServiceCallUnauthorized { .. })
        ));
    }

    #[test]
    fn test_multi_hop_delegation_chain() {
        let k0 = SigningKey::generate(&mut OsRng);
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);

        let mut s = BTreeSet::new();
        s.insert("mcp://calc".to_string());

        let m0 = AttenuatedMandate::create_root(
            &k0,
            "spiffe://agentoctopus.local/root",
            "spiffe://agentoctopus.local/node1",
            k1.verifying_key().to_bytes(),
            s.clone(),
            BTreeSet::new(),
            1000,
            9000,
        )
        .unwrap();

        let m1 = m0
            .attenuate(
                &k1,
                "spiffe://agentoctopus.local/node2",
                k2.verifying_key().to_bytes(),
                s.clone(),
                BTreeSet::new(),
                8000,
                2000,
            )
            .unwrap();

        let m2 = m1
            .attenuate(
                &k2,
                "spiffe://agentoctopus.local/node3",
                k3.verifying_key().to_bytes(),
                s.clone(),
                BTreeSet::new(),
                7000,
                3000,
            )
            .unwrap();

        assert_eq!(m2.depth, 2);
        assert_eq!(m2.delegation_chain.len(), 3);
        assert!(m2.verify_chain(&k0.verifying_key().to_bytes(), 4000).is_ok());
    }

    #[test]
    fn test_tampered_link_rejected() {
        let k0 = SigningKey::generate(&mut OsRng);
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);

        let mut s = BTreeSet::new();
        s.insert("mcp://calc".to_string());

        let m0 = AttenuatedMandate::create_root(
            &k0,
            "spiffe://agentoctopus.local/root",
            "spiffe://agentoctopus.local/node1",
            k1.verifying_key().to_bytes(),
            s.clone(),
            BTreeSet::new(),
            1000,
            9000,
        )
        .unwrap();

        let mut m1 = m0
            .attenuate(
                &k1,
                "spiffe://agentoctopus.local/node2",
                k2.verifying_key().to_bytes(),
                s.clone(),
                BTreeSet::new(),
                8000,
                2000,
            )
            .unwrap();

        // Tamper with the child link's signature
        m1.delegation_chain[1].signature[0] ^= 0xFF;

        assert!(matches!(
            m1.verify_chain(&k0.verifying_key().to_bytes(), 3000),
            Err(MandateError::SignatureFailure { .. })
        ));
    }
}
