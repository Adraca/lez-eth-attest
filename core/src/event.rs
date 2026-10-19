// Copyright (c) 2026 Abhishek Khaparde
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LP-0012 structured event definitions.
//!
//! Conforms to canonical LEZ v0.3 event architecture:
//! - Selector: first 8 bytes of sha256("<namespace>::<EventName>")
//! - Citation: lez/programs/bridge/core/src/event.rs and lee_core::program::ProgramEvent

extern crate alloc;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

/// LP-0012 event emitted when an Ethereum state/event attestation is recorded.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestationRecorded {
    pub instance_id: [u8; 32],
    pub slot: u64,
    pub chain_id: u64,
}

impl AttestationRecorded {
    pub const SELECTOR_NAME: &'static str = "attest::AttestationRecorded";
    pub const SELECTOR: [u8; 8] = [0x8a, 0x66, 0xac, 0xe6, 0xd3, 0x99, 0xd5, 0xab];

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("AttestationRecorded serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

/// LP-0012 event emitted when a finalized Ethereum header record is accepted.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HeaderRecordAccepted {
    pub instance_id: [u8; 32],
    pub slot: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
}

impl HeaderRecordAccepted {
    pub const SELECTOR_NAME: &'static str = "attest::HeaderRecordAccepted";
    pub const SELECTOR: [u8; 8] = [0x80, 0x07, 0x9f, 0xcc, 0x7a, 0x6e, 0x43, 0x70];

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("HeaderRecordAccepted serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

/// LP-0012 event emitted during sync committee transition / handoff.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommitteeHandoff {
    pub instance_id: [u8; 32],
    pub period: u64,
    pub next_sync_committee_root: [u8; 32],
}

impl CommitteeHandoff {
    pub const SELECTOR_NAME: &'static str = "attest::CommitteeHandoff";
    pub const SELECTOR: [u8; 8] = [0x54, 0x6e, 0x8c, 0xf0, 0x44, 0xd1, 0x98, 0x4e];

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("CommitteeHandoff serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn selectors_match_canonical_sha256() {
        assert_eq!(
            AttestationRecorded::SELECTOR,
            Sha256::digest(AttestationRecorded::SELECTOR_NAME.as_bytes())[..8]
        );
        assert_eq!(
            HeaderRecordAccepted::SELECTOR,
            Sha256::digest(HeaderRecordAccepted::SELECTOR_NAME.as_bytes())[..8]
        );
        assert_eq!(
            CommitteeHandoff::SELECTOR,
            Sha256::digest(CommitteeHandoff::SELECTOR_NAME.as_bytes())[..8]
        );
    }
}
