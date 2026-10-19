//! Core types representing headers, chain configurations, and roots.

use borsh::{BorshDeserialize, BorshSerialize};

pub type Hash256 = [u8; 32];
pub type Address20 = [u8; 20];

/// Finalized header record stored by the consensus tracking component.
/// In this prototype, this is supplied as a trusted input (light-client stub).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HeaderRecord {
    pub chain_id: u64,
    pub slot: u64,
    pub beacon_root: Hash256,
    pub block_number: u64,
    pub block_hash: Hash256,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
}

/// Execution header fields checked for binding consistency against HeaderRecord.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionHeaderBinding {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: Hash256,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
}

impl ExecutionHeaderBinding {
    /// Verifies that this execution header matches the trusted finalized record.
    pub fn verify_bound(&self, record: &HeaderRecord) -> Result<(), crate::error::AttestError> {
        if self.chain_id != record.chain_id {
            return Err(crate::error::AttestError::ChainIdMismatch);
        }
        if self.block_number != record.block_number
            || self.block_hash != record.block_hash
            || self.state_root != record.state_root
            || self.receipts_root != record.receipts_root
        {
            return Err(crate::error::AttestError::HeaderMismatch);
        }
        Ok(())
    }
}
