//! Statement generation, chain binding, and query evaluation.

extern crate alloc;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use crate::error::AttestError;
use crate::mpt::{verify_account_storage, verify_receipt_log, AccountStorageProof, ReceiptProof};
use crate::predicate::{Field, Predicate};
use crate::types::{Hash256, HeaderRecord};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Proof {
    Storage(AccountStorageProof),
    Log(ReceiptProof),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Query {
    pub chain_id: u64,
    pub proof: Proof,
    pub target_slot: Option<Hash256>,
    pub predicates: Vec<Predicate>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Statement {
    pub statement_id: Hash256,
    pub chain_id: u64,
    pub block_hash: Hash256,
    pub block_number: u64,
}

fn word32(b: &[u8]) -> Hash256 {
    let mut w = [0u8; 32];
    let n = b.len().min(32);
    w[32 - n..].copy_from_slice(&b[b.len() - n..]);
    w
}

pub fn evaluate(record: &HeaderRecord, query: &Query) -> Result<Statement, AttestError> {
    if query.chain_id != record.chain_id {
        return Err(AttestError::ChainIdMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"attest/statement/v1");
    hasher.update(record.chain_id.to_be_bytes());
    hasher.update(record.block_hash);
    hasher.update(record.block_number.to_be_bytes());

    match &query.proof {
        Proof::Storage(p) => {
            if let Some(target) = query.target_slot {
                if target != p.slot {
                    return Err(AttestError::SlotMismatch);
                }
            }
            let acct = verify_account_storage(&record.state_root, p)?;
            for pred in &query.predicates {
                let val = match pred.field {
                    Field::AccountBalance => acct.balance,
                    Field::AccountNonce => acct.nonce,
                    Field::SlotValue => acct.slot_value,
                    _ => return Err(AttestError::MalformedInput),
                };
                pred.eval(&val)?;
            }
            hasher.update([0u8]); // proof kind: 0 = storage/account
            hasher.update(p.address);
            hasher.update(p.slot);
            hasher.update(acct.slot_value);
            hasher.update(acct.balance);
            hasher.update(acct.nonce);
        }
        Proof::Log(p) => {
            let log = verify_receipt_log(&record.receipts_root, p)?;
            if log.status != 1 {
                return Err(AttestError::TxExecutionReverted);
            }
            for pred in &query.predicates {
                let val = match pred.field {
                    Field::LogAddress => word32(&log.address),
                    Field::LogTopic(i) => *log.topics.get(i as usize).ok_or(AttestError::MalformedInput)?,
                    Field::LogDataWord(i) => {
                        let offset = 32 * i as usize;
                        let slice = log.data.get(offset..offset + 32).ok_or(AttestError::MalformedInput)?;
                        word32(slice)
                    }
                    _ => return Err(AttestError::MalformedInput),
                };
                pred.eval(&val)?;
            }
            hasher.update([1u8]); // proof kind: 1 = log
            hasher.update(p.tx_index.to_be_bytes());
            hasher.update(p.log_index.to_be_bytes());
            hasher.update(log.address);
            for t in &log.topics {
                hasher.update(t);
            }
            hasher.update(&log.data);
        }
    }

    let statement_id: Hash256 = hasher.finalize().into();
    Ok(Statement {
        statement_id,
        chain_id: record.chain_id,
        block_hash: record.block_hash,
        block_number: record.block_number,
    })
}
