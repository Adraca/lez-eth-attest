//! attest-core: Verification core crate (no_std, shared by program + host)
//!
//! Provides MPT inclusion proofs via audited alloy-trie/alloy-rlp crates,
//! predicate evaluation, chain binding, and deterministic statement ID generation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod event;
pub mod mpt;
pub mod predicate;
pub mod statement;
pub mod types;

pub use error::AttestError;
pub use event::{AttestationRecorded, CommitteeHandoff, HeaderRecordAccepted};
pub use mpt::{
    be32, keccak256, verify_account_storage, verify_receipt_log, verify_trie_proof,
    AccountSlotState, AccountStorageProof, ReceiptLog, ReceiptProof, EMPTY_ROOT,
};
pub use predicate::{Cmp, Field, Predicate};
pub use statement::{evaluate, Proof, Query, Statement};
pub use types::{Address20, ExecutionHeaderBinding, Hash256, HeaderRecord};
