//! Reference consumer: Native ETH balance verifier with nullifiers (U#6).

extern crate alloc;
use alloc::collections::BTreeSet;
use attest_core::{
    error::AttestError,
    predicate::{Cmp, Field, Predicate},
    statement::{evaluate, Proof, Query},
    types::{Address20, Hash256, HeaderRecord},
};

pub struct EthBalanceConsumer {
    pub expected_chain_id: u64,
    pub target_account: Address20,
    pub nullifiers: BTreeSet<Hash256>,
}

impl EthBalanceConsumer {
    pub fn new(expected_chain_id: u64, target_account: Address20) -> Self {
        Self {
            expected_chain_id,
            target_account,
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn consume_balance(
        &mut self,
        record: &HeaderRecord,
        proof: attest_core::mpt::AccountStorageProof,
        required_balance: Hash256,
    ) -> Result<Hash256, AttestError> {
        if proof.address != self.target_account {
            return Err(AttestError::SlotMismatch);
        }

        let query = Query {
            chain_id: self.expected_chain_id,
            proof: Proof::Storage(proof),
            target_slot: None,
            predicates: vec![
                Predicate::new(Field::AccountBalance, Cmp::Ge, required_balance),
            ],
        };

        let statement = evaluate(record, &query)?;

        // Enforce uniqueness with statement-derived nullifier
        if !self.nullifiers.insert(statement.statement_id) {
            return Err(AttestError::PredicateUnsatisfied); // Double-spend attempt
        }

        Ok(statement.statement_id)
    }
}
