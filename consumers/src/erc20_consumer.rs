//! Reference consumer: ERC-20 Transfer log receipt verifier with nullifiers (U#6).

extern crate alloc;
use alloc::collections::BTreeSet;
use attest_core::{
    error::AttestError,
    predicate::{Cmp, Field, Predicate},
    statement::{evaluate, Proof, Query},
    types::{Address20, Hash256, HeaderRecord},
};

pub const ERC20_TRANSFER_TOPIC: Hash256 = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

pub struct Erc20TransferConsumer {
    pub expected_chain_id: u64,
    pub token_contract: Address20,
    pub nullifiers: BTreeSet<Hash256>,
}

impl Erc20TransferConsumer {
    pub fn new(expected_chain_id: u64, token_contract: Address20) -> Self {
        Self {
            expected_chain_id,
            token_contract,
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn consume_transfer(
        &mut self,
        record: &HeaderRecord,
        proof: attest_core::mpt::ReceiptProof,
        min_amount: Hash256,
    ) -> Result<Hash256, AttestError> {
        let mut token_word = [0u8; 32];
        token_word[12..].copy_from_slice(&self.token_contract);

        let query = Query {
            chain_id: self.expected_chain_id,
            proof: Proof::Log(proof),
            target_slot: None,
            predicates: vec![
                Predicate::new(Field::LogAddress, Cmp::Eq, token_word),
                Predicate::new(Field::LogTopic(0), Cmp::Eq, ERC20_TRANSFER_TOPIC),
                Predicate::new(Field::LogDataWord(0), Cmp::Ge, min_amount),
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
