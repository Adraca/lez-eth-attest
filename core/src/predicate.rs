//! Predicate expressions and evaluation over attested state.

use borsh::{BorshDeserialize, BorshSerialize};
use crate::error::AttestError;
use crate::types::Hash256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Field {
    AccountBalance,
    AccountNonce,
    SlotValue,
    LogAddress,
    LogTopic(u8),
    LogDataWord(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Predicate {
    pub field: Field,
    pub cmp: Cmp,
    pub expected: Hash256,
}

impl Predicate {
    pub fn new(field: Field, cmp: Cmp, expected: Hash256) -> Self {
        Self { field, cmp, expected }
    }

    pub fn eq(field: Field, expected: Hash256) -> Self {
        Self::new(field, Cmp::Eq, expected)
    }

    pub fn ne(field: Field, expected: Hash256) -> Self {
        Self::new(field, Cmp::Ne, expected)
    }

    pub fn eval(&self, actual: &Hash256) -> Result<(), AttestError> {
        let satisfied = match self.cmp {
            Cmp::Eq => actual == &self.expected,
            Cmp::Ne => actual != &self.expected,
            Cmp::Lt => actual < &self.expected,
            Cmp::Le => actual <= &self.expected,
            Cmp::Gt => actual > &self.expected,
            Cmp::Ge => actual >= &self.expected,
        };
        if satisfied {
            Ok(())
        } else {
            Err(AttestError::PredicateUnsatisfied)
        }
    }
}
