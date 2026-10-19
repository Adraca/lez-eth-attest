//! Attest Protocol Error Scheme.
//!
//! Structured 4-digit error codes categorized by subsystem:
//! - 31xx: Input Validation & Encoding
//! - 32xx: Consensus Anchor & Chain Binding
//! - 33xx: Merkle-Patricia Trie & Inclusion Verification
//! - 34xx: Predicate & State Assertion
//! - 35xx: LEZ Program State Machine & Lifecycle

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = false)]
#[repr(u32)]
pub enum AttestError {
    /// 3101: Input data or field size is malformed.
    MalformedInput = 3101,

    /// 3201: Consensus anchor indicates header is not finalized.
    HeaderNotFinalized = 3201,
    /// 3202: Chain ID does not match expected target network.
    ChainIdMismatch = 3202,
    /// 3203: Execution header does not bind to trusted header record.
    HeaderMismatch = 3203,

    /// 3301: Cryptographic trie proof failed verification against root.
    ProofVerificationFailed = 3301,
    /// 3302: Proof target key/slot does not match query assertion.
    SlotMismatch = 3302,

    /// 3401: Declared predicate does not hold on verified state.
    PredicateUnsatisfied = 3401,
    /// 3402: Transaction receipt indicates execution reverted.
    TxExecutionReverted = 3402,

    /// 3501: Provided account metadata count does not match instruction.
    AccountCountMismatch = 3501,
    /// 3502: Instance or header account already initialized.
    InstanceAlreadyInitialized = 3502,
    /// 3503: Required header record account not found or uninitialized.
    HeaderRecordNotFound = 3503,
}

impl AttestError {
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedInput => "3101: malformed input data or payload",
            Self::HeaderNotFinalized => "3201: block header not marked finalized by consensus anchor",
            Self::ChainIdMismatch => "3202: chain ID mismatch: cross-chain replay rejected",
            Self::HeaderMismatch => "3203: execution header root does not match bound beacon record",
            Self::ProofVerificationFailed => "3301: MPT inclusion proof verification failed against root",
            Self::SlotMismatch => "3302: proof target does not match query key",
            Self::PredicateUnsatisfied => "3401: asserted predicate evaluated to false",
            Self::TxExecutionReverted => "3402: transaction status indicates execution reverted",
            Self::AccountCountMismatch => "3501: wrong number of account metas for instruction",
            Self::InstanceAlreadyInitialized => "3502: instance already initialized",
            Self::HeaderRecordNotFound => "3503: header record account empty or not found",
        }
    }
}

impl core::fmt::Display for AttestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
