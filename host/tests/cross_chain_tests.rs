//! Cross-chain binding and Sepolia test vectors.

use attest_core::error::AttestError;
use attest_core::predicate::{Cmp, Field, Predicate};
use attest_core::statement::{evaluate, Proof, Query};
use attest_host::vectors::{load_header_record, load_receipt_proof, load_storage_proof};

const SEPOLIA_CHAIN_ID: u64 = 11155111;
const MAINNET_CHAIN_ID: u64 = 1;

const SEPOLIA_BLOCK_JSON: &str = include_str!("../../vectors/sepolia/block.json");
const SEPOLIA_GETPROOF_JSON: &str = include_str!("../../vectors/sepolia/getproof.json");
const SEPOLIA_RECEIPT_JSON: &str = include_str!("../../vectors/sepolia/receipt-proof.json");

const MAINNET_BLOCK_JSON: &str = include_str!("../../vectors/mainnet/block.json");

#[test]
fn test_sepolia_permit2_storage_and_balance_verification() {
    let record = load_header_record(SEPOLIA_CHAIN_ID, SEPOLIA_BLOCK_JSON);
    let proof = load_storage_proof(SEPOLIA_GETPROOF_JSON);
    let query = Query {
        chain_id: SEPOLIA_CHAIN_ID,
        proof: Proof::Storage(proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::AccountBalance, Cmp::Eq, [0u8; 32])],
    };
    let stmt = evaluate(&record, &query).expect("sepolia permit2 proof verifies");
    assert_eq!(stmt.chain_id, SEPOLIA_CHAIN_ID);
}

#[test]
fn test_sepolia_receipt_proof_verification() {
    let record = load_header_record(SEPOLIA_CHAIN_ID, SEPOLIA_BLOCK_JSON);
    let proof = load_receipt_proof(SEPOLIA_RECEIPT_JSON);
    let query = Query {
        chain_id: SEPOLIA_CHAIN_ID,
        proof: Proof::Log(proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::LogTopic(0), Cmp::Ne, [0u8; 32])],
    };
    let stmt = evaluate(&record, &query).expect("sepolia receipt proof verifies");
    assert_eq!(stmt.chain_id, SEPOLIA_CHAIN_ID);
}

#[test]
fn test_same_contract_cross_chain_rejected() {
    let sepolia_record = load_header_record(SEPOLIA_CHAIN_ID, SEPOLIA_BLOCK_JSON);
    let sepolia_proof = load_storage_proof(SEPOLIA_GETPROOF_JSON);

    // Case 1: Query expects Mainnet chain ID, but record is for Sepolia
    let query_mainnet = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(sepolia_proof.clone()),
        target_slot: None,
        predicates: vec![],
    };
    assert_eq!(evaluate(&sepolia_record, &query_mainnet), Err(AttestError::ChainIdMismatch));

    // Case 2: Query expects Sepolia chain ID, but record is for Mainnet
    let mainnet_record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let query_sepolia = Query {
        chain_id: SEPOLIA_CHAIN_ID,
        proof: Proof::Storage(sepolia_proof),
        target_slot: None,
        predicates: vec![],
    };
    assert_eq!(evaluate(&mainnet_record, &query_sepolia), Err(AttestError::ChainIdMismatch));
}

#[test]
fn test_replayed_proof_under_wrong_root_rejected() {
    let mut spoofed_mainnet_record = load_header_record(SEPOLIA_CHAIN_ID, MAINNET_BLOCK_JSON);
    spoofed_mainnet_record.chain_id = SEPOLIA_CHAIN_ID;
    let sepolia_proof = load_storage_proof(SEPOLIA_GETPROOF_JSON);
    let query = Query {
        chain_id: SEPOLIA_CHAIN_ID,
        proof: Proof::Storage(sepolia_proof),
        target_slot: None,
        predicates: vec![],
    };
    assert_eq!(evaluate(&spoofed_mainnet_record, &query), Err(AttestError::ProofVerificationFailed));
}
