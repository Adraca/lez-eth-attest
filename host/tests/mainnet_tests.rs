//! Tests on real Ethereum Mainnet block data.

use attest_core::error::AttestError;
use attest_core::predicate::{Cmp, Field, Predicate};
use attest_core::statement::{evaluate, Proof, Query};
use attest_host::vectors::{load_header_record, load_receipt_proof, load_storage_proof};

const MAINNET_CHAIN_ID: u64 = 1;
const BLOCK_JSON: &str = include_str!("../../vectors/mainnet/block.json");
const GETPROOF_JSON: &str = include_str!("../../vectors/mainnet/getproof.json");
const RECEIPT_PROOF_JSON: &str = include_str!("../../vectors/mainnet/receipt-proof.json");

#[test]
fn test_mainnet_permit2_storage_verification() {
    let record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    let proof = load_storage_proof(GETPROOF_JSON);
    let query = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::SlotValue, Cmp::Eq, [0u8; 32])],
    };
    let stmt = evaluate(&record, &query).expect("mainnet permit2 storage proof verifies");
    assert_eq!(stmt.chain_id, MAINNET_CHAIN_ID);
    assert_eq!(stmt.block_number, 26207220);
}

#[test]
fn test_mainnet_receipt_log_verification() {
    let record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    let proof = load_receipt_proof(RECEIPT_PROOF_JSON);
    let query = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Log(proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::LogTopic(0), Cmp::Ne, [0u8; 32])],
    };
    let stmt = evaluate(&record, &query).expect("mainnet receipt proof verifies");
    assert_eq!(stmt.chain_id, MAINNET_CHAIN_ID);
}

#[test]
fn test_tampered_state_and_receipt_roots_rejected() {
    let mut record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    record.state_root[0] ^= 0xff;
    let query = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(load_storage_proof(GETPROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    assert_eq!(evaluate(&record, &query), Err(AttestError::ProofVerificationFailed));

    let mut record2 = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    record2.receipts_root[0] ^= 0xff;
    let query2 = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Log(load_receipt_proof(RECEIPT_PROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    assert_eq!(evaluate(&record2, &query2), Err(AttestError::ProofVerificationFailed));
}

#[test]
fn test_proof_for_different_slot_rejected() {
    let record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    let proof = load_storage_proof(GETPROOF_JSON);
    let wrong_slot = [0x99; 32];
    let query = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(proof),
        target_slot: Some(wrong_slot),
        predicates: vec![],
    };
    assert_eq!(evaluate(&record, &query), Err(AttestError::SlotMismatch));
}

#[test]
fn test_identical_state_yields_identical_id() {
    let record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    let q1 = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(load_storage_proof(GETPROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    let q2 = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(load_storage_proof(GETPROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    let s1 = evaluate(&record, &q1).unwrap();
    let s2 = evaluate(&record, &q2).unwrap();
    assert_eq!(s1.statement_id, s2.statement_id);
}

#[test]
fn test_distinct_nonce_yields_distinct_statement_id() {
    let record = load_header_record(MAINNET_CHAIN_ID, BLOCK_JSON);
    let q1 = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Storage(load_storage_proof(GETPROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    let s1 = evaluate(&record, &q1).unwrap();
    // Receipt proof produces a distinct statement id from storage proof
    let q_log = Query {
        chain_id: MAINNET_CHAIN_ID,
        proof: Proof::Log(load_receipt_proof(RECEIPT_PROOF_JSON)),
        target_slot: None,
        predicates: vec![],
    };
    let s_log = evaluate(&record, &q_log).unwrap();
    assert_ne!(s1.statement_id, s_log.statement_id, "Distinct state proofs must yield distinct statement IDs per F#6");
}


