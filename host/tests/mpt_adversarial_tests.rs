// Copyright (c) 2026 Abhishek Khaparde
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial MPT verification test suite (audit major #5).
//!
//! Validates verify_trie_proof against crafted proofs:
//! 1. Wrong trie root
//! 2. Truncated proof nodes
//! 3. Extra unreferenced / injected nodes
//! 4. Tampered leaf node payload
//! 5. Exclusion proof presented as an inclusion proof

use alloy_primitives::B256;
use attest_core::{
    error::AttestError,
    mpt::{keccak256, verify_account_storage, verify_trie_proof, AccountStorageProof},
};
use attest_host::vectors::{hex_to_20, load_header_record, load_storage_proof};
use nybbles::Nibbles;

const MAINNET_CHAIN_ID: u64 = 1;
const MAINNET_BLOCK_JSON: &str = include_str!("../../vectors/mainnet/block.json");
const MAINNET_GETPROOF_JSON: &str = include_str!("../../vectors/mainnet/getproof.json");

#[test]
fn test_mpt_wrong_root_rejected() {
    let _record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let p = load_storage_proof(MAINNET_GETPROOF_JSON);
    let acct_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.address)));

    let wrong_root = [0xffu8; 32];
    let err = verify_trie_proof(&wrong_root, &acct_key, &p.account_proof)
        .expect_err("wrong root must fail");
    assert_eq!(err, AttestError::ProofVerificationFailed);
}

#[test]
fn test_mpt_truncated_proof_rejected() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let p = load_storage_proof(MAINNET_GETPROOF_JSON);
    let acct_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.address)));

    // Drop the leaf node
    let truncated = p.account_proof[..p.account_proof.len() - 1].to_vec();
    let err = verify_trie_proof(&record.state_root, &acct_key, &truncated)
        .expect_err("truncated proof must fail");
    assert_eq!(err, AttestError::ProofVerificationFailed);
}

#[test]
fn test_mpt_extra_node_rejected() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let p = load_storage_proof(MAINNET_GETPROOF_JSON);
    let acct_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.address)));

    // Inject an extra unreferenced node into proof
    let mut extra = p.account_proof.clone();
    extra.push(vec![0xf8, 0x40, 0x80, 0x80, 0x80]);
    let err = verify_trie_proof(&record.state_root, &acct_key, &extra)
        .expect_err("extra unreferenced node must fail");
    assert_eq!(err, AttestError::ProofVerificationFailed);
}

#[test]
fn test_mpt_tampered_leaf_value_rejected() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let p = load_storage_proof(MAINNET_GETPROOF_JSON);
    let acct_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.address)));

    // Tamper with the leaf node
    let mut tampered = p.account_proof.clone();
    let leaf = tampered.last_mut().expect("has leaf");
    let len = leaf.len();
    leaf[len - 4] ^= 0x5a;

    let err = verify_trie_proof(&record.state_root, &acct_key, &tampered)
        .expect_err("tampered leaf value must fail");
    assert_eq!(err, AttestError::ProofVerificationFailed);
}

#[test]
fn test_mpt_exclusion_proof_as_inclusion_rejected() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let p = load_storage_proof(MAINNET_GETPROOF_JSON);

    // Present proof under an address that does not exist in the trie
    let ghost_address = hex_to_20("0x000000000000000000000000000000000000dead");
    let ghost_proof = AccountStorageProof {
        address: ghost_address,
        account_proof: p.account_proof,
        slot: p.slot,
        storage_proof: p.storage_proof,
    };

    let err = verify_account_storage(&record.state_root, &ghost_proof)
        .expect_err("exclusion proof presented as inclusion must be rejected");
    assert_eq!(err, AttestError::ProofVerificationFailed);
}
