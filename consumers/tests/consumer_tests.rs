//! Integration tests for reference consumers demonstrating nullifiers and replay protection.

use attest_consumers::erc20_consumer::Erc20TransferConsumer;
use attest_consumers::eth_balance_consumer::EthBalanceConsumer;
use attest_core::error::AttestError;
use attest_host::vectors::{hex_to_20, load_header_record, load_receipt_proof, load_storage_proof};

const MAINNET_CHAIN_ID: u64 = 1;
const SEPOLIA_CHAIN_ID: u64 = 11155111;

const MAINNET_BLOCK_JSON: &str = include_str!("../../vectors/mainnet/block.json");
const MAINNET_RECEIPT_JSON: &str = include_str!("../../vectors/mainnet/receipt-proof.json");

const SEPOLIA_BLOCK_JSON: &str = include_str!("../../vectors/sepolia/block.json");
const SEPOLIA_GETPROOF_JSON: &str = include_str!("../../vectors/sepolia/getproof.json");

#[test]
fn test_erc20_consumer_transfer_and_nullifier() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let proof = load_receipt_proof(MAINNET_RECEIPT_JSON);

    // USDC contract address on Mainnet
    let usdc_addr = hex_to_20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    let mut consumer = Erc20TransferConsumer::new(MAINNET_CHAIN_ID, usdc_addr);

    // First consumption: should succeed and record nullifier
    let nullifier = consumer
        .consume_transfer(&record, proof.clone(), [0u8; 32])
        .expect("first transfer consumption succeeds");
    assert!(consumer.nullifiers.contains(&nullifier));

    // Second consumption with exact same proof: must be rejected by nullifier!
    let err = consumer
        .consume_transfer(&record, proof, [0u8; 32])
        .expect_err("second consumption must fail");
    assert_eq!(err, AttestError::PredicateUnsatisfied);
}

#[test]
fn test_erc20_consumer_rejects_wrong_token() {
    let record = load_header_record(MAINNET_CHAIN_ID, MAINNET_BLOCK_JSON);
    let proof = load_receipt_proof(MAINNET_RECEIPT_JSON);

    let wrong_token = hex_to_20("0x1111111111111111111111111111111111111111");
    let mut consumer = Erc20TransferConsumer::new(MAINNET_CHAIN_ID, wrong_token);

    let err = consumer
        .consume_transfer(&record, proof, [0u8; 32])
        .expect_err("wrong token must fail predicate");
    assert_eq!(err, AttestError::PredicateUnsatisfied);
}

#[test]
fn test_eth_balance_consumer_and_nullifier() {
    let record = load_header_record(SEPOLIA_CHAIN_ID, SEPOLIA_BLOCK_JSON);
    let proof = load_storage_proof(SEPOLIA_GETPROOF_JSON);

    let permit2_addr = hex_to_20("0x000000000022d473030f116ddee9f6b43ac78ba3");
    let mut consumer = EthBalanceConsumer::new(SEPOLIA_CHAIN_ID, permit2_addr);

    let min_balance = [0u8; 32];

    // First consumption: should succeed and record nullifier
    let nullifier = consumer
        .consume_balance(&record, proof.clone(), min_balance)
        .expect("first balance consumption succeeds");
    assert!(consumer.nullifiers.contains(&nullifier));

    // Second consumption: duplicate nullifier rejected!
    let err = consumer
        .consume_balance(&record, proof, min_balance)
        .expect_err("replayed balance consumption must fail");
    assert_eq!(err, AttestError::PredicateUnsatisfied);
}

#[test]
fn test_eth_balance_consumer_rejects_wrong_account() {
    let record = load_header_record(SEPOLIA_CHAIN_ID, SEPOLIA_BLOCK_JSON);
    let proof = load_storage_proof(SEPOLIA_GETPROOF_JSON);

    let wrong_addr = hex_to_20("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let mut consumer = EthBalanceConsumer::new(SEPOLIA_CHAIN_ID, wrong_addr);

    let err = consumer
        .consume_balance(&record, proof, [0u8; 32])
        .expect_err("wrong account address must be rejected");
    assert_eq!(err, AttestError::SlotMismatch);
}
