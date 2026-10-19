//! Utilities for loading real Mainnet and Sepolia test vectors.

use attest_core::mpt::{AccountStorageProof, ReceiptProof};
use attest_core::types::{Address20, Hash256, HeaderRecord};
use serde_json::Value;

pub fn hex_to_32(s: &str) -> Hash256 {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let padded = if raw.len() < 64 {
        format!("{:0>64}", raw)
    } else {
        raw.to_string()
    };
    let bytes = hex::decode(&padded).expect("valid hex for Hash256");
    assert_eq!(bytes.len(), 32, "Hash256 must be 32 bytes");
    bytes.try_into().unwrap()
}

pub fn hex_to_20(s: &str) -> Address20 {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).expect("valid hex for Address20");
    assert_eq!(bytes.len(), 20, "Address20 must be 20 bytes");
    bytes.try_into().unwrap()
}

pub fn hex_to_vec(s: &str) -> Vec<u8> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(raw).expect("valid hex bytes")
}

pub fn load_header_record(chain_id: u64, block_json: &str) -> HeaderRecord {
    let v: Value = serde_json::from_str(block_json).expect("valid block json");
    let res = &v["result"];
    let num_str = res["number"].as_str().expect("number hex");
    let block_number = u64::from_str_radix(num_str.strip_prefix("0x").unwrap_or(num_str), 16).unwrap();
    HeaderRecord {
        chain_id,
        slot: block_number,
        beacon_root: [0x55; 32], // beacon root stub
        block_number,
        block_hash: hex_to_32(res["hash"].as_str().unwrap()),
        state_root: hex_to_32(res["stateRoot"].as_str().unwrap()),
        receipts_root: hex_to_32(res["receiptsRoot"].as_str().unwrap()),
    }
}

pub fn load_storage_proof(getproof_json: &str) -> AccountStorageProof {
    let v: Value = serde_json::from_str(getproof_json).expect("valid getproof json");
    let res = &v["result"];
    let address = hex_to_20(res["address"].as_str().unwrap());
    let account_proof = res["accountProof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| hex_to_vec(node.as_str().unwrap()))
        .collect();
    let sp = &res["storageProof"][0];
    let slot = hex_to_32(sp["key"].as_str().unwrap());
    let storage_proof = sp["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| hex_to_vec(node.as_str().unwrap()))
        .collect();
    AccountStorageProof { address, account_proof, slot, storage_proof }
}

pub fn load_receipt_proof(receipt_proof_json: &str) -> ReceiptProof {
    let v: Value = serde_json::from_str(receipt_proof_json).expect("valid receipt proof json");
    let tx_index = v["tx_index"].as_u64().expect("tx_index integer");
    let proof = v["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| hex_to_vec(node.as_str().unwrap()))
        .collect();
    ReceiptProof { tx_index, proof, log_index: 0 }
}
