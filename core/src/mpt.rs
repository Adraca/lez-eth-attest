//! Audited MPT and RLP verification adapter using alloy-trie and alloy-rlp.

extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header};
use alloy_trie::proof::{verify_proof, ProofVerificationError};
use alloy_trie::TrieAccount;
use borsh::{BorshDeserialize, BorshSerialize};
use nybbles::Nibbles;
use tiny_keccak::{Hasher, Keccak};

use crate::error::AttestError;
use crate::types::{Address20, Hash256};

pub const EMPTY_ROOT: Hash256 = alloy_trie::EMPTY_ROOT_HASH.0;

pub fn keccak256(data: &[u8]) -> Hash256 {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

pub fn be32(v: &[u8]) -> Result<Hash256, AttestError> {
    if v.len() > 32 { return Err(AttestError::ProofVerificationFailed); }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

fn next_bytes<'a>(buf: &mut &'a [u8], list: bool) -> Result<&'a [u8], AttestError> {
    Header::decode_bytes(buf, list).map_err(|_| AttestError::ProofVerificationFailed)
}

pub fn verify_trie_proof(root: &Hash256, key: &Nibbles, proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, AttestError> {
    let root_b256 = B256::from_slice(root);
    let p_bytes: Vec<Bytes> = proof.iter().map(|n| Bytes::copy_from_slice(n)).collect();
    let p_refs: Vec<&Bytes> = p_bytes.iter().collect();

    match verify_proof(root_b256, *key, None, p_refs.iter().copied()) {
        Ok(()) => Ok(None),
        Err(ProofVerificationError::ValueMismatch { path, got: Some(val), .. }) if path == *key => {
            verify_proof(root_b256, *key, Some(val.to_vec()), p_refs.iter().copied())
                .map_err(|_| AttestError::ProofVerificationFailed)?;
            Ok(Some(val.to_vec()))
        }
        Err(_) => Err(AttestError::ProofVerificationFailed),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountStorageProof {
    pub address: Address20,
    pub account_proof: Vec<Vec<u8>>,
    pub slot: Hash256,
    pub storage_proof: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountSlotState {
    pub nonce: Hash256,
    pub balance: Hash256,
    pub storage_root: Hash256,
    pub code_hash: Hash256,
    pub slot_value: Hash256,
}

pub fn verify_account_storage(state_root: &Hash256, p: &AccountStorageProof) -> Result<AccountSlotState, AttestError> {
    let acct_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.address)));
    let acct_enc = verify_trie_proof(state_root, &acct_key, &p.account_proof)?.ok_or(AttestError::ProofVerificationFailed)?;
    let acct = TrieAccount::decode(&mut &acct_enc[..]).map_err(|_| AttestError::ProofVerificationFailed)?;
    let storage_root = acct.storage_root.0;

    let slot_value = if storage_root == EMPTY_ROOT && p.storage_proof.is_empty() {
        [0u8; 32]
    } else {
        let slot_key = Nibbles::unpack(B256::from_slice(&keccak256(&p.slot)));
        match verify_trie_proof(&storage_root, &slot_key, &p.storage_proof)? {
            Some(enc) => be32(next_bytes(&mut enc.as_slice(), false)?)?,
            None => [0u8; 32],
        }
    };

    Ok(AccountSlotState {
        nonce: be32(&acct.nonce.to_be_bytes())?,
        balance: acct.balance.to_be_bytes::<32>(),
        storage_root,
        code_hash: acct.code_hash.0,
        slot_value,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptProof {
    pub tx_index: u64,
    pub proof: Vec<Vec<u8>>,
    pub log_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptLog {
    pub status: u8,
    pub address: Address20,
    pub topics: Vec<Hash256>,
    pub data: Vec<u8>,
}

pub fn verify_receipt_log(receipts_root: &Hash256, p: &ReceiptProof) -> Result<ReceiptLog, AttestError> {
    let mut key_bytes = Vec::new();
    p.tx_index.encode(&mut key_bytes);
    let key = Nibbles::unpack(Bytes::from(key_bytes));

    let receipt_raw = verify_trie_proof(receipts_root, &key, &p.proof)?.ok_or(AttestError::ProofVerificationFailed)?;
    let mut body = if receipt_raw.first().copied().unwrap_or(0) < 0x7f { &receipt_raw[1..] } else { &receipt_raw[..] };

    let mut payload = next_bytes(&mut body, true)?;
    let status = next_bytes(&mut payload, false)?.first().copied().unwrap_or(0);
    let _gas = next_bytes(&mut payload, false)?;
    let _bloom = next_bytes(&mut payload, false)?;
    let mut logs = next_bytes(&mut payload, true)?;

    for idx in 0..=p.log_index {
        let mut log = next_bytes(&mut logs, true)?;
        if idx == p.log_index {
            let address: Address20 = next_bytes(&mut log, false)?.try_into().map_err(|_| AttestError::ProofVerificationFailed)?;
            let mut topics_slice = next_bytes(&mut log, true)?;
            let mut topics = Vec::new();
            while !topics_slice.is_empty() {
                let topic: Hash256 = next_bytes(&mut topics_slice, false)?.try_into().map_err(|_| AttestError::ProofVerificationFailed)?;
                topics.push(topic);
            }
            let data = next_bytes(&mut log, false)?.to_vec();
            return Ok(ReceiptLog { status, address, topics, data });
        }
    }
    Err(AttestError::ProofVerificationFailed)
}
