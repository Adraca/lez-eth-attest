//! BLS12-381 Ethereum sync-committee signature verification core.

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BlsUpdateInput {
    pub header_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
    pub sync_committee_bits: Vec<u8>,
    pub pubkeys: Vec<[u8; 48]>,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct StoredCommittee {
    pub commitment: [u8; 32],
    pub full_aggregate: [u8; 96],
    pub uncompressed_pubkeys: Vec<[u8; 96]>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RotateCommitteeInput {
    pub pubkeys: Vec<[u8; 48]>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RotateCommitteeOutput {
    pub commitment: [u8; 32],
    pub full_aggregate: [u8; 96],
    pub cycles: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct VerifyUpdateInput {
    pub header_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
    pub sync_committee_bits: Vec<u8>,
    pub signature: [u8; 96],
    pub stored_committee: StoredCommittee,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum GuestAction {
    RotateCommittee(RotateCommitteeInput),
    VerifyUpdate(VerifyUpdateInput),
    LegacyFullUpdate(BlsUpdateInput),
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Default)]
pub struct ProfileBreakdown {
    pub pubkey_decompression_cycles: u64,
    pub aggregation_cycles: u64,
    pub signing_root_cycles: u64,
    pub hash_to_curve_cycles: u64,
    pub signature_decompression_cycles: u64,
    pub miller_loop_cycles: u64,
    pub final_exponentiation_cycles: u64,
    pub total_measured_cycles: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Default)]
pub struct UpdateProfileBreakdown {
    pub commitment_check_cycles: u64,
    pub aggregation_cycles: u64,
    pub signing_root_cycles: u64,
    pub hash_to_curve_cycles: u64,
    pub signature_decompression_cycles: u64,
    pub miller_loop_cycles: u64,
    pub final_exponentiation_cycles: u64,
    pub total_measured_cycles: u64,
}

pub const COMMITMENT_DOMAIN_TAG: &[u8] = b"SYNC_COMMITTEE_COMMITMENT_V1";

pub fn compute_committee_commitment(
    full_aggregate: &[u8; 96],
    uncompressed_pubkeys: &[[u8; 96]],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN_TAG);
    hasher.update(full_aggregate);
    for pk in uncompressed_pubkeys {
        hasher.update(pk);
    }
    hasher.finalize().into()
}

pub fn rotate_committee(input: &RotateCommitteeInput) -> Result<StoredCommittee, String> {
    let mut uncompressed_pubkeys = Vec::with_capacity(input.pubkeys.len());
    let mut full_agg = G1Projective::identity();
    for pk_bytes in &input.pubkeys {
        let pt_opt = G1Affine::from_compressed(pk_bytes);
        if pt_opt.is_none().into() {
            return Err("invalid compressed pubkey in rotate_committee".into());
        }
        let pt = pt_opt.unwrap();
        if bool::from(pt.is_identity()) {
            return Err("identity pubkey rejected in rotate_committee".into());
        }
        full_agg += G1Projective::from(pt);
        uncompressed_pubkeys.push(pt.to_uncompressed());
    }
    let full_affine = G1Affine::from(full_agg);
    if bool::from(full_affine.is_identity()) {
        return Err("full aggregate pubkey is identity".into());
    }
    let full_aggregate = full_affine.to_uncompressed();
    let commitment = compute_committee_commitment(&full_aggregate, &uncompressed_pubkeys);
    Ok(StoredCommittee {
        commitment,
        full_aggregate,
        uncompressed_pubkeys,
    })
}

pub fn aggregate_from_stored(
    stored: &StoredCommittee,
    sync_committee_bits: &[u8],
) -> Result<G1Affine, String> {
    let computed_commitment = compute_committee_commitment(
        &stored.full_aggregate,
        &stored.uncompressed_pubkeys,
    );
    if computed_commitment != stored.commitment {
        return Err("stored committee commitment mismatch".into());
    }

    let num_keys = stored.uncompressed_pubkeys.len();
    let mut signers_count = 0;
    for i in 0..num_keys {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < sync_committee_bits.len() && (sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0 {
            signers_count += 1;
        }
    }

    if signers_count == 0 {
        return Err("zero signers participating".into());
    }

    // Optimization: If more than half the committee signed, subtract non-signers
    let agg = if signers_count > num_keys / 2 {
        let full_opt = G1Affine::from_uncompressed_unchecked(&stored.full_aggregate);
        if full_opt.is_none().into() {
            return Err("invalid full_aggregate point".into());
        }
        let mut res = G1Projective::from(full_opt.unwrap());
        for (i, pk_raw) in stored.uncompressed_pubkeys.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let is_signer = byte_idx < sync_committee_bits.len() && (sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0;
            if !is_signer {
                let pt_opt = G1Affine::from_uncompressed_unchecked(pk_raw);
                if pt_opt.is_none().into() {
                    return Err("invalid non-signer pubkey".into());
                }
                res -= G1Projective::from(pt_opt.unwrap());
            }
        }
        res
    } else {
        let mut res = G1Projective::identity();
        for (i, pk_raw) in stored.uncompressed_pubkeys.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let is_signer = byte_idx < sync_committee_bits.len() && (sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0;
            if is_signer {
                let pt_opt = G1Affine::from_uncompressed_unchecked(pk_raw);
                if pt_opt.is_none().into() {
                    return Err("invalid signer pubkey".into());
                }
                res += G1Projective::from(pt_opt.unwrap());
            }
        }
        res
    };

    let affine = G1Affine::from(agg);
    if bool::from(affine.is_identity()) {
        return Err("aggregate pubkey is identity".into());
    }
    Ok(affine)
}

pub fn verify_stored_committee_update(input: &VerifyUpdateInput) -> bool {
    let signing_root = compute_signing_root(
        &input.header_root,
        &input.fork_version,
        &input.genesis_validators_root,
    );
    let agg_pubkey = match aggregate_from_stored(&input.stored_committee, &input.sync_committee_bits) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    verify_bls_signature(&agg_pubkey, &signing_root, &input.signature)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compute_signing_root(
    header_root: &[u8; 32],
    fork_version: &[u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut fork_data_input = [0u8; 64];
    fork_data_input[..4].copy_from_slice(fork_version);
    fork_data_input[32..].copy_from_slice(genesis_validators_root);
    let fork_data_root = sha256(&fork_data_input);

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    let mut signing_input = [0u8; 64];
    signing_input[..32].copy_from_slice(header_root);
    signing_input[32..].copy_from_slice(&domain);
    sha256(&signing_input)
}

pub fn aggregate_participating_pubkeys(
    pubkeys: &[[u8; 48]],
    bits: &[u8],
) -> Option<G1Affine> {
    let mut agg = G1Projective::identity();
    let mut count = 0;
    for (i, pk_bytes) in pubkeys.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < bits.len() && (bits[byte_idx] & (1 << bit_idx)) != 0 {
            let pt_opt = G1Affine::from_compressed(pk_bytes);
            if pt_opt.is_none().into() {
                return None;
            }
            agg += G1Projective::from(pt_opt.unwrap());
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let affine = G1Affine::from(agg);
    if bool::from(affine.is_identity()) {
        return None;
    }
    Some(affine)
}

pub fn verify_bls_signature(
    agg_pubkey: &G1Affine,
    signing_root: &[u8; 32],
    signature_bytes: &[u8; 96],
) -> bool {
    let sig_opt = G2Affine::from_compressed(signature_bytes);
    if sig_opt.is_none().into() {
        return false;
    }
    let sig_pt = sig_opt.unwrap();

    let msg_pt = G2Affine::from(
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            signing_root,
            DST,
        ),
    );

    let neg_g1 = G1Affine::from(-G1Projective::generator());
    let sig_prep = G2Prepared::from(sig_pt);
    let msg_prep = G2Prepared::from(msg_pt);

    let pairing = multi_miller_loop(&[
        (agg_pubkey, &msg_prep),
        (&neg_g1, &sig_prep),
    ]);
    pairing.final_exponentiation() == Gt::identity()
}

pub fn verify_sync_committee_update(input: &BlsUpdateInput) -> bool {
    let signing_root = compute_signing_root(
        &input.header_root,
        &input.fork_version,
        &input.genesis_validators_root,
    );
    let agg_pubkey = match aggregate_participating_pubkeys(&input.pubkeys, &input.sync_committee_bits) {
        Some(pk) => pk,
        None => return false,
    };
    verify_bls_signature(&agg_pubkey, &signing_root, &input.signature)
}
