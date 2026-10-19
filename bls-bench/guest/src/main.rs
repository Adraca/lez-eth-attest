#![no_main]

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::entry;
use sha2::{Digest, Sha256};

entry!(main);

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

#[derive(BorshSerialize, BorshDeserialize)]
pub struct StoredCommittee {
    pub commitment: [u8; 32],
    pub full_aggregate: [u8; 96],
    pub uncompressed_pubkeys: Vec<[u8; 96]>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct RotateCommitteeInput {
    pub pubkeys: Vec<[u8; 48]>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct RotateCommitteeOutput {
    pub commitment: [u8; 32],
    pub full_aggregate: [u8; 96],
    pub cycles: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct VerifyUpdateInput {
    pub header_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
    pub sync_committee_bits: Vec<u8>,
    pub signature: [u8; 96],
    pub stored_committee: StoredCommittee,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct BlsUpdateInput {
    pub header_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
    pub sync_committee_bits: Vec<u8>,
    pub pubkeys: Vec<[u8; 48]>,
    pub signature: [u8; 96],
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum GuestAction {
    RotateCommittee(RotateCommitteeInput),
    VerifyUpdate(VerifyUpdateInput),
    LegacyFullUpdate(BlsUpdateInput),
}

#[derive(BorshSerialize, BorshDeserialize, Default)]
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

#[derive(BorshSerialize, BorshDeserialize, Default)]
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

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub const COMMITMENT_DOMAIN_TAG: &[u8] = b"SYNC_COMMITTEE_COMMITMENT_V1";

fn compute_committee_commitment(
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

fn compute_signing_root(
    header_root: &[u8; 32],
    fork_version: &[u8; 4],
    genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut fork_data_input = [0u8; 64];
    fork_data_input[..4].copy_from_slice(fork_version);
    fork_data_input[32..].copy_from_slice(genesis_validators_root);
    let fork_data_root = sha256_digest(&fork_data_input);

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    let mut signing_input = [0u8; 64];
    signing_input[..32].copy_from_slice(header_root);
    signing_input[32..].copy_from_slice(&domain);
    sha256_digest(&signing_input)
}

fn handle_rotate_committee(input: RotateCommitteeInput) {
    let t0 = risc0_zkvm::guest::env::cycle_count();

    let mut uncompressed_pubkeys = Vec::with_capacity(input.pubkeys.len());
    let mut full_agg = G1Projective::identity();
    for pk_bytes in &input.pubkeys {
        let pt_opt = G1Affine::from_compressed(pk_bytes);
        assert!(bool::from(pt_opt.is_some()), "invalid compressed pubkey in rotate_committee");
        let pt = pt_opt.unwrap();
        assert!(!bool::from(pt.is_identity()), "identity pubkey rejected in rotate_committee");
        full_agg += G1Projective::from(pt);
        uncompressed_pubkeys.push(pt.to_uncompressed());
    }
    let full_affine = G1Affine::from(full_agg);
    assert!(!bool::from(full_affine.is_identity()), "full aggregate pubkey is identity");
    let full_aggregate = full_affine.to_uncompressed();
    let commitment = compute_committee_commitment(&full_aggregate, &uncompressed_pubkeys);

    let t1 = risc0_zkvm::guest::env::cycle_count();
    let cycles = (t1 - t0) as u64;

    println!("[guest rotate_committee] Verified and committed {} pubkeys in {} cycles", input.pubkeys.len(), cycles);

    let output = RotateCommitteeOutput {
        commitment,
        full_aggregate,
        cycles,
    };
    let journal = borsh::to_vec(&output).expect("borsh encode output");
    risc0_zkvm::guest::env::commit_slice(&journal);
}

fn handle_verify_update(input: VerifyUpdateInput) {
    // 1. Commitment check
    let t0 = risc0_zkvm::guest::env::cycle_count();
    let computed_commitment = compute_committee_commitment(
        &input.stored_committee.full_aggregate,
        &input.stored_committee.uncompressed_pubkeys,
    );
    assert_eq!(computed_commitment, input.stored_committee.commitment, "committee commitment mismatch");
    let t1 = risc0_zkvm::guest::env::cycle_count();
    let commitment_check_cycles = (t1 - t0) as u64;

    // 2. Aggregation with subtraction optimization
    let t1_agg = risc0_zkvm::guest::env::cycle_count();
    let num_keys = input.stored_committee.uncompressed_pubkeys.len();
    let mut signers_count = 0;
    for i in 0..num_keys {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < input.sync_committee_bits.len() && (input.sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0 {
            signers_count += 1;
        }
    }
    assert!(signers_count > 0, "zero signers in update");

    let agg = if signers_count > num_keys / 2 {
        let full_opt = G1Affine::from_uncompressed_unchecked(&input.stored_committee.full_aggregate);
        assert!(bool::from(full_opt.is_some()), "invalid full_aggregate");
        let mut res = G1Projective::from(full_opt.unwrap());
        for (i, pk_raw) in input.stored_committee.uncompressed_pubkeys.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let is_signer = byte_idx < input.sync_committee_bits.len() && (input.sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0;
            if !is_signer {
                let pt_opt = G1Affine::from_uncompressed_unchecked(pk_raw);
                assert!(bool::from(pt_opt.is_some()), "invalid non-signer point");
                res -= G1Projective::from(pt_opt.unwrap());
            }
        }
        res
    } else {
        let mut res = G1Projective::identity();
        for (i, pk_raw) in input.stored_committee.uncompressed_pubkeys.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let is_signer = byte_idx < input.sync_committee_bits.len() && (input.sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0;
            if is_signer {
                let pt_opt = G1Affine::from_uncompressed_unchecked(pk_raw);
                assert!(bool::from(pt_opt.is_some()), "invalid signer point");
                res += G1Projective::from(pt_opt.unwrap());
            }
        }
        res
    };

    let agg_pubkey = G1Affine::from(agg);
    assert!(!bool::from(agg_pubkey.is_identity()), "aggregate pubkey is identity");
    let t2 = risc0_zkvm::guest::env::cycle_count();
    let aggregation_cycles = (t2 - t1_agg) as u64;

    // 3. Signing root SHA-256
    let t2_root = risc0_zkvm::guest::env::cycle_count();
    let signing_root = compute_signing_root(
        &input.header_root,
        &input.fork_version,
        &input.genesis_validators_root,
    );
    let t3 = risc0_zkvm::guest::env::cycle_count();
    let signing_root_cycles = (t3 - t2_root) as u64;

    // 4. hash_to_curve
    let t3_h2c = risc0_zkvm::guest::env::cycle_count();
    let msg_pt = G2Affine::from(
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&signing_root, DST),
    );
    let t4 = risc0_zkvm::guest::env::cycle_count();
    let hash_to_curve_cycles = (t4 - t3_h2c) as u64;

    // 5. Signature decompression/check + pairing prep
    let t4_sig = risc0_zkvm::guest::env::cycle_count();
    let sig_opt = G2Affine::from_compressed(&input.signature);
    assert!(bool::from(sig_opt.is_some()), "signature decompression / subgroup check failed");
    let sig_pt = sig_opt.unwrap();
    let neg_g1 = -G1Affine::generator();
    let sig_prep = G2Prepared::from(sig_pt);
    let msg_prep = G2Prepared::from(msg_pt);
    let t5 = risc0_zkvm::guest::env::cycle_count();
    let signature_decompression_cycles = (t5 - t4_sig) as u64;

    // 6. Miller loop
    let t5_miller = risc0_zkvm::guest::env::cycle_count();
    let pairing = multi_miller_loop(&[(&agg_pubkey, &msg_prep), (&neg_g1, &sig_prep)]);
    let t6 = risc0_zkvm::guest::env::cycle_count();
    let miller_loop_cycles = (t6 - t5_miller) as u64;

    // 7. Final exponentiation
    let t6_exp = risc0_zkvm::guest::env::cycle_count();
    let ok = pairing.final_exponentiation() == Gt::identity();
    let t7 = risc0_zkvm::guest::env::cycle_count();
    let final_exponentiation_cycles = (t7 - t6_exp) as u64;
    assert!(ok, "BLS sync committee signature verification failed in zkVM");

    let total_measured_cycles = commitment_check_cycles
        + aggregation_cycles
        + signing_root_cycles
        + hash_to_curve_cycles
        + signature_decompression_cycles
        + miller_loop_cycles
        + final_exponentiation_cycles;

    let profile = UpdateProfileBreakdown {
        commitment_check_cycles,
        aggregation_cycles,
        signing_root_cycles,
        hash_to_curve_cycles,
        signature_decompression_cycles,
        miller_loop_cycles,
        final_exponentiation_cycles,
        total_measured_cycles,
    };

    println!("[guest verify_update] Commitment re-check      : {:>10} cycles", commitment_check_cycles);
    println!("[guest verify_update] Fast aggregation          : {:>10} cycles", aggregation_cycles);
    println!("[guest verify_update] Signing-root SHA-256      : {:>10} cycles", signing_root_cycles);
    println!("[guest verify_update] hash_to_curve             : {:>10} cycles", hash_to_curve_cycles);
    println!("[guest verify_update] Signature decomp/prep     : {:>10} cycles", signature_decompression_cycles);
    println!("[guest verify_update] Miller loop               : {:>10} cycles", miller_loop_cycles);
    println!("[guest verify_update] Final exponentiation      : {:>10} cycles", final_exponentiation_cycles);
    println!("[guest verify_update] Total measured update     : {:>10} cycles", total_measured_cycles);

    let journal = borsh::to_vec(&(input.header_root, profile)).expect("borsh encode journal");
    risc0_zkvm::guest::env::commit_slice(&journal);
}

fn handle_legacy(input: BlsUpdateInput) {
    let t0 = risc0_zkvm::guest::env::cycle_count();
    let mut decompressed_pks: Vec<G1Affine> = Vec::with_capacity(input.pubkeys.len());
    for pk_bytes in &input.pubkeys {
        let pt_opt = G1Affine::from_compressed(pk_bytes);
        assert!(bool::from(pt_opt.is_some()), "pubkey decompression / subgroup check failed");
        decompressed_pks.push(pt_opt.unwrap());
    }
    let t1 = risc0_zkvm::guest::env::cycle_count();
    let pubkey_decompression_cycles = (t1 - t0) as u64;

    let t1_agg = risc0_zkvm::guest::env::cycle_count();
    let mut agg = G1Projective::identity();
    let mut count = 0;
    for (i, pt) in decompressed_pks.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < input.sync_committee_bits.len() && (input.sync_committee_bits[byte_idx] & (1 << bit_idx)) != 0 {
            agg += G1Projective::from(*pt);
            count += 1;
        }
    }
    assert!(count > 0, "no participating sync committee signers");
    let agg_pubkey = G1Affine::from(agg);
    assert!(!bool::from(agg_pubkey.is_identity()), "aggregate pubkey is identity");
    let t2 = risc0_zkvm::guest::env::cycle_count();
    let aggregation_cycles = (t2 - t1_agg) as u64;

    let t2_root = risc0_zkvm::guest::env::cycle_count();
    let signing_root = compute_signing_root(
        &input.header_root,
        &input.fork_version,
        &input.genesis_validators_root,
    );
    let t3 = risc0_zkvm::guest::env::cycle_count();
    let signing_root_cycles = (t3 - t2_root) as u64;

    let t3_h2c = risc0_zkvm::guest::env::cycle_count();
    let msg_pt = G2Affine::from(
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&signing_root, DST),
    );
    let t4 = risc0_zkvm::guest::env::cycle_count();
    let hash_to_curve_cycles = (t4 - t3_h2c) as u64;

    let t4_sig = risc0_zkvm::guest::env::cycle_count();
    let sig_opt = G2Affine::from_compressed(&input.signature);
    assert!(bool::from(sig_opt.is_some()), "signature decompression / subgroup check failed");
    let sig_pt = sig_opt.unwrap();
    let neg_g1 = -G1Affine::generator();
    let sig_prep = G2Prepared::from(sig_pt);
    let msg_prep = G2Prepared::from(msg_pt);
    let t5 = risc0_zkvm::guest::env::cycle_count();
    let signature_decompression_cycles = (t5 - t4_sig) as u64;

    let t5_miller = risc0_zkvm::guest::env::cycle_count();
    let pairing = multi_miller_loop(&[(&agg_pubkey, &msg_prep), (&neg_g1, &sig_prep)]);
    let t6 = risc0_zkvm::guest::env::cycle_count();
    let miller_loop_cycles = (t6 - t5_miller) as u64;

    let t6_exp = risc0_zkvm::guest::env::cycle_count();
    let ok = pairing.final_exponentiation() == Gt::identity();
    let t7 = risc0_zkvm::guest::env::cycle_count();
    let final_exponentiation_cycles = (t7 - t6_exp) as u64;
    assert!(ok, "BLS sync committee signature verification failed in zkVM");

    let total_measured_cycles = pubkey_decompression_cycles
        + aggregation_cycles
        + signing_root_cycles
        + hash_to_curve_cycles
        + signature_decompression_cycles
        + miller_loop_cycles
        + final_exponentiation_cycles;

    let profile = ProfileBreakdown {
        pubkey_decompression_cycles,
        aggregation_cycles,
        signing_root_cycles,
        hash_to_curve_cycles,
        signature_decompression_cycles,
        miller_loop_cycles,
        final_exponentiation_cycles,
        total_measured_cycles,
    };

    println!("[guest legacy] Pubkey decompression + check : {:>10} cycles", pubkey_decompression_cycles);
    println!("[guest legacy] Aggregation                  : {:>10} cycles", aggregation_cycles);
    println!("[guest legacy] Signing-root SHA-256         : {:>10} cycles", signing_root_cycles);
    println!("[guest legacy] hash_to_curve                : {:>10} cycles", hash_to_curve_cycles);
    println!("[guest legacy] Signature decompression/check: {:>10} cycles", signature_decompression_cycles);
    println!("[guest legacy] Miller loop                  : {:>10} cycles", miller_loop_cycles);
    println!("[guest legacy] Final exponentiation         : {:>10} cycles", final_exponentiation_cycles);
    println!("[guest legacy] Total measured phase cycles  : {:>10} cycles", total_measured_cycles);

    let journal_payload = borsh::to_vec(&(input.header_root, profile)).expect("borsh encode journal");
    risc0_zkvm::guest::env::commit_slice(&journal_payload);
}

fn main() {
    let mut len_bytes = [0u8; 4];
    risc0_zkvm::guest::env::read_slice(&mut len_bytes);
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut input_bytes = vec![0u8; len];
    risc0_zkvm::guest::env::read_slice(&mut input_bytes);

    if let Ok(action) = borsh::from_slice::<GuestAction>(&input_bytes) {
        match action {
            GuestAction::RotateCommittee(rot) => handle_rotate_committee(rot),
            GuestAction::VerifyUpdate(upd) => handle_verify_update(upd),
            GuestAction::LegacyFullUpdate(legacy) => handle_legacy(legacy),
        }
    } else if let Ok(legacy) = borsh::from_slice::<BlsUpdateInput>(&input_bytes) {
        handle_legacy(legacy);
    } else {
        panic!("unrecognized guest input format");
    }
}
