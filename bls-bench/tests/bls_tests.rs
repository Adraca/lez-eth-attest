use bls_bench::{
    aggregate_from_stored, aggregate_participating_pubkeys, rotate_committee,
    verify_stored_committee_update, verify_sync_committee_update, BlsUpdateInput,
    RotateCommitteeInput, VerifyUpdateInput,
};
use serde_json::Value;

fn load_test_vector() -> BlsUpdateInput {
    let raw = include_str!("../../vectors/beacon/lc_update.json");
    let v: Value = serde_json::from_str(raw).expect("parse lc_update.json");

    let header_root = hex::decode(&v["header_root"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let fork_version = hex::decode(&v["fork_version"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let genesis_validators_root = hex::decode(&v["genesis_validators_root"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let sync_committee_bits = hex::decode(&v["sync_aggregate"]["sync_committee_bits"].as_str().unwrap()[2..]).unwrap();
    let pubkeys: Vec<[u8; 48]> = v["current_sync_committee_pubkeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| hex::decode(&p.as_str().unwrap()[2..]).unwrap().try_into().unwrap())
        .collect();
    let signature = hex::decode(&v["sync_aggregate"]["sync_committee_signature"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap();

    BlsUpdateInput {
        header_root,
        fork_version,
        genesis_validators_root,
        sync_committee_bits,
        pubkeys,
        signature,
    }
}

fn create_synthetic_bitmap(signers: usize, total: usize) -> Vec<u8> {
    let mut bits = vec![0u8; (total + 7) / 8];
    for i in 0..signers {
        bits[i / 8] |= 1 << (i % 8);
    }
    bits
}

#[test]
fn test_bls_sync_committee_verification_positive() {
    let input = load_test_vector();
    assert!(
        verify_sync_committee_update(&input),
        "Real beacon sync-committee aggregate signature must verify successfully"
    );
}

#[test]
fn test_bls_sync_committee_verification_negative_flipped_bit() {
    let mut input = load_test_vector();
    // Flip one bit in the signature (audit blocker requirement)
    input.signature[10] ^= 0x01;
    assert!(
        !verify_sync_committee_update(&input),
        "Signature with flipped bit must be rejected"
    );
}

#[test]
fn test_bls_sync_committee_verification_tampered_header_root() {
    let mut input = load_test_vector();
    input.header_root[0] ^= 0x55;
    assert!(
        !verify_sync_committee_update(&input),
        "Signature under tampered header root must be rejected"
    );
}

#[test]
fn test_bls_sync_committee_verification_wrong_fork_version() {
    let mut input = load_test_vector();
    input.fork_version[0] ^= 0x01;
    assert!(
        !verify_sync_committee_update(&input),
        "Signature under wrong fork version must be rejected"
    );
}

#[test]
fn test_stored_committee_rotation_and_update_positive() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .expect("rotate committee succeeds");

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    assert!(
        verify_stored_committee_update(&update),
        "Stored committee verification must succeed for 512/512 update"
    );
}

#[test]
fn test_stored_committee_negative_flipped_bit() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    let mut update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    update.signature[10] ^= 0x01;
    assert!(
        !verify_stored_committee_update(&update),
        "Signature with flipped bit must be rejected with stored committee"
    );
}

#[test]
fn test_stored_committee_negative_tampered_header_root() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    let mut update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    update.header_root[0] ^= 0xaa;
    assert!(
        !verify_stored_committee_update(&update),
        "Tampered header root must be rejected"
    );
}

#[test]
fn test_stored_committee_negative_wrong_fork_version() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    let mut update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    update.fork_version[0] ^= 0x01;
    assert!(
        !verify_stored_committee_update(&update),
        "Wrong fork version must be rejected"
    );
}

#[test]
fn test_stored_committee_negative_tampered_commitment() {
    let input = load_test_vector();
    let mut stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();
    // Tamper with commitment
    stored.commitment[0] ^= 0xff;

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    assert!(
        !verify_stored_committee_update(&update),
        "Tampered commitment must cause verification failure"
    );
}

#[test]
fn test_stored_committee_negative_tampered_pubkey() {
    let input = load_test_vector();
    let mut stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();
    // Tamper with one coordinate byte of the first pubkey
    stored.uncompressed_pubkeys[0][10] ^= 0x01;

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    assert!(
        !verify_stored_committee_update(&update),
        "Tampered pubkey byte must violate commitment and fail verification"
    );
}

#[test]
fn test_stored_committee_negative_tampered_full_aggregate() {
    let input = load_test_vector();
    let mut stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();
    // Tamper with full_aggregate
    stored.full_aggregate[10] ^= 0x01;

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };
    assert!(
        !verify_stored_committee_update(&update),
        "Tampered full_aggregate must violate commitment and fail verification"
    );
}

#[test]
fn test_synthetic_bitmap_400_aggregation_equivalence() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    let bits400 = create_synthetic_bitmap(400, 512);

    // Fast subtraction method (> half signers)
    let fast_agg = aggregate_from_stored(&stored, &bits400).expect("fast aggregation succeeds");
    // Direct reference sum
    let ref_agg = aggregate_participating_pubkeys(&input.pubkeys, &bits400).expect("reference aggregation succeeds");

    assert_eq!(fast_agg, ref_agg, "Fast non-signer subtraction must match reference sum for 400 signers");
}

#[test]
fn test_synthetic_bitmap_342_threshold_aggregation_equivalence() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    // 342 / 512 is the 2/3 supermajority threshold
    let bits342 = create_synthetic_bitmap(342, 512);

    let fast_agg = aggregate_from_stored(&stored, &bits342).expect("fast aggregation succeeds");
    let ref_agg = aggregate_participating_pubkeys(&input.pubkeys, &bits342).expect("reference aggregation succeeds");

    assert_eq!(fast_agg, ref_agg, "Fast non-signer subtraction must match reference sum for 342 signers (2/3 threshold)");
}

#[test]
fn test_synthetic_bitmap_200_aggregation_equivalence() {
    let input = load_test_vector();
    let stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    // 200 / 512 is < 50%, triggers the direct summing branch
    let bits200 = create_synthetic_bitmap(200, 512);

    let fast_agg = aggregate_from_stored(&stored, &bits200).expect("direct aggregation succeeds");
    let ref_agg = aggregate_participating_pubkeys(&input.pubkeys, &bits200).expect("reference aggregation succeeds");

    assert_eq!(fast_agg, ref_agg, "Direct sum from stored must match reference sum for 200 signers");
}

#[test]
fn test_stored_committee_negative_identity_pubkey() {
    let mut input = load_test_vector();
    input.pubkeys[0] = bls12_381::G1Affine::identity().to_compressed();
    let res = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys,
    });
    assert!(res.is_err(), "Identity pubkey in rotate_committee must be rejected");
}

#[test]
fn test_stored_committee_negative_swapped_valid_g1_point() {
    let input = load_test_vector();
    let mut stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    // Extra Check 2(a): Swap one pubkey in witness for a valid-but-different G1 point (G1 generator)
    let alt_valid_pt = bls12_381::G1Affine::generator().to_uncompressed();
    assert_ne!(
        stored.uncompressed_pubkeys[0], alt_valid_pt,
        "Generator must differ from real committee pubkey 0"
    );
    stored.uncompressed_pubkeys[0] = alt_valid_pt;

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };

    assert!(
        !verify_stored_committee_update(&update),
        "Witness with valid-but-different G1 point must violate commitment and be rejected by verify_update"
    );
}

#[test]
fn test_stored_committee_negative_off_curve_pubkey_bytes() {
    let input = load_test_vector();
    let mut stored = rotate_committee(&RotateCommitteeInput {
        pubkeys: input.pubkeys.clone(),
    })
    .unwrap();

    // Extra Check 2(b): Replace one pubkey with bytes that are not on the curve (x=1, y=1 where y^2 != x^3 + 4)
    let mut off_curve = [0u8; 96];
    off_curve[47] = 1; // x = 1 (big-endian)
    off_curve[95] = 1; // y = 1 (big-endian)
    stored.uncompressed_pubkeys[0] = off_curve;

    let update = VerifyUpdateInput {
        header_root: input.header_root,
        fork_version: input.fork_version,
        genesis_validators_root: input.genesis_validators_root,
        sync_committee_bits: input.sync_committee_bits,
        signature: input.signature,
        stored_committee: stored,
    };

    assert!(
        !verify_stored_committee_update(&update),
        "Witness with off-curve bytes must be rejected by verify_update"
    );
}

