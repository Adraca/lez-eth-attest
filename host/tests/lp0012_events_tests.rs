// Copyright (c) 2026 Abhishek Khaparde
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for LP-0012 structured event emission in LEZ programs.

use attest_core::{
    error::AttestError,
    event::{AttestationRecorded, CommitteeHandoff, HeaderRecordAccepted},
    statement::{Proof, Query},
    types::HeaderRecord,
};
use attest_program::{
    header_account, instance_account, plan, try_apply, Effect,
    Instruction,
};
use lee_core::{
    account::AccountId,
    program::{AccountMeta, PlanInput},
};

fn dummy_plan_input(me: AccountId, target: AccountId) -> PlanInput {
    PlanInput {
        self_account_id: me,
        caller_account_id: None,
        accounts: vec![AccountMeta::new(target, true, me)],
        instruction_data: Vec::new(),
    }
}

fn dummy_header(slot: u64) -> HeaderRecord {
    HeaderRecord {
        chain_id: 1, slot, beacon_root: [1; 32], block_number: 100,
        block_hash: [2; 32], state_root: [3; 32], receipts_root: [4; 32],
    }
}

#[test]
fn test_record_header_emits_lp0012_event() {
    let me = AccountId::new([1; 32]);
    let inst_id = [9u8; 32];
    let hdr = dummy_header(42);
    let hdr_acc = header_account(&me, &inst_id, hdr.slot);

    let input = dummy_plan_input(me, hdr_acc);
    let p = plan(&input, Instruction::RecordHeader { instance_id: inst_id, header: hdr.clone() });
    assert_eq!(p.output().events.len(), 1);
    let ev = &p.output().events[0];
    assert_eq!(ev.selector, HeaderRecordAccepted::SELECTOR);

    let parsed = HeaderRecordAccepted::from_bytes(&ev.data).expect("parses event");
    assert_eq!(parsed.instance_id, inst_id);
    assert_eq!(parsed.slot, hdr.slot);
    assert_eq!(parsed.block_number, hdr.block_number);
    assert_eq!(parsed.block_hash, hdr.block_hash);
}

#[test]
fn test_record_header_rejects_conflicting_record() {
    let hdr1 = dummy_header(42);
    let mut hdr2 = dummy_header(42);
    hdr2.block_number = 999;

    let encoded1 = borsh::to_vec(&hdr1).unwrap();
    let err = try_apply(&Effect::Record(hdr2), &encoded1).expect_err("conflicting header fails");
    assert_eq!(err, AttestError::InstanceAlreadyInitialized);
}

#[test]
fn test_attest_emits_lp0012_event() {
    let me = AccountId::new([1; 32]);
    let inst_id = [9u8; 32];
    let slot = 42;
    let hdr_acc = header_account(&me, &inst_id, slot);

    let q = Query {
        chain_id: 1,
        proof: Proof::Storage(attest_core::AccountStorageProof {
            address: [0; 20], slot: [0; 32], account_proof: vec![], storage_proof: vec![],
        }),
        target_slot: None, predicates: vec![],
    };

    let input = dummy_plan_input(me, hdr_acc);
    let p = plan(&input, Instruction::Attest { instance_id: inst_id, slot, query: q.clone() });
    assert_eq!(p.output().events.len(), 1);
    let ev = &p.output().events[0];
    assert_eq!(ev.selector, AttestationRecorded::SELECTOR);

    let parsed = AttestationRecorded::from_bytes(&ev.data).expect("parses event");
    assert_eq!(parsed.instance_id, inst_id);
    assert_eq!(parsed.slot, slot);
    assert_eq!(parsed.chain_id, 1);
}

#[test]
fn test_attest_rejects_uninitialized_header_record() {
    let q = Query {
        chain_id: 1,
        proof: Proof::Storage(attest_core::AccountStorageProof {
            address: [0; 20], slot: [0; 32], account_proof: vec![], storage_proof: vec![],
        }),
        target_slot: None, predicates: vec![],
    };
    let err = try_apply(&Effect::Check(q), &[]).expect_err("empty header record fails");
    assert_eq!(err, AttestError::HeaderRecordNotFound);
}

#[test]
fn test_committee_handoff_emits_lp0012_event() {
    let me = AccountId::new([1; 32]);
    let inst_id = [9u8; 32];
    let inst_acc = instance_account(&me, &inst_id);
    let next_root = [0xcc; 32];

    let input = dummy_plan_input(me, inst_acc);
    let p = plan(&input, Instruction::StepCommitteeHandoff {
        instance_id: inst_id, period: 1888, next_sync_committee_root: next_root,
    });
    assert_eq!(p.output().events.len(), 1);
    let ev = &p.output().events[0];
    assert_eq!(ev.selector, CommitteeHandoff::SELECTOR);

    let parsed = CommitteeHandoff::from_bytes(&ev.data).expect("parses event");
    assert_eq!(parsed.instance_id, inst_id);
    assert_eq!(parsed.period, 1888);
    assert_eq!(parsed.next_sync_committee_root, next_root);
}

#[test]
fn test_committee_handoff_rejects_uninitialized_instance() {
    let effect = Effect::HandoffCommittee { period: 1888, next_sync_committee_root: [0xcc; 32] };
    let err = try_apply(&effect, &[]).expect_err("uninitialized instance rejects handoff");
    assert_eq!(err, AttestError::HeaderRecordNotFound);
}
