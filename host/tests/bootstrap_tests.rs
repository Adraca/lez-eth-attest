// Copyright (c) 2026 Abhishek Khaparde
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for F#9 weak-subjectivity bootstrap and instance lifecycle.

use attest_core::error::AttestError;
use attest_program::{
    instance_account, plan, try_apply, Effect,
    Instruction, InstanceConfig,
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

#[test]
fn test_bootstrap_from_checkpoint_positive() {
    let me = AccountId::new([1; 32]);
    let inst_id = [9u8; 32];
    let inst_acc = instance_account(&me, &inst_id);
    let ws_ckpt = [0xaa; 32];
    let sc_root = [0xbb; 32];

    let input = dummy_plan_input(me, inst_acc);
    let p = plan(&input, Instruction::BootstrapFromCheckpoint {
        instance_id: inst_id, chain_id: 1,
        ws_checkpoint_root: ws_ckpt, sync_committee_root: sc_root,
    });
    assert_eq!(p.output().effects.len(), 1);

    let effect = Effect::CreateInstance(InstanceConfig {
        chain_id: 1, ws_checkpoint_root: ws_ckpt, sync_committee_root: sc_root,
    });
    let applied = try_apply(&effect, &[]).expect("bootstrap on empty shard succeeds");
    let cfg: InstanceConfig = borsh::from_slice(&applied.unwrap()).expect("deserializes");
    assert_eq!(cfg.chain_id, 1);
    assert_eq!(cfg.ws_checkpoint_root, ws_ckpt);
    assert_eq!(cfg.sync_committee_root, sc_root);
}

#[test]
fn test_bootstrap_from_checkpoint_rejects_second_init() {
    let effect = Effect::CreateInstance(InstanceConfig {
        chain_id: 1, ws_checkpoint_root: [0xaa; 32], sync_committee_root: [0xbb; 32],
    });
    let existing_shard = vec![1u8, 2, 3];
    let err = try_apply(&effect, &existing_shard).expect_err("second init must fail");
    assert_eq!(err, AttestError::InstanceAlreadyInitialized);
}
