//! LEZ v0.3 on-chain guest program for Ethereum state and event attestation.
//! Plan/apply architecture per official logos-blockchain/logos-execution-zone.

extern crate alloc;
use alloc::vec::Vec;
use attest_core::{
    error::AttestError,
    event::{AttestationRecorded, CommitteeHandoff, HeaderRecordAccepted},
    statement::{evaluate, Query},
    types::HeaderRecord,
};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{AccountMeta, PdaSeed, Plan, PlanInput, ProgramEvent},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InstanceConfig {
    pub chain_id: u64,
    pub ws_checkpoint_root: [u8; 32],
    pub sync_committee_root: [u8; 32],
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    InitInstance { instance_id: [u8; 32], chain_id: u64 },
    BootstrapFromCheckpoint {
        instance_id: [u8; 32], chain_id: u64,
        ws_checkpoint_root: [u8; 32], sync_committee_root: [u8; 32],
    },
    RecordHeader { instance_id: [u8; 32], header: HeaderRecord },
    Attest { instance_id: [u8; 32], slot: u64, query: Query },
    StepCommitteeHandoff { instance_id: [u8; 32], period: u64, next_sync_committee_root: [u8; 32] },
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    CreateInstance(InstanceConfig),
    Record(HeaderRecord),
    Check(Query),
    HandoffCommittee { period: u64, next_sync_committee_root: [u8; 32] },
}

fn derive_pda_seed(parts: &[&[u8]]) -> PdaSeed {
    let mut buf = Vec::new();
    for p in parts { buf.extend_from_slice(p); }
    let seed: [u8; 32] = Impl::hash_bytes(&buf).as_bytes().try_into().expect("SHA256 32B");
    PdaSeed::new(seed)
}

#[must_use]
pub fn instance_account(me: &AccountId, instance_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(*instance_id))
}

#[must_use]
pub fn header_account(me: &AccountId, instance_id: &[u8; 32], slot: u64) -> AccountId {
    let seed = derive_pda_seed(&[b"attest/header/v1", instance_id, &slot.to_le_bytes()]);
    AccountId::for_public_pda(me, &seed)
}

fn extract_accounts<const N: usize>(input: &PlanInput) -> [AccountMeta; N] {
    <[AccountMeta; N]>::try_from(input.accounts.clone()).unwrap_or_else(|_| panic!("Error: {}", AttestError::AccountCountMismatch))
}

#[must_use]
pub fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let me = input.self_account_id;
    let mut plan = Plan::new(input);
    match ix {
        Instruction::InitInstance { instance_id, chain_id } => {
            let [inst] = extract_accounts::<1>(input);
            assert_eq!(inst.account_id, instance_account(&me, &instance_id));
            plan.effect(&inst, &Effect::CreateInstance(InstanceConfig {
                chain_id, ws_checkpoint_root: [0; 32], sync_committee_root: [0; 32],
            }));
        }
        Instruction::BootstrapFromCheckpoint { instance_id, chain_id, ws_checkpoint_root, sync_committee_root } => {
            let [inst] = extract_accounts::<1>(input);
            assert_eq!(inst.account_id, instance_account(&me, &instance_id));
            plan.effect(&inst, &Effect::CreateInstance(InstanceConfig {
                chain_id, ws_checkpoint_root, sync_committee_root,
            }));
        }
        Instruction::RecordHeader { instance_id, header } => {
            let [hdr] = extract_accounts::<1>(input);
            assert_eq!(hdr.account_id, header_account(&me, &instance_id, header.slot));
            let ev = HeaderRecordAccepted {
                instance_id, slot: header.slot, block_number: header.block_number,
                block_hash: header.block_hash, state_root: header.state_root,
                receipts_root: header.receipts_root,
            };
            plan.effect(&hdr, &Effect::Record(header));
            plan.event(ProgramEvent { selector: HeaderRecordAccepted::SELECTOR, data: ev.to_bytes() });
        }
        Instruction::Attest { instance_id, slot, query } => {
            let [hdr] = extract_accounts::<1>(input);
            assert_eq!(hdr.account_id, header_account(&me, &instance_id, slot));
            let ev = AttestationRecorded { instance_id, slot, chain_id: query.chain_id };
            plan.effect(&hdr, &Effect::Check(query));
            plan.event(ProgramEvent { selector: AttestationRecorded::SELECTOR, data: ev.to_bytes() });
        }
        Instruction::StepCommitteeHandoff { instance_id, period, next_sync_committee_root } => {
            let [inst] = extract_accounts::<1>(input);
            assert_eq!(inst.account_id, instance_account(&me, &instance_id));
            let ev = CommitteeHandoff { instance_id, period, next_sync_committee_root };
            plan.effect(&inst, &Effect::HandoffCommittee { period, next_sync_committee_root });
            plan.event(ProgramEvent { selector: CommitteeHandoff::SELECTOR, data: ev.to_bytes() });
        }
    }
    plan
}

pub fn try_apply(effect: &Effect, pre: &[u8]) -> Result<Option<Vec<u8>>, AttestError> {
    match effect {
        Effect::CreateInstance(cfg) => {
            if !pre.is_empty() { return Err(AttestError::InstanceAlreadyInitialized); }
            Ok(Some(borsh::to_vec(cfg).expect("borsh serialize")))
        }
        Effect::Record(header) => {
            let encoded = borsh::to_vec(header).expect("borsh serialize");
            if !pre.is_empty() && pre != encoded.as_slice() {
                return Err(AttestError::InstanceAlreadyInitialized);
            }
            Ok(Some(encoded))
        }
        Effect::Check(query) => {
            if pre.is_empty() { return Err(AttestError::HeaderRecordNotFound); }
            let r: HeaderRecord = borsh::from_slice(pre).map_err(|_| AttestError::MalformedInput)?;
            evaluate(&r, query)?;
            Ok(None)
        }
        Effect::HandoffCommittee { .. } => {
            if pre.is_empty() { return Err(AttestError::HeaderRecordNotFound); }
            Ok(None)
        }
    }
}

/// Applies effect to shard pre-data.
/// In LEZ v0.3 (`lee_core::program::run_program`), `apply` signature has no error channel.
/// State rejections must abort zkVM execution via panic (lee_core line 814).
/// `try_apply` exposes typed `AttestError` (31xx–35xx) for dry-run simulation and tests.
#[must_use]
pub fn apply(effect: Effect, pre: &[u8]) -> Option<Vec<u8>> {
    try_apply(&effect, pre).unwrap_or_else(|err| panic!("Error: {}", err))
}
