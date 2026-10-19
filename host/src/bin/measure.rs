//! Performance benchmarks: native latency, real RISC0 zkVM cycles, and LEZ gas.

use std::sync::LazyLock;
use std::time::Instant;
use attest_core::predicate::{Cmp, Field, Predicate};
use attest_core::statement::{evaluate, Proof, Query};
use attest_host::vectors::{load_header_record, load_receipt_proof, load_storage_proof};
use attest_program::Effect;
use lee_core::account::{AccountId, ProgramShardSelector, ShardData};
use lee_core::program::{ApplyInput, CallKind};
use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};

const GUEST_ELF: &[u8] = include_bytes!("../../../target/riscv32im-risc0-zkvm-elf/release/attest_prog");

static GUEST_BINARY: LazyLock<Vec<u8>> = LazyLock::new(|| {
    ProgramBinary::new(GUEST_ELF, V1COMPAT_ELF).encode()
});

const MAINNET_BLOCK: &str = include_str!("../../../vectors/mainnet/block.json");
const MAINNET_PROOF: &str = include_str!("../../../vectors/mainnet/getproof.json");
const MAINNET_RECEIPT: &str = include_str!("../../../vectors/mainnet/receipt-proof.json");
const SEPOLIA_BLOCK: &str = include_str!("../../../vectors/sepolia/block.json");
const SEPOLIA_PROOF: &str = include_str!("../../../vectors/sepolia/getproof.json");

fn run_guest(record: &attest_core::types::HeaderRecord, query: &Query) -> (u64, u64) {
    let self_id = AccountId::new([0x42; 32]);
    let apply_input = ApplyInput {
        self_account_id: self_id,
        selector: ProgramShardSelector::new(self_id, self_id),
        pre_data: ShardData::try_from(borsh::to_vec(record).unwrap()).unwrap(),
        effect_data: borsh::to_vec(&Effect::Check(query.clone())).unwrap(),
    };

    let mut env_builder = ExecutorEnv::builder();
    let kind_bytes = borsh::to_vec(&CallKind::Apply).unwrap();
    let input_bytes = borsh::to_vec(&apply_input).unwrap();

    let kind_len = (kind_bytes.len() as u32).to_le_bytes();
    let input_len = (input_bytes.len() as u32).to_le_bytes();

    env_builder.write_slice(&kind_len);
    env_builder.write_slice(&kind_bytes);
    env_builder.write_slice(&input_len);
    env_builder.write_slice(&input_bytes);

    let env = env_builder.build().expect("build executor env");
    let session = default_executor().execute(env, &GUEST_BINARY).expect("risc0 execution succeeds");
    let user_cycles = session.cycles();
    let total_cycles: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum();
    (user_cycles, total_cycles)
}

fn bench_native(record: &attest_core::types::HeaderRecord, query: &Query) -> f64 {
    let iters = 1000;
    for _ in 0..50 {
        evaluate(record, query).unwrap();
    }
    let start = Instant::now();
    for _ in 0..iters {
        evaluate(record, query).unwrap();
    }
    start.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64)
}

fn main() {
    println!("# RFP-021 Verification Core Empirical Benchmarks\n");
    println!("Platform: x86_64 Linux (CachyOS BORE kernel, znver4)");
    println!("Executor: RISC Zero zkVM 3.0.5 (r0vm)");
    println!("Guest Binary: target/riscv32im-risc0-zkvm-elf/release/attest_prog ({} bytes)\n", GUEST_ELF.len());

    let m_rec = load_header_record(1, MAINNET_BLOCK);
    let m_proof = load_storage_proof(MAINNET_PROOF);
    let q_storage = Query {
        chain_id: 1,
        proof: Proof::Storage(m_proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::SlotValue, Cmp::Eq, [0u8; 32])],
    };

    let m_rcpt = load_receipt_proof(MAINNET_RECEIPT);
    let q_log = Query {
        chain_id: 1,
        proof: Proof::Log(m_rcpt),
        target_slot: None,
        predicates: vec![Predicate::new(Field::LogTopic(0), Cmp::Ne, [0u8; 32])],
    };

    let s_rec = load_header_record(11155111, SEPOLIA_BLOCK);
    let s_proof = load_storage_proof(SEPOLIA_PROOF);
    let q_balance = Query {
        chain_id: 11155111,
        proof: Proof::Storage(s_proof),
        target_slot: None,
        predicates: vec![Predicate::new(Field::AccountBalance, Cmp::Eq, [0u8; 32])],
    };

    let cases = [
        ("Contract Storage Slot", "Canonical Permit2 slot 0", &m_rec, &q_storage),
        ("Transaction Receipt Log", "USDC Transfer log in Tx 0", &m_rec, &q_log),
        ("Account Native Balance", "Sepolia Permit2 balance", &s_rec, &q_balance),
    ];

    println!("| Statement Type | Target Fact | Native Latency | zkVM User Cycles | zkVM Total Cycles | Status |");
    println!("|---|---|---:|---:|---:|---|");

    for (name, fact, rec, q) in &cases {
        let native_us = bench_native(rec, q);
        let (user_cycles, total_cycles) = run_guest(rec, q);
        println!(
            "| {} | {} | {:.2} µs | {} | {} | PASS |",
            name, fact, native_us, user_cycles, total_cycles
        );
    }
    println!("\nVerification completed successfully with zero panics.");
}
