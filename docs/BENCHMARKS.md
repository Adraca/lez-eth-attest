# RFP-021 Verification Core Empirical Benchmarks

Empirical performance measurements of the clean-room consumer verification core (Merkle-Patricia inclusion proofs, predicate evaluations, and deterministic statement ID generation) across real Ethereum Mainnet and Sepolia datasets.

## Benchmark Methodology

All figures reported below were computed live on this machine by executing the guest binary (`attest_prog`, 377,632 bytes, RISC-V 32IM ELF) inside the official RISC Zero zkVM executor (r0vm 3.0.5) and timing native evaluations over 1,000 iterations. No synthetic or hardcoded constants are used.

- **zkVM User Cycles**: The exact number of unpadded user instruction cycles executed by the guest inside the zkVM.
- **zkVM Total Cycles**: Total cycles including power-of-two padding required for STARK proof generation across segments.
- **Native Latency**: Host wall-clock latency for full cryptographic verification on x86_64 CPU.
- **LEZ Gas**: Not measured; requires a deployed LEZ sequencer / fee market context (`lez::chain_state::apply` and `fee_program`) to compute multi-dimensional gas (execution cycles + storage bytes pricing). In the pinned `lee`/`lee_core` (`rev db66590ab8`), `lee::ValidatedStateDiff` meters zkVM execution cycles via `ExecutionCharge` (`lee/state_machine/src/validated_state_diff/mod.rs:67-69`):
  ```rust
  pub struct ExecutionCharge {
      pub cycles: Cycles,
  }
  ```
  where `Cycles = u64` (`lee/state_machine/core/src/account.rs:99-100`). Cycles are raw execution cycles, not gas.

## Exact Command & Machine

- **Machine**: Linux 6.13.6-2-cachyos-bore #1 SMP PREEMPT_DYNAMIC (znver4, x86_64)
- **Toolchain**: rustc 1.99.0 / RISC Zero toolchain 1.97.0 / r0vm 3.0.5 / LEZ v0.3.0
- **Execution Command**:
```console
cargo run --release -p attest-host --bin measure
```

## Raw Output

```text
# RFP-021 Verification Core Empirical Benchmarks

Platform: x86_64 Linux (CachyOS BORE kernel, znver4)
Executor: RISC Zero zkVM 3.0.5 (r0vm)
Guest Binary: target/riscv32im-risc0-zkvm-elf/release/attest_prog (377632 bytes)

| Statement Type | Target Fact | Native Latency | zkVM User Cycles | zkVM Total Cycles | Status |
|---|---|---:|---:|---:|---|
| Contract Storage Slot | Canonical Permit2 slot 0 | 33.08 µs | 3021145 | 3276800 | PASS |
| Transaction Receipt Log | USDC Transfer log in Tx 0 | 7.80 µs | 583702 | 1048576 | PASS |
| Account Native Balance | Sepolia Permit2 balance | 34.06 µs | 2803108 | 3145728 | PASS |

Verification completed successfully with zero panics.
```

## Observations & Analysis

1. **Consumer Verification Feasibility**: All consumer attestations execute in under 35 microseconds natively and require ~583K–3.02M user cycles in the RISC Zero zkVM, well within consumer device capabilities and typical zkVM rollup limits.
2. **Receipt Verification Efficiency**: Transaction receipt log verification requires only 583K cycles and 7.80 µs, benefiting from concise receipt trie traversal (3 MPT nodes) and direct RLP payload slicing.
3. **Storage Slot Proof Cost**: Storage proofs require traversing both the state trie (9 nodes) and the contract storage trie, totaling ~3.02M cycles.

---

## Consensus Anchor (BLS)

Empirical performance measurements of standalone Ethereum light client sync-committee aggregate BLS12-381 signature verification over a real canonical beacon block header (Mainnet slot 15,460,642, period 1887, 512/512 participating pubkeys).

- **Execution Command**:
```console
cargo run --release -p bls-bench --bin bls_measure
```
- **Proving Wall-Clock**: Not measured (full STARK proof generation for ~3.48B cycles without GPU cluster acceleration is deferred to production prover infrastructure).
- **Receipt Size**: Not measured.

### Raw Output

```text
# Ethereum Consensus Anchor (BLS12-381) Empirical Benchmark

Platform: x86_64 Linux (CachyOS BORE kernel, znver4)
Executor: RISC Zero zkVM 3.0.5 (r0vm)
Guest Binary: bls-bench-guest (644448 bytes)

Benchmarking native BLS verification... 48.63 ms
Executing in-zkVM rotate_committee (512 keys per-period)... SUCCESS (527996143 user cycles)
Executing in-zkVM verify_update (512/512 real signers)... SUCCESS (28025168 user cycles)
Benchmarking native stored committee BLS verification... 2.10 ms
Testing synthetic 400/512 bitmap aggregation... MATCH & REJECTED 512-sig (as expected)
Testing synthetic 342/512 (2/3 threshold) bitmap aggregation... MATCH & REJECTED 512-sig (as expected)
Testing negative verification (1 flipped signature bit in zkVM)... REJECTED (as expected)
Testing negative verification (tampered commitment in zkVM)... REJECTED (as expected)

| Benchmark Target | Participating Keys | Native Latency | zkVM User Cycles | zkVM Total Cycles | Status |
|---|---|---:|---:|---:|---|
| Per-Period Committee Rotation (`rotate_committee`) | 512 / 512 | - | 527996143 | 559939584 | PASS |
| Per-Update Verification (`verify_update`) | 512 / 512 | 2.10 ms | 28025168 | 29884416 | PASS |
| Full Monolithic Update (Step 1 accelerated) | 512 / 512 | 48.63 ms | 548443683 | 581042176 | PASS |
| Full Monolithic Update (unaccelerated baseline) | 512 / 512 | 47.97 ms | 3290999909 | 3488088064 | PASS |

Consensus anchor verification completed successfully with 0 panics.
```

### In-zkVM Per-Update Phase Breakdown (512/512 Signers)

| Phase | zkVM User Cycles | % of Total Measured |
|---|---:|---:|
| Commitment re-check (SHA-256 over 49KB) | 3,371,697 | 12.28% |
| Fast aggregation (subtraction optimization) | 14,935 | 0.05% |
| Signing-root SHA-256 | 18,175 | 0.07% |
| hash_to_curve (G2) | 2,879,287 | 10.49% |
| Signature decompression / subgroup check | 3,857,722 | 14.05% |
| Miller loop (multi_miller_loop) | 6,473,116 | 23.58% |
| Final exponentiation | 10,832,464 | 39.47% |
| **Total Measured Phase Cycles** | **27,447,396** | **100.00%** |
| **Total zkVM User Cycles (including runtime)** | **28,025,168** | - |

### Analysis & Consensus Anchor Architecture
1. **Decoupled Architecture Payoff**: By splitting per-period rotation (527.9M cycles, run once per ~27 hours) from per-update verification, per-slot light client verification costs drop from 548M to 28.0M cycles (~19.6x speedup over monolithic accelerated, ~117.6x over unaccelerated baseline) and 2.10 ms native latency.
2. **On-Chain State Footprint**: Only 128 bytes are stored on-chain between rotations (32-byte commitment + 96-byte uncompressed full aggregate pubkey).
3. **Sound Cryptographic Binding**: SHA-256 commitment check guarantees that unchecked deserialization in `verify_update` is strictly protected against invalid curve and twist attacks.


