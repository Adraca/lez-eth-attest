# Ethereum State Attestation in LEZ (RFP-021)

A clean-room, production-grade prototype for verifying Ethereum state and transaction receipts on the Logos Execution Zone (LEZ v0.3) using RISC Zero zkVM and audited Alloy trie verification.

---

## Capabilities & What Works

- **Audited MPT Inclusion Verification:**
  - Account storage slot proofs via `eth_getProof` (Ethereum execution state root) using pinned `alloy-trie` and `alloy-rlp`.
  - Transaction receipt log proofs via Merkle-Patricia Trie traversal (Ethereum receipts root).
  - Empty storage root handling for accounts without storage.
- **Consumer-Configurable Predicates (F#4):**
  - Flexible assertion engine over account balance, nonce, storage slot value, log topics, and log data words without modifying the guest program.
- **Chain & Block Binding (F#5):**
  - Strict binding to `chain_id`, `block_hash`, and `block_number`. Rejects cross-chain replay between Sepolia and Mainnet.
- **Deterministic Statement IDs (F#6):**
  - Collision-resistant 32-byte identifier (`SHA-256`) derived from chain ID, block metadata, query kind, target key, and attested value.
- **Reference Consumers:**
  - `ERC20Consumer`: Verifies ERC-20 `Transfer` events and tracks nullifiers against duplicate processing.
  - `EthBalanceConsumer`: Verifies native ETH minimum balance thresholds and consumes statement nullifiers.
- **Measured zkVM Cycles & LEZ Gas:**
  - Evaluated on real Ethereum Mainnet and Sepolia blocks under RISC Zero zkVM 3.0.5 (`r0vm`) executor.
  - User instruction cycles range from 1.48M (receipt log) to 3.02M (storage slot). Real benchmarks documented in `docs/BENCHMARKS.md`.

---

## What Is Stubbed

- **Beacon Light-Client Header Verification (Spec F#9):**
  - This prototype implements the immutable light-client instance lifecycle and weak-subjectivity initialization entrypoint (`bootstrap_from_checkpoint` per F#9), rejecting second initializations.
  - Header verification behind it is currently stubbed: the program accepts trusted `HeaderRecord` inputs directly, storing them into deterministic PDAs.
  - Standalone in-zkVM BLS12-381 sync committee verification is implemented and empirically benchmarked in the separate `bls-bench/` crate. Full light-client consensus verification in-program will be integrated during Milestone M1.
- **LP-0012 Structured Events:**
  - Emits canonical LP-0012 events on `plan()`: `HeaderRecordAccepted`, `AttestationRecorded`, and `CommitteeHandoff` (8-byte selectors derived from sha256). Off-chain indexers consume these events directly without polling.

---

## Target LEZ Version & Roadmap to 0.4 (Audit Minor #7)

- **Current Target (v0.3.1)**:
  - This prototype builds against and targets the latest published release of the Logos Execution Zone: **LEZ v0.3.1** (Git rev `db66590ab821a4e142c211017a3866d007f6fa77`).
  - As verified on the official LEZ release repository ([logos-blockchain/logos-execution-zone/releases](https://github.com/logos-blockchain/logos-execution-zone/releases)), `v0.3.1` (published October 11, 2026) is the latest release; LEZ testnet 0.4 is currently unreleased.
- **What Changes for Testnet 0.4**:
  - **Dependency Upgrade**: Update `lee` and `lee_core` dependency pins in `Cargo.toml` from Git commit `db66590` to the official `v0.4.0` release tag.
  - **Account/Effect API Adaptation**: Reconcile any changes to `PlanInput`/`PlanOutput` or `ApplyOutput` reserved fields (such as apply-time chained call semantics).
  - **Sequencer & Network Deployment**: Point CLI deployment harnesses and RPC providers to the public testnet 0.4 sequencer cluster, replacing local standalone test runner harnesses.

---

## Consensus Anchor (BLS)

Standalone in-zkVM Ethereum light-client sync committee BLS12-381 verification core (`bls-bench/`):
- **Per-Update Cost (`verify_update`)**: 28,025,168 user cycles (29,884,416 total cycles), 2.10 ms native latency on 512/512 signers.
- **Per-Period Cost (`rotate_committee`)**: 527,996,143 user cycles (559,939,584 total cycles), executed once per 8,192 slots (~27 hours).
- **On-Chain State Footprint**: 128 bytes between rotations (32-byte SHA-256 commitment with `b"SYNC_COMMITTEE_COMMITMENT_V1"` domain separator + 96-byte uncompressed full aggregate pubkey).
- **What Is Still Stubbed**: Cryptographic verification of initial weak-subjectivity checkpoints (currently validated via immutable instance initialization rules per F#9), multi-period handoff transition chaining (scheduled for Milestone M1), and live fee-market sequencer gas charging (Milestone M4).

---

## Reproduce & Run

### 1. Run Workspace Tests
Runs all unit, integration, cross-chain, BLS, adversarial MPT, and consumer tests:
```bash
cargo test --workspace
```

### 2. Measure State Attestation Cycles & Latency
Runs empirical benchmarks inside RISC Zero zkVM executor on real test vectors:
```bash
cargo run --release -p attest-host --bin measure
```

### 3. Measure Consensus Anchor (BLS)
Runs empirical in-zkVM benchmarks for committee rotation and slot update verification:
```bash
cargo run --release -p bls-bench --bin bls_measure
```

---

## Workspace Structure

- `core/` (`attest-core`): `no_std` MPT verification adapter, predicate engine, statement IDs, and 4-digit error scheme.
- `program/` (`attest-program`): LEZ v0.3 zkVM guest entrypoint implementing canonical `plan`/`apply`.
- `host/` (`attest-host`): Test harness, receipt proof generator (`gen_receipt_proof`), and benchmark runner (`measure`).
- `consumers/` (`attest-consumers`): Reference application consumers with statement nullifier replay protection.
- `vectors/`: Real Mainnet (Permit2 slot 0, USDC transfer) and Sepolia test vectors.
- `docs/`: Measured cycle benchmarks (`BENCHMARKS.md`) and architectural choices (`DECISIONS.md`).
- `THIRD_PARTY.md`: Attributions and licenses for reused crates and tools.

---

## Licensing

Licensed under either of:
- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)
