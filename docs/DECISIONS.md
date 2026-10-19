# Architectural & Design Decisions

This document records the architectural and design decisions made for the RFP-021 LEZ Ethereum State Attestation prototype.

---

## 1. Scope: State & Event Attestation Core
- **Context:** RFP-021 requires verifying Ethereum state and emitting verifiable statements in LEZ. The BLS sync committee light client verification is computationally heavy and tracked separately by consensus anchors.
- **Decision:** Scope this prototype to state & event attestation: Merkle-Patricia Trie (MPT) inclusion proofs, declarative predicate evaluations, chain/network binding, deterministic statement IDs, and reference consumers.
- **Rationale:** The light client anchor supplies a trusted `HeaderRecord` (block hash, number, state root, receipts root). Focusing on consumer UX, nullifiers, and cycle efficiency directly unblocks application integrations.

---

## 2. Audited Verification: Alloy Trie & Alloy RLP
- **Context:** Hand-rolled MPT and RLP parsers risk subtle edge-case vulnerabilities (divergence on branch/extension nodes, non-canonical RLP encodings, malformed nibble prefixes).
- **Decision:** Use audited, community-standard crates from the Alloy / Paradigm project (`alloy-trie` pinned at `=0.9.8` with `ethereum` feature, and `alloy-rlp` pinned at `=0.3.16`), configured with `default-features = false` for strict `no_std` execution.
- **Rationale:** `alloy-trie::proof::verify_proof` rigorously validates cryptographic proof paths against target roots, supports both inclusion and exclusion proofs, and handles branch, extension, and leaf encodings according to Ethereum consensus rules. Our codebase implements only the query, predicate, and statement binding layer.

---

## 3. Structured 4-Digit Error Code Scheme
- **Context:** Generic error codes or derivative offset schemes make debugging ambiguous and fail to distinguish input validation from cryptographic proof failure.
- **Decision:** Design a domain-partitioned 4-digit error scheme:
  - `31xx`: Input Validation & Encoding (`3101: MalformedInput`)
  - `32xx`: Consensus Anchor & Binding (`3201: HeaderNotFinalized`, `3202: ChainIdMismatch`, `3203: HeaderMismatch`)
  - `33xx`: MPT & Inclusion Proofs (`3301: ProofVerificationFailed`, `3302: SlotMismatch`)
  - `34xx`: Predicate Evaluation (`3401: PredicateUnsatisfied`, `3402: TxExecutionReverted`)
  - `35xx`: LEZ Program State Machine (`3501: AccountCountMismatch`, `3502: InstanceAlreadyInitialized`, `3503: HeaderRecordNotFound`)
- **Rationale:** Provides clear subsystem diagnostic separation, supports deterministic zkVM aborts with explicit error identifiers, and eliminates magic base constants.

---

## 4. Deterministic Statement ID Derivation
- **Context:** Reference consumers need collision-resistant identifiers to register nullifiers and guard against replay attacks across chains, blocks, or differing queries (F#5, F#6).
- **Decision:** Compute `statement_id = SHA256(b"attest/statement/v1" || chain_id || block_hash || block_number || proof_kind || query_fields || attested_values)`.
- **Rationale:** Binds the statement to both chain ID and specific block headers. If the same contract address exists on both Sepolia and Mainnet, statements remain strictly segregated.
- **Account nonce is included** in the attested values for storage/account statements. It is fixed by the block's state root, so the ID stays deterministic: the same fact at the same block always yields the same ID.
- **The light-client instance ID is deliberately excluded.** The spec ("Uniqueness is the consumer's job") requires an identifier "derived from the attested state itself", so that two consumers never derive incompatible identifiers from the same event. Binding the instance would give the same Ethereum event a different ID under each instance on the same chain, letting a consumer that trusts two instances act on one event twice. Chain binding is already carried by `chain_id` and `block_hash`.
- **Consumer guidance:** a log statement identifies one event (block, tx index, log index), so it is the right key for once-only actions such as a bridge mint. A storage/account statement identifies a state at a block; the same balance attested at a later block gets a different ID, so it must not be used as a once-only nullifier.

---

## 5. Empty Storage Root Semantics
- **Context:** Ethereum accounts without storage slots have `storageRoot = 0x56e81f171bcc...` (`alloy_trie::EMPTY_ROOT_HASH`).
- **Decision:** If an account has `EMPTY_ROOT_HASH` and an empty storage proof is supplied, return `[0u8; 32]` for the slot value.
- **Rationale:** Avoids requiring non-membership trie proofs for uninitialized storage slots in newly deployed or stateless accounts.

---

## 6. Standalone BLS12-381 Consensus Anchor Library Choice
- **Context:** Verifying Ethereum consensus finality requires aggregating participating sync-committee public keys (G1), hashing the signing root to curve (G2), and verifying the aggregate signature via a BLS12-381 pairing check.
- **Decision:** Use pure-Rust `bls12_381` (`v0.8.0`) with `sha2` (`v0.9`). We evaluated RISC Zero's patched `bls12_381` (`https://github.com/risc0/zkcrypto-bls12_381`), but its `risc0-bigint2` dependency (`v1.4.0-rc.2`) was pinned to older risc0 toolchains (1.x/2.x) and has breaking API divergence with `risc0-zkvm = "=3.0.5"`. `blst` relies on C/assembly requiring cross-compilation toolchains on `riscv32im-risc0-zkvm-elf`.
- **Rationale:** Pure-Rust `bls12_381` is audited (NCC Group/Zcash Foundation), 100% portable, builds cleanly for `riscv32im-risc0-zkvm-elf` without C toolchains, and executes verified in-zkVM sessions (3.29B user cycles, 3.48B total cycles). Prior art from `r0vm-helios` demonstrates the same architectural pattern.

---

## 7. LP-0012 Structured Event Emission
- **Context:** Off-chain indexing infrastructure needs structured logs to detect state updates and attestations without expensive polling.
- **Decision:** Conform strictly to canonical LEZ event architecture:
  - Selectors: First 8 bytes of `sha256("<namespace>::<EventName>")`.
  - Data payload: Borsh-serialized event structs.
  - Emission: In `plan()` via `plan.event(ProgramEvent { selector, data })`.
  - Events: `attest::HeaderRecordAccepted`, `attest::AttestationRecorded`, and `attest::CommitteeHandoff`.
- **Citation:** `lez/programs/bridge/core/src/event.rs:12-24` and `lee_core::program::Plan::event` (`lee/state_machine/core/src/program/mod.rs:757`).

---

## 8. zkVM Abort Semantics & Typed Error Handling (try_apply)
- **Context:** Audit minor #6 noted `apply()` used `panic!` rather than returning structured error codes.
- **Decision:** Provide a dual-layer error architecture:
  - `try_apply(effect, pre) -> Result<Option<Vec<u8>>, AttestError>` returns structured 31xx–35xx error codes for off-chain dry-run simulation and unit testing.
  - `apply(effect, pre)` delegates to `try_apply` and panics with the structured error code upon failure (`panic!("Error: {}", err)`).
- **Rationale & Citation:** In LEZ v0.3 (`lee_core::program::run_program`, cited at `lee/state_machine/core/src/program/mod.rs:814-841`), the `apply` callback has signature `FnOnce(E, &P) -> Option<D>`. It has no error channel. The LEZ state machine documentation explicitly mandates: *"A panic fails the transaction."* (line 814). Aborting execution on invalid state transitions is therefore structurally required by the LEZ circuit; `try_apply` preserves typed diagnostics for off-chain runners.

---

## 9. Safety Argument: Unchecked Deserialization via Committee Commitment Binding
- **Context:** Profiling proved pubkey decompression + subgroup checks consume 518.7M cycles (94.61% of verification). Decompressing and subgroup-checking 512 pubkeys on every slot update is prohibitive.
- **Decision:** Split consensus anchor into two entrypoints:
  1. `rotate_committee` (per-period, ~27h): Fully decompresses and subgroup-checks all 512 pubkeys using `G1Affine::from_compressed`. Precomputes `full_aggregate` and commits to `SHA256(full_aggregate || pubkeys[0..512])`.
  2. `verify_update` (per-update): Accepts the stored uncompressed pubkeys (`[u8; 96]`) and `full_aggregate`, re-checks `SHA256(full_aggregate || pubkeys[0..512]) == commitment`, and deserializes points with `G1Affine::from_uncompressed_unchecked`.
- **Safety Argument & Attack Surface:**
  - *Risk*: `from_uncompressed_unchecked` skips checking $y^2 = x^3 + 4$ and $r \cdot P = \mathcal{O}$. Malicious points not in the prime-order subgroup could enable small-subgroup or twist attacks, permitting signature forgery.
  - *Mitigation*: The commitment $C$ is computed exclusively over points validated by `from_compressed` in `rotate_committee`. By the collision resistance of SHA-256 (256-bit security), an attacker cannot substitute alternative point bytes that match $C$.
  - *Coordinate Validity*: `from_uncompressed_unchecked` still enforces canonical finite field bounds ($x, y < p$).
  - *Abort Guarantee*: Any tampering with pubkeys, full aggregate, or commitment causes a zkVM assertion panic and aborts transaction execution.
- **Verification & Negative Tests**: Verified via unit tests (`test_stored_committee_negative_tampered_pubkey`, `test_stored_committee_negative_tampered_commitment`, `test_stored_committee_negative_tampered_full_aggregate`) and in-zkVM execution, where single-bit tampered commitments or keys are strictly rejected.


