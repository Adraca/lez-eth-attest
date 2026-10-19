# Third-Party Dependencies & Reused Code

All external libraries and frameworks used in this prototype are audited, permissively licensed open-source crates.

| Component / Crate | Version / Git Rev | Source Repository / URL | License | Purpose |
|---|---|---|---|---|
| `alloy-trie` | `=0.9.8` | https://github.com/alloy-rs/trie | MIT OR Apache-2.0 | Audited Ethereum Merkle-Patricia Trie verification |
| `alloy-rlp` | `=0.3.16` | https://github.com/alloy-rs/rlp | MIT OR Apache-2.0 | Audited Ethereum RLP encoding & decoding |
| `alloy-primitives` | `=1.7.3` | https://github.com/alloy-rs/core | MIT OR Apache-2.0 | Common Ethereum types (`B256`, `Bytes`, `U256`) |
| `nybbles` | `=0.4.8` | https://github.com/alloy-rs/nybbles | MIT OR Apache-2.0 | Nibbles conversion for trie paths |
| `lee_core` / `lee` | `db66590ab8` | https://github.com/logos-blockchain/logos-execution-zone | MIT OR Apache-2.0 | Logos Execution Zone v0.3 state machine & program types |
| `risc0-zkvm` | `=3.0.5` | https://github.com/risc0/risc0 | Apache-2.0 | RISC Zero zkVM guest/host execution environment |
| `sha2` (zkVM patch) | `sha2-v0.10.8-risczero.0` | https://github.com/risc0/RustCrypto-hashes | MIT OR Apache-2.0 | RISC Zero guest-accelerated SHA-256 implementation |
| `tiny-keccak` (zkVM patch) | `v2.0.2-risczero.0` | https://github.com/risc0/tiny-keccak | CC0-1.0 / Apache-2.0 | RISC Zero guest-accelerated Keccak-256 implementation |
| `borsh` | `1.5` | https://github.com/near/borsh-rs | MIT OR Apache-2.0 | Canonical binary serialization for SPEL data structures |
| `serde` / `serde_json` | `1.0` | https://github.com/serde-rs/serde | MIT OR Apache-2.0 | Off-chain JSON vector loading |
| `bls12_381` | `0.8.0` | https://github.com/zkcrypto/bls12_381 | MIT OR Apache-2.0 | BLS12-381 pairing-friendly elliptic curve construction |
| `bls12_381` (zkVM patch) | `bls12_381/v0.8.0-risczero.1` | https://github.com/risc0/zkcrypto-bls12_381 | MIT OR Apache-2.0 | RISC Zero guest-accelerated BLS12-381 elliptic curve arithmetic |

## Prior Art (read, not used)

The following repositories were examined for consensus architecture patterns and SSZ/BLS reference structures, but are not linked dependencies of the prototype:

| Component / Project | Version / Git Rev | Source Repository / URL | License | Notes |
|---|---|---|---|---|
| `helios-consensus-core` | `0.8.3` | https://github.com/a16z/helios | MIT | Ethereum consensus BLS verification & SSZ tree hash logic reference |
| `r0vm-helios` | `463ff8d` | https://github.com/boundless-xyz/r0vm-helios | MIT | Boundless RISC Zero zkVM Ethereum light client architecture reference |

No code or test vectors from uncredited third parties are included.
