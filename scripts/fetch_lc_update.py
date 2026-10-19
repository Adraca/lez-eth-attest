#!/usr/bin/env python3
"""Fetch a canonical Ethereum light-client update from a public Beacon API.

Source URL: https://lodestar-mainnet.chainsafe.io
Endpoints:
  - /eth/v1/beacon/light_client/finality_update
  - /eth/v1/beacon/blocks/{slot}/root
  - /eth/v1/beacon/light_client/bootstrap/{finalized_root}
  - /eth/v1/beacon/genesis
  - /eth/v1/beacon/states/{slot}/fork
"""

import hashlib
import json
import os
import urllib.request

BEACON_BASE = "https://lodestar-mainnet.chainsafe.io"
HEADERS = {"User-Agent": "RFP-021-Cleanroom-BLS-Benchmark/1.0"}


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ssz_beacon_header_root(header: dict) -> bytes:
    slot = int(header["slot"])
    proposer_index = int(header["proposer_index"])
    parent_root = bytes.fromhex(header["parent_root"][2:])
    state_root = bytes.fromhex(header["state_root"][2:])
    body_root = bytes.fromhex(header["body_root"][2:])

    leaf0 = slot.to_bytes(8, "little") + b"\x00" * 24
    leaf1 = proposer_index.to_bytes(8, "little") + b"\x00" * 24
    leaf2 = parent_root
    leaf3 = state_root
    leaf4 = body_root
    leaf5 = b"\x00" * 32
    leaf6 = b"\x00" * 32
    leaf7 = b"\x00" * 32

    n0 = sha256(leaf0 + leaf1)
    n1 = sha256(leaf2 + leaf3)
    n2 = sha256(leaf4 + leaf5)
    n3 = sha256(leaf6 + leaf7)

    n01 = sha256(n0 + n1)
    n23 = sha256(n2 + n3)
    return sha256(n01 + n23)


def compute_signing_root(
    header_root: bytes,
    fork_version: bytes,
    genesis_validators_root: bytes,
) -> tuple[bytes, bytes]:
    # Domain type for sync committee: DOMAIN_SYNC_COMMITTEE = 0x07000000
    domain_type = bytes([7, 0, 0, 0])
    fork_version_chunk = fork_version + b"\x00" * 28
    fork_data_root = sha256(fork_version_chunk + genesis_validators_root)
    domain = domain_type + fork_data_root[:28]
    signing_root = sha256(header_root + domain)
    return domain, signing_root


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read().decode("utf-8"))


def main():
    print(f"Fetching finality update from {BEACON_BASE}...")
    fin_data = fetch_json(f"{BEACON_BASE}/eth/v1/beacon/light_client/finality_update")["data"]
    attested_beacon = fin_data["attested_header"]["beacon"]
    finalized_beacon = fin_data["finalized_header"]["beacon"]
    sync_aggregate = fin_data["sync_aggregate"]

    attested_slot = int(attested_beacon["slot"])
    finalized_slot = int(finalized_beacon["slot"])
    print(f"Attested slot: {attested_slot}, Finalized slot: {finalized_slot}")

    # Fetch block root of finalized block to bootstrap sync committee
    finalized_root = fetch_json(f"{BEACON_BASE}/eth/v1/beacon/blocks/{finalized_slot}/root")["data"]["root"]
    print(f"Finalized block root: {finalized_root}")

    bootstrap_data = fetch_json(f"{BEACON_BASE}/eth/v1/beacon/light_client/bootstrap/{finalized_root}")["data"]
    committee_pubkeys = bootstrap_data["current_sync_committee"]["pubkeys"]
    print(f"Loaded {len(committee_pubkeys)} sync committee pubkeys")

    genesis_data = fetch_json(f"{BEACON_BASE}/eth/v1/beacon/genesis")["data"]
    genesis_validators_root = genesis_data["genesis_validators_root"]
    print(f"Genesis validators root: {genesis_validators_root}")

    epoch = attested_slot // 32
    # Fork schedule for Mainnet:
    # Altair: 74240 (0x01000000), Bellatrix: 144896 (0x02000000), Capella: 194048 (0x03000000),
    # Deneb: 269568 (0x04000000), Electra: 364032 (0x05000000), Fulu: 411392 (0x06000000)
    if epoch >= 411392:
        fork_version = "0x06000000"
    elif epoch >= 364032:
        fork_version = "0x05000000"
    elif epoch >= 269568:
        fork_version = "0x04000000"
    elif epoch >= 194048:
        fork_version = "0x03000000"
    else:
        fork_version = "0x02000000"
    print(f"Fork version for slot {attested_slot} (epoch {epoch}): {fork_version}")

    header_root = ssz_beacon_header_root(attested_beacon)
    domain, signing_root = compute_signing_root(
        header_root,
        bytes.fromhex(fork_version[2:]),
        bytes.fromhex(genesis_validators_root[2:]),
    )

    out = {
        "source_api": f"{BEACON_BASE}/eth/v1/beacon/light_client/finality_update",
        "attested_slot": attested_slot,
        "attested_header": attested_beacon,
        "header_root": f"0x{header_root.hex()}",
        "sync_aggregate": sync_aggregate,
        "current_sync_committee_pubkeys": committee_pubkeys,
        "genesis_validators_root": genesis_validators_root,
        "fork_version": fork_version,
        "domain": f"0x{domain.hex()}",
        "signing_root": f"0x{signing_root.hex()}",
    }

    out_dir = os.path.join(os.path.dirname(__file__), "..", "vectors", "beacon")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "lc_update.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"Saved canonical light-client update vector to {out_path}")
    print(f"Attested slot: {attested_slot}")
    print(f"Header root: 0x{header_root.hex()}")
    print(f"Signing root: 0x{signing_root.hex()}")


if __name__ == "__main__":
    main()
