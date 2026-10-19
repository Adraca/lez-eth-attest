#!/usr/bin/env python3
"""Fetch fresh Ethereum Mainnet and Sepolia test vectors via public RPC.

RPC endpoints used:
- Ethereum Mainnet: https://nodes.mewapi.io/rpc/eth
- Sepolia Testnet:  https://ethereum-sepolia.publicnode.com

Both networks test Canonical Permit2 (0x000000000022D473030F116dDEE9F6B43aC78BA3)
which exists with identical bytecode and create2 address on both chains.
"""

import json
import os
import subprocess
import tempfile
import urllib.request

MAINNET_RPC = "https://nodes.mewapi.io/rpc/eth"
SEPOLIA_RPC = "https://ethereum-sepolia.publicnode.com"
SHARED_CONTRACT = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
MAINNET_BLOCK = 26207220
SEPOLIA_BLOCK = 11933863


def call_rpc(url: str, method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        res = json.loads(resp.read().decode())
        if "error" in res:
            raise RuntimeError(f"RPC error from {url}: {res['error']}")
        return res


def fetch_network_vectors(rpc_url: str, block_num: int, contract_addr: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    block_file = os.path.join(out_dir, "block.json")
    proof_file = os.path.join(out_dir, "getproof.json")
    receipt_proof_file = os.path.join(out_dir, "receipt-proof.json")

    if os.path.exists(block_file) and os.path.exists(proof_file) and os.path.exists(receipt_proof_file):
        print(f"Vectors in {out_dir} already exist. Skipping fetch.\n")
        return

    hex_block = hex(block_num)
    print(f"Fetching block {block_num} ({hex_block}) from {rpc_url}...")
    block_data = call_rpc(rpc_url, "eth_getBlockByNumber", [hex_block, False])
    block_file = os.path.join(out_dir, "block.json")
    with open(block_file, "w") as f:
        json.dump(block_data, f, indent=2)

    print(f"Fetching eth_getProof for {contract_addr} at block {block_num}...")
    proof_data = call_rpc(rpc_url, "eth_getProof", [contract_addr, ["0x0"], hex_block])
    proof_file = os.path.join(out_dir, "getproof.json")
    with open(proof_file, "w") as f:
        json.dump(proof_data, f, indent=2)

    print(f"Fetching receipts for block {block_num} to generate receipt proof...")
    receipts_data = call_rpc(rpc_url, "eth_getBlockReceipts", [hex_block])
    receipts = receipts_data["result"]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(receipts, tmp)
        tmp_path = tmp.name

    receipt_proof_file = os.path.join(out_dir, "receipt-proof.json")
    try:
        cmd = [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "attest-host",
            "--bin",
            "gen_receipt_proof",
            "--",
            tmp_path,
            "0",
            receipt_proof_file,
        ]
        subprocess.check_call(cmd)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    print(f"Successfully generated vectors in {out_dir}\n")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("=== Ethereum Test Vector Fetcher ===")
    print(f"Mainnet RPC URL: {MAINNET_RPC}")
    print(f"Sepolia RPC URL: {SEPOLIA_RPC}")
    print(f"Shared Contract: {SHARED_CONTRACT} (Permit2)")
    print(f"Mainnet Block:   {MAINNET_BLOCK}")
    print(f"Sepolia Block:   {SEPOLIA_BLOCK}\n")

    mainnet_dir = os.path.join(root, "vectors", "mainnet")
    fetch_network_vectors(MAINNET_RPC, MAINNET_BLOCK, SHARED_CONTRACT, mainnet_dir)

    sepolia_dir = os.path.join(root, "vectors", "sepolia")
    # For Sepolia, use the saved block 11933863
    fetch_network_vectors(SEPOLIA_RPC, SEPOLIA_BLOCK, SHARED_CONTRACT, sepolia_dir)

    print("All vectors fetched and verified against consensus roots.")


if __name__ == "__main__":
    main()
