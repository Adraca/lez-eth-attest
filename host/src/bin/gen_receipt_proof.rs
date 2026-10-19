use alloy_primitives::Bytes;
use alloy_rlp::{Encodable, Header};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::HashBuilder;
use nybbles::Nibbles;
use serde_json::{json, Value};
use std::env;
use std::fs;

fn rlp_list(items: &[&[u8]]) -> Vec<u8> {
    let payload_length: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::new();
    Header { list: true, payload_length }.encode(&mut out);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bytes.encode(&mut out);
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: gen_receipt_proof <receipts.json> <tx_index> <output.json>");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let tx_index: u64 = args[2].parse().expect("valid tx_index");
    let output_path = &args[3];

    let data = fs::read_to_string(input_path).expect("read receipts json");
    let receipts: Vec<Value> = serde_json::from_str(&data).expect("parse receipts json");

    let mut leaves: Vec<(Nibbles, Vec<u8>)> = Vec::new();
    for (i, r) in receipts.iter().enumerate() {
        let mut key_bytes = Vec::new();
        (i as u64).encode(&mut key_bytes);
        let key = Nibbles::unpack(Bytes::from(key_bytes));

        let status = u64::from_str_radix(r["status"].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap();
        let cum_gas = u64::from_str_radix(r["cumulativeGasUsed"].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap();
        let bloom = hex::decode(r["logsBloom"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();

        let mut logs_encoded: Vec<Vec<u8>> = Vec::new();
        for log in r["logs"].as_array().unwrap() {
            let addr = hex::decode(log["address"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
            let mut topics_encoded: Vec<Vec<u8>> = Vec::new();
            for topic in log["topics"].as_array().unwrap() {
                let t = hex::decode(topic.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
                topics_encoded.push(rlp_bytes(&t));
            }
            let data = hex::decode(log["data"].as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();

            let addr_enc = rlp_bytes(&addr);
            let topics_slices: Vec<&[u8]> = topics_encoded.iter().map(|t| t.as_slice()).collect();
            let topics_list_enc = rlp_list(&topics_slices);
            let data_enc = rlp_bytes(&data);

            let log_enc = rlp_list(&[&addr_enc, &topics_list_enc, &data_enc]);
            logs_encoded.push(log_enc);
        }

        let mut status_buf = Vec::new();
        status.encode(&mut status_buf);
        let mut cum_gas_buf = Vec::new();
        cum_gas.encode(&mut cum_gas_buf);
        let bloom_enc = rlp_bytes(&bloom);

        let logs_slices: Vec<&[u8]> = logs_encoded.iter().map(|l| l.as_slice()).collect();
        let logs_list_enc = rlp_list(&logs_slices);

        let body_buf = rlp_list(&[&status_buf, &cum_gas_buf, &bloom_enc, &logs_list_enc]);

        let tx_type = u8::from_str_radix(r["type"].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap();
        let mut final_receipt = Vec::new();
        if tx_type != 0 {
            final_receipt.push(tx_type);
        }
        final_receipt.extend(body_buf);

        leaves.push((key, final_receipt));
    }

    leaves.sort_by(|a, b| a.0.cmp(&b.0));

    let mut target_key_bytes = Vec::new();
    tx_index.encode(&mut target_key_bytes);
    let target_key = Nibbles::unpack(Bytes::from(target_key_bytes));

    let retainer = ProofRetainer::from_iter([target_key]);
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);
    for (k, v) in &leaves {
        hb.add_leaf(*k, v);
    }
    let root = hb.root();

    let proof_nodes = hb.take_proof_nodes().matching_nodes_sorted(&target_key);
    let proof_hex: Vec<String> = proof_nodes.iter().map(|(_, n)| format!("0x{}", hex::encode(n))).collect();

    let out_json = json!({
        "tx_index": tx_index,
        "receipts_root": format!("0x{}", hex::encode(root.0)),
        "proof": proof_hex
    });

    fs::write(output_path, serde_json::to_string_pretty(&out_json).unwrap()).expect("write proof json");
    println!("Wrote receipt proof to {} (root 0x{}, {} nodes)", output_path, hex::encode(root.0), proof_nodes.len());
}
