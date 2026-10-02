//! Regenerates testvectors/segment-record.json. Run once; the file is the contract
//! the gateway checks against, so never regenerate it casually.

use alecto_notary::keys::DeviceKey;
use alecto_notary::record::{canonical_json, Clock, Kind, Record, GENESIS_HASH};

fn main() {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let key = DeviceKey::from_seed(seed);
    let mut first = Record {
        v: 1,
        kind: Kind::Segment,
        device_id: "notary-test".into(),
        key_id: key.key_id(),
        camera_id: "CAM-W01".into(),
        seq: 1,
        start_utc: "2026-10-02T14:03:00.000Z".into(),
        end_utc: "2026-10-02T14:04:00.000Z".into(),
        file: Some("segments/CAM-W01/2026-10-02/140300_1.ts".into()),
        sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()),
        bytes: Some(0),
        reason: None,
        ref_seq: None,
        head_seq: None,
        head_hash: None,
        count: None,
        prev_record_hash: GENESIS_HASH.into(),
        clock: Clock { source: "ntp".into(), skew_ms: Some(400) },
        sig: String::new(),
    };
    key.sign(&mut first).unwrap();
    let first_hash = first.record_hash().unwrap();
    let mut second = first.clone();
    second.seq = 2;
    second.kind = Kind::Gap;
    second.start_utc = "2026-10-02T14:04:00.000Z".into();
    second.end_utc = "2026-10-02T14:05:30.000Z".into();
    second.file = None;
    second.sha256 = None;
    second.bytes = None;
    second.reason = Some("source_unreachable".into());
    second.prev_record_hash = first_hash.clone();
    second.sig = String::new();
    key.sign(&mut second).unwrap();

    let out = serde_json::json!({
        "description": "Contract C2 test vectors. Seed bytes are 1..=32. Implementations must reproduce signing_string, record_hash and sig exactly.",
        "seed_hex": hex::encode(seed),
        "public_key_b64": key.public_b64(),
        "key_id": key.key_id(),
        "records": [first.clone(), second.clone()],
        "vectors": [
            {
                "seq": 1,
                "signing_string": String::from_utf8(first.signing_bytes().unwrap()).unwrap(),
                "record_hash": first_hash,
            },
            {
                "seq": 2,
                "signing_string": String::from_utf8(second.signing_bytes().unwrap()).unwrap(),
                "record_hash": second.record_hash().unwrap(),
            }
        ],
        "canonical_example": {
            "input": {"b": 1, "a": {"d": [1, 2], "c": "x"}},
            "output": canonical_json(&serde_json::json!({"b": 1, "a": {"d": [1, 2], "c": "x"}})),
        }
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
