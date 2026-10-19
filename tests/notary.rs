//! QA matrix N1..N9: recorder, chain, retention, locks, and the store API.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use alecto_notary::api::{router, ApiState};
use alecto_notary::audit::Audit;
use alecto_notary::config::{ensure_loopback, Config};
use alecto_notary::keys::{key_id, parse_public_b64, verify_record, DeviceKey};
use alecto_notary::locks::LockStore;
use alecto_notary::notary::Notary;
use alecto_notary::record::{canonical_json, Kind, Record};
use alecto_notary::retention::{apply, Policy};
use alecto_notary::store::Store;
use alecto_notary::timefmt::parse;
use alecto_notary::verify::{verify_camera, Severity};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const CAM: &str = "CAM-W01";
const TOKEN: &str = "test-token-0123456789abcdef";

fn seed_key() -> DeviceKey {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    DeviceKey::from_seed(seed)
}

fn base() -> DateTime<Utc> {
    parse("2026-10-02T10:00:00.000Z").unwrap()
}

struct Rig {
    dir: TempDir,
    notary: Arc<Notary>,
}

impl Rig {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let notary = Arc::new(Notary::new(
            Store::new(dir.path().join("data")),
            seed_key(),
            "notary-test",
            "ntp",
        ));
        Self { dir, notary }
    }

    fn root(&self) -> &Path {
        &self.notary.store.root
    }

    fn fake_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    /// Seal `n` contiguous 60 s segments starting at `from_minute`.
    fn seal(&self, from_minute: i64, n: i64) -> Vec<Record> {
        (from_minute..from_minute + n)
            .map(|i| {
                let f = self.fake_file(&format!("s{i}.ts"), format!("segment-{i}").as_bytes());
                self.notary
                    .seal_segment(
                        CAM,
                        &f,
                        base() + Duration::minutes(i),
                        base() + Duration::minutes(i + 1),
                        None,
                    )
                    .unwrap()
            })
            .collect()
    }

    fn verify(&self) -> alecto_notary::verify::Report {
        verify_camera(&self.notary.store, CAM, &self.notary.public_key(), true).unwrap()
    }

    fn day_file(&self) -> PathBuf {
        self.notary.store.chain_dir(CAM).join("2026-10-02.jsonl")
    }

    fn locks(&self) -> LockStore {
        LockStore::new(
            self.notary.store.locks_dir(),
            Audit::new(self.notary.store.audit_path()),
        )
    }

    fn audit(&self) -> Audit {
        Audit::new(self.notary.store.audit_path())
    }
}

fn problems(r: &alecto_notary::verify::Report) -> String {
    r.issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| i.problem.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

// N1: contiguous segments, every record signed, chain verifies.
#[test]
fn n1_chain_of_signed_segments_verifies() {
    let rig = Rig::new();
    let recs = rig.seal(0, 5);
    assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    let report = rig.verify();
    assert!(report.ok(), "{}", problems(&report));
    assert_eq!(report.segments, 5);
    assert_eq!(report.gaps, 0);
    // Segment bytes live under segments/, not in the spool.
    assert!(rig.root().join(recs[0].file.as_ref().unwrap()).is_file());
}

// N2: flip one byte in a segment, the verifier names the file.
#[test]
fn n2_tampered_segment_is_named() {
    let rig = Rig::new();
    let recs = rig.seal(0, 3);
    let target = recs[1].file.clone().unwrap();
    let path = rig.root().join(&target);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
    let report = rig.verify();
    assert!(!report.ok());
    assert!(report
        .issues
        .iter()
        .any(|i| i.file.as_deref() == Some(target.as_str()) && i.problem.contains("hash mismatch")));
}

// N3: delete a record from the middle of a chain, the verifier reports the break.
#[test]
fn n3_removed_record_breaks_chain() {
    let rig = Rig::new();
    rig.seal(0, 5);
    let raw = std::fs::read_to_string(rig.day_file()).unwrap();
    let kept: Vec<&str> = raw.lines().enumerate().filter(|(i, _)| *i != 2).map(|(_, l)| l).collect();
    std::fs::write(rig.day_file(), kept.join("\n") + "\n").unwrap();
    // A fresh notary instance reads the tampered file from disk.
    let report = rig.verify();
    assert!(!report.ok());
    let p = problems(&report);
    assert!(p.contains("seq discontinuity"), "{p}");
    assert!(p.contains("chain break"), "{p}");
}

#[test]
fn edited_record_fails_signature() {
    let rig = Rig::new();
    rig.seal(0, 2);
    let raw = std::fs::read_to_string(rig.day_file()).unwrap();
    // Backdate the first segment by an hour.
    let edited = raw.replacen("2026-10-02T10:00:00.000Z", "2026-10-02T09:00:00.000Z", 1);
    assert_ne!(raw, edited);
    std::fs::write(rig.day_file(), edited).unwrap();
    let report = rig.verify();
    assert!(!report.ok());
    assert!(problems(&report).contains("signature does not verify"));
}

#[test]
fn wrong_public_key_fails() {
    let rig = Rig::new();
    rig.seal(0, 2);
    let (other, _) = DeviceKey::generate();
    let report = verify_camera(&rig.notary.store, CAM, &other.public(), true).unwrap();
    assert!(!report.ok());
}

// N4: a time jump becomes an explicit gap record, never silence.
#[test]
fn n4_time_jump_is_recorded_as_gap() {
    let rig = Rig::new();
    rig.seal(0, 1);
    // Next segment starts 3 minutes after the first ended.
    let f = rig.fake_file("late.ts", b"late");
    let rec = rig
        .notary
        .seal_segment(
            CAM,
            &f,
            base() + Duration::minutes(4),
            base() + Duration::minutes(5),
            Some("source_unreachable"),
        )
        .unwrap();
    assert_eq!(rec.seq, 3);
    let chain = rig.notary.store.read_chain(CAM).unwrap();
    assert_eq!(chain[1].kind, Kind::Gap);
    assert_eq!(chain[1].reason.as_deref(), Some("source_unreachable"));
    assert_eq!(chain[1].start_utc, "2026-10-02T10:01:00.000Z");
    assert_eq!(chain[1].end_utc, "2026-10-02T10:04:00.000Z");
    assert!(rig.verify().ok());
}

#[test]
fn small_jitter_is_not_a_gap() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let f = rig.fake_file("next.ts", b"next");
    rig.notary
        .seal_segment(
            CAM,
            &f,
            base() + Duration::minutes(1) + Duration::milliseconds(800),
            base() + Duration::minutes(2),
            None,
        )
        .unwrap();
    assert_eq!(rig.verify().gaps, 0);
}

// N5: retention deletes oldest unlocked segments and the chain still verifies.
#[test]
fn n5_retention_deletes_old_and_records_it() {
    let rig = Rig::new();
    let recs = rig.seal(0, 4);
    let policy = Policy {
        max_age: Duration::minutes(10),
        max_bytes: None,
    };
    // Two hours later every segment is too old.
    let now = base() + Duration::hours(2);
    let out = apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, now).unwrap();
    assert_eq!(out.deleted.len(), 4);
    for r in &recs {
        assert!(!rig.root().join(r.file.as_ref().unwrap()).exists());
    }
    let report = rig.verify();
    assert!(report.ok(), "{}", problems(&report));
    assert_eq!(report.deleted, 4);
    // Deletions are in the audit log too.
    assert_eq!(
        rig.audit().read_all().unwrap().iter().filter(|a| a.action == "retention_delete").count(),
        4
    );
}

#[test]
fn retention_size_cap_removes_oldest_first() {
    let rig = Rig::new();
    let recs = rig.seal(0, 4);
    let per = recs[0].bytes.unwrap();
    let policy = Policy {
        max_age: Duration::days(365),
        max_bytes: Some(per * 2 + 1),
    };
    let out = apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, base() + Duration::minutes(10)).unwrap();
    assert_eq!(out.deleted.iter().map(|d| d.1).collect::<Vec<_>>(), [1, 2]);
    assert!(rig.root().join(recs[3].file.as_ref().unwrap()).exists());
    assert!(rig.verify().ok());
}

// N6: a locked range survives retention.
#[test]
fn n6_locked_range_survives_retention() {
    let rig = Rig::new();
    let recs = rig.seal(0, 4);
    rig.locks()
        .create(
            CAM,
            "2026-10-02T10:01:00.000Z",
            "2026-10-02T10:02:00.000Z",
            "CASE-2026-0001",
            "Jane LP",
            "forced entry",
        )
        .unwrap();
    let policy = Policy {
        max_age: Duration::minutes(10),
        max_bytes: None,
    };
    let out = apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, base() + Duration::hours(2)).unwrap();
    assert_eq!(out.kept_locked, 1);
    assert_eq!(out.deleted.len(), 3);
    assert!(rig.root().join(recs[1].file.as_ref().unwrap()).exists());
    assert!(rig.verify().ok());
}

#[test]
fn unlock_makes_segment_deletable_and_is_audited() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let lock = rig
        .locks()
        .create(CAM, "2026-10-02T10:00:00.000Z", "2026-10-02T10:01:00.000Z", "CASE-2026-0002", "Jane LP", "hold")
        .unwrap();
    let policy = Policy { max_age: Duration::minutes(1), max_bytes: None };
    let later = base() + Duration::hours(1);
    let out = apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, later).unwrap();
    assert_eq!(out.deleted.len(), 0);
    rig.locks().delete(&lock.id, "Jane LP").unwrap();
    let out = apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, later).unwrap();
    assert_eq!(out.deleted.len(), 1);
    let actions: Vec<String> = rig.audit().read_all().unwrap().into_iter().map(|a| a.action).collect();
    assert!(actions.contains(&"lock".to_string()) && actions.contains(&"unlock".to_string()));
}

#[test]
fn lock_validation() {
    let rig = Rig::new();
    let l = rig.locks();
    assert!(l.create(CAM, "2026-10-02T10:02:00Z", "2026-10-02T10:01:00Z", "C", "a", "reason").is_err());
    assert!(l.create(CAM, "2026-10-02T10:00:00Z", "2026-10-02T10:01:00Z", "C", "  ", "reason").is_err());
    assert!(l.create(CAM, "2026-10-02T10:00:00Z", "2026-10-02T10:01:00Z", "C", "a", "x").is_err());
    assert!(l.create("../etc", "2026-10-02T10:00:00Z", "2026-10-02T10:01:00Z", "C", "a", "reason").is_err());
    assert!(l.delete("../../x", "a").is_err());
}

#[test]
fn checkpoint_verifies_and_chain_continues_after_it() {
    let rig = Rig::new();
    rig.seal(0, 3);
    let cp = rig.notary.checkpoint(CAM, base() + Duration::minutes(10)).unwrap();
    assert_eq!(cp.kind, Kind::Checkpoint);
    assert_eq!(cp.head_seq, Some(3));
    assert!(rig.verify().ok());
    // A later segment still chains after the checkpoint and gap detection is unaffected.
    rig.seal(3, 1);
    let report = rig.verify();
    assert_eq!(report.gaps, 0);
    assert!(report.ok());
    assert_eq!(report.checkpoints, 1);
}

#[test]
fn forged_checkpoint_head_is_detected() {
    let rig = Rig::new();
    rig.seal(0, 3);
    let cp = rig.notary.checkpoint(CAM, base() + Duration::minutes(10)).unwrap();
    let raw = std::fs::read_to_string(rig.day_file()).unwrap();
    let forged = raw.replace(cp.head_hash.as_ref().unwrap(), &"a".repeat(64));
    assert_ne!(raw, forged);
    std::fs::write(rig.day_file(), forged).unwrap();
    let report = rig.verify();
    assert!(!report.ok());
    assert!(problems(&report).contains("signature does not verify"));
}

#[test]
fn head_survives_restart() {
    let rig = Rig::new();
    rig.seal(0, 3);
    let fresh = Notary::new(Store::new(rig.root()), seed_key(), "notary-test", "ntp");
    let f = rig.fake_file("more.ts", b"more");
    let rec = fresh
        .seal_segment(CAM, &f, base() + Duration::minutes(3), base() + Duration::minutes(4), None)
        .unwrap();
    assert_eq!(rec.seq, 4);
    assert!(rig.verify().ok());
}

#[test]
fn orphan_files_are_reported_as_warnings() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let orphan = rig.root().join("segments").join(CAM).join("stray.ts");
    std::fs::write(&orphan, b"x").unwrap();
    let report = rig.verify();
    assert!(report.ok());
    assert!(report.issues.iter().any(|i| i.severity == Severity::Warn && i.problem.contains("orphan")));
}

// N9: test vectors shared with the gateway.
#[test]
fn n9_test_vectors_are_reproduced() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/segment-record.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let public = parse_public_b64(v["public_key_b64"].as_str().unwrap()).unwrap();
    assert_eq!(key_id(&public), v["key_id"].as_str().unwrap());
    let ex = &v["canonical_example"];
    assert_eq!(canonical_json(&ex["input"]), ex["output"].as_str().unwrap());
    let records: Vec<Record> = serde_json::from_value(v["records"].clone()).unwrap();
    let mut prev = alecto_notary::record::GENESIS_HASH.to_string();
    for (rec, vec) in records.iter().zip(v["vectors"].as_array().unwrap()) {
        assert_eq!(String::from_utf8(rec.signing_bytes().unwrap()).unwrap(), vec["signing_string"].as_str().unwrap());
        assert_eq!(rec.record_hash().unwrap(), vec["record_hash"].as_str().unwrap());
        assert_eq!(rec.prev_record_hash, prev);
        verify_record(rec, &public).unwrap();
        prev = rec.record_hash().unwrap();
    }
    // Signing the same record again with the same seed gives the same signature (Ed25519 is deterministic).
    let mut again = records[0].clone();
    again.sig = String::new();
    seed_key().sign(&mut again).unwrap();
    assert_eq!(again.sig, records[0].sig);
}

// Store API.

fn api(rig: &Rig) -> axum::Router {
    router(ApiState {
        notary: rig.notary.clone(),
        locks: rig.locks(),
        cameras: vec![CAM.to_string()],
        token: TOKEN.to_string(),
    })
}

async fn call(app: &axum::Router, method: &str, uri: &str, token: Option<&str>, body: Option<serde_json::Value>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes, headers)
}

#[tokio::test]
async fn api_requires_token() {
    let rig = Rig::new();
    let app = api(&rig);
    let (s, _, _) = call(&app, "GET", "/v1/status", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(&app, "GET", "/v1/status", Some("wrong-token-wrong-token"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(&app, "GET", "/v1/status", Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn api_serves_manifest_slice_and_segment_bytes() {
    let rig = Rig::new();
    let recs = rig.seal(0, 2);
    let f = rig.fake_file("late.ts", b"late");
    rig.notary
        .seal_segment(CAM, &f, base() + Duration::minutes(5), base() + Duration::minutes(6), Some("source_unreachable"))
        .unwrap();
    let app = api(&rig);

    let (s, body, _) = call(&app, "GET", &format!("/v1/segments?camera={CAM}&from=2026-10-02T10:00:00Z&to=2026-10-02T10:06:00Z"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kinds: Vec<&str> = v["records"].as_array().unwrap().iter().map(|r| r["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["segment", "segment", "gap", "segment"]);

    // A narrow window returns only what overlaps it.
    let (_, body, _) = call(&app, "GET", &format!("/v1/segments?camera={CAM}&from=2026-10-02T10:00:10Z&to=2026-10-02T10:00:50Z"), Some(TOKEN), None).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 1);

    // The returned records verify on the consumer side.
    let (_, kb, _) = call(&app, "GET", "/v1/pubkey", Some(TOKEN), None).await;
    let kv: serde_json::Value = serde_json::from_slice(&kb).unwrap();
    let public = parse_public_b64(kv["public_key_b64"].as_str().unwrap()).unwrap();
    let (_, body, _) = call(&app, "GET", &format!("/v1/segments?camera={CAM}"), Some(TOKEN), None).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let records: Vec<Record> = serde_json::from_value(v["records"].clone()).unwrap();
    for r in &records {
        verify_record(r, &public).unwrap();
    }

    let (s, bytes, headers) = call(&app, "GET", &format!("/v1/segments/{CAM}/1/file"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bytes, b"segment-0");
    assert_eq!(headers["x-segment-sha256"].to_str().unwrap(), recs[0].sha256.as_ref().unwrap());

    // Gap records have no file.
    let (s, _, _) = call(&app, "GET", &format!("/v1/segments/{CAM}/3/file"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = call(&app, "GET", "/v1/segments/NOPE/1/file", Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_never_serves_paths_outside_the_store() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let app = api(&rig);
    let (s, _, _) = call(&app, "GET", &format!("/v1/segments/{CAM}/1/..%2F..%2Fsecret/file"), Some(TOKEN), None).await;
    assert_ne!(s, StatusCode::OK);
    let (s, _, _) = call(&app, "GET", "/v1/segments?camera=..%2Fchain", Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_deleted_segment_is_404() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let policy = Policy { max_age: Duration::minutes(1), max_bytes: None };
    apply(&rig.notary, &rig.locks(), &rig.audit(), &[CAM.into()], &policy, base() + Duration::hours(1)).unwrap();
    let app = api(&rig);
    let (s, _, _) = call(&app, "GET", &format!("/v1/segments/{CAM}/1/file"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_locks_create_list_delete() {
    let rig = Rig::new();
    rig.seal(0, 1);
    let app = api(&rig);
    let body = serde_json::json!({
        "camera": CAM, "from": "2026-10-02T10:00:00Z", "to": "2026-10-02T10:30:00Z",
        "case_id": "CASE-2026-0007", "actor": "rule:back-door-forced", "reason": "Forced entry"
    });
    let (s, resp, _) = call(&app, "POST", "/v1/locks", Some(TOKEN), Some(body)).await;
    assert_eq!(s, StatusCode::CREATED);
    let lock: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let id = lock["id"].as_str().unwrap().to_string();

    let (_, list, _) = call(&app, "GET", "/v1/locks", Some(TOKEN), None).await;
    let v: serde_json::Value = serde_json::from_slice(&list).unwrap();
    assert_eq!(v["locks"].as_array().unwrap().len(), 1);

    let bad = serde_json::json!({"camera": CAM, "from": "2026-10-02T10:00:00Z", "to": "2026-10-02T09:00:00Z", "case_id": "C", "actor": "a", "reason": "reason"});
    let (s, _, _) = call(&app, "POST", "/v1/locks", Some(TOKEN), Some(bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let unknown = serde_json::json!({"camera": "NOPE", "from": "2026-10-02T10:00:00Z", "to": "2026-10-02T11:00:00Z", "case_id": "C", "actor": "a", "reason": "reason"});
    let (s, _, _) = call(&app, "POST", "/v1/locks", Some(TOKEN), Some(unknown)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, _, _) = call(&app, "DELETE", &format!("/v1/locks/{id}?actor=Jane"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(&app, "DELETE", &format!("/v1/locks/{id}?actor=Jane"), Some(TOKEN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// Config.

fn cfg_yaml(camera_extra: &str) -> String {
    format!(
        "device_id: notary-test\nroot: ./data\nkey_file: ./data/device.key\ncameras:\n  - id: CAM-W01\n    uri: rtsp://192.168.1.64/s\n{camera_extra}"
    )
}

#[test]
fn config_accepts_minimal_and_rejects_bad_input() {
    let ok: Config = serde_yaml::from_str(&cfg_yaml("")).unwrap();
    ok.validate().unwrap();

    // Plaintext password field does not exist: unknown field is an error.
    assert!(serde_yaml::from_str::<Config>(&cfg_yaml("    password: hunter2\n")).is_err());

    let creds: Config = serde_yaml::from_str(&cfg_yaml("").replace("rtsp://192.168.1.64/s", "rtsp://admin:pw@192.168.1.64/s")).unwrap();
    assert!(creds.validate().unwrap_err().to_string().contains("credentials in uri"));

    let dup: Config = serde_yaml::from_str(&format!("{}  - id: CAM-W01\n    uri: rtsp://x/y\n", cfg_yaml(""))).unwrap();
    assert!(dup.validate().unwrap_err().to_string().contains("duplicate"));

    let bad_id: Config = serde_yaml::from_str(&cfg_yaml("").replace("CAM-W01", "../x")).unwrap();
    assert!(bad_id.validate().is_err());
}

#[test]
fn api_bind_must_be_loopback() {
    assert!(ensure_loopback(&"127.0.0.1:8081".parse().unwrap()).is_ok());
    assert!(ensure_loopback(&"[::1]:8081".parse().unwrap()).is_ok());
    assert!(ensure_loopback(&"0.0.0.0:8081".parse().unwrap()).is_err());
    assert!(ensure_loopback(&"192.168.1.5:8081".parse().unwrap()).is_err());
}

#[test]
fn device_key_is_never_overwritten() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("device.key");
    let a = DeviceKey::create_file(&path).unwrap();
    assert!(DeviceKey::create_file(&path).is_err());
    let b = DeviceKey::load(&path).unwrap();
    assert_eq!(a.key_id(), b.key_id());
}
