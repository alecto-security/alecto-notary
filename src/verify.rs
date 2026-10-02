//! Chain verification. Used by the CLI and mirrored (not imported) by the gateway.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::error::Result;
use crate::keys::{key_id, verify_record};
use crate::notary::sha256_file;
use crate::record::{Kind, Record, GENESIS_HASH, RECORD_VERSION};
use crate::store::Store;
use crate::timefmt::parse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub seq: Option<u64>,
    pub file: Option<String>,
    pub problem: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub camera: String,
    pub records: usize,
    pub segments: usize,
    pub gaps: usize,
    pub deleted: usize,
    pub checkpoints: usize,
    pub issues: Vec<Issue>,
}

impl Report {
    pub fn ok(&self) -> bool {
        !self.issues.iter().any(|i| i.severity == Severity::Error)
    }
}

fn err(issues: &mut Vec<Issue>, seq: Option<u64>, file: Option<&str>, problem: impl Into<String>) {
    issues.push(Issue {
        severity: Severity::Error,
        seq,
        file: file.map(str::to_string),
        problem: problem.into(),
    });
}

fn warn(issues: &mut Vec<Issue>, seq: Option<u64>, file: Option<&str>, problem: impl Into<String>) {
    issues.push(Issue {
        severity: Severity::Warn,
        seq,
        file: file.map(str::to_string),
        problem: problem.into(),
    });
}

/// Verify one camera's chain: continuity, links, signatures, checkpoints, and
/// (with `check_files`) that every live segment still matches its recorded hash.
pub fn verify_camera(
    store: &Store,
    camera: &str,
    public: &VerifyingKey,
    check_files: bool,
) -> Result<Report> {
    let mut report = Report {
        camera: camera.to_string(),
        records: 0,
        segments: 0,
        gaps: 0,
        deleted: 0,
        checkpoints: 0,
        issues: Vec::new(),
    };
    let chain = match store.read_chain(camera) {
        Ok(c) => c,
        Err(e) => {
            err(&mut report.issues, None, None, format!("chain unreadable: {e}"));
            return Ok(report);
        }
    };
    report.records = chain.len();
    let expected_key_id = key_id(public);
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut prev_seq = 0u64;
    let mut hashes: HashMap<u64, String> = HashMap::new();
    let mut segments: HashMap<u64, &Record> = HashMap::new();
    let mut deleted_refs: HashSet<u64> = HashSet::new();
    let mut referenced_files: HashSet<String> = HashSet::new();
    let mut prev_end: Option<chrono::DateTime<chrono::Utc>> = None;

    for rec in &chain {
        let seq = rec.seq;
        if seq != prev_seq + 1 {
            err(
                &mut report.issues,
                Some(seq),
                None,
                format!("seq discontinuity: expected {}, found {seq}", prev_seq + 1),
            );
        }
        if rec.prev_record_hash != prev_hash {
            err(
                &mut report.issues,
                Some(seq),
                None,
                "chain break: prev_record_hash does not match the previous record",
            );
        }
        if rec.v != RECORD_VERSION {
            err(&mut report.issues, Some(seq), None, format!("unsupported record version {}", rec.v));
        }
        if rec.camera_id != camera {
            err(&mut report.issues, Some(seq), None, "record camera_id does not match its chain");
        }
        if rec.key_id != expected_key_id {
            err(&mut report.issues, Some(seq), None, "record signed by a different key id");
        }
        if verify_record(rec, public).is_err() {
            err(&mut report.issues, Some(seq), rec.file.as_deref(), "signature does not verify");
        }
        let hash = rec.record_hash()?;
        match rec.kind {
            Kind::Segment => {
                report.segments += 1;
                segments.insert(seq, rec);
                if let Some(f) = &rec.file {
                    referenced_files.insert(f.clone());
                } else {
                    err(&mut report.issues, Some(seq), None, "segment record has no file");
                }
                if rec.sha256.is_none() {
                    err(&mut report.issues, Some(seq), rec.file.as_deref(), "segment record has no sha256");
                }
            }
            Kind::Gap => report.gaps += 1,
            Kind::Deleted => {
                report.deleted += 1;
                match rec.ref_seq.and_then(|r| segments.get(&r)) {
                    Some(seg) => {
                        if seg.sha256 != rec.sha256 {
                            err(&mut report.issues, Some(seq), rec.file.as_deref(), "deleted record hash differs from the segment it removes");
                        }
                        deleted_refs.insert(seg.seq);
                    }
                    None => err(&mut report.issues, Some(seq), None, "deleted record references an unknown segment"),
                }
            }
            Kind::Checkpoint => {
                report.checkpoints += 1;
                match rec.head_seq.and_then(|h| hashes.get(&h)) {
                    Some(h) => {
                        if rec.head_hash.as_deref() != Some(h.as_str()) {
                            err(&mut report.issues, Some(seq), None, "checkpoint head_hash does not match the chain");
                        }
                    }
                    None => err(&mut report.issues, Some(seq), None, "checkpoint references an unknown head"),
                }
            }
        }
        if matches!(rec.kind, Kind::Segment | Kind::Gap) {
            match (parse(&rec.start_utc), parse(&rec.end_utc)) {
                (Ok(s), Ok(e)) => {
                    if e <= s {
                        err(&mut report.issues, Some(seq), None, "end_utc is not after start_utc");
                    }
                    if let Some(pe) = prev_end {
                        if (pe - s).num_milliseconds() > crate::notary::GAP_TOLERANCE_MS {
                            warn(&mut report.issues, Some(seq), None, "segment overlaps the previous one");
                        }
                    }
                    prev_end = Some(prev_end.map_or(e, |p| p.max(e)));
                }
                _ => err(&mut report.issues, Some(seq), None, "invalid timestamp"),
            }
        }
        hashes.insert(seq, hash.clone());
        prev_hash = hash;
        prev_seq = seq;
    }

    if check_files {
        for rec in chain.iter().filter(|r| r.kind == Kind::Segment) {
            let Some(rel) = rec.file.as_deref() else { continue };
            let path = match store.segment_path(rel) {
                Ok(p) => p,
                Err(_) => {
                    err(&mut report.issues, Some(rec.seq), Some(rel), "segment path rejected");
                    continue;
                }
            };
            if !Store::exists(&path) {
                if !deleted_refs.contains(&rec.seq) {
                    err(&mut report.issues, Some(rec.seq), Some(rel), "segment file missing and no deletion record");
                }
                continue;
            }
            match sha256_file(&path) {
                Ok((sha, bytes)) => {
                    if rec.sha256.as_deref() != Some(sha.as_str()) {
                        err(&mut report.issues, Some(rec.seq), Some(rel), "hash mismatch (file changed since sealing)");
                    } else if rec.bytes != Some(bytes) {
                        err(&mut report.issues, Some(rec.seq), Some(rel), "size mismatch");
                    }
                }
                Err(e) => err(&mut report.issues, Some(rec.seq), Some(rel), format!("unreadable: {e}")),
            }
        }
        // Files on disk that no record accounts for.
        let dir = store.segments_dir().join(camera);
        if dir.exists() {
            let mut stack = vec![dir];
            while let Some(d) = stack.pop() {
                for entry in std::fs::read_dir(&d)?.filter_map(|e| e.ok()) {
                    let p = entry.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if let Ok(rel) = p.strip_prefix(&store.root) {
                        let rel = rel.to_string_lossy().replace('\\', "/");
                        if !referenced_files.contains(&rel) {
                            warn(&mut report.issues, None, Some(&rel), "orphan segment file not in the chain");
                        }
                    }
                }
            }
        }
    }
    Ok(report)
}
