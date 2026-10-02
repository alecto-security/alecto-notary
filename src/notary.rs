//! The single writer of the signed chain. All appends go through here.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::config::valid_id;
use crate::error::{NotaryError, Result};
use crate::keys::DeviceKey;
use crate::record::{Clock, Kind, Record, GENESIS_HASH, RECORD_VERSION};
use crate::store::Store;
use crate::timefmt::{fmt, parse};

/// A segment that starts later than this after the previous one ended gets a gap record.
pub const GAP_TOLERANCE_MS: i64 = 2000;

#[derive(Debug, Clone)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
    pub end: DateTime<Utc>,
}

#[derive(Default)]
struct Draft {
    file: Option<String>,
    sha256: Option<String>,
    bytes: Option<u64>,
    reason: Option<String>,
    ref_seq: Option<u64>,
    head_seq: Option<u64>,
    head_hash: Option<String>,
    count: Option<u64>,
}

pub struct Notary {
    pub store: Store,
    key: DeviceKey,
    pub device_id: String,
    pub clock_source: String,
    heads: Mutex<HashMap<String, Option<Head>>>,
}

impl Notary {
    pub fn new(store: Store, key: DeviceKey, device_id: &str, clock_source: &str) -> Self {
        Self {
            store,
            key,
            device_id: device_id.to_string(),
            clock_source: clock_source.to_string(),
            heads: Mutex::new(HashMap::new()),
        }
    }

    pub fn key_id(&self) -> String {
        self.key.key_id()
    }

    pub fn public_b64(&self) -> String {
        self.key.public_b64()
    }

    pub fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.public()
    }

    pub fn head(&self, camera: &str) -> Result<Option<Head>> {
        let mut heads = self.heads.lock().expect("heads lock");
        self.load_head(&mut heads, camera)
    }

    fn load_head(
        &self,
        heads: &mut HashMap<String, Option<Head>>,
        camera: &str,
    ) -> Result<Option<Head>> {
        if let Some(cached) = heads.get(camera) {
            return Ok(cached.clone());
        }
        let chain = self.store.read_chain(camera)?;
        let loaded = match chain.last() {
            Some(last) => {
                let mut end: Option<DateTime<Utc>> = None;
                for r in chain
                    .iter()
                    .filter(|r| matches!(r.kind, Kind::Segment | Kind::Gap))
                {
                    let e = parse(&r.end_utc)?;
                    end = Some(end.map_or(e, |cur| cur.max(e)));
                }
                Some(Head {
                    seq: last.seq,
                    hash: last.record_hash()?,
                    end: match end {
                        Some(e) => e,
                        None => parse(&last.end_utc)?,
                    },
                })
            }
            None => None,
        };
        heads.insert(camera.to_string(), loaded.clone());
        Ok(loaded)
    }

    /// Build, sign and append one record. Caller holds the heads lock.
    fn append_locked(
        &self,
        heads: &mut HashMap<String, Option<Head>>,
        camera: &str,
        kind: Kind,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        draft: Draft,
    ) -> Result<Record> {
        let head = self.load_head(heads, camera)?;
        let (seq, prev) = match &head {
            Some(h) => (h.seq + 1, h.hash.clone()),
            None => (1, GENESIS_HASH.to_string()),
        };
        let mut record = Record {
            v: RECORD_VERSION,
            kind,
            device_id: self.device_id.clone(),
            key_id: self.key.key_id(),
            camera_id: camera.to_string(),
            seq,
            start_utc: fmt(start),
            end_utc: fmt(end),
            file: draft.file,
            sha256: draft.sha256,
            bytes: draft.bytes,
            reason: draft.reason,
            ref_seq: draft.ref_seq,
            head_seq: draft.head_seq,
            head_hash: draft.head_hash,
            count: draft.count,
            prev_record_hash: prev,
            clock: Clock {
                source: self.clock_source.clone(),
                skew_ms: None,
            },
            sig: String::new(),
        };
        self.key.sign(&mut record)?;
        self.store.append_record(&record)?;
        // Only footage-time records advance `end`; deletions and checkpoints are
        // stamped with wall time and must not hide a later gap.
        let advances = matches!(kind, Kind::Segment | Kind::Gap);
        let new_end = match (&head, advances) {
            (Some(h), true) => h.end.max(end),
            (Some(h), false) => h.end,
            (None, _) => end,
        };
        let new_head = Head {
            seq,
            hash: record.record_hash()?,
            end: new_end,
        };
        heads.insert(camera.to_string(), Some(new_head));
        Ok(record)
    }

    /// Seal a finished segment: hash it, move it into the store, append its record.
    /// A time jump since the previous record is recorded as a gap first.
    pub fn seal_segment(
        &self,
        camera: &str,
        src: &Path,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        gap_reason: Option<&str>,
    ) -> Result<Record> {
        if !valid_id(camera) {
            return Err(NotaryError::fail("invalid camera id"));
        }
        if end <= start {
            return Err(NotaryError::fail("segment end must be after start"));
        }
        let (sha, bytes) = hash_file(src)?;
        let mut heads = self.heads.lock().expect("heads lock");
        if let Some(head) = self.load_head(&mut heads, camera)? {
            if start - head.end > Duration::milliseconds(GAP_TOLERANCE_MS) {
                self.append_locked(
                    &mut heads,
                    camera,
                    Kind::Gap,
                    head.end,
                    start,
                    Draft {
                        reason: Some(gap_reason.unwrap_or("unrecorded").to_string()),
                        ..Draft::default()
                    },
                )?;
            }
        }
        let seq = self
            .load_head(&mut heads, camera)?
            .map(|h| h.seq + 1)
            .unwrap_or(1);
        let rel = format!(
            "segments/{camera}/{}/{}_{seq}.ts",
            start.format("%Y-%m-%d"),
            start.format("%H%M%S")
        );
        let dst = self.store.segment_path(&rel)?;
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        move_file(src, &dst)?;
        self.append_locked(
            &mut heads,
            camera,
            Kind::Segment,
            start,
            end,
            Draft {
                file: Some(rel),
                sha256: Some(sha),
                bytes: Some(bytes),
                ..Draft::default()
            },
        )
    }

    pub fn record_gap(
        &self,
        camera: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        reason: &str,
    ) -> Result<Record> {
        let mut heads = self.heads.lock().expect("heads lock");
        self.append_locked(
            &mut heads,
            camera,
            Kind::Gap,
            start,
            end,
            Draft {
                reason: Some(reason.to_string()),
                ..Draft::default()
            },
        )
    }

    /// Record that a segment file was removed. The proof (hash, size) stays in the chain.
    pub fn record_deleted(&self, segment: &Record, reason: &str, now: DateTime<Utc>) -> Result<Record> {
        let mut heads = self.heads.lock().expect("heads lock");
        self.append_locked(
            &mut heads,
            &segment.camera_id,
            Kind::Deleted,
            now,
            now,
            Draft {
                file: segment.file.clone(),
                sha256: segment.sha256.clone(),
                bytes: segment.bytes,
                reason: Some(reason.to_string()),
                ref_seq: Some(segment.seq),
                ..Draft::default()
            },
        )
    }

    /// Sign the current chain head. Keep copies off the box to detect tail truncation.
    pub fn checkpoint(&self, camera: &str, now: DateTime<Utc>) -> Result<Record> {
        let mut heads = self.heads.lock().expect("heads lock");
        let head = self
            .load_head(&mut heads, camera)?
            .ok_or_else(|| NotaryError::fail("no chain for camera"))?;
        self.append_locked(
            &mut heads,
            camera,
            Kind::Checkpoint,
            now,
            now,
            Draft {
                head_seq: Some(head.seq),
                head_hash: Some(head.hash),
                count: Some(head.seq),
                ..Draft::default()
            },
        )
    }
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path).map_err(|source| NotaryError::Path {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    hash_file(path)
}

fn move_file(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst)?;
    std::fs::remove_file(src)?;
    Ok(())
}
