//! Ring-buffer retention. Deletes oldest unlocked segments; every deletion is a
//! signed chain record, so the history stays honest.

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::audit::Audit;
use crate::error::Result;
use crate::locks::LockStore;
use crate::notary::Notary;
use crate::record::{Kind, Record};
use crate::store::Store;
use crate::timefmt::parse;

#[derive(Debug, Clone)]
pub struct Policy {
    pub max_age: Duration,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcome {
    pub deleted: Vec<(String, u64)>,
    pub kept_locked: usize,
    pub freed_bytes: u64,
}

pub fn apply(
    notary: &Notary,
    locks: &LockStore,
    audit: &Audit,
    cameras: &[String],
    policy: &Policy,
    now: DateTime<Utc>,
) -> Result<Outcome> {
    let mut live: Vec<Record> = Vec::new();
    for cam in cameras {
        let chain = notary.store.read_chain(cam)?;
        let gone: HashSet<u64> = chain
            .iter()
            .filter(|r| r.kind == Kind::Deleted)
            .filter_map(|r| r.ref_seq)
            .collect();
        for rec in chain {
            if rec.kind != Kind::Segment || gone.contains(&rec.seq) {
                continue;
            }
            if let Some(rel) = &rec.file {
                if Store::exists(&notary.store.segment_path(rel)?) {
                    live.push(rec);
                }
            }
        }
    }
    live.sort_by(|a, b| a.start_utc.cmp(&b.start_utc).then(a.seq.cmp(&b.seq)));
    let mut total: u64 = live.iter().map(|r| r.bytes.unwrap_or(0)).sum();
    let mut outcome = Outcome::default();
    for rec in live {
        let (start, end) = (parse(&rec.start_utc)?, parse(&rec.end_utc)?);
        let too_old = now - end > policy.max_age;
        let over_cap = policy.max_bytes.is_some_and(|cap| total > cap);
        if !too_old && !over_cap {
            continue;
        }
        if locks.is_locked(&rec.camera_id, start, end)? {
            outcome.kept_locked += 1;
            continue;
        }
        let rel = rec.file.clone().unwrap_or_default();
        std::fs::remove_file(notary.store.segment_path(&rel)?)?;
        notary.record_deleted(&rec, if too_old { "retention_age" } else { "retention_size" }, now)?;
        audit.append(
            "notary",
            "retention_delete",
            &format!("{} seq={} {}", rec.camera_id, rec.seq, rel),
        )?;
        let bytes = rec.bytes.unwrap_or(0);
        total = total.saturating_sub(bytes);
        outcome.freed_bytes += bytes;
        outcome.deleted.push((rec.camera_id.clone(), rec.seq));
    }
    Ok(outcome)
}
