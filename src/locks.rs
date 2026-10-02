//! Evidence locks: ranges of footage exempt from retention.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::audit::Audit;
use crate::config::valid_id;
use crate::error::{NotaryError, Result};
use crate::timefmt::{fmt, parse};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub id: String,
    pub camera_id: String,
    pub from: String,
    pub to: String,
    pub case_id: String,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct LockStore {
    dir: PathBuf,
    audit: Audit,
}

impl LockStore {
    pub fn new(dir: impl Into<PathBuf>, audit: Audit) -> Self {
        Self {
            dir: dir.into(),
            audit,
        }
    }

    pub fn create(
        &self,
        camera_id: &str,
        from: &str,
        to: &str,
        case_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<Lock> {
        if !valid_id(camera_id) {
            return Err(NotaryError::config("invalid camera id"));
        }
        let (start, end) = (parse(from)?, parse(to)?);
        if end <= start {
            return Err(NotaryError::config("lock range must have to after from"));
        }
        if actor.trim().is_empty() {
            return Err(NotaryError::config("actor required"));
        }
        if reason.trim().len() < 3 {
            return Err(NotaryError::config("reason required (min 3 characters)"));
        }
        if case_id.trim().is_empty() {
            return Err(NotaryError::config("case_id required"));
        }
        let mut raw = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let lock = Lock {
            id: format!("lock-{}", hex::encode(raw)),
            camera_id: camera_id.to_string(),
            from: fmt(start),
            to: fmt(end),
            case_id: case_id.trim().to_string(),
            actor: actor.trim().to_string(),
            reason: reason.trim().to_string(),
            created_at: fmt(Utc::now()),
        };
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(
            self.dir.join(format!("{}.json", lock.id)),
            serde_json::to_vec_pretty(&lock)?,
        )?;
        self.audit.append(
            &lock.actor,
            "lock",
            &format!(
                "{} {} {}..{} case={} reason={}",
                lock.id, lock.camera_id, lock.from, lock.to, lock.case_id, lock.reason
            ),
        )?;
        Ok(lock)
    }

    pub fn list(&self) -> Result<Vec<Lock>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)?.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "json") {
                out.push(serde_json::from_slice::<Lock>(&std::fs::read(&path)?)?);
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn delete(&self, id: &str, actor: &str) -> Result<()> {
        if !id.starts_with("lock-") || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(NotaryError::config("invalid lock id"));
        }
        if actor.trim().is_empty() {
            return Err(NotaryError::config("actor required"));
        }
        let path = self.dir.join(format!("{id}.json"));
        if !path.is_file() {
            return Err(NotaryError::fail("lock not found"));
        }
        std::fs::remove_file(path)?;
        self.audit.append(actor.trim(), "unlock", id)?;
        Ok(())
    }

    /// True when any lock on this camera overlaps `[start, end)`.
    pub fn is_locked(&self, camera: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<bool> {
        for lock in self.list()?.iter().filter(|l| l.camera_id == camera) {
            if parse(&lock.from)? < end && parse(&lock.to)? > start {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
