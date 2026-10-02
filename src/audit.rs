use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::timefmt::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Append-only operational log (locks, unlocks, retention). Tamper evidence for
/// footage lives in the signed chain; this answers "who did what to the box".
#[derive(Debug, Clone)]
pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let record = AuditRecord {
            ts: fmt(Utc::now()),
            actor: actor.to_string(),
            action: action.to_string(),
            detail: detail.to_string(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    pub fn read_all(&self) -> Result<Vec<AuditRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| Ok(serde_json::from_str(l)?))
            .collect()
    }
}
