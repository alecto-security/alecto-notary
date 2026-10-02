//! Flat-file storage (ADR-0003 style): one JSON-lines chain file per camera per day.
//!
//! ```text
//! <root>/segments/<camera>/<YYYY-MM-DD>/<HHMMSS>_<seq>.ts
//! <root>/chain/<camera>/<YYYY-MM-DD>.jsonl
//! <root>/spool/<camera>/        (ffmpeg writes here; sealed segments are moved out)
//! <root>/locks/<id>.json
//! <root>/audit.jsonl
//! ```

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{NotaryError, Result};
use crate::record::Record;

#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn segments_dir(&self) -> PathBuf {
        self.root.join("segments")
    }
    pub fn chain_dir(&self, camera: &str) -> PathBuf {
        self.root.join("chain").join(camera)
    }
    pub fn spool_dir(&self, camera: &str) -> PathBuf {
        self.root.join("spool").join(camera)
    }
    pub fn locks_dir(&self) -> PathBuf {
        self.root.join("locks")
    }
    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// Cameras that have a chain on disk.
    pub fn cameras(&self) -> Result<Vec<String>> {
        let dir = self.root.join("chain");
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out: Vec<String> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        out.sort();
        Ok(out)
    }

    /// All records of a camera in seq order. Day-file order is not trusted.
    pub fn read_chain(&self, camera: &str) -> Result<Vec<Record>> {
        let dir = self.chain_dir(camera);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        let mut out = Vec::new();
        for file in files {
            let raw = std::fs::read_to_string(&file).map_err(|source| NotaryError::Path {
                path: file.clone(),
                source,
            })?;
            for (n, line) in raw.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let record: Record = serde_json::from_str(line).map_err(|e| {
                    NotaryError::fail(format!("{}:{}: unreadable record: {e}", file.display(), n + 1))
                })?;
                out.push(record);
            }
        }
        out.sort_by_key(|r| r.seq);
        Ok(out)
    }

    /// Append one record to its day file and flush to disk.
    pub fn append_record(&self, record: &Record) -> Result<()> {
        let dir = self.chain_dir(&record.camera_id);
        std::fs::create_dir_all(&dir)?;
        let day = record.start_utc.get(..10).unwrap_or("unknown");
        let path = dir.join(format!("{day}.jsonl"));
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }

    /// Absolute path for a segment path stored in a record, kept inside `<root>/segments`.
    pub fn segment_path(&self, relative: &str) -> Result<PathBuf> {
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.contains('\\')
            || relative.contains("..")
            || !relative.starts_with("segments/")
        {
            return Err(NotaryError::fail("segment path rejected"));
        }
        Ok(self.root.join(relative))
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }
}
