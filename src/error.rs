use std::path::PathBuf;

use thiserror::Error;

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAIL: i32 = 2;
pub const EXIT_CONFIG: i32 = 3;

#[derive(Debug, Error)]
pub enum NotaryError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Fail(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{path}: {source}")]
    Path {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl NotaryError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn fail(msg: impl Into<String>) -> Self {
        Self::Fail(msg.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::Yaml(_) => EXIT_CONFIG,
            _ => EXIT_FAIL,
        }
    }
}

pub type Result<T> = std::result::Result<T, NotaryError>;
