use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{NotaryError, Result};

pub const TOKEN_ENV: &str = "ALECTO_NOTARY_TOKEN";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub device_id: String,
    /// Data root: `segments/`, `chain/`, `locks/`, `spool/`, `audit.jsonl`.
    pub root: PathBuf,
    /// Base64 Ed25519 seed written by `keygen`.
    pub key_file: PathBuf,
    #[serde(default = "default_segment_secs")]
    pub segment_secs: u32,
    /// `ntp` | `rtc` | `host`: how trustworthy the host clock is. Recorded in every record.
    #[serde(default = "default_clock_source")]
    pub clock_source: String,
    #[serde(default)]
    pub retention: RetentionCfg,
    #[serde(default)]
    pub api: ApiCfg,
    pub cameras: Vec<CameraCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionCfg {
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
    /// Hard cap on total unlocked segment bytes across all cameras.
    pub max_bytes: Option<u64>,
}

impl Default for RetentionCfg {
    fn default() -> Self {
        Self {
            max_age_days: default_max_age_days(),
            max_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCfg {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_token_env")]
    pub token_env: String,
}

impl Default for ApiCfg {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            token_env: default_token_env(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CameraCfg {
    pub id: String,
    pub uri: String,
    pub username: Option<String>,
    /// Name of the environment variable holding the password. Never inline.
    pub password_env: Option<String>,
    /// ffmpeg input format (`lavfi` for test sources). Default: none.
    pub input_format: Option<String>,
    /// Read the input at native frame rate (`-re`), for file or lavfi test sources.
    #[serde(default)]
    pub realtime: bool,
    /// `copy` (default, byte-exact) or an encoder name for test sources.
    pub video_codec: Option<String>,
}

fn default_segment_secs() -> u32 {
    60
}
fn default_clock_source() -> String {
    "host".into()
}
fn default_max_age_days() -> u32 {
    30
}
fn default_bind() -> SocketAddr {
    "127.0.0.1:8081".parse().expect("valid default bind")
}
fn default_token_env() -> String {
    TOKEN_ENV.into()
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| NotaryError::Path {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Config = serde_yaml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.device_id) {
            return Err(NotaryError::config(
                "device_id must be 1-64 chars of letters, digits, '-' or '_'",
            ));
        }
        if !matches!(self.clock_source.as_str(), "ntp" | "rtc" | "host") {
            return Err(NotaryError::config("clock_source must be ntp, rtc or host"));
        }
        if self.segment_secs == 0 || self.segment_secs > 3600 {
            return Err(NotaryError::config("segment_secs must be 1..=3600"));
        }
        if self.cameras.is_empty() {
            return Err(NotaryError::config("at least one camera required"));
        }
        let mut seen = HashSet::new();
        for cam in &self.cameras {
            if !valid_id(&cam.id) {
                return Err(NotaryError::config(format!(
                    "camera id {:?} must be 1-64 chars of letters, digits, '-' or '_'",
                    cam.id
                )));
            }
            if !seen.insert(cam.id.clone()) {
                return Err(NotaryError::config(format!(
                    "duplicate camera id {}",
                    cam.id
                )));
            }
            if cam.uri.trim().is_empty() {
                return Err(NotaryError::config(format!("camera {} has no uri", cam.id)));
            }
            if uri_has_credentials(&cam.uri) {
                return Err(NotaryError::config(format!(
                    "camera {}: credentials in uri are rejected; use username + password_env",
                    cam.id
                )));
            }
            if cam.password_env.is_some() && cam.username.is_none() {
                return Err(NotaryError::config(format!(
                    "camera {}: password_env needs a username",
                    cam.id
                )));
            }
        }
        Ok(())
    }
}

fn uri_has_credentials(uri: &str) -> bool {
    match uri.split_once("://") {
        Some((_, rest)) => {
            let authority = rest.split('/').next().unwrap_or("");
            authority.contains('@')
        }
        None => false,
    }
}

/// Bearer token for the store API. Must come from the environment, 16+ chars.
pub fn load_api_token(env_var: &str) -> Result<String> {
    let token = std::env::var(env_var)
        .map_err(|_| NotaryError::config(format!("{env_var} is required (random secret)")))?;
    if token.trim().len() < 16 {
        return Err(NotaryError::config(format!(
            "{env_var} must be at least 16 characters"
        )));
    }
    Ok(token)
}

/// MVP rule: no TLS support yet, so the API binds loopback only.
// ponytail: loopback-only until TLS lands, then allow LAN bind with cert+key like the gateway.
pub fn ensure_loopback(addr: &SocketAddr) -> Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(NotaryError::config(
            "non-loopback bind refused: TLS is not implemented yet (loopback only)",
        ))
    }
}
