//! Per-camera recorder: supervises one ffmpeg process that writes closed
//! segments to a spool dir, then seals each one into the chain.
//!
//! The Notary is a second RTSP client. It is never in the camera-to-recorder
//! video path, so a crash here cannot interrupt the customer's own recording.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use crate::config::CameraCfg;
use crate::error::{NotaryError, Result};
use crate::notary::Notary;

#[derive(Debug, Clone)]
pub struct RecorderOpts {
    pub ffmpeg: PathBuf,
    pub ffprobe: PathBuf,
    pub segment_secs: u32,
}

impl Default for RecorderOpts {
    fn default() -> Self {
        Self {
            ffmpeg: PathBuf::from("ffmpeg"),
            ffprobe: PathBuf::from("ffprobe"),
            segment_secs: 60,
        }
    }
}

const BACKOFF_SECS: [u64; 5] = [2, 4, 8, 16, 30];
/// Leftover spool files younger than this may still be open for writing.
const ADOPT_QUIET_SECS: u64 = 15;

/// Insert credentials into an rtsp(s) uri at the last moment. The config never
/// holds a password; it names an environment variable.
pub fn uri_with_credentials(cam: &CameraCfg) -> Result<String> {
    let (Some(user), Some(env)) = (&cam.username, &cam.password_env) else {
        return Ok(cam.uri.clone());
    };
    let pass = std::env::var(env)
        .map_err(|_| NotaryError::config(format!("camera {}: env var {env} is not set", cam.id)))?;
    let Some((scheme, rest)) = cam.uri.split_once("://") else {
        return Ok(cam.uri.clone());
    };
    Ok(format!("{scheme}://{}:{}@{rest}", pct(user), pct(&pass)))
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `run_id` keeps file names unique per ffmpeg launch, so an orphan from a hard-killed
/// Notary can never collide with the next run's output.
pub fn ffmpeg_args(cam: &CameraCfg, uri: &str, spool: &Path, segment_secs: u32, run_id: u128) -> Vec<String> {
    let mut a: Vec<String> = vec!["-hide_banner".into(), "-loglevel".into(), "error".into()];
    if cam.realtime {
        a.push("-re".into());
    }
    if let Some(fmt) = &cam.input_format {
        a.extend(["-f".into(), fmt.clone()]);
    }
    if uri.starts_with("rtsp://") || uri.starts_with("rtsps://") {
        a.extend(["-rtsp_transport".into(), "tcp".into()]);
    }
    a.extend(["-i".into(), uri.to_string(), "-map".into(), "0:v?".into(), "-map".into(), "0:a?".into()]);
    match cam.video_codec.as_deref() {
        None | Some("copy") => a.extend(["-c".into(), "copy".into()]),
        Some(codec) => {
            a.extend([
                "-c:v".into(),
                codec.to_string(),
                "-force_key_frames".into(),
                format!("expr:gte(t,n_forced*{segment_secs})"),
            ]);
        }
    }
    a.extend([
        "-f".into(),
        "segment".into(),
        "-segment_time".into(),
        segment_secs.to_string(),
        "-segment_format".into(),
        "mpegts".into(),
        "-reset_timestamps".into(),
        "1".into(),
        "-segment_list".into(),
        "pipe:1".into(),
        "-segment_list_type".into(),
        "flat".into(),
        spool.join(format!("seg_{run_id}_%06d.ts")).to_string_lossy().into_owned(),
    ]);
    a
}

/// Seal one closed spool file. End time is the file mtime, start is end minus
/// the probed duration (falls back to the configured segment length).
pub async fn seal_closed(
    notary: &Notary,
    camera: &str,
    file: &Path,
    opts: &RecorderOpts,
    gap_reason: Option<&str>,
) -> Result<crate::record::Record> {
    let meta = std::fs::metadata(file)?;
    if meta.len() == 0 {
        std::fs::remove_file(file)?;
        return Err(NotaryError::fail("empty segment discarded"));
    }
    let end: DateTime<Utc> = meta.modified()?.into();
    let secs = probe_duration(&opts.ffprobe, file)
        .await
        .unwrap_or(opts.segment_secs as f64);
    let start = end - chrono::Duration::milliseconds((secs * 1000.0) as i64);
    notary.seal_segment(camera, file, start, end, gap_reason)
}

pub async fn probe_duration(ffprobe: &Path, file: &Path) -> Option<f64> {
    let out = Command::new(ffprobe)
        .args(["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0"])
        .arg(file)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|d| *d > 0.0)
}

/// Seal anything a previous run left in the spool (a crash keeps real footage).
async fn adopt_spool(notary: &Notary, camera: &str, spool: &Path, opts: &RecorderOpts) {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(spool) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => return,
    };
    files.sort();
    for f in files {
        if f.extension().is_some_and(|x| x == "ts") {
            // A file still being written (an orphaned ffmpeg) must not be sealed: its
            // bytes would change after the hash. Leave recent files for the next pass.
            let quiet = std::fs::metadata(&f)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(ADOPT_QUIET_SECS));
            if !quiet {
                eprintln!("[{camera}] leftover {} was modified recently; not adopting yet", f.display());
                continue;
            }
            match seal_closed(notary, camera, &f, opts, Some("recorder_restart")).await {
                Ok(r) => eprintln!("[{camera}] adopted leftover segment seq={}", r.seq),
                Err(e) => eprintln!("[{camera}] leftover segment skipped: {e}"),
            }
        }
    }
}

/// Run until `shutdown` flips to true. Restarts ffmpeg with backoff and records
/// the time it was away as a gap, never as silence.
pub async fn run_camera(
    notary: Arc<Notary>,
    cam: CameraCfg,
    opts: RecorderOpts,
    mut shutdown: watch::Receiver<bool>,
) {
    let spool = notary.store.spool_dir(&cam.id);
    if let Err(e) = std::fs::create_dir_all(&spool) {
        eprintln!("[{}] cannot create spool: {e}", cam.id);
        return;
    }
    let mut attempt = 0usize;
    let mut gap_reason: Option<String> = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        adopt_spool(&notary, &cam.id, &spool, &opts).await;
        let uri = match uri_with_credentials(&cam) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("[{}] {e}", cam.id);
                return;
            }
        };
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let args = ffmpeg_args(&cam, &uri, &spool, opts.segment_secs, run_id);
        let mut child = match Command::new(&opts.ffmpeg)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[{}] cannot start ffmpeg: {e}", cam.id);
                gap_reason = Some("recorder_unavailable".into());
                if wait_or_shutdown(&mut shutdown, backoff(&mut attempt)).await {
                    return;
                }
                continue;
            }
        };
        let mut stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        let mut lines = BufReader::new(stdout).lines();
        let mut sealed_any = false;
        let mut stopping = false;
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(name)) => {
                            let name = name.trim();
                            if name.is_empty() { continue; }
                            let base = Path::new(name).file_name().map(PathBuf::from).unwrap_or_default();
                            let file = spool.join(base);
                            match seal_closed(&notary, &cam.id, &file, &opts, gap_reason.as_deref()).await {
                                Ok(r) => {
                                    sealed_any = true;
                                    gap_reason = None;
                                    attempt = 0;
                                    eprintln!("[{}] sealed seq={} {}", cam.id, r.seq, r.file.unwrap_or_default());
                                }
                                Err(e) => eprintln!("[{}] seal failed: {e}", cam.id),
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
                _ = shutdown.changed(), if !stopping => {
                    if *shutdown.borrow() {
                        stopping = true;
                        if let Some(mut s) = stdin.take() {
                            // ffmpeg finalizes the open segment on 'q'.
                            let _ = s.write_all(b"q").await;
                            let _ = s.flush().await;
                        }
                    }
                }
            }
        }
        let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(s) => s.ok(),
            Err(_) => {
                let _ = child.kill().await;
                None
            }
        };
        if stopping || *shutdown.borrow() {
            return;
        }
        let code = status.and_then(|s| s.code()).map_or("signal".into(), |c| c.to_string());
        eprintln!("[{}] ffmpeg exited ({code}); retrying", cam.id);
        if !sealed_any {
            gap_reason = Some("source_unreachable".into());
        } else {
            gap_reason = Some(format!("recorder_exit_{code}"));
        }
        if wait_or_shutdown(&mut shutdown, backoff(&mut attempt)).await {
            return;
        }
    }
}

fn backoff(attempt: &mut usize) -> Duration {
    let secs = BACKOFF_SECS[(*attempt).min(BACKOFF_SECS.len() - 1)];
    *attempt += 1;
    Duration::from_secs(secs)
}

/// Sleep, or return true when shutdown arrives first.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => *shutdown.borrow(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cam() -> CameraCfg {
        CameraCfg {
            id: "CAM-W01".into(),
            uri: "rtsp://192.168.1.64:554/s".into(),
            username: Some("svc".into()),
            password_env: Some("NOTARY_TEST_PASS".into()),
            input_format: None,
            realtime: false,
            video_codec: None,
        }
    }

    #[test]
    fn credentials_are_injected_and_encoded_from_env() {
        std::env::set_var("NOTARY_TEST_PASS", "p@ss:w/rd");
        let uri = uri_with_credentials(&cam()).unwrap();
        assert_eq!(uri, "rtsp://svc:p%40ss%3Aw%2Frd@192.168.1.64:554/s");
    }

    #[test]
    fn copy_mode_uses_stream_copy_and_tcp() {
        let args = ffmpeg_args(&cam(), "rtsp://x/y", Path::new("spool"), 60, 42);
        let joined = args.join(" ");
        assert!(joined.contains("-c copy"));
        assert!(joined.contains("-rtsp_transport tcp"));
        assert!(joined.contains("-segment_time 60"));
        assert!(joined.contains("seg_42_%06d.ts"), "{joined}");
    }

    #[test]
    fn missing_password_env_is_a_config_error() {
        let mut c = cam();
        c.password_env = Some("NOTARY_DOES_NOT_EXIST_XYZ".into());
        assert!(uri_with_credentials(&c).is_err());
    }
}
