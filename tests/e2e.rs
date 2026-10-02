//! N1 and N7 against a real ffmpeg process. Skipped when ffmpeg is not installed.

use std::sync::Arc;
use std::time::Duration;

use alecto_notary::config::CameraCfg;
use alecto_notary::keys::DeviceKey;
use alecto_notary::notary::Notary;
use alecto_notary::record::Kind;
use alecto_notary::recorder::{probe_duration, run_camera, RecorderOpts};
use alecto_notary::store::Store;
use alecto_notary::verify::verify_camera;
use tempfile::TempDir;
use tokio::sync::watch;

fn ffmpeg_available() -> bool {
    ["ffmpeg", "ffprobe"].iter().all(|b| {
        std::process::Command::new(b)
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn notary(dir: &TempDir) -> Arc<Notary> {
    let (key, _) = DeviceKey::generate();
    Arc::new(Notary::new(Store::new(dir.path().join("data")), key, "notary-e2e", "host"))
}

fn lavfi_cam(id: &str) -> CameraCfg {
    CameraCfg {
        id: id.into(),
        uri: "testsrc=size=160x120:rate=10".into(),
        username: None,
        password_env: None,
        input_format: Some("lavfi".into()),
        realtime: true,
        video_codec: Some("libx264".into()),
    }
}

// N1 (real): record a live source, every segment sealed, chain verifies, segments play.
#[tokio::test(flavor = "multi_thread")]
async fn n1_real_ffmpeg_recording_is_sealed_and_verifies() {
    if !ffmpeg_available() {
        eprintln!("ffmpeg not installed, skipping");
        return;
    }
    let dir = TempDir::new().unwrap();
    let notary = notary(&dir);
    let (tx, rx) = watch::channel(false);
    let opts = RecorderOpts {
        segment_secs: 3,
        ..RecorderOpts::default()
    };
    let task = tokio::spawn(run_camera(notary.clone(), lavfi_cam("CAM-T01"), opts.clone(), rx));
    tokio::time::sleep(Duration::from_secs(11)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("recorder stops on shutdown")
        .unwrap();

    let chain = notary.store.read_chain("CAM-T01").unwrap();
    let segments: Vec<_> = chain.iter().filter(|r| r.kind == Kind::Segment).collect();
    assert!(segments.len() >= 2, "expected at least 2 segments, got {}", segments.len());
    let report = verify_camera(&notary.store, "CAM-T01", &notary.public_key(), true).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert_eq!(report.gaps, 0, "a healthy source must not produce gaps: {:?}", report.issues);

    for seg in &segments {
        let path = notary.store.root.join(seg.file.as_ref().unwrap());
        let secs = probe_duration(&opts.ffprobe, &path).await.expect("segment is playable");
        assert!(secs > 0.5, "segment {} duration {secs}", seg.seq);
    }
    // The spool is empty: everything closed was sealed and moved out.
    let spool = notary.store.spool_dir("CAM-T01");
    let left: Vec<_> = std::fs::read_dir(&spool).unwrap().filter_map(|e| e.ok()).collect();
    assert!(left.is_empty(), "spool not empty: {left:?}");
}

// N4 (real): a source that cannot be opened does not spin hot and writes nothing false.
#[tokio::test(flavor = "multi_thread")]
async fn unreachable_source_records_nothing_and_stops_cleanly() {
    if !ffmpeg_available() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let notary = notary(&dir);
    let mut cam = lavfi_cam("CAM-T02");
    cam.input_format = None;
    cam.uri = dir.path().join("does-not-exist.mp4").to_string_lossy().into_owned();
    cam.video_codec = None;
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(run_camera(notary.clone(), cam, RecorderOpts { segment_secs: 3, ..RecorderOpts::default() }, rx));
    tokio::time::sleep(Duration::from_secs(3)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(20), task).await.expect("stops on shutdown").unwrap();
    assert!(notary.store.read_chain("CAM-T02").unwrap().is_empty());
}

// N4 (real): kill the source mid-run, restart, and the downtime becomes a gap.
#[tokio::test(flavor = "multi_thread")]
async fn restart_after_downtime_records_a_gap() {
    if !ffmpeg_available() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let notary = notary(&dir);
    let opts = RecorderOpts { segment_secs: 3, ..RecorderOpts::default() };

    // First run: record ~7 s.
    let (tx, rx) = watch::channel(false);
    let t = tokio::spawn(run_camera(notary.clone(), lavfi_cam("CAM-T03"), opts.clone(), rx));
    tokio::time::sleep(Duration::from_secs(7)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), t).await.unwrap().unwrap();

    // Downtime, then a second run.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (tx, rx) = watch::channel(false);
    let t = tokio::spawn(run_camera(notary.clone(), lavfi_cam("CAM-T03"), opts, rx));
    tokio::time::sleep(Duration::from_secs(7)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), t).await.unwrap().unwrap();

    let report = verify_camera(&notary.store, "CAM-T03", &notary.public_key(), true).unwrap();
    assert!(report.ok(), "{:?}", report.issues);
    assert!(report.gaps >= 1, "downtime must be a recorded gap");
}
