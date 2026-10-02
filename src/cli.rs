use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use clap::{Parser, Subcommand};
use tokio::sync::watch;

use crate::api::{self, ApiState};
use crate::audit::Audit;
use crate::config::{ensure_loopback, load_api_token, Config};
use crate::error::{NotaryError, Result, EXIT_FAIL, EXIT_OK};
use crate::keys::{parse_public_b64, DeviceKey};
use crate::locks::LockStore;
use crate::notary::Notary;
use crate::recorder::{self, RecorderOpts};
use crate::retention::{self, Policy};
use crate::store::Store;
use crate::timefmt::parse;
use crate::verify::verify_camera;

#[derive(Parser)]
#[command(
    name = "alecto-notary",
    version,
    about = "Record it. Sign it. Prove it was not touched."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create the device key. Never overwrites an existing key.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Record all cameras, enforce retention, serve the store API.
    Run {
        #[arg(long, default_value = "notary.yaml")]
        config: PathBuf,
    },
    /// Verify chains and segment files.
    Verify {
        #[arg(long, default_value = "notary.yaml")]
        config: PathBuf,
        #[arg(long)]
        camera: Option<String>,
        /// Verify with a public key only (base64), without the device key file.
        #[arg(long)]
        public_key: Option<String>,
        /// Skip re-hashing segment files (chain and signatures only).
        #[arg(long)]
        no_files: bool,
        #[arg(long)]
        json: bool,
    },
    /// Apply the retention policy once.
    Retain {
        #[arg(long, default_value = "notary.yaml")]
        config: PathBuf,
    },
    /// Seal an existing finished segment file into a camera chain.
    SealFile {
        #[arg(long, default_value = "notary.yaml")]
        config: PathBuf,
        #[arg(long)]
        camera: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        start: String,
        #[arg(long)]
        end: String,
    },
    /// Sign the current head of each chain. Copy the output off the box.
    Checkpoint {
        #[arg(long, default_value = "notary.yaml")]
        config: PathBuf,
        #[arg(long)]
        camera: Option<String>,
    },
    /// Check that ffmpeg and ffprobe run.
    Doctor,
}

pub async fn run() -> i32 {
    match execute(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            e.exit_code()
        }
    }
}

fn build(cfg: &Config) -> Result<Arc<Notary>> {
    let key = DeviceKey::load(&cfg.key_file)?;
    Ok(Arc::new(Notary::new(
        Store::new(&cfg.root),
        key,
        &cfg.device_id,
        &cfg.clock_source,
    )))
}

pub async fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Keygen { out } => {
            let key = DeviceKey::create_file(&out)?;
            println!("key_id     {}", key.key_id());
            println!("public_key {}", key.public_b64());
            Ok(EXIT_OK)
        }
        Command::Doctor => {
            for bin in ["ffmpeg", "ffprobe"] {
                let out = tokio::process::Command::new(bin)
                    .arg("-version")
                    .output()
                    .await
                    .map_err(|e| NotaryError::fail(format!("{bin} not runnable: {e}")))?;
                let first = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                println!("{first}");
            }
            Ok(EXIT_OK)
        }
        Command::Verify {
            config,
            camera,
            public_key,
            no_files,
            json,
        } => {
            let cfg = Config::load(&config)?;
            let public = match public_key {
                Some(b64) => parse_public_b64(&b64)?,
                None => DeviceKey::load(&cfg.key_file)?.public(),
            };
            let store = Store::new(&cfg.root);
            let cameras: Vec<String> = match camera {
                Some(c) => vec![c],
                None => cfg.cameras.iter().map(|c| c.id.clone()).collect(),
            };
            let mut all_ok = true;
            let mut reports = Vec::new();
            for cam in &cameras {
                let report = verify_camera(&store, cam, &public, !no_files)?;
                all_ok &= report.ok();
                if !json {
                    println!(
                        "{}: {} records ({} segments, {} gaps, {} deleted) {}",
                        cam,
                        report.records,
                        report.segments,
                        report.gaps,
                        report.deleted,
                        if report.ok() { "OK" } else { "FAILED" }
                    );
                    for i in &report.issues {
                        println!(
                            "  {:?} seq={} file={} {}",
                            i.severity,
                            i.seq.map_or("-".into(), |s| s.to_string()),
                            i.file.as_deref().unwrap_or("-"),
                            i.problem
                        );
                    }
                }
                reports.push(report);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
            Ok(if all_ok { EXIT_OK } else { EXIT_FAIL })
        }
        Command::Retain { config } => {
            let cfg = Config::load(&config)?;
            let notary = build(&cfg)?;
            let audit = Audit::new(notary.store.audit_path());
            let locks = LockStore::new(notary.store.locks_dir(), audit.clone());
            let cams: Vec<String> = cfg.cameras.iter().map(|c| c.id.clone()).collect();
            let policy = Policy {
                max_age: chrono::Duration::days(cfg.retention.max_age_days as i64),
                max_bytes: cfg.retention.max_bytes,
            };
            let out = retention::apply(&notary, &locks, &audit, &cams, &policy, Utc::now())?;
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(EXIT_OK)
        }
        Command::SealFile {
            config,
            camera,
            file,
            start,
            end,
        } => {
            let cfg = Config::load(&config)?;
            let notary = build(&cfg)?;
            let rec = notary.seal_segment(&camera, &file, parse(&start)?, parse(&end)?, None)?;
            println!("sealed seq={} {}", rec.seq, rec.file.unwrap_or_default());
            Ok(EXIT_OK)
        }
        Command::Checkpoint { config, camera } => {
            let cfg = Config::load(&config)?;
            let notary = build(&cfg)?;
            let cams: Vec<String> = match camera {
                Some(c) => vec![c],
                None => cfg.cameras.iter().map(|c| c.id.clone()).collect(),
            };
            for cam in cams {
                let rec = notary.checkpoint(&cam, Utc::now())?;
                println!("{}", serde_json::to_string(&rec)?);
            }
            Ok(EXIT_OK)
        }
        Command::Run { config } => run_service(config).await,
    }
}

async fn run_service(config: PathBuf) -> Result<i32> {
    let cfg = Config::load(&config)?;
    ensure_loopback(&cfg.api.bind)?;
    let token = load_api_token(&cfg.api.token_env)?;
    let notary = build(&cfg)?;
    let audit = Audit::new(notary.store.audit_path());
    let locks = LockStore::new(notary.store.locks_dir(), audit.clone());
    let cameras: Vec<String> = cfg.cameras.iter().map(|c| c.id.clone()).collect();
    println!(
        "notary {} key_id={} api={}",
        cfg.device_id,
        notary.key_id(),
        cfg.api.bind
    );

    let (tx, rx) = watch::channel(false);
    let opts = RecorderOpts {
        segment_secs: cfg.segment_secs,
        ..RecorderOpts::default()
    };
    let mut tasks = Vec::new();
    for cam in cfg.cameras.clone() {
        tasks.push(tokio::spawn(recorder::run_camera(
            notary.clone(),
            cam,
            opts.clone(),
            rx.clone(),
        )));
    }

    // Retention every 10 minutes, checkpoint daily.
    {
        let (notary, locks, audit, cams, mut rx) =
            (notary.clone(), locks.clone(), audit.clone(), cameras.clone(), rx.clone());
        let policy = Policy {
            max_age: chrono::Duration::days(cfg.retention.max_age_days as i64),
            max_bytes: cfg.retention.max_bytes,
        };
        tasks.push(tokio::spawn(async move {
            let mut last_checkpoint = Utc::now();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(600)) => {}
                    _ = rx.changed() => { if *rx.borrow() { return; } }
                }
                if let Err(e) = retention::apply(&notary, &locks, &audit, &cams, &policy, Utc::now()) {
                    eprintln!("retention failed: {e}");
                }
                if Utc::now() - last_checkpoint > chrono::Duration::hours(24) {
                    for cam in &cams {
                        if let Err(e) = notary.checkpoint(cam, Utc::now()) {
                            eprintln!("checkpoint {cam} failed: {e}");
                        }
                    }
                    last_checkpoint = Utc::now();
                }
            }
        }));
    }

    let app = api::router(ApiState {
        notary: notary.clone(),
        locks,
        cameras,
        token,
    });
    let listener = tokio::net::TcpListener::bind(cfg.api.bind).await?;
    let mut shutdown_rx = rx.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.changed().await;
    });
    let signal = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send(true);
    });
    server.await?;
    signal.abort();
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(15), t).await;
    }
    Ok(EXIT_OK)
}
