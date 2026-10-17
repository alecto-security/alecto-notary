# alecto-notary

Record camera streams continuously, seal every segment in a signed hash chain, keep a rolling buffer, and let footage be locked against deletion. Footage that went through the Notary can later be proven unaltered.

**Status:** MVP. Spec: [docs/SPEC.md](docs/SPEC.md).

![CI](https://github.com/alecto-security/alecto-notary/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

Linux/macOS:

```bash
cargo test                                # unit + API + real-ffmpeg tests (ffmpeg optional, tests skip without it)
cargo run -- keygen --out ./data/device.key
cp notary.example.yaml notary.yaml
export CAM_W01_PASS='...'
export ALECTO_NOTARY_TOKEN="$(openssl rand -hex 24)"
cargo run -- run                          # record, enforce retention, serve the store API
cargo run -- verify                       # chains, signatures, segment hashes
cargo run -- verify --public-key <b64>    # auditor mode: public key only
```

Windows (PowerShell):

```powershell
cargo test
cargo run -- keygen --out ./data/device.key
Copy-Item notary.example.yaml notary.yaml
$env:CAM_W01_PASS = '...'
$env:ALECTO_NOTARY_TOKEN = -join ((48..57) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
cargo run -- run
cargo run -- verify
cargo run -- verify --public-key <b64>
```

## What it is, and is not

| It does | It never does |
|---------|---------------|
| pull each camera's stream as a second client (`ffmpeg -c copy`, byte-exact) | sit in the camera-to-recorder video path |
| hash, chain and sign every segment (Ed25519) | transcode or modify the footage |
| record gaps and deletions as signed records | hide missing footage |
| delete only unlocked segments, oldest first | delete anything under an evidence lock |
| serve segments and records read-only | take credentials in config files or URIs |

## Layout on disk

```text
<root>/segments/<camera>/<YYYY-MM-DD>/<HHMMSS>_<seq>.ts
<root>/chain/<camera>/<YYYY-MM-DD>.jsonl      signed records, one per line
<root>/spool/<camera>/                        ffmpeg output before sealing
<root>/locks/<id>.json                        evidence locks
<root>/audit.jsonl                            who locked, unlocked, deleted
```

## Contract C2

- Record format and canonicalization: `src/record.rs`, specified in [docs/SPEC.md](docs/SPEC.md). Test vectors: `testvectors/segment-record.json` — a conforming verifier reproduces every hash and signature in that file without importing this code.
- `record_hash` = SHA-256 of the canonical record including `sig`; the next record's `prev_record_hash` points to it. First record uses 64 zeros.
- Signature = Ed25519 over the canonical record without `sig`.
- Kinds: `segment`, `gap` (explicit, with reason), `deleted` (proof stays after the file is removed), `checkpoint` (signed chain head).

## Store API (loopback + bearer token)

| Route | Purpose |
|-------|---------|
| `GET /v1/status` | device id, key id, chain head per camera |
| `GET /v1/cameras` | cameras recorded |
| `GET /v1/pubkey` | device public key |
| `GET /v1/segments?camera=&from=&to=` | contiguous record slice (segments, gaps, deletions) overlapping the window |
| `GET /v1/segments/{camera}/{seq}/file` | segment bytes, `x-segment-sha256` header |
| `POST /v1/locks` | `{camera, from, to, case_id, actor, reason}` |
| `GET /v1/locks`, `DELETE /v1/locks/{id}?actor=` | list, release |

## Known limits (stated, not hidden)

- **The signing key sits in a file** (`0600` on Linux). Someone with root on the box can rewrite history and re-sign it. Secure-element storage is the planned fix. Until then, copy `checkpoint` output off the box regularly: it exposes tail truncation and rewrites.
- **Tail truncation is only detectable against an off-box copy** of a signed head. Deleting the newest records leaves a valid shorter chain.
- **Loopback only.** The API refuses non-loopback binds until TLS is implemented.
- **Time comes from the host clock.** Every record carries `clock.source`; measured skew (`skew_ms`) is not populated yet.
- **Hard kills:** a `kill -9` or `taskkill /F` of the Notary can leave its ffmpeg children running. Run it under systemd with `KillMode=control-group`. File names carry a per-launch id, so an orphan cannot collide with the next run, and leftover spool files are sealed on the next start.
- **Orphans:** a crash between moving a segment and writing its record leaves a file the chain does not mention. `verify` reports these as warnings.
- Storage planning: 1 TB holds about 6 to 12 days of one 8MP stream. Set `max_age_days` and `max_bytes` from real bitrates.

## Security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Known limitations are listed above — a duplicate report about them is welcome but is feature work, not a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
