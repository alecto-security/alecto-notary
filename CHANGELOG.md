# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version policy for this repo (what counts as a major, minor, or patch
change) is in [CONTRIBUTING.md](CONTRIBUTING.md).

## [Unreleased]

## [0.1.0] - 2026-10-19

Initial public release. Apache-2.0.

### Added

- RTSP pull recorder: one supervised `ffmpeg -c copy` process per camera,
  60-second byte-exact MPEG-TS segments, reconnect with backoff. A lost
  window becomes a signed `gap` record with a reason, never a silent hole.
- Contract C2 signed segment records: per-segment SHA-256, Ed25519 signature,
  canonical JSON (sorted keys, no whitespace), `prev_record_hash` chain
  seeded with 64 zeros, and `record_hash` = SHA-256 of the canonical record
  including `sig`.
- Record kinds `segment`, `gap`, `deleted`, and `checkpoint`, with `seq`
  continuous across all kinds.
- Ring-buffer retention with evidence locks: deletes the oldest unlocked
  segments on age or byte limits, and records every deletion as a signed
  `deleted` record.
- Lock store: `{camera, from, to, case_id, actor, reason}` locks, every
  create and release audited in `audit.jsonl`, removed only by an explicit
  unlock.
- Store API: read-only routes plus the lock endpoints, loopback-only, bearer
  token on every route — `GET /v1/status`, `GET /v1/cameras`,
  `GET /v1/pubkey`, `GET /v1/segments`, `GET /v1/segments/{camera}/{seq}/file`,
  `POST /v1/locks`, `GET /v1/locks`, `DELETE /v1/locks/{id}`.
- CLI: `keygen` (refuses to overwrite an existing key), `run`, and `verify`,
  including `verify --public-key` auditor mode that needs nothing but the
  public key.
- Contract C2 test vectors (`testvectors/segment-record.json`, seed bytes
  1..=32) and the `examples/gen_vectors.rs` generator.
- Test suites: the `tests/notary.rs` QA matrix (N1..N9) and `tests/e2e.rs`
  real-ffmpeg recording tests, which skip themselves when ffmpeg is absent.
- CI workflow running the test suite on pushes to `main` and on pull
  requests.
- In-repo specification `docs/SPEC.md`: Contract C2 (record format and store
  API), the threat model, and the stated limits.
- Open-source release hygiene: Apache-2.0 `LICENSE`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.

### Changed

- README rebuilt around the brand header, architecture and hash-chain
  diagrams, and a real `verify` demo; a PowerShell quickstart joined the
  Linux/macOS one.

### Security

- Documented the threat model plainly instead of hiding it: the Ed25519
  signing key lives in a root-only file, tail truncation is detectable only
  against an off-box copy of a signed checkpoint, the API refuses
  non-loopback binds until TLS exists, and `skew_ms` is not populated yet.

[Unreleased]: https://github.com/alecto-security/alecto-notary/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alecto-security/alecto-notary/releases/tag/v0.1.0
