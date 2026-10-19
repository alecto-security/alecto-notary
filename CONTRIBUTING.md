# Contributing

Thanks for your interest. Issues, bug reports, and pull requests are welcome.

## Setup

- Rust stable (`rustup`).
- ffmpeg + ffprobe on `PATH` for the end-to-end tests. Without them, the
  unit and API tests still run; tests that need ffmpeg skip themselves.

```bash
cargo test
```

Windows, Linux, and macOS are all supported. If a change only works on one
OS, say so in the PR.

## The one rule that is not negotiable

**The record format is a contract (C2).** `src/record.rs` and
`testvectors/segment-record.json` define a format that external verifiers
rely on. Changing canonicalization, hashing, or signing breaks verification
of every chain already in the field. If a change needs a different format,
bump the `v` field and keep reading old versions — never mutate `v: 1`
silently. See `docs/SPEC.md`.

## Other ground rules

- No credentials in config files, URIs, logs, or records. `password_env`
  indirection only.
- The store API is read-only except `POST /v1/locks` and
  `DELETE /v1/locks/{id}`. Read routes must never mutate state.
- Missing footage is recorded, never hidden: time jumps become `gap`
  records, retention deletions become `deleted` records.
- The Notary is a second RTSP client. It must never sit in the
  camera-to-recorder path, and a crash here must not affect the site's own
  recording.
- Keep it dependency-light. Flat files, no database.

## Releases and versioning

Tags are `vX.Y.Z` (semver) on `main`, cut only after CI is green. The
version policy for this repo:

- **Major** — any change to the signed segment-record format (Contract C2)
  or to the store API contract. While the version is `0.y.z` this increments
  `y` (`0.2.0`); from `1.0.0` on it increments `x`. The format's own `v`
  field still bumps separately, so a new record version is a major release
  *and* a `v` bump, never a silent edit to `v: 1`.
- **Minor** — additive, optional changes: optional record fields that an
  older verifier can ignore, new optional query parameters, new routes.
- **Patch** — fixes that leave the wire format and API shape untouched:
  bug fixes, docs, internal refactors.

Every release adds an entry to [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- Describe the problem and the fix; link the issue if there is one.
- Add tests for behavior changes. `tests/notary.rs` is the integration
  suite; `tests/e2e.rs` covers real ffmpeg recording.
- `cargo fmt` and `cargo clippy` clean before submitting.
