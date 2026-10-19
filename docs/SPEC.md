# Alecto Notary — Specification

This document defines what the Notary does, the on-disk and wire formats it
produces, and the limits it operates under. External verifiers should treat
the record format in "Contract C2" as stable: breaking changes bump the `v`
field, never mutate a released version.

## Purpose

Record camera streams continuously to local disk for a rolling window, and
make every recorded segment provable: when it was captured, and that it has
not changed since.

It addresses two common failures: footage silently lost to retention
rollover, and doubt about tampering after the fact.

## Scope

In scope:

- RTSP pull recorder per camera, segmented, byte-exact (`ffmpeg -c copy`).
- Per-segment hash, hash chain, Ed25519 signature, signed checkpoints.
- Ring-buffer retention with evidence locks.
- Read-only store API plus a lock endpoint.
- A verifier library and CLI (`verify`, including public-key-only mode).

Out of scope:

- Sitting inline between camera and recorder. The Notary is a second RTSP
  client and is never in the camera's video path.
- Secure-element key storage (planned).
- Cloud upload, transcoding, AI.

## Separation

| Notary does | Notary never does |
|-------------|-------------------|
| record, hash, sign, retain, lock, serve segments read-only | alter or block the camera-to-recorder path |
| expose its own public key and chain | hide missing footage |
| fail closed on tamper checks | take credentials in config or URIs |

## Components

```text
camera --RTSP--> [recorder] --> segments/ (disk)
                     |
                     +--> [chain writer] --> chain/<camera>/<day>.jsonl  (signed records)
                     |
        [retention] -+--> deletes oldest unlocked segments
        [lock store]--> locks/*.json
        [store API ] --> read-only HTTP + POST /v1/locks
        [verifier  ] --> verify (lib + CLI)
```

- **recorder:** one supervised ffmpeg subprocess per camera, segment muxer,
  `-c copy`, 60-second MPEG-TS segments. Reconnect with backoff; a gap is
  recorded, never hidden.
- **chain writer:** after each segment closes, write one record (below),
  sign it, append to the day file. Flat files, no database.
- **retention:** delete oldest unlocked segments when age or byte limits are
  hit. Deletion is itself a chain event (`deleted` record), so history stays
  honest.
- **lock store:** a lock names camera, time range, case ID, actor, reason.
  Locks are audited and removed only by an explicit unlock.

## Contract C2: segment record

One JSON object per line:

```json
{
  "v": 1,
  "kind": "segment",
  "device_id": "notary-store-142",
  "key_id": "493ab7268f7ee618",
  "camera_id": "CAM-W01",
  "seq": 18211,
  "start_utc": "2026-10-02T14:03:00.000Z",
  "end_utc": "2026-10-02T14:04:00.000Z",
  "file": "segments/CAM-W01/2026-10-02/140300_18211.ts",
  "sha256": "<hex of segment bytes>",
  "bytes": 7340032,
  "prev_record_hash": "<hex>",
  "clock": {"source": "ntp", "skew_ms": 400},
  "sig": "<base64 Ed25519 over the canonical record without sig>"
}
```

- Canonicalization: sorted keys, no whitespace. `record_hash` = SHA-256 of
  the canonical record bytes with `sig` included. The next record's
  `prev_record_hash` points to it. The first record uses 64 zeros.
- Record kinds: `segment`, `gap` (explicit, with `reason`), `deleted`
  (written when retention removes a file; keeps the removed segment's hash
  and size), `checkpoint` (signed chain head). `seq` is continuous across
  all kinds and starts at 1.
- Timestamps are RFC 3339 UTC with milliseconds. `skew_ms` is an integer,
  because floats do not canonicalize reliably across implementations.
- **Checkpoint:** a signed record containing the chain head and segment
  count. Copy it off the box regularly — it is what makes tail truncation
  and rewrites detectable. An external anchor (e.g. RFC 3161 timestamp) is
  a future option.
- **Test vectors:** `testvectors/segment-record.json` (seed bytes 1..=32).
  A conforming implementation reproduces every hash and signature in that
  file without importing code from this repo.

## Test vector manifest

`testvectors/` is the frozen Contract C2 conformance corpus. Each file's
digest is pinned below, and `scripts/check-testvectors.sh` recomputes them in
CI and fails on any mismatch. A change to a vector file therefore cannot land
silently, which is what makes drift between this repo and any implementation
that mirrors these vectors detectable by either side.

| File | SHA-256 |
|------|---------|
| `segment-record.json` | `9e8dff1d7fea2015d17e91c2d8a93fac40a5fa0b2f2546f06bd272c9b0b69d6c` |

A row changes only when the format it fixes changes; a vector file for a
future record version is added as a new file and a new row, and does not
alter the digests of released ones.

## Contract C2: store API

Loopback only; non-loopback binds are refused until TLS is implemented.
Bearer-token auth on every route.

| Route | Purpose |
|-------|---------|
| `GET /v1/status` | device id, key id, chain head per camera |
| `GET /v1/cameras` | cameras recorded |
| `GET /v1/pubkey` | device public key |
| `GET /v1/segments?camera=&from=&to=` | segment records (the manifest slice) |
| `GET /v1/segments/{camera}/{seq}/file` | segment bytes, `x-segment-sha256` header |
| `POST /v1/locks` | `{camera, from, to, case_id, actor, reason}` |
| `GET /v1/locks`, `DELETE /v1/locks/{id}` | list, release |

Read endpoints never modify anything.

## Threat model and limits (stated, not hidden)

- **The signing key sits in a file** (`0600` on Linux). Someone with root on
  the box can rewrite history and re-sign it. Secure-element or TPM-class
  storage is the planned fix. Until then, copy `checkpoint` output off the
  box regularly.
- **Tail truncation is only detectable against an off-box copy** of a signed
  head. Deleting the newest records leaves a valid shorter chain.
- **Loopback only.** The API refuses non-loopback binds until TLS exists.
- **Time comes from the host clock.** Every record carries `clock.source`;
  measured `skew_ms` is not populated yet.
- **Hard kills:** `kill -9` / `taskkill /F` can leave ffmpeg children
  running. Run under a supervisor that kills the whole process group
  (`KillMode=control-group` on systemd). File names carry a per-launch id,
  so an orphan cannot collide with the next run, and leftover spool files
  are sealed on the next start.
- **Orphans:** a crash between moving a segment and writing its record
  leaves a file the chain does not mention. `verify` reports these as
  warnings.
- **Storage planning:** 1 TB holds about 6 to 12 days of one 8MP stream at
  8–16 Mbps. Set `max_age_days` and `max_bytes` from real bitrates.

## Open questions

- Does the target camera allow a second concurrent RTSP client? Some cheap
  cameras do not.
- Key custody and rotation before secure-element storage lands.
- Which external anchor, if any, for checkpoints.
