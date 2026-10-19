# AGENTS.md: AI entry point for alecto-notary

Instructions for AI coding agents working in this repo. Read fully before writing code.

## Repo purpose

Record camera streams continuously, seal every segment in a signed hash chain, keep a rolling buffer, and let footage be locked against deletion. Footage that passed through here can later be proven unaltered.

## Non-negotiable rules

1. **Never write evidence bundles.** Only the evidence gateway seals bundles. This repo supplies signed segments and records.
2. **Never sit in the camera-to-recorder path.** The Notary is a second RTSP client, and a crash here must not touch the customer's own recording.
3. **Never hide missing footage.** A time jump is a signed `gap` record; a retention deletion is a signed `deleted` record.
4. **Never overwrite or regenerate the device key.** `keygen` refuses an existing file.
5. **Never put credentials in config.** `password_env` indirection only; credentials in a URI are a config error.
6. **The record format is a contract (C2).** `testvectors/segment-record.json` is the frozen conformance corpus that other implementations mirror. Changing canonicalization or signing breaks verification of every existing chain; bump `v` instead and update every implementation that mirrors it.
7. **Never import code from other Alecto repos.** Contracts only.

## Source of truth

Spec: `docs/SPEC.md` in this repo. The record format (Contract C2) and its test vectors are the public interop contract.

## Stack

Rust, Tokio, Axum (loopback only, bearer token), ffmpeg subprocess for recording, flat files for storage (ADR-0003 style, no database), Ed25519 and SHA-256.
