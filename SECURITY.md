# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub's private security advisories:
open the repository's **Security** tab and choose **Report a vulnerability**.

Do not open a public issue for a security report.

We aim to acknowledge reports within 72 hours and will coordinate disclosure
with you before any public advisory.

## Scope

This project signs evidence. Bugs that matter most to us:

- Anything that lets a valid-looking chain be forged or a tampered segment
  pass `verify` (signature, canonicalization, or hash-chain flaws).
- API bypasses: routes reachable without the bearer token, path traversal
  outside the store root, or lock operations that skip the audit log.
- Credential handling: any path where a camera password can end up in logs,
  records, or the chain.

## Known limitations (not bugs)

The following are documented design limits and are tracked openly. Reports
about them are welcome but will be treated as feature work, not vulnerabilities:

- **The signing key is a file on disk.** An attacker with root on the host
  can rewrite history and re-sign it. Copy `checkpoint` output off the box;
  it exposes tail truncation and rewrites. Secure-element storage is planned.
- **Tail truncation is only detectable against an off-box copy** of a signed
  head. Deleting the newest records leaves a valid shorter chain.
- **Loopback only.** The API refuses non-loopback binds until TLS exists.
- **Time comes from the host clock.** `clock.source` is recorded in every
  record; measured `skew_ms` is not populated yet.

See the README "Known limits" section for the full list.
