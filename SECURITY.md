# Security

## Threat model

Darkreel is designed for **zero-knowledge** self-hosted media storage. A hosted server operator — including the legitimate admin — must not be able to recover plaintext content or metadata without a user's password or recovery code.

### In scope

- Content confidentiality against a fully compromised server process, database, and disk.
- Metadata confidentiality (filenames, types, dimensions, folder structure) against the same.
- Authentication and authorization boundaries: users cannot read, delete, or modify other users' media; non-admins cannot promote themselves; revoked admins cannot re-entrench.
- Resilience against: distributed brute force, per-IP and per-account rate-limit evasion, TOCTOU on quota/admin checks, path traversal via media IDs / chunk indices, symlink attacks on the data directory, duplicate-detection side channels, and chunk-size fingerprinting.

### Out of scope

- **Attackers with live memory access** to the server process. The decrypted master key sits in `SessionStore` for the duration of each authenticated session (up to 24 h). A live-process attacker can recover plaintext for logged-in users.
- **Attackers who compromise a user's device.** The browser (or CLI) sees plaintext; client-side compromise is client-side compromise.
- **Traffic analysis at the network layer.** Chunk sizes are bucketed (1/2/4/8/16 MB) to frustrate per-chunk fingerprinting, but per-user activity timing is visible to any on-path observer.
- **Side channels in the underlying OS, browser, or Go runtime** (e.g., Spectre, GC-driven plaintext-residue, swap to disk).

## Deployment requirements

### TLS is mandatory

Darkreel's HTTP server binds plain `http`. **It MUST be deployed behind a TLS-terminating reverse proxy** (Caddy, nginx, Traefik, Cloudflare Tunnel). Binding `-addr 0.0.0.0:8080` directly to the internet exposes JWT bearer tokens in cleartext.

If you run Darkreel behind a reverse proxy, set `TRUST_PROXY=true` so `X-Forwarded-For` is honored for per-IP rate limiting. Otherwise, leave it unset (the default) — enabling it without a trusted proxy lets any client spoof their IP.

### First-run admin bootstrap

`DARKREEL_ADMIN_PASSWORD` is required on first launch. The server writes a one-time recovery code to `<data-dir>/.recovery-code` (chmod 0600). Read it, store it somewhere safe, and delete the file. Losing the recovery code means losing the ability to recover the admin account if the password is lost.

### Data-directory permissions

The data directory holds the SQLite database (chmod 0600) and all encrypted media blobs. The server process needs read/write there. No other local user should — a local attacker with filesystem access can delete or corrupt media, and can read the encrypted blobs (though not decrypt them without a user's key material).

### JWT secret behavior

The JWT signing secret is regenerated every process start. **All sessions are invalidated on restart.** This is intentional: no persistent secret means no persistent secret to steal from disk. If session durability across restarts matters to you, see the `SetSecret` hook in `internal/auth/jwt.go`.

### Hardware / host

Run Darkreel on a host you control. The server process must never be accessible to other UIDs on the box. Containerize if sharing infrastructure. Back up the data directory with the same rigor as the server itself — the encrypted blobs are useless without the per-user keys (which live only in user-derived form), but the database contains every user's password hash and recovery-wrapped master key.

## Cryptographic notes

- Password hashing: Argon2id (t=3, m=64 MiB, p=4, 32-byte output), 32-byte random salt per user.
- Session key: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output.
- Content encryption: AES-256-GCM with 12-byte random nonce, AAD = `UTF8(mediaID) || BigEndian(uint64(chunkIndex))` for chunks, `UTF8(mediaID)` for file-key wrapping, `UTF8(userID)` for master-key wrapping. AAD binding prevents cross-file and cross-user confused-deputy attacks.
- Recovery: 32-byte random code, AES-256-GCM wrap of master key with AAD = `UTF8(userID)`.
- Nonce policy: every `EncryptBlock` / `EncryptChunk` call generates a fresh random nonce. There is no deterministic-nonce mode.

## Reporting a vulnerability

Email **baileywjohnson@gmail.com** with details. Please do not open a public issue for unfixed vulnerabilities. I'll acknowledge receipt within 7 days and aim to ship a fix within 30 days for high/critical severity.

When reporting, include:
- A clear description of the issue and impact.
- Steps to reproduce (PoC preferred, but not required).
- The Darkreel version and Go version used.
- Your threat-model assumptions (what attacker capability is required).

## Supported versions

Only the latest tagged release on `main` receives security updates. Older binaries are unsupported — keep your deployment current.

## Dependency hygiene

`govulncheck` runs on every push, PR, and weekly in CI (see `.github/workflows/security.yml`). A failing job on an unchanged branch usually means a new CVE was disclosed against one of our pinned deps — upgrade promptly.
