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

If you run Darkreel behind a reverse proxy, set `TRUST_PROXY=true` so `X-Forwarded-For` is honored for per-IP rate limiting. Otherwise leave it unset — enabling it without a trusted proxy lets any client spoof their IP. If the bind address is reachable beyond the proxy (e.g. a shared Docker network, a cluster mesh), also set `TRUST_PROXY_CIDR` to a comma-separated list of trusted proxy networks (`127.0.0.1/32,10.0.0.0/8`). Proxy headers are then honored only from peers inside those CIDRs; unset keeps the legacy "trust any upstream" behavior, which is safe only if you firewall the bind address to the proxy yourself.

### First-run admin bootstrap

`DARKREEL_ADMIN_PASSWORD` is required on first launch. The server emits the one-time recovery code to stderr (prominent banner) and also writes it to `<data-dir>/.recovery-code` (chmod 0600) so an automated setup script can pick it up. **The file auto-deletes after 5 minutes** — save the code somewhere durable during that window. A stale `.recovery-code` file left behind by a previous bootstrap is cleaned up on the next startup, so the on-disk window is always short. Losing the recovery code means losing the ability to recover the admin account if the password is lost.

### Data-directory permissions

The data directory holds the SQLite database (chmod 0600) and all encrypted media blobs. The server process needs read/write there. No other local user should — a local attacker with filesystem access can delete or corrupt media, and can read the encrypted blobs (though not decrypt them without a user's key material).

### JWT secret behavior

The JWT signing secret is regenerated every process start. **All sessions are invalidated on restart.** This is intentional: no persistent secret means no persistent secret to steal from disk. Delegation refresh tokens survive restarts (they're stored hashed in the DB, independent of the JWT secret), so connected clients like PPVDA keep working across Darkreel restarts.

JWT verification pins the accepted algorithm to exact `HS256` — not just "any HMAC variant" — so a malformed token claiming `HS384`/`HS512` can't slip through even though we never issue those. If you need persistent sessions across restarts the `SetSecret` hook in `internal/auth/jwt.go` accepts a caller-supplied secret; it now returns `ErrSecretAlreadyInitialized` on a second call instead of silently discarding the new value, so misordered callers find out.

### Hardware / host

Run Darkreel on a host you control. The server process must never be accessible to other UIDs on the box. Containerize if sharing infrastructure. Back up the data directory with the same rigor as the server itself — the encrypted blobs are useless without the per-user keys (which live only in user-derived form), but the database contains every user's password hash and recovery-wrapped master key.

- Password hashing: Argon2id (t=3, m=64 MiB, p=4, 32-byte output), 32-byte random salt per user.
- Session key: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output.
- Content encryption: AES-256-GCM with 12-byte random nonce, AAD = `UTF8(mediaID) || BigEndian(uint64(chunkIndex))` for chunks, `UTF8(mediaID)` for metadata blobs, `UTF8(userID)` for master-key wrapping. AAD binding prevents cross-file and cross-user confused-deputy attacks.
- Per-file key sealing: each media upload generates three random 32-byte symmetric keys (file, thumbnail, metadata) and seals each to the account's X25519 public key using X25519-ECDH + HKDF-SHA256 + AES-256-GCM (HKDF info = `"darkreel-seal-v1"`; 92 bytes per sealed key). The server never holds plaintext file/thumb/metadata keys and can decrypt content only if it also has the user's master key (which is cleared from the session right after login). Delegated clients (PPVDA, darkreel-cli v0.3.0+) hold only the public key, so a delegated-client compromise grants upload-only capability — not read/list/delete.
- Recovery: 32-byte random code, AES-256-GCM wrap of master key with AAD = `UTF8(userID)`. The user's X25519 private key is also wrapped twice — once under the master key, once under the recovery code — so recovery restores full access, not just auth.
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
