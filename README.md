# Darkreel

End-to-end encrypted video and photo storage with streaming playback. The server never sees your content -- all encryption and decryption happens client-side.

## Features

- **E2E encrypted** -- AES-256-GCM chunk encryption, keys derived from your password via Argon2id
- **Streaming playback** -- Chunk-based encrypted streaming with seeking via MediaSource Extensions
- **Multi-user** -- Each user has an isolated, encrypted library
- **Zero-knowledge metadata** -- File names, types, sizes, dimensions, and durations are encrypted. The server only sees opaque blobs.
- **Chunk padding** -- All encrypted chunks are padded to a fixed size on disk to prevent size-based fingerprinting
- **Secure deletion** -- Deleted media is overwritten 3 times with random data before unlinking
- **Web UI** -- Browse, upload, stream, download, and delete media from your browser
- **Single binary** -- Go binary with embedded frontend, no external dependencies
- **Self-hosted** -- Your data stays on your server

## How it works

1. Your password derives a **master key** (Argon2id) that never leaves your browser
2. Each file gets a random **file key**, encrypted with your master key and stored server-side
3. Files are split into **1 MB chunks**, each encrypted with AES-256-GCM (chunk index as AAD to prevent reordering)
4. All file metadata (name, type, MIME type, size, dimensions, duration) is encrypted into a single blob by the client -- the server stores it opaquely
5. Chunks are padded to a fixed size on disk so the server cannot determine original file sizes
6. Your browser fetches chunks, decrypts them in a Web Worker, and streams to `<video>` or `<img>`

## Minimum requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 512 MB | 1+ GB |
| Disk | 10 GB | Depends on media library size |
| OS | Linux (amd64 or arm64) | Ubuntu 22.04+ / Debian 12+ |
| Go | 1.22+ (build only) | Latest stable |

Darkreel is lightweight -- it's a single Go binary with SQLite. The main resource requirement is disk space for your encrypted media.

## Quick start

### Prerequisites

- Go 1.22+ (to build from source)

### Build and run

```bash
git clone https://github.com/baileywjohnson/darkreel.git
cd darkreel
go build -o darkreel .
./darkreel
```

The server starts at `http://localhost:8080`. Register an account via the web UI and start uploading.

### Configuration

```
./darkreel [flags]

Flags:
  -addr string   Listen address (default ":8080")
  -data string   Data directory for encrypted files and database (default "./data")
```

Examples:

```bash
# Run on port 3000 with data stored in /var/lib/darkreel
./darkreel -addr :3000 -data /var/lib/darkreel

# Listen on all interfaces
./darkreel -addr 0.0.0.0:8080
```

### Account constraints

- Username: 3-64 characters
- Password: 8-128 characters

## Security

### TLS required

Darkreel does not handle TLS itself. **You must deploy it behind a TLS-terminating reverse proxy** (nginx, Caddy, etc.) to encrypt traffic. Without TLS, passwords and encrypted content are transmitted in plaintext over the network.

### What the server knows

| Data | Server sees? |
|------|-------------|
| File content | No -- encrypted with per-file AES-256-GCM key |
| File name | No -- encrypted in metadata blob |
| File type, MIME type | No -- encrypted in metadata blob |
| File size, dimensions, duration | No -- encrypted in metadata blob |
| Thumbnails | No -- encrypted with separate per-file key |
| Number of files per user | Yes (DB row count) |
| Approximate total storage per user | Yes (disk usage, though chunks are padded) |
| Upload timestamps | Yes (for ordering) |
| Usernames | Yes (for authentication) |

### Security headers

The server sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive `Content-Security-Policy`.

## API

All media endpoints require a JWT token (obtained via login). JWTs contain only user ID and session ID -- no username or other metadata.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login, returns JWT + encrypted master key |
| POST | `/api/auth/logout` | Logout, clears session |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (`?page=`, `?limit=`) -- returns encrypted metadata blobs |
| GET | `/api/media/:id` | Get single media item |
| POST | `/api/media/upload` | Upload encrypted media (multipart: metadata + thumbnail + chunks) |
| DELETE | `/api/media/:id` | Delete media (secure shred + DB removal) |
| GET | `/api/media/:id/chunk/:index` | Get encrypted chunk (padding stripped) |
| GET | `/api/media/:id/thumbnail` | Get encrypted thumbnail |
| GET | `/api/media/:id/download` | Download all encrypted chunks concatenated |

Sorting, filtering by type, and searching are done client-side since metadata is encrypted.

## Encryption details

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads, 32-byte output |
| Master key derivation | Argon2id | Separate salt from auth hash -- cannot derive one from the other |
| File encryption | AES-256-GCM | 1 MB chunks, chunk index as AAD, random 12-byte nonce per chunk |
| Key wrapping | AES-256-GCM | File keys encrypted with master key |
| Session key | PBKDF2-SHA256 | 100k iterations, for encrypting master key in login response |
| Chunk storage | Padded | All chunks padded to fixed 1,048,604 bytes with random fill |
| Deletion | 3-pass shred | Random overwrite before unlink |

### Upload size limits

| Limit | Value |
|-------|-------|
| Max thumbnail size | 2 MB |
| Max chunk size | 2 MB |
| Max chunks per file | 50,000 (~50 GB) |
| Max total upload | 100 GB |
| Auth request body | 64 KB |

## Deployment

### Systemd

```ini
[Unit]
Description=Darkreel
After=network.target

[Service]
ExecStart=/usr/local/bin/darkreel -addr :8080 -data /var/lib/darkreel
Restart=always
User=darkreel
Group=darkreel

[Install]
WantedBy=multi-user.target
```

### Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name media.example.com;

    ssl_certificate     /etc/letsencrypt/live/media.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/media.example.com/privkey.pem;

    # No upload size limit -- Darkreel enforces its own limits
    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy (alternative)

```
media.example.com {
    reverse_proxy localhost:8080
}
```

Caddy handles TLS automatically via Let's Encrypt.

## Data directory layout

```
data/
  darkreel.db           # SQLite database (encrypted metadata, user records)
  {userID}/
    {mediaID}/
      000000.enc        # Padded encrypted chunk (fixed size)
      000001.enc
      ...
      thumb.enc         # Encrypted thumbnail
```

## Related projects

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) -- Command-line upload tool
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
