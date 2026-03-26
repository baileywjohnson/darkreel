# Darkreel

End-to-end encrypted video and photo storage with streaming playback. The server never sees your content -- all encryption and decryption happens client-side.

## Features

- **E2E encrypted** -- AES-256-GCM chunk encryption, keys derived from your password via Argon2id
- **Streaming playback** -- Chunk-based encrypted streaming with seeking via MediaSource Extensions
- **Multi-user** -- Each user has an isolated, encrypted library
- **Web UI** -- Browse, upload, stream, download, and delete media from your browser
- **Single binary** -- Go binary with embedded frontend, no external dependencies except SQLite
- **Self-hosted** -- Your data stays on your server

## How it works

1. Your password derives a **master key** (Argon2id) that never leaves your browser
2. Each file gets a random **file key**, encrypted with your master key and stored server-side
3. Files are split into **1 MB chunks**, each encrypted with AES-256-GCM
4. The server stores and serves encrypted chunks -- it cannot decrypt them
5. Your browser fetches chunks, decrypts them in a Web Worker, and streams to `<video>` or `<img>`

## Requirements

- Go 1.22+

## Quick start

```bash
git clone https://github.com/baileywjohnson/darkreel.git
cd darkreel
go build -o darkreel .
./darkreel
```

The server starts at `http://localhost:8080`. Register an account and start uploading.

## Usage

```
./darkreel [flags]

Flags:
  -addr string   Listen address (default ":8080")
  -data string   Data directory for encrypted files and database (default "./data")
```

## Examples

```bash
# Run on port 3000 with data stored in /var/lib/darkreel
./darkreel -addr :3000 -data /var/lib/darkreel

# Run with default settings
./darkreel
```

## API

All media endpoints require a JWT token (obtained via login).

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login, returns JWT + encrypted master key |
| POST | `/api/auth/logout` | Logout |

### Media

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/media` | List media (supports `?sort=`, `?order=`, `?type=`, `?page=`, `?limit=`) |
| GET | `/api/media/:id` | Get media metadata |
| POST | `/api/media/upload` | Upload encrypted media (multipart) |
| DELETE | `/api/media/:id` | Delete media |
| GET | `/api/media/:id/chunk/:index` | Get encrypted chunk |
| GET | `/api/media/:id/thumbnail` | Get encrypted thumbnail |
| GET | `/api/media/:id/download` | Download complete encrypted file |

## Encryption details

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Password hashing | Argon2id | 3 iterations, 64 MB memory, 4 threads |
| Master key derivation | Argon2id | Separate salt from auth hash |
| File encryption | AES-256-GCM | 1 MB chunks, chunk index as AAD |
| Key wrapping | AES-256-GCM | File keys encrypted with master key |
| Session key | PBKDF2-SHA256 | 100k iterations, for master key transport |

Two separate salts per user ensure the authentication hash cannot be used to derive the master key.

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

## Related projects

- [darkreel-cli](https://github.com/baileywjohnson/darkreel-cli) -- Command-line upload tool
- [ppvda](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
