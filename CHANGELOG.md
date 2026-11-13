# Changelog — DecryptLab Ultimate

## [2.0.0] — 2026-11-13

### Added — V2 subsystems
- **Metadata Intelligence Engine** (`engines/metadata`): filesystem timestamps,
  permissions (symbolic + octal), MIME, detected format, SHA-256.
- **Signature database** (`core/sigdb`, SQLite): schema auto-create, idempotent
  upsert, seed from built-ins, load/merge; optional and offline-safe.
- **Batch engine** (`core/batch`): directory walk → NDJSON, per-file checkpoint,
  **resume after interruption**, progress callback.
- **HTTP/REST API server** (`net/http_server` + `apps/api`): dependency-free
  POSIX-socket HTTP/1.1 server, thread-per-connection with cap, static PWA
  serving + routes `/api/health|version|analyze|metadata|vpn/parse|vpn/audit|
  vpn/generate`, CORS, `$PORT` support for cloud platforms.
- CLI commands `metadata`, `batch`, `sigdb`.
- **Free hosting**: `Dockerfile` (multi-stage), `docker-compose.yml` (+ optional
  Telegram profile), `render.yaml`, `fly.toml`, `Procfile`, and
  [docs/HOSTING.md](docs/HOSTING.md) (Cloudflare Pages / Render / Fly / Oracle
  Always Free / Cloudflare Tunnel, step by step).

### Tests
- 26/26 cases, 79 checks, all passing; Valgrind clean. API endpoints and CLI
  commands verified live.

## [1.0.0] — 2026-11-13

### Added — core (C++20)
- `libdlucore` static library; CMake build; warning-clean (`-Wall -Wextra -Wpedantic`).
- Utilities: in-tree Base64 (std + URL-safe), hex/hexdump, order-preserving JSON parser + serializer.
- Core: streaming FileIO, SHA-256/SHA-1/MD5 (OpenSSL EVP), Shannon entropy meter, signature DB, Intelligent File Recognition (`Detector`) with confidence/evidence and deceptive-extension detection, directory `Scanner` inventory, `Analyzer` orchestrator → unified JSON.
- Engines: read-only ZIP inspector (encrypted-entry flag, zip-bomb guard); proprietary-format inspector for `.ehi/.hc/.npvs/.hat` (documentation only, explicit limitation).
- VPN: normalized model; URI parse/emit for vmess/vless/trojan/ss (+ subscription); OpenVPN/WireGuard/V2Ray-JSON parsers; protocol/script generator for vless/vmess/trojan/shadowsocks/wireguard/openvpn/ssh/slowdns/udp with local UUID/key generation; security auditor (secret masking, weak-cipher/TLS checks, X.509 expiry).

### Added — interfaces
- CLI `decryptlab`: `scan/analyze/inspect/report/vpn{parse,audit,convert,generate}/version/menu`, JSON output, ANSI branding, interactive menu.
- Web/PWA: installable (manifest + service worker), responsive mobile+PC, 100% client-side analysis mirroring the core.
- Telegram bot: stdlib-only long-polling, whitelist, size cap, masked reports, shares the core via subprocess.

### Added — branding & docs
- JORDAN HACKER identity: ASCII logo (full/compact/terminal), SVG + PNG icons, Telegram avatar, palette.
- Docs: README, INSTALL, USER_GUIDE, DEVELOPER_GUIDE, ARCHITECTURE, SECURITY, SUPPORTED_FORMATS, VPN_FORMATS, TEST_REPORT, ROADMAP, FEATURES_INNOVATION; scripts (install/build/test/run/package/serve-web).

### Tests
- 22 unit cases / 62 checks, all passing (see TEST_REPORT.md).

### Scope
- Proprietary-config decryption and key/password extraction from non-owned files are intentionally **not** implemented (see SECURITY.md).
