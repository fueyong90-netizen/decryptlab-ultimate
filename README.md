```
            01000100 01001100 01010101
          .d88888888888888888888b.
        .8888P""       ""       "Y8888b.
       d88P    01    .--.    10    Y88b
      d8888   .--.  /0xFF\  .--.   8888b
      88888  ( OO )  \__/  ( OO )  88888
      Y8888   `--'  _.__._  `--'   8888P
       Y88b        ( 1001 )       d88P
        `Y88b.      `wwww'      .d88P'
          `"Y8b.___________.d8Y"'
```
# DecryptLab Ultimate
### Advanced File Analysis, Recovery, Cryptographic Inspection & VPN Configuration Intelligence
**by JORDAN HACKER** · C++20 · Kali Linux · offline-first

---

DecryptLab Ultimate is a modular platform to **identify, inspect, analyze, audit,
convert and generate** files and VPN configurations. One C++20 core engine drives
three interfaces: a branded **CLI**, an installable **Web/PWA** app (mobile + PC),
and a **Telegram bot**.

## What it does (honestly)

It rigorously separates, and labels in every report:

```
detection · decoding · decompression · extraction · decryption · password-recovery · repair · reconstruction
```

✅ **Implemented & tested in this release**
- Intelligent file recognition: magic signatures, structural hints, **deceptive-extension** detection, confidence + evidence.
- Fingerprinting: streaming **SHA-256 / SHA-1 / MD5** (OpenSSL), **Shannon entropy** (with the honest caveat: high entropy ≠ encryption).
- **VPN Configuration Intelligence** for *open* formats: `vmess://`, `vless://`, `trojan://`, `ss://` URIs & subscriptions, **OpenVPN**, **WireGuard**, **V2Ray/Xray JSON**.
- **VPN Security Auditor**: exposed secrets, inline private keys, weak ciphers, `allowInsecure`, legacy VMess alterId, **expired X.509 certs** (OpenSSL) — secrets **masked** by default.
- **Protocol/script generator**: VLESS, VMess, Trojan, Shadowsocks, WireGuard, OpenVPN, SSH tunnel, SlowDNS, UDP-custom — with local UUID/key generation.
- **Archive (ZIP) inspector**: read-only central-directory walk, password-protected-entry flag, **zip-bomb** heuristics.
- **Proprietary format inspector** (`.ehi/.hc/.npvs/.hat`): detects & documents structure/entropy and states the exact **limitation**.
- Directory **scanner/inventory**, unified **JSON** reports, CLI + PWA + Telegram sharing one core.

**✅ New in V2**
- **Metadata Intelligence Engine**: timestamps, permissions, MIME, hashes.
- **Signature database (SQLite)**: seed/extend the format table; optional, offline-safe.
- **Batch engine**: analyze a whole folder to NDJSON with **resume-after-interruption** (checkpoint).
- **HTTP/REST API server** (`decryptlab-api`): dependency-free C++ server that serves the PWA **and** the core API from one binary — the basis for free one-binary hosting.

## Scope & ethics (important)

DecryptLab **does not break author-applied encryption** on proprietary tunnel
configs and **does not recover or extract secrets from files you do not own**.
For `.ehi/.hc/.npvs/.hat` it reports *what the file is* and *why it can't be
decoded without the author's algorithm/key* — it never fabricates a result.
See [SECURITY.md](docs/SECURITY.md).

## Quick start (Kali Linux)

```bash
./scripts/install.sh          # deps + build  (or: ./scripts/build.sh)
./scripts/test.sh             # run the test suite
./build/bin/decryptlab        # interactive menu

# examples
./build/bin/decryptlab analyze myfile.bin
./build/bin/decryptlab vpn parse config.ovpn
./build/bin/decryptlab vpn audit node.json
./build/bin/decryptlab vpn generate --proto vless --addr my.server --port 443 --net ws --security tls

./build/bin/decryptlab metadata file.pdf          # metadata (V2)
./build/bin/decryptlab batch ~/dir --out r.ndjson # resumable batch (V2)
./build/bin/decryptlab sigdb data/signatures.db --seed   # SQLite sig DB (V2)

./build/bin/decryptlab-api --web apps/web         # API + PWA on :8090 (V2)
./scripts/serve-web.sh 8080   # the installable PWA at http://localhost:8080
DLU_TOKEN=xxxx python3 apps/telegram/bot.py   # the Telegram bot
```

## Host it free

The PWA is fully client-side → host it free for life on Cloudflare Pages /
GitHub Pages. The API+PWA binary deploys free via Docker on Render / Fly.io /
Oracle Always Free. Full step-by-step: **[docs/HOSTING.md](docs/HOSTING.md)**.
A `Dockerfile`, `render.yaml`, `fly.toml` and `docker-compose.yml` are included.

## Documentation

| Doc | |
|-----|-----|
| [INSTALL.md](docs/INSTALL.md) | Dependencies & build |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | CLI / Web / Telegram usage |
| [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Code layout, adding an engine/plugin |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules & data flow |
| [SECURITY.md](docs/SECURITY.md) | Threat model, scope, limitations |
| [SUPPORTED_FORMATS.md](docs/SUPPORTED_FORMATS.md) | Formats & real support level |
| [VPN_FORMATS.md](docs/VPN_FORMATS.md) | VPN formats & protocols |
| [TEST_REPORT.md](docs/TEST_REPORT.md) | Build & test results |
| [CHANGELOG.md](CHANGELOG.md) | Versions |
| [ROADMAP.md](docs/ROADMAP.md) | V2 plan |

## License
MIT with an acceptable-use clause — see [LICENSE](LICENSE).
```
by JORDAN HACKER
```
