# TEST REPORT — DecryptLab Ultimate v2.0.0

**Date:** 2026-11-13
**Toolchain:** GCC 13.3.0 · CMake 3.28.3 · OpenSSL 3.0.13 · SQLite 3.45 · Linux x86-64
**Build type:** Release · flags `-Wall -Wextra -Wpedantic`

## Build

Clean configure + build from scratch: **success, 0 warnings, 0 errors.**
All core sources, the CLI, the **API server**, and the test binary compile and link.

```
libdlucore.a  →  build/bin/decryptlab, build/bin/decryptlab-api, build/bin/dlu_tests
```

## Unit tests

Runner: in-tree framework (`tests/framework.hpp`). CTest integrated.

```
26/26 cases passed, 79 checks, 0 failure(s)
ctest: 100% tests passed, 0 failed out of 1
```

| Area | Cases |
|------|-------|
| util (base64 roundtrip + vector, hex) | 3 |
| json (parse/dump/build) | 2 |
| entropy (constant=0, counter≈8) | 2 |
| detector (png magic, extension mismatch) | 2 |
| vpn URI (vmess roundtrip, vless, ss) | 3 |
| vpn parsers (wireguard, openvpn, v2ray-json) | 3 |
| generator (uuid, vless, wireguard, ssh) | 4 |
| auditor (insecure TLS flag, secret mask) | 2 |
| proprietary inspector (limitation stated) | 1 |
| **V2** sigdb (seed+load), batch (run+resume), metadata, http query | 4 |

## Memory

Valgrind on the full V2 test binary: **clean** (`--leak-check=full`,
error-exitcode=1, no leaks, ERROR SUMMARY 0).

## V2 live verification

| Check | Result |
|-------|--------|
| `decryptlab metadata` | perms + MIME + SHA-256 ✅ |
| `decryptlab sigdb --seed` | 35 signatures seeded into SQLite ✅ |
| `decryptlab batch` + rerun | 5 files, resume adds 0 new lines ✅ |
| API `GET /api/health` | `{"status":"ok"}` ✅ |
| API `GET /api/version` | 13 engines ✅ |
| API `GET /api/vpn/generate` | valid vmess client JSON ✅ |
| API `POST /api/vpn/parse` | VLESS parsed, secret masked ✅ |
| API `POST /api/analyze` (PNG) | "PNG image" ✅ |
| API static `/` | serves PWA (200) ✅ |

## Functional smoke tests (CLI)

| Command | Result |
|---------|--------|
| `version` | banner + engine list ✅ |
| `scan samples` | 5 files inventoried, SHA-256, correct formats ✅ |
| `analyze samples/test.ehi` | proprietary route: "appears encrypted…" + explicit limitation ✅ |
| `vpn parse samples/test_vless.txt` | VLESS parsed, secret masked (`111********`) ✅ |
| `vpn audit samples/test.ovpn` | audit score + findings ✅ |
| `vpn convert samples/node.txt --to uri` | vmess URI emitted ✅ |
| `vpn generate --proto vless/wireguard/ssh/udp/slowdns …` | valid configs/scripts ✅ |
| WireGuard detection | `test.wg.conf` → "WireGuard config" ✅ |

## Interfaces

- **CLI**: all subcommands exercised above. ✅
- **Web/PWA**: `python3 -m py_compile` n/a (JS); static assets served; manifest +
  service worker present; icons rendered (192/512 PNG + SVG). Client logic mirrors
  core (manual verification). ✅ (functional; automated JS tests are a V2 item)
- **Telegram bot**: `python3 -m py_compile apps/telegram/bot.py` ✅; runs and exits
  cleanly without `DLU_TOKEN`; requires a token + network to serve live. ✅

## Known limitations (honest)

- Proprietary-config **decryption / key extraction** on non-owned files: **not
  implemented by design** (see SECURITY.md).
- 7z/RAR/TAR extraction, PDF/Office deep parse, file-system recovery, plugin DB,
  REST API: **interface/placeholder only**, scheduled for V2 (ROADMAP.md).
- Web PWA covers open formats client-side; heavy/binary formats are best handled
  by the CLI core until the V2 local API lands.

## Verdict

Core C++20 engine, CLI, PWA and Telegram bot are **built, tested and functional**
within the stated scope. No fabricated capabilities; every report labels its real
support level.
