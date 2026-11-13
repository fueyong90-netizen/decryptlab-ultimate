# INSTALL — DecryptLab Ultimate

## Requirements

| Component | Minimum |
|-----------|---------|
| OS | Kali Linux / Debian / Ubuntu (Linux x86-64 or arm64) |
| Compiler | GCC 11+ (tested on GCC 13.3) — C++20 |
| Build | CMake 3.16+ |
| Libraries | OpenSSL (libssl-dev), zlib (zlib1g-dev), pthreads |
| Optional | python3 (PWA server + Telegram bot), zip, gdb, valgrind |

The core has **no third-party source dependencies** beyond OpenSSL/zlib: the
JSON parser, Base64, hex and the test framework are implemented in-tree, so the
project builds on a minimal offline Kali install.

## One-shot install (Kali/Debian/Ubuntu)

```bash
./scripts/install.sh
```

This installs `build-essential g++ cmake libssl-dev zlib1g-dev python3 zip gdb
valgrind`, then builds.

## Manual build

```bash
sudo apt-get update
sudo apt-get install -y build-essential g++ cmake libssl-dev zlib1g-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Artifacts:
- `build/bin/decryptlab` — CLI
- `build/bin/dlu_tests` — test runner

## Run

```bash
./build/bin/decryptlab            # interactive menu
./build/bin/decryptlab version    # engine status
./scripts/test.sh                 # tests + ctest
./scripts/serve-web.sh 8080       # PWA at http://localhost:8080
```

## Telegram bot

```bash
export DLU_TOKEN="123456:ABC..."       # from @BotFather
export DLU_ALLOWED="11111111,22222222" # optional whitelist of user IDs
export DLU_BIN="$PWD/build/bin/decryptlab"
python3 apps/telegram/bot.py
```
No pip packages required (standard library only). Without `DLU_TOKEN` the bot
exits cleanly — the rest of the platform works without it.

## System install (optional)

```bash
sudo cmake --install build   # installs decryptlab to /usr/local/bin
```

## Troubleshooting

- *OpenSSL not found*: `sudo apt-get install libssl-dev`.
- *C++20 errors*: upgrade GCC (`g++ --version` ≥ 11).
- *PWA won't install*: serve over `http://localhost` or HTTPS (service workers
  require a secure context).
