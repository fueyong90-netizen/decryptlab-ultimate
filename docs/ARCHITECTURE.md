# Architecture — DecryptLab Ultimate

## Principle

One **C++20 core** (`libdlucore`), three thin interfaces. The CLI, the Web/PWA
and the Telegram bot all produce the same results because they call the same
engines. The decision logic is **deterministic and explainable** — no engine
invents a technical result (spec §8).

```
          ┌────────────┐   ┌────────────┐   ┌────────────────┐
          │    CLI      │   │  Web / PWA │   │  Telegram bot   │
          │ decryptlab  │   │ (app.js)   │   │  (bot.py)       │
          └─────┬──────┘   └─────┬──────┘   └────────┬───────┘
                │ direct          │ local JS /         │ subprocess
                │ calls           │ optional API       │ decryptlab
                ▼                 ▼                    ▼
          ┌──────────────────────────────────────────────────┐
          │                   libdlucore (C++20)              │
          │                                                   │
          │  core/      Analyzer (orchestrator), Scanner,     │
          │             Detector, Entropy, Hashing, FileIO,   │
          │             Branding, Signatures                  │
          │  engines/   archive(zip), proprietary-inspector   │
          │  vpn/       model, uri, parser, generator,        │
          │             auditor                               │
          │  util/      base64, hex, json                     │
          └──────────────────────────────────────────────────┘
                              │
                     OpenSSL (EVP, RAND, X509), zlib, pthreads
```

## Orchestration flow (`core::Analyzer::analyze`)

1. **Identify** — existence, size, declared extension.
2. **Fingerprint** — streaming SHA-256/SHA-1 (memory-safe for large files).
3. **Measure** — Shannon entropy (streamed).
4. **Recognize** — `Detector` returns ranked hypotheses with evidence; flags
   extension mismatch.
5. **Route** — by extension/format to the right engine:
   - `.ehi/.hc/.npvs/.hat` → `ProprietaryInspector` (document only).
   - ZIP → `inspect_zip` (read-only structure, zip-bomb guard).
   - open VPN config/URI → `vpn::parse_any` + `vpn::audit_*`.
6. **Report** — one structured `util::Json`; secrets masked by default.

## Key interfaces

- `Result<T>` — exception-free status/value/error for hot paths.
- `Support` enum — every capability can declare its real level
  (`implemented+tested`, `partial`, `interface-only`, `unsupported`).
- `VpnProfile` / `VpnDocument` — protocol-agnostic normalized model; parsers
  fill it, generators and converters emit from it.

## Memory & performance (modest hardware, 8 GB RAM target)

- Hashing and entropy use **streaming** (`stream_file`, 1 MiB blocks) — whole
  files are never required in memory.
- `read_all` enforces a configurable byte ceiling; large inputs must stream.
- ZIP inspection reads the central directory only; it never decompresses
  untrusted data (zip-bomb safe) and caps entry count / ratio.
- Threads are configurable; the default build links pthreads for future
  parallel batch processing.

## Extensibility

- New signatures: extend `builtin_signatures()` (or, in V2, load from the
  signature DB / plugins).
- New format engine: implement an inspector returning a structured report and
  route it in `Analyzer::analyze`. See DEVELOPER_GUIDE.md.
- The `IFileEngine`-style contract is realized today by the per-engine report
  structs; V2 promotes it to a registered polymorphic interface + plugin loader.
