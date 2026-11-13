# Innovation — 15+ differentiating features (spec §12)

For each: utility · architecture · dependencies · dev cost · **now / V2** · status here.

1. **Explainable detection with evidence & confidence** — users see *why* a verdict
   was reached. Arch: `Detector` attaches evidence strings per hypothesis. Deps:
   none. Cost: low. **Now.** ✅ implemented.
2. **Deceptive-extension detector** — flags content/extension mismatch (malware
   triage). Arch: compare top signature's extension set vs. declared ext. Deps:
   none. Cost: low. **Now.** ✅.
3. **Honest entropy interpretation** — qualitative label + explicit "entropy ≠
   encryption" caveat, stopping false "encrypted" calls. Deps: none. Cost: low.
   **Now.** ✅.
4. **Unified multi-interface core** — CLI/Web/Telegram share one engine; identical
   results. Arch: `libdlucore` + thin front-ends. Cost: medium. **Now.** ✅.
5. **Installable offline PWA** — field use on phones with no backend. Arch: service
   worker + WebCrypto client logic. Deps: none. Cost: medium. **Now.** ✅.
6. **VPN protocol/script generator** — creates vless/vmess/trojan/ss/wg/ovpn/ssh/
   slowdns/udp configs with locally-generated keys. Arch: `vpn::generate` from the
   normalized model. Deps: OpenSSL RAND. Cost: medium. **Now.** ✅.
7. **VPN security auditor with secret masking** — turns configs into a risk score +
   findings; secrets never shown. Arch: `vpn::audit_*` + `mask_*`. Deps: OpenSSL
   X509. Cost: medium. **Now.** ✅.
8. **Round-trip config converter** — any parsed profile → URI / V2Ray / outbound.
   Arch: model-centric emit. Deps: none. Cost: low. **Now.** ✅.
9. **Zip-bomb-safe archive inspection** — read central directory only; ratio/entry
   caps. Arch: `inspect_zip`. Deps: none. Cost: low. **Now.** ✅.
10. **Proprietary-format honest inspector** — documents `.ehi/.hc/.npvs/.hat` and
    states the exact limitation instead of faking a decrypt. Arch:
    `ProprietaryInspector`. Deps: none. Cost: low. **Now.** ✅.
11. **Streaming, memory-bounded pipeline** — runs on 8 GB RAM / modest CPU. Arch:
    `stream_file` blocks + in-memory ceiling. Deps: none. Cost: low. **Now.** ✅.
12. **Deterministic JSON reports** — scriptable, diff-able, machine-readable across
    all commands. Arch: in-tree `util::Json`. Deps: none. Cost: low. **Now.** ✅.
13. **Dependency-light core** — no external JSON/test libs; builds on minimal
    offline Kali. Cost: medium (write in-tree). **Now.** ✅.
14. **X.509 expiry auditing** — flags expired/expiring embedded certs. Arch: OpenSSL
    `ASN1_TIME_diff`. Deps: OpenSSL. Cost: low. **Now.** ✅.
15. **Subscription expansion** — decodes base64/multi-URI subscription blobs to a
    profile list. Arch: `parse_subscription`. Deps: none. Cost: low. **Now.** ✅.
16. **Forensic read-only posture** — never overwrites originals; non-destructive by
    default. Cost: low. **Now.** ✅ (policy enforced in engines).

### Selected for V2 (designed, not yet built)
17. **Signature/plugin database (SQLite)** — hot-loadable formats & engines. Deps:
    SQLite (available). Cost: high. **V2.**
18. **Batch/queue engine with resume** — folders, grouped reports, checkpointing.
    Cost: high. **V2.**
19. **Local REST API** — Web talks to the C++ core for heavy formats. Deps: a light
    HTTP lib. Cost: medium. **V2.**
20. **File-carving / deleted-file recovery** — via proven libs. Cost: high. **V2.**

Rationale for the cut line: items 1–16 are high-value, low/medium cost, and
shippable against the honest-scope constraint; 17–20 need larger subsystems and
are scheduled for V2 (see ROADMAP.md).
