# Roadmap — DecryptLab Ultimate V2

## Theme
Keep the honest scope; deepen real capability and scale.

## V1.1 (hardening)
- Grouped **batch processing** over folders with a queue + resume/checkpoints.
- **Metadata Intelligence Engine**: PDF/Office/EXIF structural metadata extraction.
- OpenVPN inline-block (`<ca>/<cert>/<key>`) parsing + audit.
- More signatures; CSV/JSON report export from the CLI.

## V2.0 (subsystems)
- **Plugin ecosystem**: versioned, isolated plugins (new formats/engines) loaded
  at runtime; promote per-engine structs to a registered `IFileEngine` interface.
- **Signature & learning database** (SQLite): hot-updatable, verifiable, optional
  offline.
- **Archive engine** via libarchive: safe extraction/repair for 7z/rar/tar.
- **Crypto decryption with user-supplied keys** for standard containers (OpenSSL
  EVP, PEM/PKCS#12) — owner-key only, never universal.
- **File-system recovery** (deleted-file carving) via proven libraries.
- **Local REST API** so the Web app offloads heavy formats to the C++ core; Web
  gains history/forensic workspace persistence.
- **Forensic workspace**: evidence folders, operation journal, timeline, chain of
  custody, read-only source mode.

## V2.x (performance & UX)
- Controlled multithreading for batch; cancellation; economy mode tuning.
- Optional GPU acceleration for hashing/entropy (never a hard dependency).
- Telegram inline keyboards & downloadable redacted reports.
- i18n (FR/EN) across interfaces.

## Non-goals (permanent)
- No universal decryption claims; no breaking author-applied protection on
  configs you don't own; no credential theft or network-protection bypass.
