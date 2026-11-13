# SECURITY — DecryptLab Ultimate

## Intended use

DecryptLab Ultimate is for analysis and recovery of **files you own or are
explicitly authorized to process**. It is a defensive/forensic and authoring
tool.

## What it deliberately does NOT do

- It does **not** break author-applied encryption/obfuscation on proprietary
  tunnel configs (`.ehi`, `.hc`, `.npvs`, `.hat`). It detects and documents them
  and states precisely why they can't be decoded without the format's algorithm
  and key.
- It does **not** recover, crack, brute-force or extract passwords/keys from
  files you do not own.
- It does **not** include credential theft, unauthorized access to third-party
  systems, or network-protection circumvention.
- It does **not** forward user files or secrets to any third party.

These boundaries are intentional and match the project brief's own constraints
(«ne pas voler d'identifiants», «ne pas contourner de protections réseau»,
«ne jamais prétendre déchiffrer un format propriétaire sans sa clé»).

## Honest capability labels

Every report distinguishes: **detection · decoding · decompression · extraction
· decryption · password-recovery · repair · reconstruction**, and never presents
one as another. High entropy is never, by itself, reported as proof of
encryption.

## Secret handling

- Secrets (UUIDs, passwords, private keys) are **masked by default**
  (`abc********`) in all reports and interfaces.
- `--reveal` (CLI) / the reveal checkbox (Web) show secrets — intended only for
  your own files.
- Logs are designed to avoid writing secrets.

## Input-safety hardening

- **ZIP bombs**: inspection is read-only (central directory only); it never
  decompresses untrusted data and caps entry count and compression ratio.
- **Path handling**: the scanner skips permission-denied entries and operates on
  regular files only.
- **Memory**: streaming hashing/entropy and a configurable in-memory ceiling
  prevent resource exhaustion on large inputs.
- **Original files**: analysis is non-destructive; the tool never overwrites the
  input.

## Interface security

- **Telegram**: configurable whitelist (`DLU_ALLOWED`), upload size cap
  (`DLU_MAX_MB`), no automatic forwarding of files/keys, runs without a token
  (feature simply disabled).
- **Web/PWA**: fully client-side; no upload endpoint, so files stay on-device.

## Reporting issues

This is a reference build. Treat generated keys/configs as secrets, set file
permissions to `600`, and rotate anything committed by accident.
