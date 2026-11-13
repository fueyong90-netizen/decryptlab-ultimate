# SUPPORTED FORMATS — real support level

Levels: **I** implemented+tested · **P** partial · **IF** interface only · **—** not supported.

## Recognition (signature detection)

| Family | Formats | Level |
|--------|---------|-------|
| Archives | ZIP, RAR, 7Z, GZIP, BZIP2, XZ, ZSTD | **I** (detect) |
| Documents | PDF, OLE2 (doc/xls/ppt), RTF | **I** (detect) |
| Office OOXML | DOCX/XLSX/PPTX (ZIP-based) | **I** (detect as ZIP) |
| Binary | ELF, PE/EXE, Mach-O, WASM | **I** (detect) |
| Images | PNG, JPEG, GIF, WEBP, TIFF, BMP | **I** (detect) |
| Media | MP3/ID3, FLAC, WAV, MKV, MP4 | **I** (detect) |
| Database | SQLite | **I** (detect) |
| Disk images | ISO9660 | **I** (detect) |
| Crypto | PEM, PGP armored, OpenSSL salted, LUKS | **I** (detect) |

## Deep handling

| Capability | Formats | Level | Notes |
|------------|---------|-------|-------|
| Hashing | any | **I** | SHA-256/SHA-1/MD5, streamed |
| Entropy | any | **I** | Shannon, streamed; honest caveat |
| Deceptive-extension detection | any | **I** | content vs. extension |
| ZIP structure inspection | ZIP | **I** | read-only, encrypted-entry flag, zip-bomb guard |
| ZIP extraction / repair | ZIP | **IF** | planned; not in this build |
| PDF/Office metadata & structure | PDF, OOXML | **IF** | detected; deep parse planned (V2) |
| Archive extraction (7z/rar/tar) | — | **IF** | libarchive integration planned |
| File-system recovery (deleted files) | — | **IF** | planned (V2) |

## VPN (see VPN_FORMATS.md)

| Capability | Level |
|------------|-------|
| Open URIs (vmess/vless/trojan/ss) parse + emit | **I** |
| OpenVPN / WireGuard / V2Ray-JSON parse | **I** |
| Subscription (base64 / multi-URI) parse | **I** |
| Security audit + secret masking | **I** |
| Config/script generation (9 protocols) | **I** |
| Format conversion (uri/v2ray/outbound) | **I** |
| Proprietary `.ehi/.hc/.npvs/.hat` detection + documentation | **I** |
| Proprietary decryption / key extraction | **—** | out of scope (see SECURITY.md) |

## Cryptographic inspection

| Capability | Level |
|------------|-------|
| PEM/X.509 certificate parse + expiry check | **I** (OpenSSL) |
| Crypto-container recognition (PGP, LUKS, OpenSSL salted) | **I** (detect) |
| Decryption with a **user-supplied** key for standard containers | **IF** | planned via OpenSSL EVP |
| Universal/author-key decryption | **—** | impossible by design; never claimed |
