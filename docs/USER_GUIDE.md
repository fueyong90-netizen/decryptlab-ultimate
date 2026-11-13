# USER GUIDE — DecryptLab Ultimate

## 1. CLI

```
decryptlab <command> [options]
```

| Command | Description |
|---------|-------------|
| `scan <path>` | Inventory a file or directory: size, SHA-256, format, mismatch flag |
| `analyze <file>` | Full analysis → JSON (detection, entropy, routed engine) |
| `inspect <file>` | Alias of `analyze` |
| `report <file>` | Human-readable analysis |
| `vpn parse <file>` | Parse an OPEN VPN config / URI / subscription (secrets masked) |
| `vpn audit <file>` | Security audit of a VPN config |
| `vpn convert <file> --to X` | Convert a profile → `uri`, `v2ray`, `json`, `outbound` |
| `vpn generate --proto P ...` | Generate a config/script for YOUR server |
| `version` | Version + engine status |
| `menu` | Interactive menu (Kali-styled) |

**Global options:** `--json`, `--no-color`, `--no-hash`, `--reveal`, `-o <file>`.

### Examples

```bash
# Inventory a folder with hashes
decryptlab scan ~/Downloads --json

# Identify a file with a lying extension
decryptlab report suspicious.txt       # may report "ELF binary" + mismatch

# Inspect a proprietary tunnel config (honest, no cracking)
decryptlab analyze config.ehi          # documents structure + states limitation

# Parse your own VPN config
decryptlab vpn parse my.ovpn
decryptlab vpn parse node_vless.txt --reveal   # show secrets (your files only)

# Audit a config for security problems
decryptlab vpn audit client.json

# Convert a vmess URI to a V2Ray client config
decryptlab vpn convert node.txt --to v2ray -o client.json

# Generate configs/scripts for a server you run
decryptlab vpn generate --proto vless      --addr my.cdn.net --port 443 --net ws --security tls -o vless.json
decryptlab vpn generate --proto wireguard  --addr wg.server  --port 51820 -o wg0.conf
decryptlab vpn generate --proto ssh        --addr 1.2.3.4 --port 22 --user root -o ssh.sh
decryptlab vpn generate --proto slowdns    --addr tunnel.example --ns ns.example -o slowdns.sh
decryptlab vpn generate --proto udp        --port 36712 -o udp.json
```

## 2. Web / PWA (mobile + PC)

```bash
./scripts/serve-web.sh 8080
```
Open `http://localhost:8080`, then **Install** from the browser menu to add it to
your home screen / desktop. It runs **100% locally** — files never leave the
browser. Panels: Analyse, VPN Intelligence, Générateur, Audit sécurité.

The PWA performs real client-side analysis (magic detection, entropy, SHA-256
via WebCrypto, URI/config parsing, generation, audit). It works offline after
first load thanks to the service worker.

## 3. Telegram bot

Start it with a token, then in Telegram:

| Command | Action |
|---------|--------|
| `/start`, `/help`, `/status` | Info & engine status |
| *(send a file)* or `/report` | Analyze an uploaded file |
| `/vpn <uri or config>` | Parse a pasted config |
| `/audit <config>` | Security audit |
| `/generate <proto> <addr> [port]` | Generate a config |

Security: whitelist (`DLU_ALLOWED`), size cap (`DLU_MAX_MB`), masked secrets,
no third-party forwarding.

## Reading a report

Every analysis labels the **support level** and, for protected inputs, an
explicit **limitation**. Entropy is annotated: *high entropy alone is not proof
of encryption*. Secrets are shown masked (`abc********`) unless you pass
`--reveal` on your own files.
