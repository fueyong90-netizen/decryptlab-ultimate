#!/usr/bin/env bash
# DecryptLab Ultimate - serve the installable PWA locally (no backend needed).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8080}"
cd "$ROOT/apps/web"
echo "[*] PWA DecryptLab Ultimate -> http://localhost:${PORT}"
echo "    (Installable sur mobile/PC : menu du navigateur -> Installer l'application)"
exec python3 -m http.server "${PORT}"
