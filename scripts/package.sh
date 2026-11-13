#!/usr/bin/env bash
# DecryptLab Ultimate - build a clean distributable ZIP.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/.."
NAME="DecryptLab-Ultimate"
OUT="${NAME}.zip"

echo "[*] Nettoyage des artefacts de build..."
rm -rf "$ROOT/build"

echo "[*] Création de ${OUT}..."
rm -f "$OUT"
zip -r -q "$OUT" "$NAME" \
  -x "*/build/*" "*/.git/*" "*.o" "*.a"

echo "[+] Archive créée : $(pwd)/${OUT}"
unzip -l "$OUT" | tail -1
