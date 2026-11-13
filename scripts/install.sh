#!/usr/bin/env bash
# DecryptLab Ultimate - dependency installer for Kali Linux / Debian / Ubuntu
set -euo pipefail

echo "[*] DecryptLab Ultimate - installation des dépendances"
if ! command -v apt-get >/dev/null 2>&1; then
  echo "[!] apt-get introuvable. Installez manuellement: g++ cmake libssl-dev zlib1g-dev."
  exit 1
fi

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

$SUDO apt-get update
$SUDO apt-get install -y \
  build-essential g++ cmake \
  libssl-dev zlib1g-dev \
  python3 zip gdb valgrind

echo "[+] Dépendances installées."
echo "[*] Compilation..."
"$(dirname "$0")/build.sh" Release
echo "[+] Installation terminée. Lancez: ./scripts/run.sh"
