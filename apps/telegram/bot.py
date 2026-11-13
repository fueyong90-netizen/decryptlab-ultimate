#!/usr/bin/env python3
"""
DecryptLab Ultimate — Telegram bot (by JORDAN HACKER).

Zero pip dependencies: uses only the Python standard library (urllib) for
Telegram long-polling. It calls the same C++ core (the `decryptlab` binary),
so the bot, CLI and web app share one engine — no duplicated logic.

Security:
  - Whitelist of authorized user IDs (DLU_ALLOWED), empty = allow all (dev only).
  - File size limit (DLU_MAX_MB).
  - Secrets are masked in reports (the core masks by default).
  - Proprietary formats (.ehi/.hc/.npvs/.hat) are DOCUMENTED, never cracked.
  - Never forwards user files or secrets to third parties.

Config via environment:
  DLU_TOKEN        Telegram bot token (required)
  DLU_BIN          Path to decryptlab binary (default: ./build/bin/decryptlab)
  DLU_ALLOWED      Comma-separated allowed user IDs (optional)
  DLU_MAX_MB       Max upload size in MB (default: 20)
"""
import os, sys, json, time, subprocess, tempfile, urllib.request, urllib.parse, urllib.error

TOKEN   = os.environ.get("DLU_TOKEN", "").strip()
BIN     = os.environ.get("DLU_BIN", os.path.join(os.path.dirname(__file__), "..", "..", "build", "bin", "decryptlab"))
ALLOWED = {x.strip() for x in os.environ.get("DLU_ALLOWED", "").split(",") if x.strip()}
MAX_MB  = int(os.environ.get("DLU_MAX_MB", "20"))
API     = f"https://api.telegram.org/bot{TOKEN}"
FILEAPI = f"https://api.telegram.org/file/bot{TOKEN}"

WELCOME = (
    "☠ *DecryptLab Ultimate*\n"
    "_by JORDAN HACKER_\n\n"
    "Assistant d'analyse, d'intelligence VPN et de génération de protocoles.\n\n"
    "✅ Analyse de fichiers (signature, entropie, SHA-256)\n"
    "✅ Parse de configs VPN ouvertes (vmess/vless/trojan/ss, OpenVPN, WireGuard, V2Ray)\n"
    "✅ Audit de sécurité (secrets masqués)\n"
    "✅ Génération de configs (vless/vmess/trojan/ss/wireguard/openvpn/ssh/slowdns/udp)\n\n"
    "⚠️ Les formats propriétaires (.ehi/.hc/.npvs/.hat) sont *documentés*, "
    "jamais déchiffrés : l'outil ne casse pas la protection d'un auteur et "
    "n'extrait pas de secrets de fichiers que vous ne possédez pas.\n\n"
    "Commandes : /help"
)
HELP = (
    "*Commandes*\n"
    "/start — accueil\n"
    "/help — cette aide\n"
    "/status — état du moteur\n"
    "/analyze — envoyez ensuite un fichier\n"
    "/vpn `<uri|config>` — analyse une config collée\n"
    "/audit `<config>` — audit de sécurité\n"
    "/generate `<proto> <adresse> [port]` — génère une config\n"
    "/report — joignez un fichier avec la légende /report\n\n"
    "Protocoles /generate : vless vmess trojan shadowsocks wireguard openvpn ssh slowdns udp"
)

def api(method, **params):
    data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode()
    try:
        with urllib.request.urlopen(f"{API}/{method}", data=data, timeout=70) as r:
            return json.load(r)
    except urllib.error.URLError as e:
        print("API error:", e); return {}

def send(chat_id, text, markdown=True):
    # Telegram messages cap at 4096 chars.
    for i in range(0, len(text), 3900):
        api("sendMessage", chat_id=chat_id, text=text[i:i+3900],
            parse_mode="Markdown" if markdown else None,
            disable_web_page_preview="true")

def allowed(uid):
    return not ALLOWED or str(uid) in ALLOWED

def run_core(args, stdin_file=None):
    try:
        cp = subprocess.run([os.path.abspath(BIN), "--no-color"] + args,
                            capture_output=True, text=True, timeout=120)
        return (cp.stdout or cp.stderr).strip()
    except FileNotFoundError:
        return "⚠️ Binaire decryptlab introuvable. Compilez le projet (build.sh)."
    except subprocess.TimeoutExpired:
        return "⚠️ Opération trop longue, annulée."

def handle_file(chat_id, doc, caption):
    size = doc.get("file_size", 0)
    if size > MAX_MB * 1024 * 1024:
        return send(chat_id, f"⚠️ Fichier trop volumineux (max {MAX_MB} Mo).")
    fid = doc["file_id"]
    info = api("getFile", file_id=fid)
    if not info.get("ok"):
        return send(chat_id, "⚠️ Impossible de récupérer le fichier.")
    path = info["result"]["file_path"]
    name = doc.get("file_name", "upload.bin")
    with tempfile.TemporaryDirectory() as td:
        local = os.path.join(td, os.path.basename(name))
        try:
            urllib.request.urlretrieve(f"{FILEAPI}/{path}", local)
        except Exception as e:
            return send(chat_id, f"⚠️ Téléchargement échoué: {e}")
        send(chat_id, f"🔍 Analyse de `{name}`…")
        out = run_core(["report", local])
    send(chat_id, "```\n" + out[:3800] + "\n```")

def handle_text(chat_id, text):
    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("/start",):   return send(chat_id, WELCOME)
    if cmd in ("/help",):    return send(chat_id, HELP)
    if cmd in ("/status",):  return send(chat_id, "```\n" + run_core(["version"]) + "\n```")
    if cmd in ("/analyze", "/report"):
        return send(chat_id, "📎 Envoyez maintenant le fichier à analyser.")
    if cmd in ("/vpn", "/audit"):
        if not arg: return send(chat_id, "Usage : " + cmd + " <uri ou config>")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(arg); tmp = f.name
        sub = "parse" if cmd == "/vpn" else "audit"
        out = run_core(["vpn", sub, tmp]); os.unlink(tmp)
        return send(chat_id, "```\n" + out[:3800] + "\n```")
    if cmd == "/generate":
        a = arg.split()
        if not a: return send(chat_id, "Usage : /generate <proto> <adresse> [port]")
        proto = a[0]; addr = a[1] if len(a) > 1 else "example.com"
        port = a[2] if len(a) > 2 else "443"
        out = run_core(["vpn", "generate", "--proto", proto, "--addr", addr, "--port", port])
        return send(chat_id, "```\n" + out[:3800] + "\n```")
    return send(chat_id, "Commande inconnue. /help")

def main():
    if not TOKEN:
        print("DLU_TOKEN non défini. Le bot ne démarre pas (c'est voulu sans token).")
        sys.exit(0)
    print("DecryptLab Ultimate Telegram bot démarré.")
    offset = None
    while True:
        res = api("getUpdates", offset=offset, timeout=60)
        if not res.get("ok"):
            time.sleep(3); continue
        for upd in res["result"]:
            offset = upd["update_id"] + 1
            msg = upd.get("message") or upd.get("channel_post")
            if not msg: continue
            chat_id = msg["chat"]["id"]
            uid = msg.get("from", {}).get("id", chat_id)
            if not allowed(uid):
                send(chat_id, "⛔ Accès non autorisé (whitelist DLU_ALLOWED)."); continue
            if "document" in msg:
                handle_file(chat_id, msg["document"], msg.get("caption", ""))
            elif "text" in msg:
                handle_text(chat_id, msg["text"])

if __name__ == "__main__":
    main()
