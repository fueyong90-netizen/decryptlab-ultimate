# HÉBERGEMENT 100 % GRATUIT — DecryptLab Ultimate

Ce guide explique, étape par étape, comment mettre DecryptLab Ultimate en ligne
sans payer. Il y a **trois briques** indépendantes ; choisissez selon le besoin :

| Brique | Besoin d'un serveur ? | Hébergement gratuit |
|--------|----------------------|---------------------|
| **PWA (Web)** | ❌ Non (tourne dans le navigateur) | GitHub Pages / Cloudflare Pages / Netlify |
| **API C++ + PWA** (`decryptlab-api`) | ✅ Oui (Docker) | Render / Fly.io / Koyeb / Oracle Always Free |
| **Bot Telegram** | ✅ Oui (process qui tourne) | Oracle Always Free / même conteneur / Termux |

> La PWA est **déjà complète toute seule** : analyse, parse VPN, audit et
> génération se font côté navigateur. Pour 90 % des usages, l'**Option A suffit**
> et c'est gratuit à vie.

---

## OPTION A — La PWA seule, gratuite à vie (le plus simple)

La PWA est une appli statique installable (mobile + PC). Zéro serveur, zéro coût.

### A.1 — Cloudflare Pages (recommandé, gratuit illimité)
1. Créez un compte sur https://dash.cloudflare.com (gratuit).
2. Poussez ce dépôt sur GitHub (voir §Préparer GitHub plus bas).
3. Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** →
   **Connect to Git** → choisissez le dépôt.
4. Réglages de build :
   - **Build command** : *(laisser vide)*
   - **Build output directory** : `apps/web`
5. **Save and Deploy**. Vous obtenez une URL `https://xxxx.pages.dev`.
6. Sur mobile/PC : ouvrez l'URL → menu du navigateur → **Installer l'application**.

### A.2 — GitHub Pages (alternative)
1. Dépôt GitHub → **Settings** → **Pages**.
2. **Source** : *Deploy from a branch* → branche `main` → dossier `/` (ou `/docs`).
   - GitHub Pages sert la racine ; copiez le contenu de `apps/web/` à la racine
     d'une branche `gh-pages`, OU utilisez l'action ci-dessous.
3. Plus simple : créez `.github/workflows/pages.yml` :
```yaml
name: Deploy PWA
on: { push: { branches: [main] } }
permissions: { pages: write, id-token: write }
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: { name: github-pages }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-pages-artifact@v3
        with: { path: apps/web }
      - uses: actions/deploy-pages@v4
```
4. L'URL est `https://<utilisateur>.github.io/<dépôt>/`.

### A.3 — Netlify (alternative, glisser-déposer)
1. https://app.netlify.com → **Add new site** → **Deploy manually**.
2. Glissez le dossier `apps/web/` dans la zone. URL `https://xxxx.netlify.app`
   immédiate.

---

## OPTION B — API C++ + PWA (un seul binaire, Docker)

Utile si vous voulez l'analyse côté serveur (gros fichiers, endpoints `/api/...`).
Le `Dockerfile` fourni compile le C++ et sert l'API **et** la PWA sur `$PORT`.

### B.1 — Render.com (gratuit, le plus simple)
1. Poussez le dépôt sur GitHub.
2. https://render.com → **New** → **Web Service** → connectez le dépôt.
3. Render détecte `render.yaml` (runtime Docker, plan `free`, healthcheck
   `/api/health`). Validez.
4. Après build : URL `https://decryptlab-ultimate.onrender.com`.
   - Endpoints : `/`, `/api/health`, `/api/version`, `/api/vpn/generate?...`
   - ⚠️ Le plan gratuit **s'endort** après ~15 min d'inactivité (premier accès
     lent le temps du réveil). Sans gravité pour un outil perso.

### B.2 — Fly.io (gratuit, pas de mise en veille agressive)
```bash
# Installez flyctl : https://fly.io/docs/flyctl/install/
fly auth signup           # compte gratuit
fly launch --copy-config --now   # lit fly.toml + Dockerfile
# -> URL https://decryptlab-ultimate.fly.dev
```

### B.3 — Koyeb / Railway (alternatives)
- **Koyeb** : https://app.koyeb.com → **Create Service** → **GitHub** → Dockerfile
  → port `8090`. Offre gratuite d'une instance.
- **Railway** : https://railway.app → **New Project** → **Deploy from GitHub** →
  il lit le `Dockerfile` et injecte `$PORT` (déjà géré par le binaire).

### B.4 — Tester en local d'abord
```bash
docker build -t decryptlab .
docker run -p 8090:8090 decryptlab
# http://localhost:8090  (PWA)  +  http://localhost:8090/api/health
```

---

## OPTION C — Bot Telegram gratuit

Le bot a besoin d'un process qui tourne en continu.

### C.1 — Créer le bot (gratuit)
1. Dans Telegram, parlez à **@BotFather** → `/newbot` → choisissez un nom.
2. Il vous donne un **token** `123456:ABC...`. Gardez-le secret.
3. Avatar : envoyez `assets/branding/telegram-avatar.png` à BotFather via
   `/setuserpic`.

### C.2 — Oracle Cloud « Always Free » (vraiment gratuit, 24/7 — recommandé)
Oracle offre des VM ARM gratuites **à vie** (parfaites pour un bot + l'API).
1. Créez un compte sur https://www.oracle.com/cloud/free/ (carte demandée pour
   vérification, **non débitée** sur les ressources Always Free).
2. **Create a VM instance** → image **Ubuntu 22.04** → forme **VM.Standard.A1.Flex**
   (ARM, Always Free, jusqu'à 4 vCPU / 24 Go RAM).
3. Connectez-vous en SSH, puis :
```bash
sudo apt update && sudo apt install -y git docker.io
git clone <votre-dépôt> && cd DecryptLab-Ultimate
# API + PWA :
sudo docker compose up -d --build
# Bot Telegram :
export DLU_TOKEN="123456:ABC..."
sudo -E docker compose --profile telegram up -d
```
   L'API tourne sur le port 8090 ; ouvrez-le dans la *Security List* Oracle si
   vous voulez l'exposer.

### C.3 — Sur la même instance que l'API (Render/Fly)
Render/Fly lancent **une** commande. Pour y ajouter le bot, lancez un second
service gratuit dédié au bot avec `python3 apps/telegram/bot.py` et la variable
`DLU_TOKEN` (sur Render : *New → Background Worker*).

### C.4 — Depuis un téléphone Android (Termux, 100 % gratuit)
```bash
pkg install python git
git clone <votre-dépôt> && cd DecryptLab-Ultimate
export DLU_TOKEN="123456:ABC..."
python3 apps/telegram/bot.py        # (analyse via l'API distante si pas de binaire local)
```

---

## OPTION D — Auto-hébergement chez vous + URL publique gratuite

1. Sur votre PC/serveur maison :
```bash
docker compose up -d --build       # http://localhost:8090
```
2. Exposez-le gratuitement avec **Cloudflare Tunnel** (pas d'IP fixe requise) :
```bash
# https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
cloudflared tunnel --url http://localhost:8090
# -> une URL publique https://xxxx.trycloudflare.com instantanée et gratuite
```

---

## Préparer GitHub (commun à la plupart des options)

```bash
cd DecryptLab-Ultimate
git init && git add . && git commit -m "DecryptLab Ultimate"
git branch -M main
git remote add origin https://github.com/<vous>/decryptlab-ultimate.git
git push -u origin main
```

## Limites des offres gratuites (à savoir)

- **PWA statique** : aucune limite réelle, pas de veille → *le choix le plus sûr*.
- **Render free** : mise en veille après ~15 min (réveil lent au 1er accès), ~750 h/mois.
- **Fly.io / Koyeb** : petite instance gratuite, quotas de bande passante.
- **Oracle Always Free** : gratuit à vie, le plus puissant, mais création de compte
  plus longue.
- Ne commitez jamais votre `DLU_TOKEN` ni de clés : utilisez les variables
  d'environnement de la plateforme.

## Recommandation

- Usage perso / mobile : **Option A (Cloudflare Pages)** — gratuit à vie, rien à gérer.
- Besoin de l'API serveur : **Option B (Render)** pour commencer, **Fly.io** si la
  veille gêne.
- Bot 24/7 : **Oracle Always Free** (Option C.2).
