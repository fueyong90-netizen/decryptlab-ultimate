# DecryptLab Ultimate — Identité visuelle

**Créateur : JORDAN HACKER**

## Palette

| Rôle | Couleur | Hex |
|------|---------|-----|
| Noir profond (fond) | ⬛ | `#050505` |
| Rouge néon (identité JORDAN HACKER) | 🟥 | `#FF1717` |
| Rouge sombre | 🟥 | `#780000` |
| Blanc (nom du logiciel) | ⬜ | `#FFFFFF` |
| Vert terminal (états positifs) | 🟩 | `#00FF66` |

Le **rouge** = identité du créateur. Le **blanc** = nom du logiciel. Le **vert** est réservé aux états techniques positifs (OK, Ready, succès).

## Fichiers

| Fichier | Usage |
|---------|-------|
| `logo-terminal.txt` | Logo ASCII monochrome pour la CLI |
| `../../apps/web/icons/icon.svg` | Logo vectoriel (crâne + os + nom) |
| `../../apps/web/icons/icon-192.png` / `icon-512.png` | Icônes PWA |
| `telegram-avatar.png` | Avatar carré 512×512 pour le bot Telegram |

## Variantes

- **Logo complet** : crâne ASCII + wordmark `DECRYPTLAB ULTIMATE` (blanc) + `by JORDAN HACKER` (rouge) — généré par `dlu::brand::logo_full()`.
- **Logo compact** : `☠ DECRYPTLAB ULTIMATE by JORDAN HACKER` — `dlu::brand::logo_compact()`.
- **Version terminal monochrome** : `logo_full(false)` / `logo-terminal.txt`.
- **Icône carrée Telegram / PWA** : `icon.svg` rendu en PNG.

Toutes les variantes conservent une excellente lisibilité sur fond sombre et dans un terminal 80 colonnes.
