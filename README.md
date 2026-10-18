# 🛡️ Security QA Pipeline — OWASP Juice Shop

Pipeline CI/CD de **tests de sécurité automatisés** combinant QA fonctionnel et cybersécurité offensive, exécuté sur l'application volontairement vulnérable **OWASP Juice Shop**.

> Positionnement : QA Automation avec sensibilité cybersécurité — un seul projet qui sert deux profils (QA Engineer / Cybersecurity Analyst).

![CI](https://github.com/Mariaam24/security-qa-pipeline/actions/workflows/security-pipeline.yml/badge.svg)

---

## 🎯 Objectif

Démontrer une capacité à :
- Automatiser des tests QA classiques (fonctionnels, API)
- Automatiser des tests de sécurité ciblés (auth, IDOR, injections)
- Intégrer un scanner DAST (OWASP ZAP) dans un pipeline CI
- Faire échouer un build en cas de vulnérabilité critique (gate de sécurité)
- Produire un rapport de sécurité structuré et mappé à l'OWASP Top 10

## 🏗️ Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌───────────────────┐
│  OWASP Juice     │◄────►│  Tests pytest     │      │  OWASP ZAP         │
│  Shop (Docker)   │      │  (auth/IDOR/inj.) │      │  (scan DAST)       │
└─────────────────┘      └──────────────────┘      └───────────────────┘
          ▲                         │                          │
          │                         ▼                          ▼
          │                 ┌──────────────────────────────────────┐
          └─────────────────│   GitHub Actions : security-pipeline  │
                            │   → fail si vulnérabilité critique    │
                            │   → génère rapport Markdown/JSON       │
                            └──────────────────────────────────────┘
```

## 📦 Stack technique

| Composant | Rôle |
|---|---|
| **OWASP Juice Shop** | Application cible volontairement vulnérable |
| **Docker / docker-compose** | Orchestration de l'environnement de test |
| **pytest + requests** | Tests de sécurité API (auth, IDOR, injections) |
| **OWASP ZAP** (mode baseline + full scan) | Scan DAST automatisé |
| **GitHub Actions** | Pipeline CI/CD, gate qualité/sécurité |
| **Python** | Script de génération de rapport consolidé |

## 🧪 Ce qui est testé

### 1. Authentification (`tests/test_auth.py`)
- Connexion avec identifiants invalides (pas de fuite d'info sur l'existence du compte)
- Absence de limitation de tentatives (brute force)
- Contournement d'authentification (injection SQL dans le login)
- Validation du token JWT (expiration, altération)

### 2. Contrôle d'accès / IDOR (`tests/test_idor.py`)
- Accès au panier d'un autre utilisateur via manipulation d'ID
- Accès aux commandes/recus d'un autre utilisateur
- Modification du profil d'un autre utilisateur

### 3. Injections (`tests/test_injection.py`)
- Injection SQL dans la recherche produit et le login
- XSS stocké/réfléchi dans les champs commentaires/feedback
- Injection dans les paramètres d'URL

### 4. Scan ZAP (`zap/`)
- Baseline scan (passif) à chaque pipeline
- Full scan (actif, avec attaques) sur branche `main` / planifié
- Résultats exportés en JSON + mappés OWASP Top 10

## 🚀 Lancer le projet en local

```bash
# 1. Cloner le repo
git clone https://github.com/Mariaam24/security-qa-pipeline.git
cd security-qa-pipeline

# 2. Lancer la cible vulnérable
docker compose up -d juice-shop

# 3. Installer les dépendances Python
pip install -r requirements.txt

# 4. Lancer les tests de sécurité
pytest tests/ -v --html=reports/pytest-report.html

# 5. Lancer le scan ZAP (baseline, rapide)
docker compose run --rm zap-baseline

# 6. Générer le rapport consolidé
python scripts/generate_security_report.py
```

Le rapport final est généré dans `reports/security-report.md`.

## 📊 Exemple de rapport de sécurité

Voir [`docs/owasp-top10-mapping.md`](docs/owasp-top10-mapping.md) pour le mapping complet,
et `reports/security-report.md` (généré après exécution) pour un exemple de sortie :

| Vulnérabilité | Gravité | Preuve | Recommandation | OWASP Top 10 |
|---|---|---|---|---|
| Bypass login via injection SQL (`' OR 1=1--`) | Critique | Requête POST /rest/user/login avec payload, 200 OK + token | Utiliser des requêtes paramétrées / ORM | A03:2021 – Injection |
| IDOR sur /api/BasketItems/{id} | Élevée | Accès panier d'un autre user en changeant l'ID | Vérifier l'ownership côté serveur à chaque requête | A01:2021 – Broken Access Control |

## 🛑 Gate de sécurité CI/CD

Le pipeline GitHub Actions **échoue automatiquement** si :
- Un test pytest de sécurité échoue (ex : IDOR confirmé, bypass auth)
- ZAP remonte une alerte de niveau `High` ou `Critical`

Voir [`.github/workflows/security-pipeline.yml`](.github/workflows/security-pipeline.yml)

## ⚠️ Avertissement éthique

Ce projet cible **exclusivement** OWASP Juice Shop, une application développée par l'OWASP
spécifiquement pour l'entraînement à la sécurité. Aucune technique ici ne doit être utilisée
contre un système sans autorisation explicite.

## 📁 Structure du repo

```
security-qa-pipeline/
├── .github/workflows/security-pipeline.yml  # Pipeline CI
├── docker-compose.yml                       # Juice Shop + ZAP
├── requirements.txt
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_idor.py
│   └── test_injection.py
├── zap/
│   └── zap-rules.tsv                        # Règles d'exclusion ZAP
├── scripts/
│   └── generate_security_report.py          # Rapport consolidé
├── docs/
│   └── owasp-top10-mapping.md
└── reports/                                  # Rapports générés (gitignored sauf exemples)
```

## 👤 Auteur

Projet réalisé dans le cadre d'un portfolio QA Automation / Cybersécurité.
