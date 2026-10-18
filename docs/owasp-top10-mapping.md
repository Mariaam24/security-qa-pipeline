# Mapping OWASP Top 10 (2021) ↔ Tests du projet

| OWASP Top 10 2021 | Catégorie | Couvert par | Type de contrôle |
|---|---|---|---|
| A01:2021 | Broken Access Control | `tests/test_idor.py` | Tests API (pytest) |
| A02:2021 | Cryptographic Failures | Scan ZAP (en-têtes, TLS, cookies) | DAST |
| A03:2021 | Injection | `tests/test_injection.py`, `tests/test_auth.py` (bypass SQLi) | Tests API + DAST |
| A04:2021 | Insecure Design | Scan ZAP (passif) | DAST |
| A05:2021 | Security Misconfiguration | Scan ZAP (en-têtes HTTP manquants, CORS, versions exposées) | DAST |
| A06:2021 | Vulnerable and Outdated Components | *(hors périmètre V1 — piste d'extension avec `npm audit` / `pip-audit` / `trivy`)* | SCA (à ajouter) |
| A07:2021 | Identification and Authentication Failures | `tests/test_auth.py` | Tests API (pytest) |
| A08:2021 | Software and Data Integrity Failures | Scan ZAP | DAST |
| A09:2021 | Security Logging and Monitoring Failures | *(hors périmètre V1)* | — |
| A10:2021 | Server-Side Request Forgery (SSRF) | Scan ZAP (actif) | DAST |

## Légende

- **Tests API (pytest)** : tests ciblés, écrits manuellement, qui vérifient un comportement
  de sécurité précis (ex : refus d'un token altéré, refus d'un accès IDOR).
- **DAST** : scan dynamique automatisé par OWASP ZAP, qui explore l'application et teste
  des payloads génériques (injection, XSS, en-têtes de sécurité, etc.).
- **SCA** (Software Composition Analysis) : analyse des dépendances tierces — non inclus
  dans la V1 de ce projet mais mentionné comme piste d'évolution crédible (A06).

## Pistes d'évolution

1. Ajouter `pip-audit` / `npm audit` ou **Trivy** pour couvrir A06 (composants vulnérables).
2. Ajouter des tests de logs/alerting (A09) si l'application expose des logs consultables.
3. Étendre les tests IDOR à d'autres ressources (avis produits, adresses de livraison).
4. Ajouter des tests de sécurité sur les en-têtes HTTP (CSP, HSTS, X-Frame-Options) en pytest
   en complément du scan ZAP, pour un contrôle plus déterministe en CI.
