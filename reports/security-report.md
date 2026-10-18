# 🛡️ Rapport de sécurité — Security QA Pipeline

Généré le 2026-10-18 10:56 UTC

## 1. Résumé exécutif
- Tests de sécurité exécutés : **13**
- Tests échoués (vulnérabilités confirmées) : **9**
- Alertes ZAP détectées : **10**
- Alertes ZAP critiques/élevées : **0**

## 2. Résultats des tests pytest (auth / IDOR / injections)

| Test | Fichier | Statut | OWASP Top 10 | Détail |
|---|---|---|---|---|
| test_login_invalid_credentials_no_information_leak | tests.test_auth | ✅ PASS | A07:2021 - Identification and Authentication Failures |  |
| test_login_sql_injection_bypass | tests.test_auth | ❌ FAIL | A07:2021 - Identification and Authentication Failures | AssertionError: CRITIQUE : contournement d'authentification possible via injection SQL sur /rest/user/login (payload: '  |
| test_no_rate_limiting_on_login_bruteforce | tests.test_auth | ❌ FAIL | A07:2021 - Identification and Authentication Failures | AssertionError: Aucune limitation de tentatives détectée après 10 échecs consécutifs : risque de brute force sur l'authe |
| test_jwt_token_structure_and_expiration | tests.test_auth | ❌ FAIL | A07:2021 - Identification and Authentication Failures | AssertionError: Le token JWT ne contient pas de claim d'expiration (exp).
assert 'exp' in {'bid': 6, 'data': {'createdAt |
| test_jwt_token_tampering_rejected | tests.test_auth | ❌ FAIL | A07:2021 - Identification and Authentication Failures | AssertionError: CRITIQUE : un token JWT altéré a été accepté par l'API.
assert 200 in (401, 403)
 +  where 200 = <Respon |
| test_idor_access_other_user_basket | tests.test_idor | ❌ FAIL | A01:2021 - Broken Access Control | AssertionError: IDOR CONFIRMÉ : accès au panier #2 d'un autre utilisateur via manipulation d'ID (statut 200).
assert '2' |
| test_idor_access_other_user_order | tests.test_idor | ❌ FAIL | A01:2021 - Broken Access Control | AssertionError: IDOR potentiel : la commande #1 est accessible sans vérification d'appartenance (statut {resp.status_cod |
| test_idor_modify_other_user_profile | tests.test_idor | ✅ PASS | A01:2021 - Broken Access Control |  |
| test_missing_function_level_access_control_admin_endpoint | tests.test_idor | ❌ FAIL | A01:2021 - Broken Access Control | AssertionError: Contrôle d'accès manquant sur un endpoint sensible : /rest/admin/application-version
assert (200 != 200  |
| test_sql_injection_in_search | tests.test_injection | ❌ FAIL | A03:2021 - Injection | AssertionError: CRITIQUE : fuite de message d'erreur SQL avec le payload ''; DROP TABLE Products;--' sur /rest/products/ |
| test_xss_stored_in_feedback | tests.test_injection | ✅ PASS | A03:2021 - Injection |  |
| test_reflected_xss_in_search_query | tests.test_injection | ✅ PASS | A03:2021 - Injection |  |
| test_nosql_or_sql_login_injection_variants | tests.test_injection | ❌ FAIL | A03:2021 - Injection | AssertionError: CRITIQUE : contournement d'authentification via injection avec le payload email='admin@juice-sh.op'--'
a |

## 3. Résultats du scan OWASP ZAP

| Vulnérabilité | Gravité | OWASP Top 10 | Instances | Preuve | Correction recommandée |
|---|---|---|---|---|---|
| Content Security Policy (CSP) Header Not Set | Medium | Voir OWASP Top 10 - à classer manuellement | 5 | <p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attack | <p>Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.</p> |
| Cross-Domain Misconfiguration | Medium | A05:2021 - Security Misconfiguration | 5 | <p>Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.</p> | <p>Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).</p><p>Configure the "Access-Control-Allow-Origin" HTTP header to a more rest |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low | Voir OWASP Top 10 - à classer manuellement | 5 | <p>Cross-Origin-Embedder-Policy header is a response header that prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).</ | <p>Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.</p><p>If |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low | Voir OWASP Top 10 - à classer manuellement | 5 | <p>Cross-Origin-Opener-Policy header is a response header that allows a site to control if others included documents share the same browsing context. Sharing the same browsing context with untrusted d | <p>Ensure that the application/web server sets the Cross-Origin-Opener-Policy header appropriately, and that it sets the Cross-Origin-Opener-Policy header to 'same-origin' for documents.</p><p>'same-o |
| Dangerous JS Functions | Low | Voir OWASP Top 10 - à classer manuellement | 2 | <p>A dangerous JS function seems to be in use that would leave the site vulnerable.</p> | <p>See the references for security advice on the use of these functions.</p> |
| Deprecated Feature Policy Header Set | Low | A05:2021 - Security Misconfiguration (en-têtes manquants) | 5 | <p>The header has now been renamed to Permissions-Policy.</p> | <p>Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header instead of the Feature-Policy header.</p> |
| Modern Web Application | Informational | Voir OWASP Top 10 - à classer manuellement | 5 | <p>The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.</p> | <p>This is an informational alert and so no changes are required.</p> |
| Non-Storable Content | Informational | Voir OWASP Top 10 - à classer manuellement | 1 | <p>The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stor | <p>The content may be marked as storable by ensuring that the following conditions are satisfied:</p><p>The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD" |
| Storable and Cacheable Content | Informational | Voir OWASP Top 10 - à classer manuellement | 1 | <p>The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response  | <p>Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content b |
| Storable but Non-Cacheable Content | Informational | Voir OWASP Top 10 - à classer manuellement | 5 | <p>The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar re |  |

## 4. Verdict du pipeline

🔴 **BUILD EN ÉCHEC** : au moins une vulnérabilité critique/élevée détectée.