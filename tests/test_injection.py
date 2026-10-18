"""
Tests de sécurité — Injections (SQL / XSS)
OWASP Top 10 : A03:2021 - Injection
"""
import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE Products;--",
    "' UNION SELECT * FROM Users--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
]


def test_sql_injection_in_search(base_url):
    """La recherche produit ne doit jamais renvoyer une erreur SQL brute (fuite d'infos)
    ni des résultats anormaux indiquant une injection réussie."""
    for payload in SQLI_PAYLOADS:
        resp = requests.get(f"{base_url}/rest/products/search", params={"q": payload})
        body_lower = resp.text.lower()
        assert "sqlite" not in body_lower and "syntax error" not in body_lower, (
            f"CRITIQUE : fuite de message d'erreur SQL avec le payload '{payload}' "
            "sur /rest/products/search (indique une injection SQL exploitable)."
        )


def test_xss_stored_in_feedback(base_url, auth_headers):
    """
    Un commentaire/feedback contenant du JS ne doit pas être restitué tel quel
    (doit être échappé/sanitisé) pour éviter un XSS stocké.
    """
    for payload in XSS_PAYLOADS:
        resp = requests.post(
            f"{base_url}/api/Feedbacks",
            json={"comment": payload, "rating": 1},
            headers=auth_headers,
        )
        if resp.status_code in (200, 201):
            created = resp.json().get("data", {})
            stored_comment = created.get("comment", "")
            assert "<script>" not in stored_comment and "onerror=" not in stored_comment, (
                f"CRITIQUE : XSS stocké confirmé — le payload '{payload}' a été "
                "enregistré sans échappement dans /api/Feedbacks."
            )


def test_reflected_xss_in_search_query(base_url):
    """Vérifie que le payload XSS renvoyé dans la réponse (reflected) est bien échappé."""
    payload = "<script>alert('xss')</script>"
    resp = requests.get(f"{base_url}/rest/products/search", params={"q": payload})
    assert payload not in resp.text, (
        "CRITIQUE : XSS réfléchi — le payload est renvoyé tel quel dans la réponse "
        "de /rest/products/search sans échappement HTML."
    )


def test_nosql_or_sql_login_injection_variants(base_url):
    """Teste plusieurs variantes de payloads d'injection sur le endpoint de login."""
    injection_emails = [
        "admin@juice-sh.op'--",
        "' OR 1=1 LIMIT 1 -- -",
        '{"$gt": ""}',
    ]
    for email in injection_emails:
        resp = requests.post(
            f"{base_url}/rest/user/login",
            json={"email": email, "password": "x"},
        )
        assert resp.status_code != 200, (
            f"CRITIQUE : contournement d'authentification via injection avec "
            f"le payload email='{email}'"
        )
