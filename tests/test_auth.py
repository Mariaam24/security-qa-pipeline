"""
Tests de sécurité — Authentification
OWASP Top 10 : A07:2021 - Identification and Authentication Failures
             : A03:2021 - Injection (bypass via SQLi)
"""
import time
import jwt
import pytest
import requests


def test_login_invalid_credentials_no_information_leak(base_url):
    """Un login invalide ne doit pas révéler si l'email existe ou non."""
    resp_unknown_email = requests.post(
        f"{base_url}/rest/user/login",
        json={"email": "inconnu@example.com", "password": "whatever"},
    )
    resp_wrong_password = requests.post(
        f"{base_url}/rest/user/login",
        json={"email": "admin@juice-sh.op", "password": "wrongpass"},
    )
    assert resp_unknown_email.status_code == resp_wrong_password.status_code, (
        "Fuite d'information : les réponses diffèrent selon que l'email existe ou non "
        "(permet l'énumération de comptes)."
    )


def test_login_sql_injection_bypass(base_url):
    """
    Tentative de contournement d'authentification par injection SQL classique.
    Payload historique connu pour fonctionner sur des apps vulnérables type Juice Shop.
    """
    payload = {
        "email": "' OR 1=1--",
        "password": "anything",
    }
    resp = requests.post(f"{base_url}/rest/user/login", json=payload)
    assert resp.status_code != 200, (
        "CRITIQUE : contournement d'authentification possible via injection SQL "
        f"sur /rest/user/login (payload: {payload['email']})"
    )


def test_no_rate_limiting_on_login_bruteforce(base_url):
    """
    Vérifie qu'un nombre élevé de tentatives échouées déclenche une protection
    (verrouillage de compte, CAPTCHA, ou code HTTP 429).
    """
    responses = []
    for _ in range(10):
        r = requests.post(
            f"{base_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "wrongpass"},
        )
        responses.append(r.status_code)
        time.sleep(0.2)

    assert 429 in responses or any(code == 403 for code in responses), (
        "Aucune limitation de tentatives détectée après 10 échecs consécutifs : "
        "risque de brute force sur l'authentification."
    )


def test_jwt_token_structure_and_expiration(auth_token):
    """Vérifie que le JWT émis contient bien une date d'expiration (exp) exploitable."""
    decoded = jwt.decode(auth_token, options={"verify_signature": False})
    assert "exp" in decoded, "Le token JWT ne contient pas de claim d'expiration (exp)."


def test_jwt_token_tampering_rejected(base_url, auth_token):
    """Un JWT altéré (payload modifié) ne doit jamais être accepté par l'API."""
    header, payload, signature = auth_token.split(".")
    tampered_token = f"{header}.{payload}X.{signature}"  # casse le payload

    resp = requests.get(
        f"{base_url}/rest/user/whoami",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert resp.status_code in (401, 403), (
        "CRITIQUE : un token JWT altéré a été accepté par l'API."
    )
