import os
import time
import pytest
import requests

BASE_URL = os.getenv("TARGET_URL", "http://localhost:3002")

# Compte de test créé automatiquement pour les scénarios d'authentification
TEST_USER_EMAIL = "qa.security.test@example.com"
TEST_USER_PASSWORD = "Str0ngP@ssw0rd!"


def wait_for_target(url: str, timeout: int = 90):
    start = time.time()
    last_error = None
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                return True
        except requests.exceptions.RequestException as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(
        f"Cible {url} indisponible après {timeout}s (dernière erreur : {last_error})"
    )


@pytest.fixture(scope="session", autouse=True)
def ensure_target_up():
    wait_for_target(BASE_URL)


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def registered_user(base_url):
    """Crée un utilisateur de test dédié aux scénarios de sécurité."""
    payload = {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD,
        "passwordRepeat": TEST_USER_PASSWORD,
        "securityQuestion": {"id": 1},
        "securityAnswer": "qa-automation",
    }
    requests.post(f"{base_url}/api/Users", json=payload)
    return {"email": TEST_USER_EMAIL, "password": TEST_USER_PASSWORD}


@pytest.fixture(scope="session")
def auth_token(base_url, registered_user):
    """Retourne un token JWT valide pour l'utilisateur de test."""
    resp = requests.post(
        f"{base_url}/rest/user/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert resp.status_code == 200, "Impossible d'obtenir un token pour l'utilisateur de test"
    return resp.json()["authentication"]["token"]


@pytest.fixture(scope="session")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
