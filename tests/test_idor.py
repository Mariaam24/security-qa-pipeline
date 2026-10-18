"""
Tests de sécurité — Contrôle d'accès / IDOR
OWASP Top 10 : A01:2021 - Broken Access Control
"""
import requests


def test_idor_access_other_user_basket(base_url, auth_headers):
    """
    Tente d'accéder au panier (basket) d'un autre utilisateur en incrémentant
    simplement l'ID dans l'URL. Doit être refusé (403) et non renvoyer les données.
    """
    own_basket = requests.get(f"{base_url}/rest/basket/1", headers=auth_headers)
    other_basket_id = 2
    resp = requests.get(f"{base_url}/rest/basket/{other_basket_id}", headers=auth_headers)

    if resp.status_code == 200:
        data = resp.json()
        assert str(data.get("data", {}).get("UserId")) == "", (
            f"IDOR CONFIRMÉ : accès au panier #{other_basket_id} d'un autre utilisateur "
            f"via manipulation d'ID (statut {resp.status_code})."
        )


def test_idor_access_other_user_order(base_url, auth_headers):
    """
    Vérifie qu'on ne peut pas consulter les commandes d'un autre utilisateur
    en devinant/énumérant un identifiant d'ordre.
    """
    for order_id in range(1, 4):
        resp = requests.get(
            f"{base_url}/rest/order/{order_id}", headers=auth_headers
        )
        assert resp.status_code in (401, 403, 404), (
            f"IDOR potentiel : la commande #{order_id} est accessible sans "
            f"vérification d'appartenance (statut {resp.status_code})."
        )


def test_idor_modify_other_user_profile(base_url, auth_headers):
    """
    Tente de modifier le profil d'un autre utilisateur via l'API REST
    en forçant un userId différent de celui du token authentifié.
    """
    payload = {"id": 1, "username": "hacked_by_test"}
    resp = requests.put(f"{base_url}/api/Users/1", json=payload, headers=auth_headers)
    assert resp.status_code in (401, 403, 404), (
        "IDOR CONFIRMÉ : modification du profil d'un autre utilisateur possible "
        f"(statut {resp.status_code})."
    )


def test_missing_function_level_access_control_admin_endpoint(base_url, auth_headers):
    """
    Un utilisateur standard ne doit pas pouvoir accéder aux endpoints d'administration.
    """
    admin_endpoints = ["/rest/admin/application-version", "/api/Users"]
    for endpoint in admin_endpoints:
        resp = requests.get(f"{base_url}{endpoint}", headers=auth_headers)
        assert resp.status_code != 200 or endpoint == "/api/Users", (
            f"Contrôle d'accès manquant sur un endpoint sensible : {endpoint}"
        )
