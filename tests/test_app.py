"""Tests unitaires de la Notes App (client de test Flask, SQLite temporaire).

Ils verifient le comportement fonctionnel *et* les proprietes de securite
corrigees au TP1 (requetes parametrees, echappement, validation d'entree,
anti-SSRF...). Si l'une de ces corrections etait annulee par erreur, le job
"Build et tests unitaires" du pipeline echouerait.
"""
import io
import sqlite3
from contextlib import closing

import pytest
import requests

PASSWORD = "Correct-Horse-9"


def register(client, username="alice", password=PASSWORD):
    return client.post("/register", data={"username": username, "password": password})


def login(client, username="alice", password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def upload(client, content: bytes, name="notes.yml"):
    return client.post(
        "/import",
        data={"file": (io.BytesIO(content), name)},
        content_type="multipart/form-data",
    )


@pytest.fixture()
def auth(client):
    """Client deja inscrit et connecte sous le nom 'alice'."""
    register(client)
    login(client)
    return client


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
def test_login_page_is_public(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "Connexion" in resp.get_data(as_text=True)


def test_index_requires_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")


def test_register_login_logout_flow(client):
    assert register(client).status_code == 302
    assert login(client).status_code == 302

    page = client.get("/")
    assert page.status_code == 200
    assert "Mes notes" in page.get_data(as_text=True)
    assert "alice" in page.get_data(as_text=True)

    assert client.get("/logout").status_code == 302
    assert client.get("/").status_code == 302


def test_duplicate_username_is_rejected(client):
    register(client)
    resp = register(client)
    assert resp.status_code == 200
    assert "indisponible" in resp.get_data(as_text=True)


@pytest.mark.parametrize("username, password", [("alice", "mauvais"), ("inconnu", PASSWORD)])
def test_login_with_bad_credentials_fails(client, username, password):
    register(client)
    resp = login(client, username, password)
    assert resp.status_code == 200
    assert "Identifiants invalides" in resp.get_data(as_text=True)


def test_passwords_are_stored_hashed(client, notes_app):
    register(client)
    with closing(sqlite3.connect(notes_app.DATABASE)) as db:
        stored = db.execute("SELECT password FROM users WHERE username = 'alice'").fetchone()[0]
    assert PASSWORD not in stored
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_session_cookie_is_httponly_and_samesite(client):
    register(client)
    cookie = login(client).headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_no_default_admin_account_without_env_password(client, notes_app):
    with closing(sqlite3.connect(notes_app.DATABASE)) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_admin_account_is_created_from_env_password(tmp_path, monkeypatch, notes_app):
    monkeypatch.setattr(notes_app, "DATABASE", str(tmp_path / "admin.db"))
    monkeypatch.setattr(notes_app, "ADMIN_PASSWORD", "Admin-Pass-12345")
    notes_app.init_db()
    with notes_app.app.test_client() as client:
        assert login(client, "admin", "Admin-Pass-12345").status_code == 302
        assert client.get("/").status_code == 200


# --------------------------------------------------------------------------
# Notes et recherche
# --------------------------------------------------------------------------
def test_add_and_list_notes(auth):
    assert auth.post("/notes", data={"title": "Courses", "content": "Lait et pain"}).status_code == 302
    page = auth.get("/").get_data(as_text=True)
    assert "Courses" in page
    assert "Lait et pain" in page


def test_notes_are_isolated_between_users(client):
    register(client, "alice")
    login(client, "alice")
    client.post("/notes", data={"title": "Note privee de Alice", "content": "confidentiel"})
    client.get("/logout")

    register(client, "bob")
    login(client, "bob")
    assert "Note privee de Alice" not in client.get("/").get_data(as_text=True)
    found = client.get("/search", query_string={"q": "privee"}).get_data(as_text=True)
    assert "Note privee de Alice" not in found
    assert "Aucune note" in found


def test_search_filters_notes_by_title(auth):
    auth.post("/notes", data={"title": "Courses", "content": "lait"})
    auth.post("/notes", data={"title": "Travail", "content": "rapport"})
    page = auth.get("/search", query_string={"q": "Cour"}).get_data(as_text=True)
    assert "Courses" in page
    assert "Travail" not in page


def test_search_is_not_sql_injectable(auth):
    auth.post("/notes", data={"title": "Courses", "content": "lait"})
    page = auth.get("/search", query_string={"q": "zzz' OR '1'='1"}).get_data(as_text=True)
    assert "Courses" not in page


def test_search_output_is_html_escaped(auth):
    payload = "<script>alert(1)</script>"
    page = auth.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert payload not in page
    assert "&lt;script&gt;" in page


# --------------------------------------------------------------------------
# Import YAML
# --------------------------------------------------------------------------
def test_import_valid_yaml_creates_notes(auth):
    resp = upload(auth, b"- title: Import un\n  content: a\n- title: Import deux\n  content: b\n")
    assert resp.status_code == 302
    page = auth.get("/").get_data(as_text=True)
    assert "Import un" in page
    assert "Import deux" in page


@pytest.mark.parametrize(
    "content",
    [
        b"- title: [pas ferme",  # YAML invalide
        b"title: x\ncontent: y\n",  # un dict au lieu d'une liste
        b"- title: sans contenu\n",  # champ manquant
        b"- title: 1\n  content: 2\n",  # types non textuels
        b"!!python/object/apply:os.system ['echo pwned']",  # objet Python : refuse par safe_load
    ],
)
def test_import_rejects_invalid_or_dangerous_yaml(auth, content):
    assert upload(auth, content).status_code == 400


def test_import_without_file_is_rejected(auth):
    assert auth.post("/import").status_code == 400


def test_import_rejects_oversized_upload(auth):
    assert upload(auth, b"a" * (1024 * 1024 + 10)).status_code == 413


def test_import_requires_login(client):
    assert upload(client, b"- title: a\n  content: b\n").status_code == 302


# --------------------------------------------------------------------------
# Preferences
# --------------------------------------------------------------------------
def test_preferences_theme_is_whitelisted(auth):
    auth.post("/preferences", data={"theme": "dark"})
    assert "Theme actuel : <b>dark</b>" in auth.get("/preferences").get_data(as_text=True)

    auth.post("/preferences", data={"theme": "<script>"})
    page = auth.get("/preferences").get_data(as_text=True)
    assert "Theme actuel : <b>light</b>" in page
    assert "<script>" not in page


# --------------------------------------------------------------------------
# Outils reseau : ping (injection de commande) et fetch (SSRF)
# --------------------------------------------------------------------------
def test_ping_requires_login(client):
    assert client.get("/tools/ping", query_string={"host": "127.0.0.1"}).status_code == 302


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1; id", "localhost", "$(id)", "1.2.3.4 && cat /etc/passwd", "-c 100 1.1.1.1"],
)
def test_ping_rejects_anything_but_an_ip_address(auth, host):
    assert auth.get("/tools/ping", query_string={"host": host}).status_code == 400


def test_ping_runs_without_a_shell(auth, notes_app, monkeypatch):
    calls = []

    class Result:
        stdout = b"1 packets transmitted"
        stderr = b""

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr(notes_app.subprocess, "run", fake_run)
    resp = auth.get("/tools/ping", query_string={"host": "127.0.0.1"})

    assert resp.status_code == 200
    args, kwargs = calls[0]
    assert args == ["/bin/ping", "-c", "1", "127.0.0.1"]
    assert not kwargs.get("shell")
    assert "packets transmitted" in resp.get_data(as_text=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost:5000/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/admin",
        "http://[::1]/",
        "file:///etc/passwd",
        "ftp://example.com/",
        "gopher://example.com/",
    ],
)
def test_fetch_blocks_non_public_targets(auth, url):
    assert auth.get("/tools/fetch", query_string={"url": url}).status_code == 400


def test_fetch_requires_login(client):
    assert client.get("/tools/fetch", query_string={"url": "https://example.com"}).status_code == 302


def test_fetch_public_url_uses_timeout_and_no_redirect(auth, notes_app, monkeypatch):
    captured = {}

    class FakeResponse:
        text = "<html>contenu distant</html>"

    def fake_get(url, **kwargs):
        captured.update(kwargs, url=url)
        return FakeResponse()

    monkeypatch.setattr(notes_app.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port))])
    monkeypatch.setattr(notes_app.requests, "get", fake_get)

    resp = auth.get("/tools/fetch", query_string={"url": "https://example.com/page"})

    assert resp.status_code == 200
    assert captured["timeout"] == 5
    assert captured["allow_redirects"] is False
    assert "verify" not in captured or captured["verify"] is True
    assert "&lt;html&gt;" in resp.get_data(as_text=True)


def test_fetch_reports_unreachable_host_as_bad_gateway(auth, notes_app, monkeypatch):
    def failing_get(url, **kwargs):
        raise requests.ConnectionError("injoignable")

    monkeypatch.setattr(notes_app.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("93.184.216.34", port))])
    monkeypatch.setattr(notes_app.requests, "get", failing_get)
    assert auth.get("/tools/fetch", query_string={"url": "https://example.com"}).status_code == 502


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://93.184.216.34/", True),
        ("https://[2606:2800:220:1:248:1893:25c8:1946]/", True),
        ("http://127.0.0.1/", False),
        ("http://192.168.1.10/", False),
        ("http://169.254.169.254/", False),
        ("javascript:alert(1)", False),
        ("http:///sans-hote", False),
    ],
)
def test_is_public_http_url(notes_app, url, expected):
    assert notes_app.is_public_http_url(url) is expected


def test_is_public_http_url_rejects_unresolvable_host(notes_app, monkeypatch):
    def unresolvable(host, port):
        raise notes_app.socket.gaierror("nom inconnu")

    monkeypatch.setattr(notes_app.socket, "getaddrinfo", unresolvable)
    assert notes_app.is_public_http_url("https://hote-inexistant.invalid/") is False


# --------------------------------------------------------------------------
# En-tetes de securite
# --------------------------------------------------------------------------
def test_security_headers_are_set(client):
    resp = client.get("/login")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


# --------------------------------------------------------------------------
# Diagnostic reseau
# --------------------------------------------------------------------------
def test_diagnostic_shows_resolution_result(client, notes_app, monkeypatch):
    class Result:
        stdout = "127.0.0.1       localhost\n"
        stderr = ""

    monkeypatch.setattr(notes_app.subprocess, "run", lambda *args, **kwargs: Result())
    resp = client.get("/diagnostic", query_string={"host": "localhost"})
    assert resp.status_code == 200
    assert "127.0.0.1" in resp.get_data(as_text=True)
