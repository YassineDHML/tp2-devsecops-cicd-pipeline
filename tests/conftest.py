"""Configuration commune des tests : base SQLite temporaire et client Flask."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1] / "app"

# Le module applicatif lit son environnement et initialise la base a l'import :
# la configuration de test est donc fixee avant de l'importer.
os.environ["SECRET_KEY"] = "cle-de-test-sans-valeur-secrete"
os.environ.pop("ADMIN_PASSWORD", None)
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="notes-test-"), "import.db")
sys.path.insert(0, str(APP_DIR))

import app as notes_app_module  # noqa: E402


@pytest.fixture()
def notes_app(tmp_path, monkeypatch):
    """Module applicatif branche sur une base SQLite vierge, propre a chaque test."""
    monkeypatch.setattr(notes_app_module, "DATABASE", str(tmp_path / "test.db"))
    monkeypatch.setattr(notes_app_module, "ADMIN_PASSWORD", None)
    notes_app_module.init_db()
    return notes_app_module


@pytest.fixture()
def client(notes_app):
    notes_app.app.config.update(TESTING=True)
    with notes_app.app.test_client() as test_client:
        yield test_client
