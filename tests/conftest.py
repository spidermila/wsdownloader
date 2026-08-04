"""
Shared pytest fixtures.

app.py and downloader.py both read their DATA_DIR/DOWNLOADS_DIR/DB_PATH
configuration from environment variables at *import time*. To keep tests
isolated from each other and from a developer's real ./data directory,
these fixtures point those env vars at a fresh temporary directory and
then (re)import the modules so they pick up the new paths.
"""
import importlib

import pytest


@pytest.fixture()
def temp_env(tmp_path, monkeypatch):
    """Point DATA_DIR/DOWNLOADS_DIR/DB_PATH at an isolated temp directory."""
    data_dir = tmp_path / 'data'
    downloads_dir = tmp_path / 'downloads'
    db_path = data_dir / 'downloader.db'

    monkeypatch.setenv('DATA_DIR', str(data_dir))
    monkeypatch.setenv('DOWNLOADS_DIR', str(downloads_dir))
    monkeypatch.setenv('DB_PATH', str(db_path))
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret-key')

    return {
        'data_dir': data_dir,
        'downloads_dir': downloads_dir,
        'db_path': db_path,
    }


@pytest.fixture()
def app_module(temp_env):
    """A freshly (re)imported app.py bound to the isolated temp DB/paths."""
    import app as app_mod
    importlib.reload(app_mod)
    app_mod.init_db()
    return app_mod


@pytest.fixture()
def downloader_module(app_module):
    """A freshly (re)imported downloader.py sharing app_module's DB."""
    import downloader as downloader_mod
    importlib.reload(downloader_mod)
    return downloader_mod


@pytest.fixture()
def client(app_module):
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client
