"""Basic sanity tests for app.py that are independent of the size feature."""
import sqlite3


def test_human_size_formats_bytes(app_module):
    assert app_module._human_size(0) == '0 B'
    assert app_module._human_size(512) == '512 B'
    assert app_module._human_size(1024) == '1.0 KB'
    assert app_module._human_size(1024 * 1024) == '1.0 MB'
    assert app_module._human_size(1024 * 1024 * 1024) == '1.0 GB'


def test_validate_url_accepts_http_and_https(app_module):
    assert app_module.validate_url('https://example.com/file.mp4') == 'ok'
    assert app_module.validate_url('http://example.com/file.mp4') == 'ok'


def test_validate_url_rejects_invalid_scheme(app_module):
    assert app_module.validate_url('ftp://example.com/file.mp4') != 'ok'


def test_validate_url_rejects_garbage(app_module):
    assert app_module.validate_url('not a url') != 'ok'


def test_init_db_creates_links_table(app_module):
    conn = sqlite3.connect(app_module.DB_PATH)
    try:
        columns = [
            row[1] for row in conn.execute('PRAGMA table_info(links)')
        ]
    finally:
        conn.close()
    assert 'url' in columns
    assert 'status' in columns
    assert 'size_bytes' in columns


def test_add_link_if_new_inserts_row(app_module):
    with app_module.app.app_context():
        added, url, row_id = app_module.add_link_if_new(
            'https://example.com/a.mp4',
        )
        assert added is True
        assert url == 'https://example.com/a.mp4'
        assert row_id is not None


def test_add_link_if_new_ignores_duplicates(app_module):
    with app_module.app.app_context():
        app_module.add_link_if_new('https://example.com/a.mp4')
        added, _url, row_id = app_module.add_link_if_new(
            'https://example.com/a.mp4',
        )
        assert added is False
        assert row_id is None


def test_link_get_file_name_and_human_size(app_module):
    link = app_module.Link('https://example.com/some/file.mp4')
    assert link.get_file_name() == 'file.mp4'
    link.size_bytes = 2048
    assert link.get_human_size() == '2.0 KB'
