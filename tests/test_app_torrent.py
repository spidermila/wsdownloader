"""Tests for the torrent code paths in app.py (issue #39)."""


MAGNET = 'magnet:?xt=urn:btih:0123456789abcdef&dn=example'


def _enable_torrents(app_module):
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute(
            'UPDATE settings SET torrent_enabled = 1 WHERE id = 1',
        )
        db.commit()


def test_validate_url_rejects_magnet_when_disabled(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url(MAGNET) != 'ok'


def test_validate_url_accepts_magnet_when_enabled(app_module):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        assert app_module.validate_url(MAGNET) == 'ok'


def test_validate_url_rejects_magnet_without_btih(app_module):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        assert app_module.validate_url('magnet:?xt=urn:sha1:xyz') != 'ok'


def test_validate_url_rejects_dot_torrent_when_disabled(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url(
            'https://example.com/file.torrent',
        ) != 'ok'


def test_validate_url_accepts_dot_torrent_when_enabled(app_module):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        assert app_module.validate_url(
            'https://example.com/file.torrent',
        ) == 'ok'


def test_add_link_with_kind_persists(app_module):
    with app_module.app.app_context():
        added, url, row_id = app_module.add_link_if_new(
            MAGNET, kind=app_module.torrent.KIND_MAGNET,
        )
        assert added and row_id is not None
        db = app_module.get_db()
        row = db.execute(
            'SELECT kind FROM links WHERE id = ?', (row_id,),
        ).fetchone()
        assert row['kind'] == 'magnet'


def test_link_display_name_for_magnet(app_module):
    link = app_module.Link(MAGNET)
    link.kind = 'magnet'
    assert link.get_file_name() == 'example'


def test_link_display_name_for_magnet_without_dn(app_module):
    link = app_module.Link('magnet:?xt=urn:btih:aaaa')
    link.kind = 'magnet'
    # Falls back to the raw URL truncated to 60 chars
    assert link.get_file_name().startswith('magnet:?xt=')


def test_index_post_rejects_magnet_when_disabled(client):
    resp = client.post('/', data={'link': MAGNET}, follow_redirects=False)
    assert resp.status_code == 302


def test_index_post_accepts_magnet_when_enabled(app_module, client):
    _enable_torrents(app_module)
    resp = client.post('/', data={'link': MAGNET}, follow_redirects=False)
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT kind FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
        assert row is not None
        assert row['kind'] == 'magnet'


def test_index_post_flags_duplicate_torrent(app_module, client):
    _enable_torrents(app_module)
    client.post('/', data={'link': MAGNET})
    resp = client.post('/', data={'link': MAGNET})
    assert resp.status_code == 302


def test_settings_torrent_updates_all_fields(app_module, client):
    resp = client.post(
        '/settings/torrent',
        data={
            'torrent_enabled': 'on',
            'torrent_seed_mode': 'ratio',
            'torrent_seed_value': '1.5',
        },
    )
    assert resp.status_code == 302
    with app_module.app.app_context():
        s = app_module.get_settings()
        assert s['torrent_enabled'] == 1
        assert s['torrent_seed_mode'] == 'ratio'
        assert s['torrent_seed_value'] == 1.5


def test_settings_torrent_rejects_invalid_seed_mode(app_module, client):
    client.post(
        '/settings/torrent',
        data={'torrent_seed_mode': 'garbage', 'torrent_seed_value': '1'},
    )
    with app_module.app.app_context():
        assert app_module.get_settings()['torrent_seed_mode'] == 'off'


def test_settings_torrent_clamps_negative_value(app_module, client):
    client.post(
        '/settings/torrent',
        data={'torrent_seed_mode': 'ratio', 'torrent_seed_value': '-5'},
    )
    with app_module.app.app_context():
        assert app_module.get_settings()['torrent_seed_value'] == 0.0


def test_settings_torrent_handles_unparseable_value(app_module, client):
    client.post(
        '/settings/torrent',
        data={'torrent_seed_mode': 'ratio', 'torrent_seed_value': 'abc'},
    )
    with app_module.app.app_context():
        assert app_module.get_settings()['torrent_seed_value'] == 0.0


def test_delete_link_calls_aria2_for_torrent(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        _, _, row_id = app_module.add_link_if_new(
            MAGNET, kind=app_module.torrent.KIND_MAGNET,
        )
        db = app_module.get_db()
        db.execute(
            'UPDATE links SET external_id = ? WHERE id = ?',
            ('gid42', row_id),
        )
        db.commit()

    calls = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def remove(self, gid):
            calls.append(('remove', gid))

        def remove_download_result(self, gid):
            calls.append(('remove_download_result', gid))

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    assert calls == [
        ('remove', 'gid42'), ('remove_download_result', 'gid42'),
    ]


def test_delete_link_swallows_aria2_error(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        _, _, row_id = app_module.add_link_if_new(
            MAGNET, kind=app_module.torrent.KIND_MAGNET,
        )
        db = app_module.get_db()
        db.execute(
            'UPDATE links SET external_id = ? WHERE id = ?',
            ('gid42', row_id),
        )
        db.commit()

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def remove(self, gid):
            raise app_module.torrent.Aria2Error('boom')

        def remove_download_result(self, gid):
            raise app_module.torrent.Aria2Error('boom')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302


def test_delete_link_skips_aria2_for_http(app_module, client, monkeypatch):
    with app_module.app.app_context():
        app_module.add_link_if_new('https://example.com/a.mp4')

    called = []

    class BoomClient:
        def __init__(self, *a, **kw):
            called.append('init')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', BoomClient)
    resp = client.post(
        '/delete', data={'url': 'https://example.com/a.mp4'},
    )
    assert resp.status_code == 302
    assert called == []


def test_list_downloaded_files_shows_directories(app_module):
    root = app_module.DOWNLOADS_PATH
    (root / 'subdir').mkdir(parents=True, exist_ok=True)
    (root / 'subdir' / 'a.mp4').write_bytes(b'x' * 100)
    (root / 'subdir' / 'b.mp4').write_bytes(b'y' * 50)
    (root / 'plain.mp4').write_bytes(b'z' * 10)

    files = app_module.list_downloaded_files()
    by_name = {f['name']: f for f in files}
    assert 'subdir' in by_name
    assert by_name['subdir']['is_dir'] is True
    assert 'plain.mp4' in by_name
    assert by_name['plain.mp4']['is_dir'] is False


def test_delete_file_removes_directory(app_module, client):
    root = app_module.DOWNLOADS_PATH
    (root / 'torr').mkdir(parents=True, exist_ok=True)
    (root / 'torr' / 'a.mp4').write_bytes(b'x')

    resp = client.post('/delete-file', data={'filename': 'torr'})
    assert resp.status_code == 302
    assert not (root / 'torr').exists()


def test_link_to_dict_includes_kind(app_module):
    link = app_module.Link(MAGNET)
    link.kind = 'magnet'
    with app_module.app.app_context():
        d = app_module.link_to_dict(link)
    assert d['kind'] == 'magnet'


def test_torrents_enabled_helper_survives_db_error(app_module, monkeypatch):
    def boom():
        raise RuntimeError('db is unhappy')

    monkeypatch.setattr(app_module, 'get_settings', boom)
    assert app_module._torrents_enabled() is False


def test_index_post_http_link_added(app_module, client, monkeypatch):
    monkeypatch.setattr(
        app_module, 'test_url', lambda url: (True, 12345),
    )
    resp = client.post(
        '/', data={'link': 'https://example.com/a.mp4'},
    )
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT size_bytes FROM links WHERE url = ?',
            ('https://example.com/a.mp4',),
        ).fetchone()
        assert row['size_bytes'] == 12345


def test_index_post_http_link_unreachable(app_module, client, monkeypatch):
    monkeypatch.setattr(
        app_module, 'test_url', lambda url: (False, None),
    )
    resp = client.post(
        '/', data={'link': 'https://example.com/nope.mp4'},
    )
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT id FROM links WHERE url = ?',
            ('https://example.com/nope.mp4',),
        ).fetchone()
        assert row is None


def test_index_post_http_link_duplicate(app_module, client, monkeypatch):
    monkeypatch.setattr(
        app_module, 'test_url', lambda url: (True, None),
    )
    client.post('/', data={'link': 'https://example.com/dup.mp4'})
    resp = client.post('/', data={'link': 'https://example.com/dup.mp4'})
    assert resp.status_code == 302


def test_index_post_invalid_url(client):
    resp = client.post('/', data={'link': 'not a link'})
    assert resp.status_code == 302


def test_delete_torrent_without_external_id_noop(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    with app_module.app.app_context():
        app_module.add_link_if_new(MAGNET, kind='magnet')

    called = []

    class BoomClient:
        def __init__(self, *a, **kw):
            called.append('init')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', BoomClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    assert called == []


def test_dir_size_survives_os_error(app_module):
    class BrokenFile:
        name = 'broken'

        def is_file(self):
            return True

        def stat(self):
            raise OSError('vanished')

    class OkFile:
        name = 'ok'

        def is_file(self):
            return True

        def stat(self):
            class S:
                st_size = 42
            return S()

    class FakePath:
        def rglob(self, pattern):
            return iter([BrokenFile(), OkFile()])

    assert app_module._dir_size(FakePath()) == 42
