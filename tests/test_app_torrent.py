"""Tests for the torrent code paths in app.py (issue #39)."""
import sqlite3

import pytest

TORRENT_URL = 'https://example.com/x.torrent'
MAGNET = (
    'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567'
    '&dn=example'
)


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
        added, _url, row_id = app_module.add_link_if_new(
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

    staged = app_module.TORRENTS_DIR / f'link-{row_id}.torrent'
    staged.write_bytes(b'stub')

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
    assert not staged.exists()


def test_delete_link_preserves_row_on_aria2_error(
    app_module, client, monkeypatch,
):
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

        def force_remove(self, gid):
            raise app_module.torrent.Aria2Error('boom')

        def remove_download_result(self, gid):
            raise app_module.torrent.Aria2Error('boom')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
        assert row is not None


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


def test_link_to_dict_includes_kind_and_connections(app_module):
    link = app_module.Link(MAGNET)
    link.kind = 'magnet'
    link.connections = 5
    link.upload_speed_bps = 2048
    link.uploaded_bytes = 500
    link.size_bytes = 1000
    with app_module.app.app_context():
        d = app_module.link_to_dict(link)
    assert d['kind'] == 'magnet'
    assert d['connections'] == 5
    assert d['upload_speed_bps'] == 2048
    assert d['uploaded_bytes'] == 500
    assert d['ratio'] == 0.5


def test_link_to_dict_ratio_zero_when_size_zero(app_module):
    link = app_module.Link(MAGNET)
    link.uploaded_bytes = 999
    link.size_bytes = 0
    with app_module.app.app_context():
        d = app_module.link_to_dict(link)
    assert d['ratio'] == 0.0


def _make_torrent_row(
    app_module, url=MAGNET, kind='magnet',
    external_id='gidA', status='downloading',
):
    with app_module.app.app_context():
        _, _, row_id = app_module.add_link_if_new(url, kind=kind)
        db = app_module.get_db()
        db.execute(
            'UPDATE links SET external_id = ?, status = ? WHERE id = ?',
            (external_id, status, row_id),
        )
        db.commit()


class _AriaStub:
    def __init__(self):
        self.calls = []

    def pause(self, gid):
        self.calls.append(('pause', gid))

    def unpause(self, gid):
        self.calls.append(('unpause', gid))

    def remove(self, gid):
        self.calls.append(('remove', gid))

    def remove_download_result(self, gid):
        self.calls.append(('remove_result', gid))


def test_pause_torrent_updates_status(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)
    stub = _AriaStub()
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: stub,
    )
    resp = client.post('/torrent/pause', data={'url': MAGNET})
    assert resp.status_code == 302
    assert ('pause', 'gidA') in stub.calls
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row['status'] == 'paused'


def test_pause_torrent_rejects_http(app_module, client):
    with app_module.app.app_context():
        app_module.add_link_if_new('https://example.com/x.mp4')
    resp = client.post(
        '/torrent/pause', data={'url': 'https://example.com/x.mp4'},
    )
    assert resp.status_code == 302


def test_pause_torrent_rejects_missing_url(client):
    resp = client.post('/torrent/pause', data={'url': ''})
    assert resp.status_code == 302


def test_pause_torrent_rejects_before_enqueue(app_module, client):
    _enable_torrents(app_module)
    _make_torrent_row(app_module, external_id='', status='downloading')
    resp = client.post('/torrent/pause', data={'url': MAGNET})
    assert resp.status_code == 302
    assert _status(app_module) == 'downloading'


def test_pause_torrent_handles_aria_error(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    class Bad:
        def pause(self, gid):
            raise app_module.torrent.Aria2Error('nope')

    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: Bad(),
    )
    resp = client.post('/torrent/pause', data={'url': MAGNET})
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row['status'] == 'downloading'


def test_resume_torrent_updates_status(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module, status='paused')
    stub = _AriaStub()
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: stub,
    )
    resp = client.post('/torrent/resume', data={'url': MAGNET})
    assert resp.status_code == 302
    assert ('unpause', 'gidA') in stub.calls
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row['status'] == 'downloading'


def test_resume_torrent_rejects_missing_url(client):
    resp = client.post('/torrent/resume', data={'url': ''})
    assert resp.status_code == 302


def test_resume_torrent_handles_aria_error(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module, status='paused')

    class Bad:
        def unpause(self, gid):
            raise app_module.torrent.Aria2Error('nope')

    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: Bad(),
    )
    resp = client.post('/torrent/resume', data={'url': MAGNET})
    assert resp.status_code == 302


def test_stop_seeding_removes_row_and_calls_aria(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module, status='seeding')
    stub = _AriaStub()
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: stub,
    )
    resp = client.post(
        '/torrent/stop-seeding', data={'url': MAGNET},
    )
    assert resp.status_code == 302
    assert ('remove', 'gidA') in stub.calls
    assert ('remove_result', 'gidA') in stub.calls
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row is None


def test_stop_seeding_rejects_http(app_module, client):
    with app_module.app.app_context():
        app_module.add_link_if_new('https://example.com/x.mp4')
    resp = client.post(
        '/torrent/stop-seeding',
        data={'url': 'https://example.com/x.mp4'},
    )
    assert resp.status_code == 302


def test_stop_seeding_rejects_missing_url(client):
    resp = client.post('/torrent/stop-seeding', data={'url': ''})
    assert resp.status_code == 302


def test_torrent_details_rejects_missing_url(client):
    resp = client.get('/torrent/details')
    assert resp.status_code == 302


def test_torrent_details_rejects_http(app_module, client):
    with app_module.app.app_context():
        app_module.add_link_if_new('https://example.com/a.mp4')
    resp = client.get(
        '/torrent/details?url=https://example.com/a.mp4',
    )
    assert resp.status_code == 302


def test_torrent_details_renders_without_external_id(
    app_module, client,
):
    from urllib.parse import quote
    _enable_torrents(app_module)
    _make_torrent_row(app_module, external_id=None)
    resp = client.get(f'/torrent/details?url={quote(MAGNET)}')
    assert resp.status_code == 200
    assert b'Detail torrentu' in resp.data
    assert b'nejsou dostupn' in resp.data


def test_torrent_details_renders_full(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    class Stub:
        def tell_status(self, gid):
            return {
                'status': 'active', 'totalLength': '1000',
                'completedLength': '500', 'downloadSpeed': '1024',
                'uploadSpeed': '128', 'uploadLength': '256',
                'connections': '3', 'seeder': 'false',
                'infoHash': 'deadbeef', 'pieceLength': '16384',
                'numPieces': '61',
                'files': [{
                    'path': '/downloads/movie.mp4',
                    'length': '1000', 'completedLength': '500',
                }],
                'bittorrent': {
                    'comment': 'Test', 'mode': 'single',
                    'creationDate': 1700000000,
                },
            }

        def get_peers(self, gid):
            return [
                {
                    'ip': '1.2.3.4', 'port': '51413',
                    'downloadSpeed': '512', 'uploadSpeed': '64',
                    'seeder': 'true', 'amChoking': 'false',
                    'peerChoking': 'true', 'bitfield': 'ffff',
                },
            ]

        def get_servers(self, gid):
            return []

    from urllib.parse import quote
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: Stub(),
    )
    resp = client.get(f'/torrent/details?url={quote(MAGNET)}')
    assert resp.status_code == 200
    body = resp.data.decode('utf-8')
    assert 'Detail torrentu' in body
    assert 'deadbeef' in body
    assert '1.2.3.4' in body
    assert 'movie.mp4' in body


def test_torrent_details_handles_aria2_error(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    class BadClient:
        def tell_status(self, gid):
            raise app_module.torrent.Aria2Error('rpc down')

    from urllib.parse import quote
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: BadClient(),
    )
    resp = client.get(f'/torrent/details?url={quote(MAGNET)}')
    assert resp.status_code == 200
    assert b'rpc down' in resp.data


def test_torrents_enabled_helper_survives_db_error(app_module, monkeypatch):
    import sqlite3 as _sqlite3

    def boom():
        raise _sqlite3.OperationalError('database is locked')

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


# --- New tests for graceful remove, bulk actions, global limits, files ------

def test_remove_prefers_graceful_over_force(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    calls = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def remove(self, gid):
            calls.append(('remove', gid))

        def force_remove(self, gid):
            calls.append(('force_remove', gid))

        def remove_download_result(self, gid):
            calls.append(('remove_result', gid))

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    assert ('remove', 'gidA') in calls
    assert ('force_remove', 'gidA') not in calls


def test_remove_returns_false_when_both_graceful_and_force_fail(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def remove(self, gid):
            raise app_module.torrent.Aria2Error('busy')

        def force_remove(self, gid):
            raise app_module.torrent.Aria2Error('still busy')

        def remove_download_result(self, gid):
            raise AssertionError('should not be called')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row is not None


def test_remove_falls_back_to_force_when_graceful_fails(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    calls = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def remove(self, gid):
            calls.append(('remove', gid))
            raise app_module.torrent.Aria2Error('busy')

        def force_remove(self, gid):
            calls.append(('force_remove', gid))

        def remove_download_result(self, gid):
            calls.append(('remove_result', gid))

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/delete', data={'url': MAGNET})
    assert resp.status_code == 302
    assert [c[0] for c in calls] == [
        'remove', 'force_remove', 'remove_result',
    ]


def test_pause_all_updates_all_downloading_rows(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module, url=MAGNET, external_id='g1')
    other = MAGNET.replace('0123456789abcdef' * 2, 'a' * 32)
    _make_torrent_row(
        app_module, url=other, external_id='g2', status='seeding',
    )

    seen = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def pause_all(self):
            seen.append('pause_all')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/torrent/pause-all')
    assert resp.status_code == 302
    assert seen == ['pause_all']
    with app_module.app.app_context():
        db = app_module.get_db()
        rows = db.execute(
            "SELECT status FROM links WHERE kind = 'magnet'",
        ).fetchall()
    # Covers reviewer finding: bulk pause must also flip 'seeding' rows,
    # not just 'downloading'.
    assert all(r['status'] == 'paused' for r in rows)


def test_pause_all_preserves_terminal_statuses(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(
        app_module, url=MAGNET, external_id='g1', status='failed',
    )

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def pause_all(self):
            pass

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    client.post('/torrent/pause-all')
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row['status'] == 'failed'


def test_resume_all_updates_paused_rows(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(
        app_module, url=MAGNET, external_id='g1', status='paused',
    )
    seen = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def unpause_all(self):
            seen.append('unpause_all')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/torrent/resume-all')
    assert resp.status_code == 302
    assert seen == ['unpause_all']
    with app_module.app.app_context():
        db = app_module.get_db()
        row = db.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    assert row['status'] == 'downloading'


def test_settings_persists_speed_limits_and_pushes_to_aria2(
    app_module, client, monkeypatch,
):
    pushed = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def is_available(self):
            return True

        def change_global_option(self, options):
            pushed.append(dict(options))

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post(
        '/settings/torrent',
        data={
            'torrent_enabled': 'on',
            'torrent_seed_mode': 'off',
            'torrent_seed_value': '0',
            'torrent_max_dl_kib': '1024',
            'torrent_max_ul_kib': '512',
        },
    )
    assert resp.status_code == 302
    with app_module.app.app_context():
        s = app_module.get_settings()
    assert s['torrent_max_dl_bps'] == 1024 * 1024
    assert s['torrent_max_ul_bps'] == 512 * 1024
    assert pushed and pushed[-1] == {
        'max-overall-download-limit': str(1024 * 1024),
        'max-overall-upload-limit': str(512 * 1024),
    }


def test_global_stats_endpoint(app_module, client, monkeypatch):
    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def get_global_stat(self):
            return {
                'downloadSpeed': '2048', 'uploadSpeed': '1024',
                'numActive': '3', 'numWaiting': '1', 'numStopped': '0',
            }

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.get('/torrent/global-stats')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['available'] is True
    assert body['download_speed_bps'] == 2048
    assert body['num_active'] == 3


def test_global_stats_endpoint_error(app_module, client, monkeypatch):
    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def get_global_stat(self):
            raise app_module.torrent.Aria2Error('down')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.get('/torrent/global-stats')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['available'] is False


def test_select_files_calls_change_option(app_module, client, monkeypatch):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    seen = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def tell_status(self, gid, keys=None):
            return {
                'files': [
                    {
                        'index': '1', 'path': '/a', 'length': '100',
                        'completedLength': '0', 'selected': 'true',
                    },
                    {
                        'index': '2', 'path': '/b', 'length': '200',
                        'completedLength': '0', 'selected': 'true',
                    },
                    {
                        'index': '3', 'path': '/c', 'length': '300',
                        'completedLength': '0', 'selected': 'true',
                    },
                ],
            }

        def change_option(self, gid, options):
            seen.append((gid, dict(options)))

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post(
        '/torrent/select-files',
        data={'url': MAGNET, 'file_index': ['1', '3']},
    )
    assert resp.status_code == 302
    assert seen == [('gidA', {'select-file': '1,3'})]


def test_select_files_rejects_empty_selection(
    app_module, client, monkeypatch,
):
    _enable_torrents(app_module)
    _make_torrent_row(app_module)

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def tell_status(self, gid, keys=None):
            return {
                'files': [{
                    'index': '1', 'path': '/a', 'length': '1',
                    'completedLength': '0', 'selected': 'true',
                }],
            }

        def change_option(self, gid, options):
            raise AssertionError('should not be called')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', FakeClient)
    resp = client.post('/torrent/select-files', data={'url': MAGNET})
    assert resp.status_code == 302


GID_NOT_FOUND = "{'code': 1, 'message': 'GID 0123456789abcdef is not found'}"
OTHER = MAGNET.replace('0123456789abcdef' * 2, 'b' * 32)
HTTP_URL = 'https://example.com/x.mp4'


def _status(app_module, url=MAGNET):
    with app_module.app.app_context():
        row = app_module.get_db().execute(
            'SELECT status FROM links WHERE url = ?', (url,),
        ).fetchone()
    return row['status'] if row else None


def _forbid_client(app_module, monkeypatch):
    def boom(*a, **kw):
        raise AssertionError('aria2 must not be contacted')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', boom)


def _flashes(client):
    with client.session_transaction() as sess:
        return [m for _cat, m in sess.get('_flashes', [])]


def _http_row(app_module, status='downloading'):
    with app_module.app.app_context():
        app_module.add_link_if_new(HTTP_URL)
        db = app_module.get_db()
        db.execute(
            'UPDATE links SET status = ? WHERE url = ?', (status, HTTP_URL),
        )
        db.commit()


# --- FR-2 resume with lost / empty GID ---------------------------------

@pytest.mark.parametrize('gid', ['', None])
def test_resume_torrent_empty_gid_sets_downloading(
    app_module, client, monkeypatch, gid,
):
    _make_torrent_row(app_module, external_id=gid, status='paused')
    _forbid_client(app_module, monkeypatch)
    resp = client.post('/torrent/resume', data={'url': MAGNET})
    assert resp.status_code == 302
    assert _status(app_module) == 'downloading'
    assert _flashes(client) == ['Torrent bude znovu přidán do aria2.']


def test_resume_torrent_lost_gid_sets_downloading(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module, status='paused')

    class Lost:
        def unpause(self, gid):
            raise app_module.torrent.Aria2Error(GID_NOT_FOUND)

    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: Lost(),
    )
    client.post('/torrent/resume', data={'url': MAGNET})
    assert _status(app_module) == 'downloading'


def test_resume_lost_gid_then_loop_reenqueues_once(
    app_module, client, downloader_module, monkeypatch,
):
    _make_torrent_row(
        app_module, url=TORRENT_URL, kind='torrent', external_id='',
        status='paused',
    )
    _enable_torrents(app_module)
    with app_module.app.app_context():
        row_id = app_module.get_db().execute(
            'SELECT id FROM links WHERE url = ?', (TORRENT_URL,),
        ).fetchone()['id']
    downloader_module._torrent_file_path(row_id).write_bytes(b'bytes')

    adds = []

    class Aria:
        def is_available(self):
            return True

        def add_torrent(self, data, opts):
            adds.append(data)
            return 'newgid'

        def tell_status(self, gid):
            return {'status': 'active'}

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Aria(),
    )
    downloader_module.torrent_loop()
    assert adds == []
    client.post('/torrent/resume', data={'url': TORRENT_URL})
    downloader_module.torrent_loop()
    downloader_module.torrent_loop()
    assert adds == [b'bytes']
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        gid = conn.execute(
            'SELECT external_id FROM links WHERE id = ?', (row_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    assert gid == 'newgid'


def test_resume_torrent_rejects_http(app_module, client):
    _http_row(app_module)
    client.post('/torrent/resume', data={'url': HTTP_URL})
    assert _flashes(client) == ['Není to torrent.']


# --- FR-7 details with lost / empty GID --------------------------------

def test_torrent_details_lost_gid_renders_200(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module)

    class Lost:
        def tell_status(self, gid):
            raise app_module.torrent.Aria2Error(GID_NOT_FOUND)

    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: Lost(),
    )
    resp = client.get('/torrent/details', query_string={'url': MAGNET})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'bude automaticky znovu přidán' in body
    assert "'code': 1" not in body


# --- FR-13 / AC-12 stop seeding ----------------------------------------

def test_stop_seeding_deletes_staged_file(app_module, client, monkeypatch):
    _make_torrent_row(app_module, status='seeding')
    with app_module.app.app_context():
        row_id = app_module.get_db().execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()['id']
    staged = app_module.TORRENTS_DIR / f'link-{row_id}.torrent'
    staged.write_bytes(b'x')
    emitted = []
    monkeypatch.setattr(
        app_module.socketio, 'emit', lambda *a, **kw: emitted.append(a),
    )
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: _AriaStub(),
    )
    client.post('/torrent/stop-seeding', data={'url': MAGNET})
    assert not staged.exists()
    assert _status(app_module) is None
    assert emitted == [('link_deleted', {'url': MAGNET})]


def test_stop_seeding_keeps_row_and_file_on_remove_failure(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module, status='seeding')
    with app_module.app.app_context():
        row_id = app_module.get_db().execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()['id']
    staged = app_module.TORRENTS_DIR / f'link-{row_id}.torrent'
    staged.write_bytes(b'x')
    monkeypatch.setattr(
        app_module, '_remove_from_aria2', lambda gid: False,
    )
    client.post('/torrent/stop-seeding', data={'url': MAGNET})
    assert staged.exists()
    assert _status(app_module) == 'seeding'


# --- AC-8 _remove_from_aria2 -------------------------------------------

class _RemoveClient:
    def __init__(self, app_module, remove=None, force=None, result=None):
        self.torrent = app_module.torrent
        self.remove_exc = remove
        self.force_exc = force
        self.result_exc = result
        self.calls = []

    def _maybe(self, name, exc):
        self.calls.append(name)
        if exc:
            raise self.torrent.Aria2Error(exc)

    def remove(self, gid):
        self._maybe('remove', self.remove_exc)

    def force_remove(self, gid):
        self._maybe('force_remove', self.force_exc)

    def remove_download_result(self, gid):
        self._maybe('remove_result', self.result_exc)


def _use(app_module, monkeypatch, stub):
    monkeypatch.setattr(
        app_module.torrent, 'Aria2Client', lambda *a, **kw: stub,
    )


def test_remove_force_not_found_returns_true(app_module, monkeypatch):
    stub = _RemoveClient(app_module, remove='busy', force=GID_NOT_FOUND)
    _use(app_module, monkeypatch, stub)
    assert app_module._remove_from_aria2('gidA') is True
    assert stub.calls == ['remove', 'force_remove']


def test_remove_graceful_and_force_not_found(app_module, monkeypatch):
    stub = _RemoveClient(
        app_module, remove=GID_NOT_FOUND, force=GID_NOT_FOUND,
    )
    _use(app_module, monkeypatch, stub)
    assert app_module._remove_from_aria2('gidA') is True


def test_remove_force_other_error_returns_false_and_route_keeps_row(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module)
    stub = _RemoveClient(app_module, remove='busy', force='still busy')
    _use(app_module, monkeypatch, stub)
    assert app_module._remove_from_aria2('gidA') is False
    client.post('/delete', data={'url': MAGNET})
    assert _status(app_module) == 'downloading'
    assert 'Nepodařilo se odebrat torrent z aria2. Zkuste to znovu.' in (
        _flashes(client)
    )


def test_remove_ignores_remove_result_error(app_module, monkeypatch):
    stub = _RemoveClient(app_module, result='gone')
    _use(app_module, monkeypatch, stub)
    assert app_module._remove_from_aria2('gidA') is True
    assert stub.calls == ['remove', 'remove_result']


def test_remove_empty_id_creates_no_client(app_module, monkeypatch):
    _forbid_client(app_module, monkeypatch)
    assert app_module._remove_from_aria2('') is True


# --- FR-9 / AC-10 bulk actions -----------------------------------------

class _BulkClient:
    def __init__(self, *a, **kw):
        pass

    def pause_all(self):
        pass

    def unpause_all(self):
        pass


def test_pause_all_includes_empty_gid_rows(app_module, client, monkeypatch):
    _make_torrent_row(app_module, url=MAGNET, external_id='g1')
    _make_torrent_row(app_module, url=OTHER, external_id='', status='new')
    third = MAGNET.replace('0123456789abcdef' * 2, 'c' * 32)
    _make_torrent_row(
        app_module, url=third, external_id=None, status='new',
    )
    monkeypatch.setattr(app_module.torrent, 'Aria2Client', _BulkClient)
    client.post('/torrent/pause-all')
    assert _status(app_module, MAGNET) == 'paused'
    assert _status(app_module, OTHER) == 'paused'
    assert _status(app_module, third) == 'paused'


def test_resume_all_includes_empty_gid_paused_rows(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module, url=MAGNET, external_id='', status='paused')
    _make_torrent_row(
        app_module, url=OTHER, external_id='g', status='failed',
    )
    monkeypatch.setattr(app_module.torrent, 'Aria2Client', _BulkClient)
    client.post('/torrent/resume-all')
    assert _status(app_module, MAGNET) == 'downloading'
    assert _status(app_module, OTHER) == 'failed'


def test_bulk_actions_leave_http_rows(app_module, client, monkeypatch):
    _http_row(app_module, status='downloading')
    monkeypatch.setattr(app_module.torrent, 'Aria2Client', _BulkClient)
    client.post('/torrent/pause-all')
    assert _status(app_module, HTTP_URL) == 'downloading'
    client.post('/torrent/resume-all')
    assert _status(app_module, HTTP_URL) == 'downloading'


def test_bulk_action_aria2_error_leaves_db(app_module, client, monkeypatch):
    _make_torrent_row(app_module)

    class Bad(_BulkClient):
        def pause_all(self):
            raise app_module.torrent.Aria2Error('down')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', Bad)
    client.post('/torrent/pause-all')
    assert _status(app_module) == 'downloading'
    assert _flashes(client) == ['Nepodařilo se provést akci v aria2.']


def test_bulk_action_invalid(app_module):
    assert app_module._bulk_torrent_action('explode') == (
        'Neplatná akce.', 'error',
    )


# --- FR-15 / AC-23 validate_url ----------------------------------------

def test_validate_url_rejects_out_of_range_port(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url('http://example.com:99999/x') == (
            'Neplatný link.'
        )


def test_index_post_out_of_range_port_is_not_500(client):
    resp = client.post('/', data={'link': 'http://example.com:99999/x'})
    assert resp.status_code == 302


def test_validate_url_rejects_bracketed_ipv4(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url('http://[1.2.3.4]/x') == (
            'Neplatný link.'
        )


def test_index_post_bracketed_ipv4_is_not_500(client):
    resp = client.post('/', data={'link': 'http://[1.2.3.4]/x'})
    assert resp.status_code == 302


def test_index_post_unreachable_url_is_not_500(client, monkeypatch):
    import requests

    def boom(*a, **kw):
        raise requests.ConnectionError('unreachable')

    monkeypatch.setattr(requests, 'head', boom)
    resp = client.post('/', data={'link': 'http://[::1]/x'})
    assert resp.status_code == 302


def test_index_get_webshare_unreachable_is_not_500(client, monkeypatch):
    import requests

    def boom(*a, **kw):
        raise requests.ConnectionError('unreachable')

    monkeypatch.setattr(requests, 'post', boom)
    with client.application.app_context():
        db = client.application.view_functions['index'].__globals__['get_db']()
        db.execute("UPDATE settings SET token = 'abc'")
        db.commit()
    assert client.get('/').status_code == 200


def test_api_post_non_xml_200_is_connection_failed(app_module, monkeypatch):
    import requests

    class Resp:
        status_code = 200
        text = '<html>not closed'

    monkeypatch.setattr(requests, 'post', lambda *a, **kw: Resp())
    assert app_module.api_post('http://x', {}, {}) == (
        'Connection failed', '<dummy></dummy>',
    )
    assert app_module.check_token('abc') is None


def test_validate_url_rejects_bad_ipv4(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url('http://300.1.1.1/x') == (
            'Neplatný link.'
        )


# --- coverage gap tests ------------------------------------------------

def test_validate_url_accepts_valid_ipv4(app_module):
    with app_module.app.app_context():
        assert app_module.validate_url('http://10.0.0.1:8080/x') == 'ok'


def test_init_db_migrates_pre_torrent_schema(app_module):
    app_module.DB_PATH.unlink()
    conn = sqlite3.connect(app_module.DB_PATH)
    try:
        conn.execute(
            'CREATE TABLE links (id INTEGER PRIMARY KEY AUTOINCREMENT, '
            'url TEXT NOT NULL UNIQUE, status TEXT, pct_downloaded INTEGER)',
        )
        conn.execute(
            'CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK (id = 1), '
            'token TEXT, auto_download INTEGER, user_name TEXT, '
            'password_hash TEXT)',
        )
        conn.commit()
    finally:
        conn.close()

    app_module.init_db()

    conn = sqlite3.connect(app_module.DB_PATH)
    try:
        links = {r[1] for r in conn.execute('PRAGMA table_info(links)')}
        settings = {
            r[1] for r in conn.execute('PRAGMA table_info(settings)')
        }
    finally:
        conn.close()
    assert {
        'size_bytes', 'speed_bps', 'kind', 'external_id', 'connections',
        'upload_speed_bps', 'uploaded_bytes',
    } <= links
    assert {
        'dark_mode', 'torrent_enabled', 'torrent_seed_mode',
        'torrent_seed_value', 'torrent_max_dl_bps', 'torrent_max_ul_bps',
    } <= settings


def test_get_settings_defaults_when_row_missing(app_module):
    conn = sqlite3.connect(app_module.DB_PATH)
    try:
        conn.execute('DELETE FROM settings')
        conn.commit()
    finally:
        conn.close()
    with app_module.app.app_context():
        assert app_module.get_settings()['torrent_enabled'] == 0


def test_row_to_link_minimal_row(app_module):
    class Row(dict):
        pass

    link = app_module._row_to_link(
        Row(
            url='https://example.com/a.mp4', status='new', pct_downloaded=0,
            size_bytes=0, speed_bps=None,
        ),
    )
    assert link.url == 'https://example.com/a.mp4'


def test_row_to_link_null_values(app_module):
    row = {
        'url': MAGNET, 'status': 'new', 'pct_downloaded': 0,
        'size_bytes': 0, 'speed_bps': None, 'kind': None,
        'external_id': None, 'connections': None,
        'upload_speed_bps': None, 'uploaded_bytes': None,
    }
    link = app_module._row_to_link(row)
    assert link.kind == 'http'
    assert link.connections == 0
    assert link.uploaded_bytes == 0


def test_magnet_has_valid_btih_variants(app_module):
    check = app_module._magnet_has_valid_btih
    assert check('magnet:?dn=x&xt=urn:btih:' + 'a' * 40) is True
    assert check('magnet:?dn=only') is False
    assert check('magnet:?xt=urn:sha1:' + 'a' * 40) is False
    assert check('magnet:?xt=urn:btih:short') is False
    assert check('xt=urn:btih:' + 'A' * 32) is True


def test_add_link_if_new_empty_and_db_error(app_module, monkeypatch):
    assert app_module.add_link_if_new('  ') == (False, '', None)

    class Bad:
        def execute(self, *a, **kw):
            raise sqlite3.Error('locked')

    monkeypatch.setattr(app_module, 'get_db', lambda: Bad())
    assert app_module.add_link_if_new(MAGNET) == (False, MAGNET, None)


def test_index_get_clears_invalid_token(app_module, client, monkeypatch):
    cleared = []
    monkeypatch.setattr(app_module, 'check_token', lambda t: False)
    monkeypatch.setattr(
        app_module, 'save_token_value', lambda v: cleared.append(v),
    )
    assert client.get('/').status_code == 200
    assert cleared == ['']


def test_delete_link_without_url_or_unknown(client):
    assert client.post('/delete', data={'url': ''}).status_code == 302
    assert client.post('/delete', data={'url': 'nope'}).status_code == 302


def test_delete_staged_torrent_file_survives_os_error(app_module):
    staged = app_module.TORRENTS_DIR / 'link-7.torrent'
    staged.mkdir()
    (staged / 'child').write_bytes(b'x')
    app_module._delete_staged_torrent_file(7)
    assert staged.exists()


def test_parse_speed_limit_kib(app_module):
    parse = app_module._parse_speed_limit_kib
    assert parse('abc') == 0
    assert parse('-5') == 0
    assert parse(None) == 0
    assert parse('2') == 2048


def test_torrent_status_files_edge_cases(app_module, monkeypatch):
    assert app_module._torrent_status_files('') == []

    class Bad:
        def tell_status(self, gid, keys=None):
            raise app_module.torrent.Aria2Error('down')

    _use(app_module, monkeypatch, Bad())
    assert app_module._torrent_status_files('g') == []


class _FilesClient:
    def __init__(self, torrent_mod, files, change_exc=None):
        self.torrent = torrent_mod
        self.files = files
        self.change_exc = change_exc
        self.changed = []

    def tell_status(self, gid, keys=None):
        return {'files': self.files}

    def change_option(self, gid, options):
        if self.change_exc:
            raise self.torrent.Aria2Error(self.change_exc)
        self.changed.append(options)


def test_select_files_rejects_row_without_gid(app_module, client):
    _make_torrent_row(app_module, external_id='')
    client.post('/torrent/select-files', data={'url': MAGNET})
    assert _flashes(client) == [
        'Torrent nemá zatím k dispozici seznam souborů.',
    ]


def test_select_files_rejects_when_files_unavailable(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module)
    _use(app_module, monkeypatch, _FilesClient(app_module.torrent, []))
    client.post('/torrent/select-files', data={'url': MAGNET})
    assert _flashes(client) == ['Nelze načíst seznam souborů torrentu.']


def test_select_files_tolerates_bad_index_and_aria_error(
    app_module, client, monkeypatch,
):
    _make_torrent_row(app_module)
    stub = _FilesClient(
        app_module.torrent, [{'index': 'x'}, {'index': '2'}], 'nope',
    )
    _use(app_module, monkeypatch, stub)
    client.post(
        '/torrent/select-files',
        data={'url': MAGNET, 'file_index': ['1', '2']},
    )
    assert _flashes(client) == ['Nepodařilo se uložit výběr souborů.']


def test_index_get_keeps_valid_token(app_module, client, monkeypatch):
    monkeypatch.setattr(app_module, 'check_token', lambda t: True)
    assert client.get('/').status_code == 200
