"""Tests for the torrent code paths in app.py (issue #39)."""


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
    _make_torrent_row(app_module, external_id=None)
    resp = client.post('/torrent/pause', data={'url': MAGNET})
    assert resp.status_code == 302


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
    _make_torrent_row(app_module, url=other, external_id='g2')

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
    assert all(r['status'] == 'paused' for r in rows)


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
