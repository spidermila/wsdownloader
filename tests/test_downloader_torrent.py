"""Tests for the torrent worker in downloader.py (issue #39)."""
import sqlite3
import threading

import pytest
import requests


MAGNET = (
    'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567'
    '&dn=example'
)
TORRENT_URL = 'https://example.com/x.torrent'


def _seed_torrent_row(
    downloader_module, url, kind, external_id=None,
    status='new',
):
    downloader_module.add_link_if_new(url)
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        conn.execute(
            'UPDATE links SET kind = ?, external_id = ?, status = ? '
            'WHERE url = ?',
            (kind, external_id, status, url),
        )
        conn.commit()
    finally:
        conn.close()


def test_fetch_oldest_skips_torrents(downloader_module):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    downloader_module.add_link_if_new('https://example.com/a.mp4')

    row = downloader_module.fetch_oldest()
    assert row is not None
    assert row['url'] == 'https://example.com/a.mp4'


def test_fetch_oldest_returns_space_waiting_rows(downloader_module):
    """space_waiting rows must remain visible so main_loop() can retry
    them once free space recovers."""
    url = 'https://example.com/a.mp4'
    downloader_module.add_link_if_new(url)
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        conn.execute(
            'UPDATE links SET status = ? WHERE url = ?',
            ('space_waiting', url),
        )
        conn.commit()
    finally:
        conn.close()

    row = downloader_module.fetch_oldest()
    assert row is not None
    assert row['url'] == url
    assert row['status'] == 'space_waiting'


def test_fetch_active_torrents_only_returns_torrent_kinds(downloader_module):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    _seed_torrent_row(downloader_module, TORRENT_URL, 'torrent')
    downloader_module.add_link_if_new('https://example.com/a.mp4')

    rows = downloader_module.fetch_active_torrents()
    urls = {r['url'] for r in rows}
    assert urls == {MAGNET, TORRENT_URL}


def test_fetch_active_torrents_skips_failed(downloader_module):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet', status='failed',
    )
    assert downloader_module.fetch_active_torrents() == []


def test_set_external_id_by_id(downloader_module):
    added, _, row_id = downloader_module.add_link_if_new(MAGNET)
    assert added
    assert downloader_module.set_external_id_by_id(row_id, 'gid99') is True
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT external_id FROM links WHERE id = ?', (row_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'gid99'


def test_set_connections_by_id(downloader_module):
    added, _, row_id = downloader_module.add_link_if_new(MAGNET)
    assert added
    assert downloader_module.set_connections_by_id(row_id, 7) is True
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT connections FROM links WHERE id = ?', (row_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 7


def test_set_connections_by_id_handles_db_error(
    downloader_module, monkeypatch,
):
    class BadConn:
        def execute(self, *a, **kw):
            raise sqlite3.Error('locked')

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(downloader_module, 'get_db', lambda: BadConn())
    assert downloader_module.set_connections_by_id(1, 3) is False


def test_set_upload_stats_by_id(downloader_module):
    added, _, row_id = downloader_module.add_link_if_new(MAGNET)
    assert added
    assert downloader_module.set_upload_stats_by_id(row_id, 1024, 999) is True
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT upload_speed_bps, uploaded_bytes FROM links '
            'WHERE id = ?', (row_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 1024
    assert row[1] == 999


def test_set_upload_stats_by_id_handles_db_error(
    downloader_module, monkeypatch,
):
    class BadConn:
        def execute(self, *a, **kw):
            raise sqlite3.Error('locked')

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(downloader_module, 'get_db', lambda: BadConn())
    assert downloader_module.set_upload_stats_by_id(1, 1, 1) is False


def test_apply_status_preserves_user_paused(downloader_module, monkeypatch):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidP', status='paused',
    )
    _enable_torrents_in_db(downloader_module)

    class Client:
        def tell_status(self, gid):
            return {
                'status': 'active', 'totalLength': '100',
                'completedLength': '10', 'downloadSpeed': '1024',
                'connections': '2', 'uploadSpeed': '0', 'uploadLength': '0',
            }

        def is_available(self):
            return True

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Client(),
    )
    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'paused'


def test_torrent_loop_skips_enqueue_when_user_paused(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id=None, status='paused',
    )
    _enable_torrents_in_db(downloader_module)

    called = []

    class Client:
        def is_available(self):
            return True

        def add_uri(self, *a, **kw):
            called.append('add_uri')
            return 'gid'

        def tell_status(self, *a, **kw):
            called.append('tell_status')
            return {}

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Client(),
    )
    downloader_module.torrent_loop()
    assert called == []


def test_seeding_enabled_helper(downloader_module):
    assert downloader_module._seeding_enabled(
        {'torrent_seed_mode': 'off', 'torrent_seed_value': 0},
    ) is False
    assert downloader_module._seeding_enabled(
        {'torrent_seed_mode': 'ratio', 'torrent_seed_value': 1.0},
    ) is True
    assert downloader_module._seeding_enabled(
        {'torrent_seed_mode': 'time', 'torrent_seed_value': 30},
    ) is True
    assert downloader_module._seeding_enabled(
        {'torrent_seed_mode': 'ratio', 'torrent_seed_value': 0},
    ) is False


def test_fetch_torrent_bytes_returns_content(downloader_module, monkeypatch):
    class _R:
        content = b'torrent-payload'

        def raise_for_status(self):
            pass

    monkeypatch.setattr(
        downloader_module.requests, 'get',
        lambda *a, **kw: _R(),
    )
    assert downloader_module._fetch_torrent_bytes(TORRENT_URL) == (
        b'torrent-payload'
    )


def test_fetch_torrent_bytes_returns_none_on_error(
    downloader_module, monkeypatch,
):
    def boom(*a, **kw):
        raise requests.RequestException('unreachable')

    monkeypatch.setattr(downloader_module.requests, 'get', boom)
    assert downloader_module._fetch_torrent_bytes(TORRENT_URL) is None


class FakeClient:
    def __init__(self):
        self.calls = []
        self.status_response = {}
        self.raise_on_status = False

    def add_uri(self, uri, opts):
        self.calls.append(('add_uri', uri, opts))
        return 'gid-uri'

    def add_torrent(self, data, opts):
        self.calls.append(('add_torrent', data, opts))
        return 'gid-torrent'

    def tell_status(self, gid):
        self.calls.append(('tell_status', gid))
        if self.raise_on_status:
            from torrent import Aria2Error
            raise Aria2Error('boom')
        return self.status_response

    def remove_download_result(self, gid):
        self.calls.append(('remove_download_result', gid))

    def is_available(self):
        return True


def test_enqueue_torrent_magnet(downloader_module):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    row = downloader_module.fetch_active_torrents()[0]
    client = FakeClient()

    gid = downloader_module._enqueue_torrent(row, client, {'dir': '/tmp'})
    assert gid == 'gid-uri'
    assert client.calls[0][0] == 'add_uri'


def test_enqueue_torrent_file(downloader_module, monkeypatch):
    _seed_torrent_row(downloader_module, TORRENT_URL, 'torrent')
    monkeypatch.setattr(
        downloader_module, '_fetch_torrent_bytes',
        lambda url: b'torrent-bytes',
    )
    row = downloader_module.fetch_active_torrents()[0]
    client = FakeClient()

    gid = downloader_module._enqueue_torrent(row, client, {})
    assert gid == 'gid-torrent'
    assert client.calls[0][0] == 'add_torrent'
    # Staged file lives under TORRENTS_DIR, not DOWNLOADS_PATH.
    staged = downloader_module._torrent_file_path(row['id'])
    assert staged.exists()
    assert staged.parent == downloader_module.TORRENTS_DIR
    assert staged.read_bytes() == b'torrent-bytes'
    assert not any(downloader_module.DOWNLOADS_PATH.glob('*.torrent'))


def test_enqueue_torrent_file_uses_cached_bytes(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(downloader_module, TORRENT_URL, 'torrent')
    row = downloader_module.fetch_active_torrents()[0]
    downloader_module._torrent_file_path(row['id']).write_bytes(b'cached')

    def _boom(url):
        raise AssertionError('should not refetch when cached')

    monkeypatch.setattr(downloader_module, '_fetch_torrent_bytes', _boom)
    client = FakeClient()
    gid = downloader_module._enqueue_torrent(row, client, {})
    assert gid == 'gid-torrent'
    assert client.calls[0] == ('add_torrent', b'cached', {})


def test_enqueue_torrent_file_download_failure(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(downloader_module, TORRENT_URL, 'torrent')
    monkeypatch.setattr(
        downloader_module, '_fetch_torrent_bytes', lambda url: None,
    )
    row = downloader_module.fetch_active_torrents()[0]
    assert downloader_module._enqueue_torrent(row, FakeClient(), {}) is None


def test_torrent_loop_skips_when_disabled(downloader_module, monkeypatch):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    called = []
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client',
        lambda *a, **kw: called.append('init') or FakeClient(),
    )
    downloader_module.torrent_loop()
    assert called == []


def test_torrent_loop_skips_when_aria2_unavailable(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    _enable_torrents_in_db(downloader_module)

    class Down:
        def is_available(self):
            return False

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Down(),
    )
    downloader_module.torrent_loop()  # must not raise


def _enable_torrents_in_db(downloader_module):
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        conn.execute('UPDATE settings SET torrent_enabled = 1 WHERE id = 1')
        conn.commit()
    finally:
        conn.close()


def test_torrent_loop_enqueues_new_magnet(downloader_module, monkeypatch):
    _seed_torrent_row(downloader_module, MAGNET, 'magnet')
    _enable_torrents_in_db(downloader_module)

    client = FakeClient()
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT external_id, status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'gid-uri'
    assert row[1] == 'downloading'


def test_torrent_loop_marks_failed_when_enqueue_fails(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(downloader_module, TORRENT_URL, 'torrent')
    _enable_torrents_in_db(downloader_module)

    monkeypatch.setattr(
        downloader_module, '_fetch_torrent_bytes', lambda url: None,
    )
    client = FakeClient()
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT id, status FROM links WHERE url = ?', (TORRENT_URL,),
        ).fetchone()
    finally:
        conn.close()
    assert row[1] == 'failed'
    assert not downloader_module._torrent_file_path(row[0]).exists()


def test_torrent_loop_retries_space_waiting_row_after_recovery(
    downloader_module, monkeypatch,
):
    """Once free space recovers, a row previously parked as space_waiting
    must be reconsidered and enqueued."""
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet', status='space_waiting',
    )
    _enable_torrents_in_db(downloader_module)

    monkeypatch.setattr(
        downloader_module, 'get_fs_usage', lambda: {'percent_free': 50.0},
    )
    client = FakeClient()
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    downloader_module.torrent_loop()

    assert any(c[0] == 'add_uri' for c in client.calls)
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT status, external_id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'downloading'
    assert row[1] == 'gid-uri'


def test_torrent_loop_polls_active_gid(downloader_module, monkeypatch):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidX', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    client = FakeClient()
    client.status_response = {
        'status': 'active',
        'totalLength': '1000',
        'completedLength': '500',
        'downloadSpeed': '2048',
        'connections': '4',
    }
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT status, pct_downloaded, size_bytes, speed_bps, '
            'connections FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'downloading'
    assert row[1] == 50
    assert row[2] == 1000
    assert row[3] == 2048
    assert row[4] == 4


def test_torrent_loop_removes_completed_row(downloader_module, monkeypatch):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidX', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    client = FakeClient()
    client.status_response = {
        'status': 'complete', 'totalLength': '10', 'completedLength': '10',
        'downloadSpeed': '0',
    }
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    # Stage a fake .torrent file to prove it gets cleaned up.
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row_id = conn.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()[0]
    finally:
        conn.close()
    staged = downloader_module._torrent_file_path(row_id)
    staged.write_bytes(b'stub')

    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row is None
    assert ('remove_download_result', 'gidX') in client.calls
    assert not staged.exists()


def test_torrent_loop_keeps_row_while_seeding(downloader_module, monkeypatch):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidX', status='downloading',
    )
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        conn.execute(
            'UPDATE settings SET torrent_enabled=1, '
            "torrent_seed_mode='ratio', torrent_seed_value=1.0",
        )
        conn.commit()
    finally:
        conn.close()

    client = FakeClient()
    client.status_response = {
        'status': 'complete', 'totalLength': '10', 'completedLength': '10',
        'downloadSpeed': '0', 'seeder': 'true',
    }
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    downloader_module.torrent_loop()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'seeding'
    assert ('remove_download_result', 'gidX') not in client.calls


def test_torrent_loop_logs_error_on_aria_error_state(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidX', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    client = FakeClient()
    client.status_response = {
        'status': 'error', 'totalLength': '0', 'completedLength': '0',
        'downloadSpeed': '0', 'errorMessage': 'tracker unreachable',
    }
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row_id = conn.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()[0]
    finally:
        conn.close()
    staged = downloader_module._torrent_file_path(row_id)
    staged.write_bytes(b'stub')

    downloader_module.torrent_loop()
    assert not staged.exists()

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT status FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
        err = conn.execute(
            'SELECT error_message FROM download_errors WHERE file_id = ?',
            ('gidX',),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 'failed'
    assert err is not None
    assert 'tracker' in err[0]


def test_torrent_loop_tolerates_tell_status_failure(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidX', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    client = FakeClient()
    client.raise_on_status = True
    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: client,
    )
    downloader_module.torrent_loop()  # must not raise


def test_torrent_worker_stops_on_event(downloader_module, monkeypatch):
    monkeypatch.setattr(downloader_module, 'torrent_loop', lambda: None)
    stop = threading.Event()
    t = threading.Thread(
        target=downloader_module.torrent_worker,
        args=(stop, 0),
        daemon=True,
    )
    t.start()
    stop.set()
    t.join(timeout=2)
    assert not t.is_alive()


def test_torrent_worker_swallows_exceptions(downloader_module, monkeypatch):
    boom_calls = {'n': 0}

    def boom():
        boom_calls['n'] += 1
        if boom_calls['n'] >= 2:
            raise RuntimeError('planned')
        raise RuntimeError('one more time')

    monkeypatch.setattr(downloader_module, 'torrent_loop', boom)
    stop = threading.Event()
    t = threading.Thread(
        target=downloader_module.torrent_worker,
        args=(stop, 0),
        daemon=True,
    )
    t.start()
    import time as _t
    _t.sleep(0.05)
    stop.set()
    t.join(timeout=2)
    assert boom_calls['n'] >= 2


def test_set_external_id_by_id_handles_db_error(
    downloader_module, monkeypatch,
):
    class BadConn:
        def execute(self, *a, **kw):
            raise sqlite3.Error('locked')

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(downloader_module, 'get_db', lambda: BadConn())
    assert downloader_module.set_external_id_by_id(1, 'g') is False


def test_apply_status_error_state_ignores_remove_failure(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidY', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    class Client:
        def tell_status(self, gid):
            return {
                'status': 'error', 'totalLength': '0',
                'completedLength': '0', 'downloadSpeed': '0',
                'errorMessage': 'nope',
            }

        def remove_download_result(self, gid):
            raise downloader_module.torrent.Aria2Error('removal failed')

        def is_available(self):
            return True

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Client(),
    )
    downloader_module.torrent_loop()  # must not raise


def test_apply_status_complete_ignores_remove_failure(
    downloader_module, monkeypatch,
):
    _seed_torrent_row(
        downloader_module, MAGNET, 'magnet',
        external_id='gidZ', status='downloading',
    )
    _enable_torrents_in_db(downloader_module)

    class Client:
        def tell_status(self, gid):
            return {
                'status': 'complete', 'totalLength': '10',
                'completedLength': '10', 'downloadSpeed': '0',
            }

        def remove_download_result(self, gid):
            raise downloader_module.torrent.Aria2Error('nope')

        def is_available(self):
            return True

    monkeypatch.setattr(
        downloader_module.torrent, 'Aria2Client', lambda *a, **kw: Client(),
    )
    downloader_module.torrent_loop()  # must complete the row anyway

    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT id FROM links WHERE url = ?', (MAGNET,),
        ).fetchone()
    finally:
        conn.close()
    assert row is None


def test_new_fetches_close_their_connections(downloader_module, monkeypatch):
    """Regression: fetch_oldest, fetch_active_torrents, get_settings,
    add_link_if_new must not leak sqlite3 connections."""
    opened = []
    real_get_db = downloader_module.get_db

    def tracking_get_db():
        conn = real_get_db()
        opened.append(conn)
        return conn

    monkeypatch.setattr(downloader_module, 'get_db', tracking_get_db)

    downloader_module.fetch_oldest()
    downloader_module.fetch_active_torrents()
    downloader_module.get_settings()
    downloader_module.add_link_if_new('https://example.com/x.mp4')

    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute('SELECT 1')


def test_try_remove_result_noop_on_empty_gid(downloader_module):
    class Client:
        def remove_download_result(self, gid):
            raise AssertionError('should not be called')
    downloader_module._try_remove_result(Client(), '')


def test_main_starts_worker_and_stops_on_exception(
    downloader_module, monkeypatch,
):
    call_count = {'n': 0}

    def one_shot():
        call_count['n'] += 1
        raise SystemExit(0)

    monkeypatch.setattr(downloader_module, 'main_loop', one_shot)
    monkeypatch.setattr(downloader_module, 'torrent_loop', lambda: None)

    with pytest.raises(SystemExit):
        downloader_module.main()
    assert call_count['n'] == 1
