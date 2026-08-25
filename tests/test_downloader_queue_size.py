"""
Tests for the queue file size feature (issue #43) on the downloader side:
Webshare queue metadata ('size' field) is captured for a newly added link
without needing an extra HTTP request.
"""


def test_add_link_if_new_returns_row_id(downloader_module):
    added, url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )
    assert added is True
    assert url == 'https://example.com/a.mp4'
    assert row_id is not None


def test_add_link_if_new_ignores_duplicate_and_returns_no_id(
    downloader_module,
):
    downloader_module.add_link_if_new('https://example.com/a.mp4')
    added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )
    assert added is False
    assert row_id is None


def test_store_queue_file_size_sets_size_from_webshare_metadata(
    downloader_module,
):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {'ident': 'abc123', 'name': 'a.mp4', 'size': '987654'},
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 987654


def test_store_queue_file_size_ignores_missing_size(downloader_module):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {'ident': 'abc123', 'name': 'a.mp4'},
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 0


def test_store_queue_file_size_rejects_negative_size(downloader_module):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {'ident': 'abc123', 'name': 'a.mp4', 'size': '-1'},
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 0


def test_store_queue_file_size_rejects_size_above_int64_max(
    downloader_module,
):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {
            'ident': 'abc123', 'name': 'a.mp4', 'size': str(2 ** 63),
        },
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 0


def test_store_queue_file_size_accepts_int64_max_size(downloader_module):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {
            'ident': 'abc123', 'name': 'a.mp4', 'size': str(2 ** 63 - 1),
        },
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 2 ** 63 - 1


def test_store_queue_file_size_ignores_unparseable_size(downloader_module):
    _added, _url, row_id = downloader_module.add_link_if_new(
        'https://example.com/a.mp4',
    )

    downloader_module._store_queue_file_size(
        row_id, {'ident': 'abc123', 'name': 'a.mp4', 'size': 'not-a-number'},
    )

    row = downloader_module.fetch_oldest()
    assert row['size_bytes'] == 0


def test_main_loop_stores_size_for_webshare_queue_files(
    downloader_module, monkeypatch,
):
    """
    Simulates syncing the Webshare queue: main_loop() should persist the
    file size reported by the queue API immediately, without waiting for
    the download to start.
    """
    settings = {
        'id': 1, 'token': 'tok', 'auto_download': 1,
        'user_name': '', 'password_hash': '',
    }
    monkeypatch.setattr(
        downloader_module, 'get_settings', lambda: settings,
    )
    monkeypatch.setattr(
        downloader_module, 'check_token', lambda token: True,
    )
    monkeypatch.setattr(
        downloader_module, 'get_queue', lambda token: (
            'OK', [{
                'ident': 'abc123',
                'name': 'movie.mp4',
                'size': '104857600',
            }],
        ),
    )
    monkeypatch.setattr(
        downloader_module, 'get_download_link', lambda token, file_id: (
            'OK', 'https://webshare.example/download/abc123/movie.mp4',
        ),
    )
    dequeued = []
    monkeypatch.setattr(
        downloader_module, 'dequeue_file',
        lambda token, file_id: dequeued.append(file_id) or 'OK',
    )

    class _FakeHeadResponse:
        status_code = 404  # avoid triggering an actual download attempt
        headers: dict = {}

    monkeypatch.setattr(
        downloader_module.requests, 'head',
        lambda *args, **kwargs: _FakeHeadResponse(),
    )
    # The 404 branch above calls sleep(10) - skip the real wait in tests.
    monkeypatch.setattr(downloader_module, 'sleep', lambda seconds: None)

    downloader_module.main_loop()

    import sqlite3
    conn = sqlite3.connect(downloader_module.DB_PATH)
    try:
        row = conn.execute(
            'SELECT size_bytes FROM links '
            'WHERE url = ?',
            ('https://webshare.example/download/abc123/movie.mp4',),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == 104857600
    assert dequeued == ['abc123']
