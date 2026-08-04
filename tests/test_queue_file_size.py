"""
Tests for the "show queue file sizes" feature (issue #43).

Covers the universal (non-Webshare-specific) size probing done in app.py:
test_url() reads Content-Length from a plain HTTP HEAD response, and the
size is persisted immediately when a link is added, plus surfaced as a
total queue size.
"""


class _FakeHeadResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def test_test_url_returns_size_from_content_length(app_module, monkeypatch):
    def fake_head(url, allow_redirects=True):
        return _FakeHeadResponse(
            status_code=200, headers={'Content-Length': '12345'},
        )

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    ok, size = app_module.test_url('https://example.com/file.bin')

    assert ok is True
    assert size == 12345


def test_test_url_without_content_length_returns_none_size(
    app_module, monkeypatch,
):
    def fake_head(url, allow_redirects=True):
        return _FakeHeadResponse(status_code=200, headers={})

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    ok, size = app_module.test_url('https://example.com/file.bin')

    assert ok is True
    assert size is None


def test_test_url_unreachable_link_returns_false_and_none(
    app_module, monkeypatch,
):
    def fake_head(url, allow_redirects=True):
        return _FakeHeadResponse(status_code=404, headers={})

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    ok, size = app_module.test_url('https://example.com/missing.bin')

    assert ok is False
    assert size is None


def test_test_url_works_for_arbitrary_non_webshare_link(
    app_module, monkeypatch,
):
    """The size probing is generic HTTP - it isn't Webshare-specific."""
    seen_urls = []

    def fake_head(url, allow_redirects=True):
        seen_urls.append(url)
        return _FakeHeadResponse(
            status_code=200, headers={'Content-Length': '999'},
        )

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    ok, size = app_module.test_url('https://some-random-cdn.example/x.iso')

    assert ok is True
    assert size == 999
    assert seen_urls == ['https://some-random-cdn.example/x.iso']


def test_set_file_size_by_id_updates_row(app_module):
    with app_module.app.app_context():
        _added, _url, row_id = app_module.add_link_if_new(
            'https://example.com/a.mp4',
        )
        updated = app_module.set_file_size_by_id(row_id, 5555)
        links = app_module.read_links_from_db()

    assert updated is True
    assert links[0].size_bytes == 5555


def test_get_total_queue_size_sums_all_links(app_module):
    with app_module.app.app_context():
        _added1, _url1, id1 = app_module.add_link_if_new(
            'https://example.com/a.mp4',
        )
        _added2, _url2, id2 = app_module.add_link_if_new(
            'https://example.com/b.mp4',
        )
        app_module.set_file_size_by_id(id1, 1000)
        app_module.set_file_size_by_id(id2, 2500)

        total = app_module.get_total_queue_size()

    assert total == 3500


def test_get_total_queue_size_is_zero_when_empty(app_module):
    with app_module.app.app_context():
        total = app_module.get_total_queue_size()

    assert total == 0


def test_build_full_update_payload_includes_total_size(app_module):
    link_a = app_module.Link('https://example.com/a.mp4')
    link_a.size_bytes = 1000
    link_b = app_module.Link('https://example.com/b.mp4')
    link_b.size_bytes = 500

    payload = app_module.build_full_update_payload(
        [link_a, link_b], files=[], fs={}, errors=[],
    )

    assert payload['total_queue_size'] == 1500
    assert payload['total_queue_size_human'] == app_module._human_size(1500)
    assert len(payload['links']) == 2


def test_index_post_stores_size_for_new_link(client, app_module, monkeypatch):
    """Adding a link via the web form should immediately store its size."""

    def fake_head(url, allow_redirects=True):
        return _FakeHeadResponse(
            status_code=200, headers={'Content-Length': '42000'},
        )

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    response = client.post(
        '/', data={'link': 'https://example.com/new-file.mp4'},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app_module.app.app_context():
        links = app_module.read_links_from_db()
    assert len(links) == 1
    assert links[0].size_bytes == 42000


def test_index_page_shows_total_queue_size(client, app_module, monkeypatch):
    def fake_head(url, allow_redirects=True):
        return _FakeHeadResponse(
            status_code=200, headers={'Content-Length': '2048'},
        )

    monkeypatch.setattr(app_module.requests, 'head', fake_head)

    client.post(
        '/', data={'link': 'https://example.com/new-file.mp4'},
        follow_redirects=True,
    )

    response = client.get('/')

    assert response.status_code == 200
    assert b'2.0 KB' in response.data
