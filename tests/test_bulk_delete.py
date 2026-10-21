import pytest

MAGNET_A = 'magnet:?xt=urn:btih:' + 'a' * 40
MAGNET_B = 'magnet:?xt=urn:btih:' + 'b' * 40
HTTP_A = 'https://example.com/a.mp4'
HTTP_B = 'https://example.com/b.mp4'


def _flashes(client):
    with client.session_transaction() as sess:
        return list(sess.get('_flashes', []))


def _urls(app_module):
    with app_module.app.app_context():
        rows = app_module.get_db().execute('SELECT url FROM links').fetchall()
    return {r['url'] for r in rows}


def _add(app_module, url, kind='http', external_id=None):
    with app_module.app.app_context():
        _, _, row_id = app_module.add_link_if_new(url, kind=kind)
        db = app_module.get_db()
        db.execute(
            'UPDATE links SET external_id = ? WHERE id = ?',
            (external_id, row_id),
        )
        db.commit()
    return row_id


@pytest.fixture()
def emits(app_module, monkeypatch):
    calls = []
    monkeypatch.setattr(
        app_module.socketio, 'emit', lambda *a, **kw: calls.append(a),
    )
    return calls


# --- footer / version ---

def test_footer_default_dev(client):
    resp = client.get('/')
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert 'href="https://github.com/spidermila/wsdownloader"' in body
    assert 'target="_blank"' in body
    assert 'rel="noopener noreferrer"' in body
    assert '>dev</a>' in body


def test_footer_version(app_module, client, monkeypatch):
    monkeypatch.setattr(app_module, 'APP_VERSION', '1.2.3')
    assert '>v1.2.3</a>' in client.get('/').get_data(as_text=True)


def test_empty_app_version_env_is_dev(temp_env, monkeypatch):
    import importlib

    import app as app_mod
    monkeypatch.setenv('APP_VERSION', '')
    importlib.reload(app_mod)
    assert app_mod.APP_VERSION == 'dev'


# --- files ---

def test_bulk_delete_files_and_dir(app_module, client, emits):
    root = app_module.DOWNLOADS_PATH
    (root / 'a.txt').write_text('x')
    (root / 'b.txt').write_text('x')
    (root / 'dir').mkdir()
    (root / 'dir' / 'c.txt').write_text('x')

    resp = client.post(
        '/delete-file', data={'filename': ['a.txt', 'b.txt', 'dir']},
    )
    assert resp.status_code == 302
    assert [p for p in root.iterdir() if p.name != '.cache'] == []
    assert _flashes(client) == [('success', 'Odstraněno: 3')]
    assert [e[0] for e in emits].count('file_deleted') == 3


def test_bulk_delete_files_missing_is_partial(app_module, client):
    root = app_module.DOWNLOADS_PATH
    (root / 'a.txt').write_text('x')
    resp = client.post(
        '/delete-file', data={'filename': ['nope.txt', 'a.txt']},
    )
    assert resp.status_code == 302
    assert not (root / 'a.txt').exists()
    cat, msg = _flashes(client)[0]
    assert cat == 'warning'
    assert 'Odstraněno: 1' in msg and 'nope.txt' in msg


def test_bulk_delete_files_path_traversal(app_module, client):
    root = app_module.DOWNLOADS_PATH
    sentinel = root.parent / 'outside.txt'
    sentinel.write_text('keep')
    (root / 'ok.txt').write_text('x')
    resp = client.post(
        '/delete-file',
        data={'filename': ['../outside.txt', '/etc/passwd', 'ok.txt']},
    )
    assert resp.status_code == 302
    assert sentinel.exists()
    assert not (root / 'ok.txt').exists()
    cat, msg = _flashes(client)[0]
    assert cat == 'warning' and '(2)' in msg


def test_bulk_delete_files_all_failed_is_error(client):
    client.post('/delete-file', data={'filename': ['x', 'y']})
    assert _flashes(client)[0][0] == 'error'


def test_delete_file_blank_values(client):
    resp = client.post('/delete-file', data={'filename': ['', '  ']})
    assert resp.status_code == 302
    assert _flashes(client) == [('error', 'Zadán název souboru.')]


def test_bulk_delete_files_duplicates_counted_once(app_module, client):
    (app_module.DOWNLOADS_PATH / 'a.txt').write_text('x')
    client.post('/delete-file', data={'filename': ['a.txt', 'a.txt']})
    assert _flashes(client) == [('success', 'Odstraněn soubor: a.txt')]
    assert not (app_module.DOWNLOADS_PATH / 'a.txt').exists()


def test_delete_file_names_not_stripped(app_module, client):
    (app_module.DOWNLOADS_PATH / 'a.mkv').write_text('x')
    client.post('/delete-file', data={'filename': 'a.mkv '})
    assert (app_module.DOWNLOADS_PATH / 'a.mkv').exists()
    assert _flashes(client) == [('error', 'Soubor nenalezen: a.mkv ')]


def test_rename_old_name_not_stripped(app_module, client, emits):
    root = app_module.DOWNLOADS_PATH
    (root / 'a.mkv').write_text('x')
    r = client.post(
        '/rename-file', data={'old_name': 'a.mkv ', 'new_name': 'b.mkv'},
    )
    assert r.status_code == 404
    assert (root / 'a.mkv').exists()
    (root / 'a.mkv ').write_text('y')
    r = client.post(
        '/rename-file', data={'old_name': 'a.mkv ', 'new_name': 'b.mkv'},
    )
    assert r.json['success']
    assert (root / 'a.mkv').exists() and (root / 'b.mkv').exists()
    r = client.post(
        '/rename-file', data={'old_name': '  ', 'new_name': 'c.mkv'},
    )
    assert r.status_code == 400


def test_delete_file_awkward_name(app_module, client):
    name = 'he said "hi" & <script>ž.txt'
    other = 'kůň.txt'
    (app_module.DOWNLOADS_PATH / name).write_text('x')
    (app_module.DOWNLOADS_PATH / other).write_text('x')
    client.post('/delete-file', data={'filename': [name, other]})
    assert not [
        p for p in app_module.DOWNLOADS_PATH.iterdir() if p.name != '.cache'
    ]


def test_bulk_delete_files_error_isolated(app_module, client, monkeypatch):
    root = app_module.DOWNLOADS_PATH
    (root / 'd').mkdir()
    (root / 'a.txt').write_text('x')

    def boom(*a, **kw):
        raise OSError('nope')

    monkeypatch.setattr(app_module.shutil, 'rmtree', boom)
    client.post('/delete-file', data={'filename': ['d', 'a.txt']})
    assert not (root / 'a.txt').exists()
    assert (root / 'd').exists()
    assert _flashes(client)[0][0] == 'warning'


def test_bulk_flash_caps_names(client):
    long = 'n' * 100
    names = [f'{i}{long}' for i in range(8)]
    client.post('/delete-file', data={'filename': names})
    msg = _flashes(client)[0][1]
    assert 'a další 3' in msg
    assert long not in msg
    assert '…' in msg


@pytest.mark.parametrize(
    ('setup', 'expected'), [
        ('file', 'Odstraněn soubor: s.txt'),
        ('dir', 'Odstraněna složka: s.txt'),
        ('missing', 'Soubor nenalezen: s.txt'),
    ],
)
def test_single_file_messages(app_module, client, setup, expected):
    p = app_module.DOWNLOADS_PATH / 's.txt'
    if setup == 'file':
        p.write_text('x')
    elif setup == 'dir':
        p.mkdir()
    client.post('/delete-file', data={'filename': 's.txt'})
    assert _flashes(client)[0][1] == expected


def test_single_file_invalid_and_error(app_module, client, monkeypatch):
    client.post('/delete-file', data={'filename': '../x'})
    assert _flashes(client) == [('error', 'Neplatná cesta k souboru.')]

    (app_module.DOWNLOADS_PATH / 'e.txt').write_text('x')

    def boom(self, *a, **kw):
        raise OSError('nope')

    monkeypatch.setattr(app_module.Path, 'unlink', boom)
    client.post('/delete-file', data={'filename': 'e.txt'})
    assert (
        'error', 'Chyba při odstraňování souboru: e.txt',
    ) in _flashes(client)


# --- links ---

class _Aria:
    calls: list[tuple[str, str]] = []

    def __init__(self, *a, **kw):
        pass

    def remove(self, gid):
        self.calls.append(('remove', gid))

    def remove_download_result(self, gid):
        self.calls.append(('purge', gid))


def test_bulk_delete_links_http_and_magnet(app_module, client, monkeypatch):
    _Aria.calls = []
    monkeypatch.setattr(app_module.torrent, 'Aria2Client', _Aria)
    _add(app_module, HTTP_A)
    _add(app_module, HTTP_B)
    rid = _add(app_module, MAGNET_A, 'magnet', 'gid1')
    staged = app_module.TORRENTS_DIR / f'link-{rid}.torrent'
    staged.write_bytes(b'x')

    resp = client.post('/delete', data={'url': [HTTP_A, MAGNET_A]})
    assert resp.status_code == 302
    assert _urls(app_module) == {HTTP_B}
    assert ('remove', 'gid1') in _Aria.calls
    assert not staged.exists()
    assert _flashes(client) == [('success', 'Odstraněno: 2')]


def test_bulk_delete_links_aria2_failure(app_module, client, monkeypatch):
    class Failing(_Aria):
        def remove(self, gid):
            raise app_module.torrent.Aria2Error('boom')

        def force_remove(self, gid):
            raise app_module.torrent.Aria2Error('boom')

    monkeypatch.setattr(app_module.torrent, 'Aria2Client', Failing)
    _add(app_module, HTTP_A)
    _add(app_module, MAGNET_A, 'magnet', 'gid1')
    client.post('/delete', data={'url': [HTTP_A, MAGNET_A]})
    assert _urls(app_module) == {MAGNET_A}
    cat, msg = _flashes(client)[0]
    assert cat == 'warning' and MAGNET_A[:60] in msg
    assert HTTP_A not in msg


def test_bulk_delete_links_unknown_url(app_module, client):
    _add(app_module, HTTP_A)
    client.post('/delete', data={'url': ['https://nope/', HTTP_A]})
    assert _urls(app_module) == set()
    assert 'https://nope/' in _flashes(client)[0][1]


def test_bulk_delete_links_exception_isolated(
    app_module, client, monkeypatch,
):
    def boom(external_id):
        raise RuntimeError('boom')

    monkeypatch.setattr(app_module, '_remove_from_aria2', boom)
    _add(app_module, HTTP_A)
    _add(app_module, MAGNET_A, 'magnet', 'gid1')
    client.post('/delete', data={'url': [MAGNET_A, HTTP_A]})
    assert _urls(app_module) == {MAGNET_A}
    assert _flashes(client)[0][0] == 'warning'


def test_single_link_messages(app_module, client, monkeypatch):
    _add(app_module, HTTP_A)
    client.post('/delete', data={'url': HTTP_A})
    client.post('/delete', data={'url': HTTP_A})
    assert _flashes(client) == [
        ('success', f'Odstraněno: {HTTP_A}'),
        ('error', f'Nenalezeno: {HTTP_A}'),
    ]

    def boom(external_id):
        raise RuntimeError('boom')

    monkeypatch.setattr(app_module, '_remove_from_aria2', boom)
    _add(app_module, MAGNET_B, 'magnet', 'g')
    client.post('/delete', data={'url': MAGNET_B})
    assert (
        'error', f'Chyba při odstraňování: {MAGNET_B}',
    ) in _flashes(client)


def test_bulk_delete_unparseable_url_is_not_500(client):
    resp = client.post(
        '/delete', data={'url': ['http://[x/a', 'https://nope/']},
    )
    assert resp.status_code == 302
    assert 'http://[x/a' in _flashes(client)[-1][1]
