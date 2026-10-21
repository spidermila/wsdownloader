"""Regression gate: a Webshare/URL outage must never 500 or log out."""
import pytest
import requests

TOKEN = 'abc'


class FakeResponse:
    def __init__(self, status_code=200, text=''):
        self.status_code = status_code
        self.text = text
        self.headers = {}


def _raiser(exc):
    def boom(*a, **kw):
        raise exc
    return boom


FAILURES = {
    'connection-error': _raiser(requests.ConnectionError('down')),
    'timeout': _raiser(requests.Timeout('slow')),
    'html-200': lambda *a, **kw: FakeResponse(200, '<html><body>x</body>'),
    'wellformed-html-200': lambda *a, **kw: FakeResponse(
        200, '<html><body>x</body></html>',
    ),
    'empty-200': lambda *a, **kw: FakeResponse(200, ''),
    'http-503': lambda *a, **kw: FakeResponse(503, 'unavailable'),
}

ROUTES = {
    'index': ('get', '/', {}),
    'login': ('post', '/login', {'user_name': 'u', 'password': 'p'}),
    'add-webshare': (
        'post', '/', {'link': 'https://webshare.cz/file/abc123/video.mp4'},
    ),
    'add-http': ('post', '/', {'link': 'http://example.com/a.mp4'}),
    'add-ipv6': ('post', '/', {'link': 'http://[::1]/x'}),
}


def _set_token(app_module, token):
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute('UPDATE settings SET token = ?', (token,))
        db.commit()


def _get_token(app_module):
    with app_module.app.app_context():
        return app_module.get_settings()['token']


@pytest.mark.parametrize('token', ['', TOKEN], ids=['no-token', 'token'])
@pytest.mark.parametrize('route', ROUTES)
@pytest.mark.parametrize('failure', FAILURES)
def test_outage_is_not_500_and_keeps_token(
    app_module, client, monkeypatch, failure, route, token,
):
    _set_token(app_module, token)
    handler = FAILURES[failure]
    for name in ('post', 'head', 'get'):
        monkeypatch.setattr(requests, name, handler)
    method, path, data = ROUTES[route]
    resp = getattr(client, method)(path, data=data)
    assert resp.status_code < 500
    assert _get_token(app_module) == token


def test_rejected_token_is_cleared(app_module, client, monkeypatch):
    _set_token(app_module, TOKEN)
    monkeypatch.setattr(
        requests, 'post',
        lambda *a, **kw: FakeResponse(
            200, '<response><status>FATAL</status></response>',
        ),
    )
    assert client.get('/').status_code == 200
    assert _get_token(app_module) == ''


def test_valid_token_is_kept(app_module, client, monkeypatch):
    _set_token(app_module, TOKEN)
    monkeypatch.setattr(
        requests, 'post',
        lambda *a, **kw: FakeResponse(
            200, '<response><status>OK</status></response>',
        ),
    )
    assert app_module.check_token(TOKEN) is True
    assert client.get('/').status_code == 200
    assert _get_token(app_module) == TOKEN


@pytest.mark.parametrize('module', ['app_module', 'downloader_module'])
def test_api_post_sets_timeout(request, monkeypatch, module):
    mod = request.getfixturevalue(module)
    seen = {}

    def fake_post(*a, **kw):
        seen.update(kw)
        return FakeResponse(200, '<response><status>OK</status></response>')
    monkeypatch.setattr(requests, 'post', fake_post)
    result, _ = mod.api_post('http://x/', data={}, headers={})
    assert result == 'OK'
    assert seen['timeout'] == 30
