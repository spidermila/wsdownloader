"""Tests for the torrent.py helper module (aria2 RPC wrapper + helpers)."""
import base64

import pytest
import requests


@pytest.fixture()
def torrent_module(temp_env):
    """Freshly import torrent.py so it picks up the isolated DATA_DIR."""
    import importlib
    import torrent as torrent_mod
    importlib.reload(torrent_mod)
    return torrent_mod


def test_classify_recognises_magnet(torrent_module):
    assert torrent_module.classify('magnet:?xt=urn:btih:abc') == 'magnet'


def test_classify_recognises_torrent_file(torrent_module):
    assert torrent_module.classify(
        'https://example.com/file.torrent',
    ) == 'torrent'
    assert torrent_module.classify(
        'HTTPS://example.com/PATH.Torrent?token=x',
    ) == 'torrent'


def test_classify_treats_regular_url_as_http(torrent_module):
    assert torrent_module.classify('https://example.com/a.mp4') == 'http'
    assert torrent_module.classify('') == 'http'


def test_read_or_create_secret_persists(torrent_module, tmp_path):
    secret_file = tmp_path / '.aria2-secret'
    first = torrent_module.read_or_create_secret(secret_file)
    second = torrent_module.read_or_create_secret(secret_file)
    assert first == second
    assert len(first) == 64  # 32 bytes hex


def test_get_secret_prefers_env(torrent_module, monkeypatch):
    monkeypatch.setenv('ARIA2_RPC_SECRET', 'env-secret')
    client = torrent_module.Aria2Client()
    assert client.secret == 'env-secret'


def test_get_secret_falls_back_to_file(
    torrent_module, monkeypatch, tmp_path,
):
    monkeypatch.delenv('ARIA2_RPC_SECRET', raising=False)
    secret_path = tmp_path / '.aria2-secret'
    monkeypatch.setattr(
        torrent_module, 'DEFAULT_SECRET_FILE', secret_path,
    )
    client = torrent_module.Aria2Client()
    assert client.secret
    assert secret_path.exists()


class _FakeResponse:
    def __init__(self, data=None, text='', raise_json=False):
        self._data = data
        self.text = text
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError('bad json')
        return self._data


def test_call_returns_result(torrent_module, monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        captured['url'] = url
        captured['payload'] = json
        return _FakeResponse(data={'result': 'gid123'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret='sekret')
    gid = client.add_uri('magnet:?xt=urn:btih:abc')
    assert gid == 'gid123'
    assert captured['payload']['method'] == 'aria2.addUri'
    assert captured['payload']['params'][0] == 'token:sekret'


def test_call_raises_on_transport_error(torrent_module, monkeypatch):
    def fake_post(*a, **kw):
        raise requests.RequestException('boom')

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret='s').get_version()


def test_call_raises_on_non_json(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(text='not json', raise_json=True),
    )
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret='s').get_version()


def test_call_raises_on_rpc_error(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(
            data={'error': {'code': 1, 'message': 'nope'}},
        ),
    )
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret='s').get_version()


def test_add_torrent_base64_encodes_payload(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['params'] = json['params']
        return _FakeResponse(data={'result': 'g'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret='s')
    client.add_torrent(b'raw-bytes', {'dir': '/downloads'})
    assert seen['params'][1] == base64.b64encode(b'raw-bytes').decode('ascii')
    assert seen['params'][3] == {'dir': '/downloads'}


def test_tell_status_default_keys(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['params'] = json['params']
        return _FakeResponse(data={'result': {}})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    torrent_module.Aria2Client(secret='s').tell_status('gid1')
    assert 'status' in seen['params'][2]
    assert 'downloadSpeed' in seen['params'][2]


def test_tell_status_custom_keys(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json, timeout):  # noqa: A002
        seen['p'] = json['params']
        return _FakeResponse(data={'result': {}})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    torrent_module.Aria2Client(secret='s').tell_status('gid1', ['status'])
    assert seen['p'][2] == ['status']


def test_remove_and_change_option(torrent_module, monkeypatch):
    seen = []

    def fake_post(url, json, timeout):  # noqa: A002
        seen.append(json['method'])
        return _FakeResponse(data={'result': 'ok'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret='s')
    client.remove('g')
    client.remove_download_result('g')
    client.change_option('g', {'seed-ratio': '1.0'})
    assert seen == [
        'aria2.forceRemove',
        'aria2.removeDownloadResult',
        'aria2.changeOption',
    ]


def test_is_available_true(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(data={'result': {'version': '1.37.0'}}),
    )
    assert torrent_module.Aria2Client(secret='s').is_available() is True


def test_is_available_false_on_error(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: (_ for _ in ()).throw(
            requests.RequestException('down'),
        ),
    )
    assert torrent_module.Aria2Client(secret='s').is_available() is False


def test_seed_options_off(torrent_module):
    assert torrent_module.seed_options('off', 0) == {
        'seed-time': '0', 'seed-ratio': '0.0',
    }


def test_seed_options_ratio(torrent_module):
    opts = torrent_module.seed_options('ratio', 1.5)
    assert opts['seed-ratio'] == '1.5'
    assert int(opts['seed-time']) > 0


def test_seed_options_time(torrent_module):
    opts = torrent_module.seed_options('time', 30)
    assert opts['seed-time'] == '30'
    assert opts['seed-ratio'] == '0.0'


def test_seed_options_ignored_when_value_zero(torrent_module):
    assert torrent_module.seed_options('ratio', 0) == {
        'seed-time': '0', 'seed-ratio': '0.0',
    }


def test_map_status_transitions(torrent_module):
    assert torrent_module.map_status('active', False) == 'downloading'
    assert torrent_module.map_status('waiting', False) == 'new'
    assert torrent_module.map_status('paused', False) == 'paused'
    assert torrent_module.map_status('complete', False) == 'downloaded'
    assert torrent_module.map_status('complete', True) == 'seeding'
    assert torrent_module.map_status('error', False) == 'failed'
    assert torrent_module.map_status('removed', False) == 'failed'
    assert torrent_module.map_status('unknown-state', False) == 'new'
