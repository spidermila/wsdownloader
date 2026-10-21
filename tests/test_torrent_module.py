"""Tests for the torrent.py helper module (aria2 RPC wrapper + helpers)."""
import base64
import os
import re
import secrets
import stat

import pytest
import requests

TEST_RPC_SECRET = secrets.token_hex(16)


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


def test_read_or_create_secret_creates_0600(torrent_module, tmp_path):
    secret_file = tmp_path / 'sub' / '.aria2-secret'
    old = os.umask(0)
    try:
        token = torrent_module.read_or_create_secret(secret_file)
    finally:
        os.umask(old)
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert re.fullmatch(r'[0-9a-f]{64}', token)
    assert secret_file.read_text() == token


def test_read_or_create_secret_opens_with_0600(
    torrent_module, tmp_path, monkeypatch,
):
    modes = []
    real_open = os.open

    def spy(path, flags, mode=0o777):
        modes.append(mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(torrent_module.os, 'open', spy)
    torrent_module.read_or_create_secret(tmp_path / '.aria2-secret')
    assert modes == [0o600]


def test_read_or_create_secret_reuses_trimmed(torrent_module, tmp_path):
    secret_file = tmp_path / '.aria2-secret'
    secret_file.write_text('  abc123\n')
    assert torrent_module.read_or_create_secret(secret_file) == 'abc123'


def test_read_or_create_secret_regenerates_empty(torrent_module, tmp_path):
    secret_file = tmp_path / '.aria2-secret'
    secret_file.write_text('\n')
    secret_file.chmod(0o644)
    token = torrent_module.read_or_create_secret(secret_file)
    assert len(token) == 64
    assert secret_file.read_text() == token
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600


def test_default_secret_file_under_temp_data_dir(torrent_module, temp_env):
    assert torrent_module.DEFAULT_SECRET_FILE == (
        temp_env['data_dir'] / '.aria2-secret'
    )


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
    client = torrent_module.Aria2Client(secret=TEST_RPC_SECRET)
    gid = client.add_uri('magnet:?xt=urn:btih:abc')
    assert gid == 'gid123'
    assert captured['payload']['method'] == 'aria2.addUri'
    assert captured['payload']['params'][0] == f'token:{TEST_RPC_SECRET}'


def test_call_raises_on_transport_error(torrent_module, monkeypatch):
    def fake_post(*a, **kw):
        raise requests.RequestException('boom')

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret=TEST_RPC_SECRET).get_version()


def test_call_raises_on_non_json(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(text='not json', raise_json=True),
    )
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret=TEST_RPC_SECRET).get_version()


def test_call_raises_on_rpc_error(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(
            data={'error': {'code': 1, 'message': 'nope'}},
        ),
    )
    with pytest.raises(torrent_module.Aria2Error):
        torrent_module.Aria2Client(secret=TEST_RPC_SECRET).get_version()


def test_add_torrent_base64_encodes_payload(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['params'] = json['params']
        return _FakeResponse(data={'result': 'g'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret=TEST_RPC_SECRET)
    client.add_torrent(b'raw-bytes', {'dir': '/downloads'})
    assert seen['params'][1] == base64.b64encode(b'raw-bytes').decode('ascii')
    assert seen['params'][3] == {'dir': '/downloads'}


def test_tell_status_default_keys(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['params'] = json['params']
        return _FakeResponse(data={'result': {}})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    torrent_module.Aria2Client(secret=TEST_RPC_SECRET).tell_status('gid1')
    assert 'status' in seen['params'][2]
    assert 'downloadSpeed' in seen['params'][2]
    assert 'followedBy' in seen['params'][2]


def test_tell_status_custom_keys(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json, timeout):  # noqa: A002
        seen['p'] = json['params']
        return _FakeResponse(data={'result': {}})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).tell_status('gid1', ['status'])
    assert seen['p'][2] == ['status']


def test_get_peers_returns_list(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(
            data={'result': [{'ip': '1.2.3.4'}]},
        ),
    )
    peers = torrent_module.Aria2Client(secret=TEST_RPC_SECRET).get_peers('g')
    assert peers == [{'ip': '1.2.3.4'}]


def test_get_peers_returns_empty_on_error(torrent_module, monkeypatch):
    def boom(*a, **kw):
        raise requests.RequestException('boom')

    monkeypatch.setattr(torrent_module.requests, 'post', boom)
    assert torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).get_peers('g') == []


def test_get_servers_returns_list(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(
            data={'result': [{'index': '1', 'servers': []}]},
        ),
    )
    servers = torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).get_servers('g')
    assert servers[0]['index'] == '1'


def test_get_servers_returns_empty_on_error(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: (_ for _ in ()).throw(
            requests.RequestException('down'),
        ),
    )
    assert torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).get_servers('g') == []


def test_get_peers_returns_empty_when_result_is_none(
    torrent_module, monkeypatch,
):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(data={'result': None}),
    )
    assert torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).get_peers('g') == []


def test_remove_and_change_option(torrent_module, monkeypatch):
    seen = []

    def fake_post(url, json, timeout):  # noqa: A002
        seen.append(json['method'])
        return _FakeResponse(data={'result': 'ok'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret=TEST_RPC_SECRET)
    client.remove('g')
    client.force_remove('g')
    client.remove_download_result('g')
    client.change_option('g', {'seed-ratio': '1.0'})
    assert seen == [
        'aria2.remove',
        'aria2.forceRemove',
        'aria2.removeDownloadResult',
        'aria2.changeOption',
    ]


def test_is_available_true(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: _FakeResponse(data={'result': {'version': '1.37.0'}}),
    )
    assert torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).is_available() is True


def test_is_available_false_on_error(torrent_module, monkeypatch):
    monkeypatch.setattr(
        torrent_module.requests, 'post',
        lambda *a, **kw: (_ for _ in ()).throw(
            requests.RequestException('down'),
        ),
    )
    assert torrent_module.Aria2Client(
        secret=TEST_RPC_SECRET,
    ).is_available() is False


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
    assert torrent_module.map_status('active', True) == 'seeding'
    assert torrent_module.map_status('complete', True) == 'downloaded'
    assert torrent_module.map_status('waiting', True) == 'new'
    assert torrent_module.map_status('error', False) == 'failed'
    assert torrent_module.map_status('removed', False) == 'failed'
    assert torrent_module.map_status('unknown-state', False) == 'new'


def test_parse_select_file_indices_filters_and_sorts(torrent_module):
    assert torrent_module.parse_select_file_indices(
        ['3', '1', '2', '2', '99', 'x', '', '0', '-1'],
        allowed_indices={1, 2, 3, 4, 5},
    ) == [1, 2, 3]


def test_parse_select_file_indices_respects_sparse_allowed_set(
    torrent_module,
):
    assert torrent_module.parse_select_file_indices(
        ['1', '2', '3'], allowed_indices={1, 3, 5},
    ) == [1, 3]


def test_parse_select_file_indices_empty(torrent_module):
    assert torrent_module.parse_select_file_indices(
        [], allowed_indices={1, 2, 3},
    ) == []


def test_global_limit_options(torrent_module):
    assert torrent_module.global_limit_options(1024, 0) == {
        'max-overall-download-limit': '1024',
        'max-overall-upload-limit': '0',
    }
    assert torrent_module.global_limit_options(-5, None) == {
        'max-overall-download-limit': '0',
        'max-overall-upload-limit': '0',
    }


@pytest.mark.parametrize(
    ('attr', 'args', 'method', 'params'),
    [
        ('remove', ('g',), 'aria2.remove', ['g']),
        ('force_remove', ('g',), 'aria2.forceRemove', ['g']),
        (
            'remove_download_result', ('g',),
            'aria2.removeDownloadResult', ['g'],
        ),
        ('pause', ('g',), 'aria2.pause', ['g']),
        ('unpause', ('g',), 'aria2.unpause', ['g']),
        ('pause_all', (), 'aria2.pauseAll', []),
        ('unpause_all', (), 'aria2.unpauseAll', []),
        (
            'change_global_option', ({'a': 'b'},), 'aria2.changeGlobalOption',
            [{'a': 'b'}],
        ),
        ('get_global_stat', (), 'aria2.getGlobalStat', []),
        ('get_version', (), 'aria2.getVersion', []),
    ],
)
def test_simple_rpc_wrappers(
    torrent_module, monkeypatch, attr, args, method, params,
):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['method'] = json['method']
        seen['params'] = json['params'][1:]
        return _FakeResponse(data={'result': 'OK'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret=TEST_RPC_SECRET)
    assert getattr(client, attr)(*args) == 'OK'
    assert seen == {'method': method, 'params': params}


def test_add_uri_sends_uri_and_options(torrent_module, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        seen['params'] = json['params'][1:]
        return _FakeResponse(data={'result': 'gid'})

    monkeypatch.setattr(torrent_module.requests, 'post', fake_post)
    client = torrent_module.Aria2Client(secret=TEST_RPC_SECRET)
    assert client.add_uri('magnet:?xt=x', {'k': 'v'}) == 'gid'
    assert seen['params'] == [['magnet:?xt=x'], {'k': 'v'}]
    client.add_uri('magnet:?xt=x')
    assert seen['params'] == [['magnet:?xt=x'], {}]


def test_apply_global_limits_success_and_failure(torrent_module):
    calls = []

    class Ok:
        def change_global_option(self, opts):
            calls.append(opts)

    class Bad:
        def change_global_option(self, opts):
            raise torrent_module.Aria2Error('boom')

    assert torrent_module.apply_global_limits(Ok(), 5, 6) is True
    assert calls == [{
        'max-overall-download-limit': '5',
        'max-overall-upload-limit': '6',
    }]
    assert torrent_module.apply_global_limits(Bad(), 5, 6) is False
