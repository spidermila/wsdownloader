"""aria2 JSON-RPC client and helpers shared by app.py and downloader.py."""
import base64
import logging
import os
import secrets
from pathlib import Path
from typing import Any
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR') or (APP_ROOT / 'data'))
DEFAULT_SECRET_FILE = DATA_DIR / '.aria2-secret'

DEFAULT_RPC_URL = os.getenv('ARIA2_RPC_URL') or 'http://127.0.0.1:6800/jsonrpc'
DEFAULT_LISTEN_PORT = int(os.getenv('ARIA2_LISTEN_PORT') or 51413)

KIND_HTTP = 'http'
KIND_MAGNET = 'magnet'
KIND_TORRENT = 'torrent'

STATUS_MAP = {
    'active': 'downloading',
    'waiting': 'new',
    'paused': 'paused',
    'complete': 'downloaded',
    'error': 'failed',
    'removed': 'failed',
}


def classify(url: str) -> str:
    """Return 'magnet', 'torrent', or 'http' based on URL shape."""
    lowered = (url or '').strip().lower()
    if lowered.startswith('magnet:?'):
        return KIND_MAGNET
    parsed = urlparse(lowered)
    if parsed.scheme in ('http', 'https'):
        path = parsed.path.rsplit('?', 1)[0]
        if path.endswith('.torrent'):
            return KIND_TORRENT
    return KIND_HTTP


def read_or_create_secret(path: Optional[Path] = None) -> str:
    """Return aria2 RPC secret, generating and persisting one if missing."""
    if path is None:
        path = DEFAULT_SECRET_FILE
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    path.write_text(token)
    os.chmod(path, 0o600)
    return token


def _get_secret() -> str:
    env_secret = os.getenv('ARIA2_RPC_SECRET')
    if env_secret:
        return env_secret
    return read_or_create_secret()


class Aria2Error(Exception):
    pass


class Aria2Client:
    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        secret: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.rpc_url = rpc_url
        self.secret = secret if secret is not None else _get_secret()
        self.timeout = timeout

    def _call(self, method: str, *params: Any) -> Any:
        payload = {
            'jsonrpc': '2.0',
            'id': secrets.token_hex(8),
            'method': method,
            'params': [f'token:{self.secret}', *params],
        }
        try:
            resp = requests.post(
                self.rpc_url, json=payload, timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise Aria2Error(f'RPC transport error: {exc}') from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise Aria2Error(f'RPC non-JSON response: {resp.text!r}') from exc
        if 'error' in data:
            raise Aria2Error(str(data['error']))
        return data.get('result')

    def add_uri(self, uri: str, options: Optional[dict] = None) -> str:
        return self._call('aria2.addUri', [uri], options or {})

    def add_torrent(
        self, torrent_bytes: bytes, options: Optional[dict] = None,
    ) -> str:
        encoded = base64.b64encode(torrent_bytes).decode('ascii')
        return self._call('aria2.addTorrent', encoded, [], options or {})

    def tell_status(self, gid: str, keys: Optional[list[str]] = None) -> dict:
        if keys is None:
            keys = [
                'status', 'totalLength', 'completedLength', 'downloadSpeed',
                'uploadSpeed', 'uploadLength', 'connections', 'files',
                'bittorrent', 'errorCode', 'errorMessage', 'seeder',
            ]
        return self._call('aria2.tellStatus', gid, keys)

    def remove(self, gid: str) -> str:
        return self._call('aria2.forceRemove', gid)

    def remove_download_result(self, gid: str) -> str:
        return self._call('aria2.removeDownloadResult', gid)

    def pause(self, gid: str) -> str:
        return self._call('aria2.pause', gid)

    def unpause(self, gid: str) -> str:
        return self._call('aria2.unpause', gid)

    def change_option(self, gid: str, options: dict) -> str:
        return self._call('aria2.changeOption', gid, options)

    def get_version(self) -> dict:
        return self._call('aria2.getVersion')

    def is_available(self) -> bool:
        try:
            self.get_version()
            return True
        except Aria2Error:
            return False


# Minutes in a year — effectively "no time limit" when seeding by ratio.
_SEED_TIME_UNLIMITED_MIN = 525600


def seed_options(mode: str, value: float) -> dict:
    """Translate settings.torrent_seed_* into aria2 per-download options."""
    if mode == 'ratio' and value > 0:
        return {
            'seed-ratio': f'{value}',
            'seed-time': f'{_SEED_TIME_UNLIMITED_MIN}',
        }
    if mode == 'time' and value > 0:
        return {'seed-time': f'{int(value)}', 'seed-ratio': '0.0'}
    return {'seed-time': '0', 'seed-ratio': '0.0'}


def map_status(aria_status: str, seeding_enabled: bool) -> str:
    """Map aria2 status string to the app's status vocabulary."""
    if aria_status == 'complete' and seeding_enabled:
        return 'seeding'
    return STATUS_MAP.get(aria_status, 'new')
