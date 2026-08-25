import hashlib
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from threading import Lock
from threading import Thread
from time import sleep
from typing import Optional
from urllib.parse import urlparse

import requests
from flask import flash
from flask import Flask
from flask import g
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import url_for
from flask_socketio import emit
from flask_socketio import SocketIO
from passlib.hash import md5_crypt

import torrent


def configure_logging() -> logging.Logger:
    level = os.getenv('LOG_LEVEL', 'INFO').upper()

    formatter = logging.Formatter(
        fmt='[%(asctime)s.%(msecs)03d] %(levelname)s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    gunicorn_logger = logging.getLogger('gunicorn.error')
    if gunicorn_logger.handlers:
        for handler in gunicorn_logger.handlers:
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)
        root_logger.setLevel(gunicorn_logger.level or level)
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    root_logger.setLevel(level)
    logging.captureWarnings(True)
    return logging.getLogger(__name__)


app = Flask(__name__)
logger = configure_logging()

# Set secret key for session/flash support
app.secret_key = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)


# --- Configurable paths ---
# In dev, default to project-local ./data and ./downloads
# In Docker, we set env vars to keep using /data and /downloads
APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR') or (APP_ROOT / 'data'))
DOWNLOADS_PATH = Path(os.getenv('DOWNLOADS_DIR') or (APP_ROOT / 'downloads'))
DB_PATH = Path(os.getenv('DB_PATH') or (DATA_DIR / 'downloader.db'))

# Ensure directories exist before using them
DATA_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_PATH.mkdir(parents=True, exist_ok=True)

BASE_URL = 'https://webshare.cz/api/'

# SQLite's INTEGER columns are signed 64-bit; reject sizes outside that
# range (as well as negative sizes) instead of trying to store them.
MAX_SIZE_BYTES = 2 ** 63 - 1


def _validate_size_bytes(size_bytes: int) -> Optional[int]:
    """Return size_bytes if it's a plausible, storable file size, else None."""
    if size_bytes < 0 or size_bytes > MAX_SIZE_BYTES:
        logger.warning(
            '_validate_size_bytes() Rejected out-of-range size: %d',
            size_bytes,
        )
        return None
    return size_bytes


_appHasRunBefore = False

socketio = SocketIO(app, cors_allowed_origins='*', async_mode='gevent')

# Background monitoring state
_last_db_hash = None
_monitor_thread = None
_monitor_running = False


class Link:
    def __init__(self, url: str):
        self.url = url
        self.status = 'new'
        self.pct_downloaded = 0
        self.size_bytes = 0
        self.speed_bps = 0
        self.kind = torrent.KIND_HTTP
        self.external_id: Optional[str] = None

    def get_file_name(self) -> str:
        if self.kind == torrent.KIND_MAGNET:
            return _magnet_display_name(self.url)
        try:
            _purl = Path(urlparse(url=self.url).path)
            return _purl.name
        except:  # NOQA: E722
            logger.error('unable to extract file name from url %s', self.url)
            raise

    def get_human_size(self) -> str:
        return _human_size(self.size_bytes)


def _magnet_display_name(url: str) -> str:
    match = re.search(r'[?&]dn=([^&]+)', url or '')
    if match:
        from urllib.parse import unquote_plus
        return unquote_plus(match.group(1))
    return url[:60]


def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # rows as dict-like objects
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc) -> None:
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT new,
                pct_downloaded INTEGER DEFAULT 0,
                size_bytes INTEGER DEFAULT 0,
                speed_bps INTEGER DEFAULT 0,
                kind TEXT NOT NULL DEFAULT 'http',
                external_id TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                token TEXT DEFAULT '',
                auto_download INTEGER NOT NULL DEFAULT 1,
                user_name TEXT DEFAULT '',
                password_hash TEXT DEFAULT '',
                dark_mode INTEGER NOT NULL DEFAULT 0,
                torrent_enabled INTEGER NOT NULL DEFAULT 0,
                torrent_seed_mode TEXT NOT NULL DEFAULT 'off',
                torrent_seed_value REAL NOT NULL DEFAULT 0
            )
        """)
        conn.execute('INSERT OR IGNORE INTO settings (id) VALUES (1)')

        # New errors table for tracking download errors
        conn.execute("""
            CREATE TABLE IF NOT EXISTS download_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                error_type TEXT NOT NULL,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                retry_count INTEGER DEFAULT 0,
                UNIQUE(file_id)
            )
        """)

        cursor = conn.execute('PRAGMA table_info(settings)')
        columns = [row[1] for row in cursor.fetchall()]
        if 'dark_mode' not in columns:
            conn.execute(
                'ALTER TABLE settings ADD COLUMN dark_mode INTEGER '
                'NOT NULL DEFAULT 0',
            )
        if 'torrent_enabled' not in columns:
            conn.execute(
                'ALTER TABLE settings ADD COLUMN torrent_enabled INTEGER '
                'NOT NULL DEFAULT 0',
            )
        if 'torrent_seed_mode' not in columns:
            conn.execute(
                'ALTER TABLE settings ADD COLUMN torrent_seed_mode TEXT '
                "NOT NULL DEFAULT 'off'",
            )
        if 'torrent_seed_value' not in columns:
            conn.execute(
                'ALTER TABLE settings ADD COLUMN torrent_seed_value REAL '
                'NOT NULL DEFAULT 0',
            )

        cursor = conn.execute('PRAGMA table_info(links)')
        columns = [row[1] for row in cursor.fetchall()]
        if 'size_bytes' not in columns:
            conn.execute(
                'ALTER TABLE links ADD COLUMN size_bytes INTEGER DEFAULT 0',
            )
        if 'speed_bps' not in columns:
            conn.execute(
                'ALTER TABLE links ADD COLUMN speed_bps INTEGER DEFAULT 0',
            )
        if 'kind' not in columns:
            conn.execute(
                'ALTER TABLE links ADD COLUMN kind TEXT NOT NULL '
                "DEFAULT 'http'",
            )
        if 'external_id' not in columns:
            conn.execute('ALTER TABLE links ADD COLUMN external_id TEXT')

        conn.commit()
    finally:
        conn.close()


def get_settings() -> dict:
    db = get_db()
    row = db.execute("""
        SELECT id, token, auto_download, user_name, password_hash, dark_mode,
               torrent_enabled, torrent_seed_mode, torrent_seed_value
        FROM settings WHERE id = 1
    """).fetchone()
    if not row:
        return {
            'id': 1,
            'token': '',
            'auto_download': 0,
            'user_name': '',
            'password_hash': '',
            'dark_mode': 0,
            'torrent_enabled': 0,
            'torrent_seed_mode': 'off',
            'torrent_seed_value': 0,
        }
    return dict(row)


def get_salt(user_name: str) -> str | None:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'salt/'
    data = {'username_or_email': user_name}
    try:
        response = requests.post(url, data=data, headers=headers)
        xml = ET.fromstring(response.content)
        status_elem = xml.find('status')
        salt_elem = xml.find('salt')
        if status_elem is None or salt_elem is None:
            return None
        status = status_elem.text
        salt = salt_elem.text
        if status != 'OK' or salt is None:
            return None
        return salt
    except Exception:
        return None


def save_credentials(user_name: str, password: str) -> bool:
    user_name = (user_name or '').strip()
    password = password or ''
    if not user_name or not password:
        return False
    salt = get_salt(user_name)
    if salt is None:
        logger.error('Failed to get salt for user %s', user_name)
        return False
    password_hash = hashlib.sha1(
        md5_crypt.hash(password, salt=salt).encode('utf-8'),
    ).hexdigest()
    db = get_db()
    db.execute(
        """
        UPDATE settings
           SET user_name = ?, password_hash = ?
         WHERE id = 1
    """, (user_name, password_hash),
    )
    db.commit()
    return True


def api_post(url: str | bytes, data: dict, headers: dict) -> tuple[str, str]:
    try:
        response = requests.post(url, data=data, headers=headers)
    except ConnectionError as e:
        logger.error(
            'Connection failed strerror=%s, errno=%s, filename=%s',
            e.strerror, e.errno, e.filename,
        )
        return ('Connection failed', '<dummy></dummy>')
    rc = response.status_code
    if rc != 200:
        logger.error('Got RC: %d, response.text=%r', rc, response.text)
        return ('Connection failed', '<dummy></dummy>')
    return ('OK', response.text)


def save_token_value(token: str) -> None:
    db = get_db()
    db.execute('UPDATE settings SET token = ? WHERE id = 1', (token or '',))
    db.commit()


def login_and_get_token() -> str | None:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'login/'
    settings = get_settings()
    digest = hashlib.md5(
        (
            settings['user_name'] + ':Webshare:' +
            settings['password_hash']
        ).encode('utf-8'),
    ).hexdigest()

    data = {
        'username_or_email': settings['user_name'],
        'password': settings['password_hash'],
        'digest': digest,
        'keep_logged_in': 1,
    }
    result, payload = api_post(url, data=data, headers=headers)
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            logger.info('login OK')
            token_element = root.find('token')
            if isinstance(token_element, ET.Element):
                return str(token_element.text)
    return None


def check_token(token: str) -> bool:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'user_data/'
    data = {
        'wst': token,
    }
    if len(token) < 1:
        logger.info('No token is set - user is not logged in.')
        return False
    _, payload = api_post(url, data=data, headers=headers)
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            logger.info('check_token() OK')
            return True
    logger.error('check_token() failed')
    return False


def dequeue_file(token: str, file_id: str) -> str | None:
    """Remove a file from the Webshare download queue."""
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'dequeue_file/'
    data = {
        'ident': file_id,
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        logger.error(
            f'dequeue_file() Connection failed for file_id={file_id}',
        )
        return None

    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element) and status.text == 'OK':
        logger.info(f'dequeue_file() Successfully dequeued file_id={file_id}')
        return status.text

    logger.warning(f'dequeue_file() Failed to dequeue file_id={file_id}')
    return None


def _row_to_link(row) -> Link:
    link = Link(url=row['url'])
    link.status = row['status']
    link.pct_downloaded = row['pct_downloaded']
    link.size_bytes = row['size_bytes']
    link.speed_bps = row['speed_bps'] or 0
    if 'kind' in row.keys():
        link.kind = row['kind'] or torrent.KIND_HTTP
    if 'external_id' in row.keys():
        link.external_id = row['external_id']
    return link


def read_links_from_db() -> list[Link]:
    db = get_db()
    rows = db.execute("""
        SELECT id, url, created_at, status, pct_downloaded, size_bytes,
               speed_bps, kind, external_id
        FROM links ORDER by created_at DESC
    """).fetchall()
    if len(rows) == 0:
        logger.info('read_links_from_db() No links found in database')
        return []
    return [_row_to_link(row) for row in rows]


def read_download_errors() -> list[dict]:
    """Read all download errors from the database."""
    db = get_db()
    rows = db.execute("""
        SELECT id, file_id, file_name, error_type, error_message,
               created_at
        FROM download_errors
        ORDER BY created_at DESC
    """).fetchall()
    return [dict(row) for row in rows]


def delete_download_error(file_id: str) -> bool:
    """Delete a download error by file_id."""
    db = get_db()
    cur = db.execute(
        'DELETE FROM download_errors WHERE file_id = ?',
        (file_id,),
    )
    db.commit()
    return cur.rowcount > 0


MAGNET_RE = re.compile(
    r'^magnet:\?(?:[a-zA-Z0-9._%+-]+=[^&\s]+&?)+$',
)


def _torrents_enabled() -> bool:
    try:
        return bool(get_settings().get('torrent_enabled'))
    except sqlite3.Error:
        return False


def validate_url(url) -> str:
    if url and url.startswith('magnet:?'):
        if not _torrents_enabled():
            return 'Torrenty nejsou povoleny. Zapněte je v nastavení.'
        if not MAGNET_RE.fullmatch(url) or 'xt=urn:btih:' not in url.lower():
            return 'Neplatný magnet link.'
        return 'ok'

    URL_RE = re.compile(
        r"""
    ^
    (?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://
    (?:(?P<userinfo>[^/\s@]+(?::[^/\s@]*)?)@)?
    (?P<host>
        localhost
    | \[[0-9A-Fa-f:.]+\]
    | \d{1,3}(?:\.\d{1,3}){3}
    | (?:[A-Za-z0-9]
            (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
        )
        (?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+
        \.?
    )
    (?::(?P<port>\d{1,5}))?
    (?P<path>/[^\s?#]*)?
    (?:\?(?P<query>[^\s#]*))?
    (?:\#(?P<fragment>[^\s]*))?
    $
    """, re.VERBOSE,
    )

    if not URL_RE.fullmatch(url):
        return 'Neplatný link.'

    p = urlparse(url)
    allowed_schemes = {'http', 'https'}
    if allowed_schemes is not None and p.scheme.lower() not in allowed_schemes:
        logger.error(
            'Invalid URL scheme: %s, allowed: %s', p.scheme, allowed_schemes,
        )
        return 'Neplatný link.'

    if torrent.classify(url) == torrent.KIND_TORRENT \
            and not _torrents_enabled():
        return 'Torrenty nejsou povoleny. Zapněte je v nastavení.'

    if p.port is not None and not (0 <= p.port <= 65535):
        logger.error('Invalid URL port: %s', p.port)
        return 'Neplatný link.'

    host = p.hostname or ''
    if (
        host.count('.') == 3 and
        all(part.isdigit() for part in host.split('.'))
    ):
        parts = [int(x) for x in host.split('.')]
        if any(not (0 <= x <= 255) for x in parts):
            logger.error('Invalid IPv4 address: %s', host)
            return 'Neplatný link.'
    logger.info('URL validated successfully: %s', url)
    return 'ok'


def test_url(url: str) -> tuple[bool, Optional[int]]:
    """
    Probe a URL with a HEAD request. Returns whether it is reachable and,
    when available, its size in bytes (from the Content-Length header).
    This works for any HTTP(S) link, not just Webshare ones.
    """
    response = requests.head(url, allow_redirects=True)
    if response.status_code == 200:
        logger.info('URL test succeeded: %s', url)
        content_length = response.headers.get('Content-Length')
        size_bytes = None
        if content_length is not None:
            try:
                size_bytes = _validate_size_bytes(int(content_length))
            except ValueError:
                size_bytes = None
        return (True, size_bytes)
    logger.info('URL test failed: %s', url)
    return (False, None)


def add_link_if_new(
    link_raw: str, kind: str = torrent.KIND_HTTP,
) -> tuple[bool, str, Optional[int]]:
    url = (link_raw or '').strip()
    if not url:
        return (False, '', None)

    db = get_db()
    try:
        cur = db.execute(
            'INSERT OR IGNORE INTO links (url, kind) VALUES (?, ?)',
            (url, kind),
        )
        db.commit()
        added = cur.rowcount > 0
        row_id = cur.lastrowid if added else None
        if added:
            logger.info(
                'add_link_if_new() Link added (kind=%s): %s', kind, url,
            )
        else:
            logger.warning('add_link_if_new() Link already exists: %s', url)
        return (added, url, row_id)
    except sqlite3.Error:
        logger.error('add_link_if_new() Error adding link: %s', url)
        return (False, url, None)


def set_file_size_by_id(row_id: int, size_bytes: int) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            'UPDATE links SET size_bytes = ? WHERE id = ?',
            (size_bytes, row_id),
        )
        db.commit()
        updated = cur.rowcount > 0
        logger.info(
            'set_file_size_by_id() Updated row %d with size_bytes=%d: %s',
            row_id, size_bytes, 'Success' if updated else 'Row not found',
        )
        return updated
    except sqlite3.Error as e:
        logger.error('set_file_size_by_id() Database error: %s', e)
        return False


def get_total_queue_size() -> int:
    """Sum of size_bytes for all links currently in the queue."""
    db = get_db()
    row = db.execute("""
        SELECT COALESCE(SUM(size_bytes), 0) AS total FROM links
    """).fetchone()
    return int(row['total']) if row else 0


def _human_size(num_bytes: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(num_bytes)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.0f} {u}" if u == 'B' else f"{size:.1f} {u}"
        size /= 1024
    return '0 B'


def _human_speed(bytes_per_sec: int) -> str:
    if not bytes_per_sec or bytes_per_sec <= 0:
        return ''
    kbps = bytes_per_sec / 1024
    if kbps < 1024:
        return f"{kbps:.1f} KB/s"
    return f"{kbps / 1024:.1f} MB/s"


def get_fs_usage(base_path: Optional[Path] = None) -> dict:
    if base_path is None:
        base_path = DOWNLOADS_PATH
    try:
        usage = shutil.disk_usage(str(base_path))
        total, used, free = usage.total, usage.used, usage.free
        percent_free = 0.0 if total == 0 else (free / total) * 100.0
        return {
            'total': total,
            'used': used,
            'free': free,
            'total_h': _human_size(total),
            'used_h': _human_size(used),
            'free_h': _human_size(free),
            'percent_free': round(percent_free, 1),
            'mount_display': str(base_path),
        }
    except Exception as e:
        logger.error(
            'get_fs_usage() Error getting fs usage for %s: %s', base_path, e,
        )
        return {
            'total': 0, 'used': 0, 'free': 0,
            'total_h': '0 B', 'used_h': '0 B', 'free_h': '0 B',
            'percent_free': 0.0,
            'mount_display': str(base_path),
        }


def _dir_size(path: Path) -> int:
    total = 0
    for sub in path.rglob('*'):
        if sub.is_file():
            try:
                total += sub.stat().st_size
            except OSError:
                pass
    return total


def list_downloaded_files() -> list[dict]:
    files: list[dict] = []
    try:
        root = DOWNLOADS_PATH.resolve()
        if not root.exists():
            return files
        for p in sorted(root.iterdir(), key=lambda x: x.name.lower()):
            if p.name[0] == '.':
                continue
            if p.is_file():
                files.append({
                    'name': p.name,
                    'size': _human_size(p.stat().st_size),
                    'is_dir': False,
                })
            elif p.is_dir():
                files.append({
                    'name': p.name,
                    'size': _human_size(_dir_size(p)),
                    'is_dir': True,
                })
    except Exception as e:
        logger.error(
            'list_downloaded_files() Error listing files in %s: %s',
            DOWNLOADS_PATH, e,
        )
    return files


def get_db_state_hash() -> str:
    """Generate a hash representing the current state of links and files."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT url, status, pct_downloaded, size_bytes, speed_bps
            FROM links ORDER BY url
        """).fetchall()

        # Also include errors in state hash
        error_rows = conn.execute("""
            SELECT file_id, error_type, retry_count
            FROM download_errors ORDER BY file_id
        """).fetchall()
        conn.close()

        state_parts = []
        for row in rows:
            state_part = (
                f"{row['url']}:{row['status']}:"
                f"{row['pct_downloaded']}:{row['size_bytes']}:"
                f"{row['speed_bps']}"
            )
            state_parts.append(state_part)

        # Add errors to state
        for row in error_rows:
            state_parts.append(
                f"err:{row['file_id']}:"
                f"{row['error_type']}:{row['retry_count']}",
            )

        if DOWNLOADS_PATH.exists():
            files = sorted([
                f.name for f in DOWNLOADS_PATH.iterdir()
                if f.name[0] != '.'
            ])
            state_parts.extend(files)

        state_str = '|'.join(state_parts)
        return hashlib.md5(state_str.encode()).hexdigest()
    except Exception as e:
        logger.error(
            'get_db_state_hash() Error computing state hash: %s', e,
        )
        return ''


def monitor_database_changes():
    """Background thread that monitors for database/filesystem changes."""
    global _last_db_hash

    logger.info('monitor_database_changes() Thread started')

    _last_db_hash = get_db_state_hash()

    while _monitor_running:
        try:
            sleep(5)

            current_hash = get_db_state_hash()

            if current_hash and current_hash != _last_db_hash:
                _last_db_hash = current_hash

                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""
                    SELECT url, status, pct_downloaded, size_bytes,
                           speed_bps, kind, external_id
                    FROM links ORDER BY created_at DESC
                """).fetchall()

                # Also fetch errors
                error_rows = conn.execute("""
                    SELECT id, file_id, file_name, error_type, error_message,
                           created_at, retry_count
                    FROM download_errors ORDER BY created_at DESC
                """).fetchall()
                conn.close()

                links = [_row_to_link(row) for row in rows]

                errors = [dict(row) for row in error_rows]
                files = list_downloaded_files()
                fs = get_fs_usage(DOWNLOADS_PATH)

                payload = build_full_update_payload(links, files, fs, errors)
                socketio.emit('full_update', payload)
                logger.info(
                    'monitor_database_changes() Emitted update: '
                    '%d links, %d files', len(links), len(files),
                )

        except Exception as e:
            logger.error(
                'monitor_database_changes() Error in monitor thread: %s', e,
            )
            import traceback
            traceback.print_exc()

    logger.info('monitor_database_changes() Thread stopped')


def start_monitor():
    """Start the background monitoring thread."""
    global _monitor_thread, _monitor_running

    if _monitor_thread is None or not _monitor_thread.is_alive():
        _monitor_running = True
        _monitor_thread = Thread(target=monitor_database_changes, daemon=True)
        _monitor_thread.start()
        logger.info('start_monitor() Monitor thread started')


def stop_monitor():
    """Stop the background monitoring thread."""
    global _monitor_running
    _monitor_running = False
    logger.info('stop_monitor() Monitor thread stopping...')


@app.before_request
def before_request():
    global _appHasRunBefore
    if not _appHasRunBefore:
        init_db()
        start_monitor()
        _appHasRunBefore = True


def _handle_http_add(url_input: str) -> None:
    url_ok, content_length = test_url(url_input)
    if not url_ok:
        logger.error('index() Link nedostupný, input was: %s', url_input)
        flash('Link nedostupný', 'error')
        return
    added, value, row_id = add_link_if_new(url_input)
    if not added:
        flash(f"Již existuje: {value}", 'warning')
        return
    logger.info('index() HTTP link added: %s', value)
    flash(f"Přidáno: {value}", 'success')
    new_link = Link(value)
    if row_id is not None and content_length is not None:
        set_file_size_by_id(row_id, content_length)
        new_link.size_bytes = content_length
    socketio.emit('link_added', link_to_dict(new_link))


def _handle_torrent_add(url_input: str, kind: str) -> None:
    added, value, _row_id = add_link_if_new(url_input, kind=kind)
    if not added:
        flash(f"Již existuje: {value}", 'warning')
        return
    logger.info('index() Torrent link added (kind=%s): %s', kind, value)
    flash(f"Přidáno (torrent): {value}", 'success')
    new_link = Link(value)
    new_link.kind = kind
    socketio.emit('link_added', link_to_dict(new_link))


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url_input = request.form.get('link', '')
        val_message = validate_url(url_input)
        if val_message != 'ok':
            logger.error(
                'index() URL validation failed, input was: %s', url_input,
            )
            flash(val_message, 'error')
            return redirect(url_for('index'))

        kind = torrent.classify(url_input)
        if kind == torrent.KIND_HTTP:
            _handle_http_add(url_input)
        else:
            _handle_torrent_add(url_input, kind)
        return redirect(url_for('index'))

    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    errors = read_download_errors()
    total_queue_size = get_total_queue_size()

    settings = get_settings()
    if not check_token(settings['token']):
        save_token_value('')
        settings = get_settings()

    return render_template(
        'index.html',
        links=links,
        files=files,
        fs=fs,
        settings=settings,
        errors=errors,
        total_queue_size=total_queue_size,
        total_queue_size_human=_human_size(total_queue_size),
    )


@app.route('/links', methods=['GET'])
def get_links():
    links = read_links_from_db()
    result = {}
    for link in links:
        if link.status == 'downloading':
            result['link'] = (link.pct_downloaded)
    result['link_count'] = len(links)
    return jsonify(result)


@app.route('/health', methods=['GET'])
def healthcheck():
    return 'OK', 200


@app.post('/login')
def save_login():
    user_name = (request.form.get('user_name') or '').strip()
    password = request.form.get('password') or ''
    if not user_name or not password:
        logger.error('save_login() Missing username or password')
        flash('Je třeba vyplnit uživatelské jméno i heslo.', 'error')
        return redirect(url_for('index'))

    if not save_credentials(user_name, password):
        logger.error(
            'save_login() Failed to save credentials for user %s', user_name,
        )
        flash('Přihlášení selhalo', 'error')
        return redirect(url_for('index'))
    token = login_and_get_token()
    if not token:
        logger.error(
            'save_login() Failed to obtain token for user %s', user_name,
        )
        flash('Přihlášení selhalo', 'error')
        return redirect(url_for('index'))
    save_token_value(token)
    logger.info('save_login() User %s logged in successfully', user_name)
    flash('Úspěšné přihlášení', 'success')
    return redirect(url_for('index'))


@app.post('/logout')
def logout():
    save_token_value('')
    db = get_db()
    db.execute(
        """
        UPDATE settings
           SET user_name = '', password_hash = ''
         WHERE id = 1
    """,
    )
    db.commit()
    logger.info('logout() User logged out successfully')
    flash('Odhlášení proběhlo úspěšně', 'success')
    return redirect(url_for('index'))


def _remove_from_aria2(external_id: str) -> None:
    if not external_id:
        return
    try:
        client = torrent.Aria2Client()
        client.remove(external_id)
        client.remove_download_result(external_id)
    except torrent.Aria2Error as exc:
        logger.warning(
            '_remove_from_aria2() Failed to remove GID %s: %s',
            external_id, exc,
        )


@app.route('/delete', methods=['POST'])
def delete_link():
    url_to_delete = (request.form.get('url') or '').strip()
    if not url_to_delete:
        logger.error('delete_link() No URL provided')
        flash('Žádná URL poskytnuta.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    row = db.execute(
        'SELECT kind, external_id FROM links WHERE url = ?',
        (url_to_delete,),
    ).fetchone()
    cur = db.execute('DELETE FROM links WHERE url = ?', (url_to_delete,))
    db.commit()

    if cur.rowcount > 0:
        if row is not None and row['kind'] != torrent.KIND_HTTP:
            _remove_from_aria2(row['external_id'])
        logger.info('delete_link() Link deleted: %s', url_to_delete)
        flash(f"Odstraněno: {url_to_delete}", 'success')
        socketio.emit('link_deleted', {'url': url_to_delete})
    else:
        logger.warning('delete_link() Link not found: %s', url_to_delete)
        flash(f"Nenalezeno: {url_to_delete}", 'error')
    return redirect(url_for('index'))


@app.route('/delete-file', methods=['POST'])
def delete_file():
    filename = (request.form.get('filename') or '').strip()
    if not filename:
        logger.error('delete_file() No filename provided')
        flash('Zadán název souboru.', 'error')
        return redirect(url_for('index'))

    try:
        root = DOWNLOADS_PATH.resolve()
        candidate = (root / filename).resolve()

        if not str(candidate).startswith(str(root) + os.sep):
            logger.error(
                'delete_file() Invalid file path: %s is outside of %s',
                candidate, root,
            )
            flash('Neplatná cesta k souboru.', 'error')
            return redirect(url_for('index'))

        if candidate.exists() and candidate.is_file():
            candidate.unlink()
            _clear_file_caches(candidate)
            logger.info('delete_file() File deleted: %s', candidate)
            flash(f"Odstraněn soubor: {filename}", 'success')
            socketio.emit('file_deleted', {'filename': filename})
        elif candidate.exists() and candidate.is_dir():
            shutil.rmtree(candidate)
            logger.info('delete_file() Directory deleted: %s', candidate)
            flash(f"Odstraněna složka: {filename}", 'success')
            socketio.emit('file_deleted', {'filename': filename})
        else:
            logger.warning('delete_file() File not found: %s', candidate)
            flash(f"Soubor nenalezen: {filename}", 'error')
    except Exception as e:
        logger.error('delete_file() Error deleting file %s: %s', filename, e)
        flash(f"Chyba při odstraňování souboru: {filename}", 'error')

    return redirect(url_for('index'))


@app.route('/rename-file', methods=['POST'])
def rename_file():
    """Rename a file in the downloads directory."""
    old_name = (request.form.get('old_name') or '').strip()
    new_name = (request.form.get('new_name') or '').strip()

    if not old_name or not new_name:
        logger.error('rename_file() Missing old_name or new_name')
        return jsonify({
            'success': False,
            'error': 'Chybí název souboru.',
        }), 400

    # Validate new filename
    if '/' in new_name or '\\' in new_name:
        logger.error(
            f'rename_file() Path separator in filename: {new_name}',
        )
        return jsonify({
            'success': False,
            'error': 'Neplatný název souboru.',
        }), 400

    if new_name.startswith('.'):
        logger.error(f'rename_file() Hidden file not allowed: {new_name}')
        return jsonify({
            'success': False,
            'error': 'Neplatný název souboru.',
        }), 400

    # Remove dangerous characters
    if '\x00' in new_name or '\n' in new_name or '\r' in new_name:
        logger.error('rename_file() Invalid characters in filename')
        return jsonify({
            'success': False,
            'error': 'Neplatný název souboru.',
        }), 400

    try:
        root = DOWNLOADS_PATH.resolve()
        old_path = (root / old_name).resolve()
        new_path = (root / new_name).resolve()

        # Security check: ensure paths are within downloads directory
        if not str(old_path).startswith(str(root) + os.sep):
            logger.error(f'rename_file() Invalid old path: {old_path}')
            return jsonify({
                'success': False,
                'error': 'Neplatná cesta.',
            }), 400

        if not str(new_path).startswith(str(root) + os.sep):
            logger.error(f'rename_file() Invalid new path: {new_path}')
            return jsonify({
                'success': False,
                'error': 'Neplatná cesta.',
            }), 400

        if not old_path.exists() or not old_path.is_file():
            logger.warning(f'rename_file() File not found: {old_path}')
            return jsonify({
                'success': False,
                'error': 'Soubor nenalezen.',
            }), 404

        if new_path.exists():
            logger.warning(f'rename_file() Target file exists: {new_path}')
            return jsonify({
                'success': False,
                'error': 'Soubor s tímto názvem již existuje.',
            }), 409

        old_path.rename(new_path)
        logger.info(f'rename_file() Renamed: {old_name} -> {new_name}')
        socketio.emit(
            'file_renamed', {
                'old_name': old_name,
                'new_name': new_name,
            },
        )
        return jsonify({'success': True, 'new_name': new_name})

    except Exception as e:
        logger.error(
            f'rename_file() Error renaming {old_name} to {new_name}: {e}',
        )
        return jsonify({
            'success': False,
            'error': 'Chyba při přejmenování.',
        }), 500


@app.post('/settings/auto-download')
def update_auto_download():
    raw = request.form.get('auto_download')
    enabled = 1 if str(raw).lower() in ('on', '1', 'true', 'yes') else 0

    db = get_db()
    db.execute(
        'UPDATE settings SET auto_download = ? WHERE id = 1',
        (enabled,),
    )
    db.commit()
    logger.info(
        'update_auto_download() Auto-download %s',
        'enabled' if enabled else 'disabled',
    )
    flash(
        f'Automatické stahování {"zapnuto" if enabled else "vypnuto"}.',
        'success',
    )
    return redirect(url_for('index'))


@app.post('/settings/torrent')
def update_torrent_settings():
    enabled = 1 if request.form.get('torrent_enabled') else 0
    seed_mode = (request.form.get('torrent_seed_mode') or 'off').strip()
    if seed_mode not in ('off', 'ratio', 'time'):
        seed_mode = 'off'
    try:
        seed_value = float(request.form.get('torrent_seed_value') or 0)
    except ValueError:
        seed_value = 0.0
    if seed_value < 0:
        seed_value = 0.0

    db = get_db()
    db.execute(
        'UPDATE settings SET torrent_enabled = ?, torrent_seed_mode = ?, '
        'torrent_seed_value = ? WHERE id = 1',
        (enabled, seed_mode, seed_value),
    )
    db.commit()
    logger.info(
        'update_torrent_settings() torrent_enabled=%d seed_mode=%s '
        'seed_value=%s', enabled, seed_mode, seed_value,
    )
    flash(
        f'Torrenty {"zapnuty" if enabled else "vypnuty"}.',
        'success',
    )
    return redirect(url_for('index'))


@app.post('/settings/dark-mode')
def update_dark_mode():
    dark_mode = 1 if request.form.get('dark_mode') else 0
    db = get_db()
    db.execute('UPDATE settings SET dark_mode = ? WHERE id = 1', (dark_mode,))
    db.commit()
    logger.info(
        'update_dark_mode() Dark mode %s',
        'enabled' if dark_mode else 'disabled',
    )
    return redirect(url_for('index'))


@app.route('/help', methods=['GET'])
def help_page():
    settings = get_settings()
    return render_template('help.html', settings=settings)


@app.route('/error/dismiss', methods=['POST'])
def dismiss_error():
    """Dismiss/delete an error from the queue and dequeue from Webshare."""
    file_id = (request.form.get('file_id') or '').strip()
    if not file_id:
        flash('Chybí ID souboru.', 'error')
        return redirect(url_for('index'))

    # First, try to dequeue from Webshare
    settings = get_settings()
    token = settings.get('token', '')
    if token and check_token(token):
        dequeue_result = dequeue_file(token, file_id)
        if dequeue_result:
            logger.info(
                f'dismiss_error() Dequeued from Webshare: file_id={file_id}',
            )
        else:
            logger.warning(
                f'dismiss_error() Failed to dequeue: file_id={file_id}',
            )

    # Then delete from local errors table
    if delete_download_error(file_id):
        logger.info(f'dismiss_error() Dismissed error: file_id={file_id}')
        flash('Soubor byl odstraněn z fronty.', 'success')
        socketio.emit('error_dismissed', {'file_id': file_id})
    else:
        logger.warning(f'dismiss_error() Error not found: file_id={file_id}')
        flash('Chyba nebyla nalezena.', 'error')

    return redirect(url_for('index'))


@app.route('/stream/<path:filename>')
def stream_file(filename):
    """Serve a file from the downloads directory with range request support."""
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        logger.error('stream_file() Path traversal attempt: %s', filename)
        return 'Forbidden', 403

    if not candidate.exists() or not candidate.is_file():
        logger.warning('stream_file() File not found: %s', filename)
        return 'Not Found', 404

    file_size = candidate.stat().st_size
    mime_type, _ = mimetypes.guess_type(str(candidate))
    if not mime_type:
        mime_type = 'application/octet-stream'

    range_header = request.headers.get('Range')

    if range_header:
        try:
            byte_range = range_header.replace('bytes=', '')
            parts = byte_range.split('-')
            start = int(parts[0]) if parts[0] else 0
            end = int(parts[1]) if parts[1] else file_size - 1
        except (ValueError, IndexError):
            return 'Bad Request', 400

        end = min(end, file_size - 1)
        length = end - start + 1

        def generate():
            with open(candidate, 'rb') as f:
                f.seek(start)
                remaining = length
                chunk_size = 65536
                while remaining > 0:
                    chunk = f.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk

        headers = {
            'Content-Range': f'bytes {start}-{end}/{file_size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(length),
            'Content-Type': mime_type,
        }
        return app.response_class(generate(), status=206, headers=headers)

    def generate_full():
        with open(candidate, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                yield chunk

    headers = {
        'Accept-Ranges': 'bytes',
        'Content-Length': str(file_size),
        'Content-Type': mime_type,
    }
    return app.response_class(generate_full(), status=200, headers=headers)


@app.route('/player/<path:filename>')
def player(filename):
    """Render the video player page for a file."""
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        logger.error('player() Path traversal attempt: %s', filename)
        return 'Forbidden', 403

    if not candidate.exists() or not candidate.is_file():
        logger.warning('player() File not found: %s', filename)
        return 'Not Found', 404

    ua = request.user_agent.string
    is_ios = any(x in ua for x in ('iPhone', 'iPad', 'iPod'))
    native_ok = False if is_ios else _is_native_playback_ok(candidate)
    response = make_response(
        render_template(
            'player.html',
            filename=filename,
            is_ios=is_ios,
            native_ok=native_ok,
        ),
    )
    response.headers['Cache-Control'] = 'no-store'
    return response


@socketio.on('connect')
def handle_connect():
    """Send current state when client connects."""
    logger.info('handle_connect() Client connected via WebSocket')
    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    errors = read_download_errors()
    emit('full_update', build_full_update_payload(links, files, fs, errors))


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info('handle_disconnect() Client disconnected from WebSocket')


@socketio.on('request_update')
def handle_request_update():
    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    errors = read_download_errors()
    emit('full_update', build_full_update_payload(links, files, fs, errors))


def link_to_dict(link: Link) -> dict:
    return {
        'url': link.url,
        'file_name': link.get_file_name(),
        'status': link.status,
        'pct_downloaded': link.pct_downloaded,
        'size_bytes': link.size_bytes,
        'human_size': link.get_human_size(),
        'speed_bps': link.speed_bps,
        'human_speed': _human_speed(link.speed_bps),
        'kind': link.kind,
    }


def build_full_update_payload(
    links: list[Link], files: list[dict], fs: dict, errors: list[dict],
) -> dict:
    total_queue_size = sum(link.size_bytes for link in links)
    return {
        'links': [link_to_dict(link) for link in links],
        'files': files,
        'fs': fs,
        'errors': errors,
        'total_queue_size': total_queue_size,
        'total_queue_size_human': _human_size(total_queue_size),
    }


@app.after_request
def add_no_cache(response):
    if request.endpoint in (
        'stream_file', 'player', 'stream_track', 'subtitle_track',
        'hls_playlist', 'hls_segment', 'hls_cancel',
    ):
        return response
    response.headers['Cache-Control'] = (
        'no-store, no-cache, must-revalidate, max-age=0'
    )
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


_LANG_NAMES = {
    'ces': 'Čeština', 'cze': 'Čeština', 'cs': 'Čeština',
    'eng': 'Angličtina', 'en': 'Angličtina',
    'deu': 'Němčina', 'ger': 'Němčina', 'de': 'Němčina',
    'fra': 'Francouzština', 'fre': 'Francouzština', 'fr': 'Francouzština',
    'spa': 'Španělština', 'es': 'Španělština',
    'ita': 'Italština', 'it': 'Italština',
    'pol': 'Polština', 'pl': 'Polština',
    'slk': 'Slovenština', 'slo': 'Slovenština', 'sk': 'Slovenština',
    'hun': 'Maďarština', 'hu': 'Maďarština',
    'rus': 'Ruština', 'ru': 'Ruština',
    'jpn': 'Japonština', 'ja': 'Japonština',
    'zho': 'Čínština', 'chi': 'Čínština', 'zh': 'Čínština',
    'kor': 'Korejština', 'ko': 'Korejština',
    'por': 'Portugalština', 'pt': 'Portugalština',
    'nld': 'Nizozemština', 'dut': 'Nizozemština', 'nl': 'Nizozemština',
    'swe': 'Švédština', 'sv': 'Švédština',
    'nor': 'Norština', 'nb': 'Norština', 'nn': 'Norština',
    'dan': 'Dánština', 'da': 'Dánština',
    'fin': 'Finština', 'fi': 'Finština',
    'ukr': 'Ukrajinština', 'uk': 'Ukrajinština',
    'tur': 'Turečtina', 'tr': 'Turečtina',
    'ara': 'Arabština', 'ar': 'Arabština',
    'heb': 'Hebrejština', 'he': 'Hebrejština',
    'hin': 'Hindština', 'hi': 'Hindština',
    'und': '',
}

_CHANNEL_LABELS = {1: 'Mono', 2: 'Stereo', 6: '5.1', 8: '7.1'}

_CODEC_DISPLAY = {
    'aac': 'AAC', 'ac3': 'AC3', 'eac3': 'EAC3', 'dts': 'DTS',
    'mp3': 'MP3', 'flac': 'FLAC', 'vorbis': 'Vorbis', 'opus': 'Opus',
    'truehd': 'TrueHD', 'mlp': 'MLP',
    'pcm_s16le': 'PCM', 'pcm_s24le': 'PCM', 'pcm_s32le': 'PCM',
}


def _track_label(
    n, language, title, codec, channels=None,
    fallback_prefix='Stopa',
):
    lang_name = _LANG_NAMES.get(language.lower(), language) if language else ''
    codec_str = _CODEC_DISPLAY.get(codec, codec.upper() if codec else '')
    ch_str = (
        _CHANNEL_LABELS.get(channels, f'{channels}ch')
        if channels else ''
    )
    details_parts = [p for p in [codec_str, ch_str] if p]
    details = f' ({", ".join(details_parts)})' if details_parts else ''

    if title and lang_name:
        return f'{title} — {lang_name}{details}'
    if title:
        return f'{title}{details}'
    if lang_name:
        return f'{lang_name}{details}'
    return f'{fallback_prefix} {n}{details}'


@app.route('/file-info/<path:filename>')
def file_info(filename):
    """Return audio and subtitle track info for a file using ffprobe."""
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        return jsonify({'error': 'Forbidden'}), 403
    if not candidate.exists() or not candidate.is_file():
        return jsonify({'error': 'Not found'}), 404

    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'quiet',
                '-print_format', 'json',
                '-show_streams',
                str(candidate),
            ],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(result.stdout)
    except FileNotFoundError:
        logger.error('file_info() ffprobe not found')
        return jsonify({'error': 'ffprobe not available'}), 500
    except Exception as e:
        logger.error('file_info() Error running ffprobe: %s', e)
        return jsonify({'error': str(e)}), 500

    audio_tracks = []
    subtitle_tracks = []

    for stream in data.get('streams', []):
        codec_type = stream.get('codec_type', '')
        tags = stream.get('tags', {})
        index = stream.get('index', 0)
        language = tags.get('language') or tags.get('LANGUAGE') or ''
        title = tags.get('title') or tags.get('TITLE') or ''
        codec = stream.get('codec_name', '')

        if codec_type == 'audio':
            channels = stream.get('channels', 0)
            audio_tracks.append({
                'index': index,
                'label': _track_label(
                    len(audio_tracks) + 1, language, title, codec,
                    channels, fallback_prefix='Stopa',
                ),
            })
        elif codec_type == 'subtitle':
            # Skip image-based codecs — cannot convert to WebVTT
            if codec in _IMAGE_SUBTITLE_CODECS:
                continue
            subtitle_tracks.append({
                'index': index,
                'lang': language or 'und',
                'label': _track_label(
                    len(subtitle_tracks) + 1, language, title, codec,
                    fallback_prefix='Titulky',
                ),
            })

    return jsonify({
        'audio_tracks': audio_tracks,
        'subtitle_tracks': subtitle_tracks,
    })


_stream_bitrate_cache: dict = {}
_video_codec_cache: dict = {}
_video_pix_fmt_cache: dict = {}

# Fixed output bitrate used for iOS transcoding.
# Video 1500 kbps + audio 128 kbps ≈ 203 KB/s.
# The same constant is used for byte-offset → seek-time conversion, so the
# estimate stays accurate regardless of the source file's own bitrate.
_IOS_STREAM_BITRATE_BPS: int = (1500 + 128) * 1000 // 8


def _get_video_codec(candidate) -> str:
    """Return the source video codec name for stream 0 (e.g. 'h264')."""
    key = str(candidate)
    if key in _video_codec_cache:
        return _video_codec_cache[key]
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-select_streams', 'v:0',
                '-show_entries', 'stream=codec_name',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                str(candidate),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        codec = result.stdout.strip().lower()
    except Exception:
        codec = 'unknown'
    _video_codec_cache[key] = codec
    return codec


def _get_video_pix_fmt(candidate) -> str:
    """Return the pixel format of the first video stream (e.g. 'yuv420p')."""
    key = str(candidate)
    if key in _video_pix_fmt_cache:
        return _video_pix_fmt_cache[key]
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-select_streams', 'v:0',
                '-show_entries', 'stream=pix_fmt',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                str(candidate),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pix_fmt = result.stdout.strip().lower()
    except Exception:
        pix_fmt = 'unknown'
    _video_pix_fmt_cache[key] = pix_fmt
    return pix_fmt


_HLS_SEGMENT_TIME = 4  # seconds per HLS segment


def _get_video_duration(candidate: Path) -> Optional[float]:
    """Return video duration in seconds via ffprobe, or None on error."""
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                str(candidate),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return float(result.stdout.strip())
    except Exception:
        return None


def _build_vod_playlist(duration: float) -> str:
    """Return a complete HLS VOD playlist string for the given total duration.

    Segment entries use the nominal _HLS_SEGMENT_TIME duration.  The real .ts
    files may differ slightly at keyframe boundaries, but hls.js/Video.js use
    the timestamps inside each segment so the EXTINF values are just hints.
    Including #EXT-X-ENDLIST from the start makes the player show the full
    seekbar and treat this as VOD rather than a live stream.
    """
    seg_time = _HLS_SEGMENT_TIME
    n_full = int(duration / seg_time)
    remainder = duration - n_full * seg_time

    lines = [
        '#EXTM3U',
        '#EXT-X-VERSION:3',
        f'#EXT-X-TARGETDURATION:{seg_time}',
        '#EXT-X-MEDIA-SEQUENCE:0',
        '#EXT-X-PLAYLIST-TYPE:VOD',
    ]
    for i in range(n_full):
        lines.append(f'#EXTINF:{seg_time:.6f},')
        lines.append(f'seg{i:05d}.ts')
    if remainder > 0.1:
        lines.append(f'#EXTINF:{remainder:.6f},')
        lines.append(f'seg{n_full:05d}.ts')
    lines.append('#EXT-X-ENDLIST')
    return '\n'.join(lines) + '\n'


def _is_native_playback_ok(candidate) -> bool:
    """
    Return True if the file can be played natively in desktop browsers without
    transcoding: H.264 video + AAC audio (common in MKV/MP4 files).

    When True the player uses stream_file (raw bytes, range requests, full
    seekbar). When False it falls back to stream_track (ffmpeg transcode).
    """
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-show_entries', 'stream=codec_name,codec_type',
                '-of', 'json',
                str(candidate),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        streams = json.loads(result.stdout).get('streams', [])
        video_ok = any(
            s.get('codec_type') == 'video' and s.get('codec_name') == 'h264'
            for s in streams
        )
        audio_ok = any(
            s.get('codec_type') == 'audio' and s.get('codec_name') == 'aac'
            for s in streams
        )
        return video_ok and audio_ok
    except Exception:
        return False


def _get_file_bitrate(candidate, file_size: int) -> int:
    """Return estimated output bytes/sec based on file size and duration."""
    key = str(candidate)
    if key in _stream_bitrate_cache:
        return _stream_bitrate_cache[key]
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                str(candidate),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        duration_sec = float(result.stdout.strip())
        bitrate_Bps = int(
            file_size / duration_sec,
        ) if duration_sec > 0 else 625_000
    except Exception:
        bitrate_Bps = 625_000  # fallback: 5 Mbps
    _stream_bitrate_cache[key] = bitrate_Bps
    return bitrate_Bps


def _skip_mp4_init_boxes(proc):
    """
    Yield chunks from proc.stdout, skipping initial MP4 initialization boxes
    (ftyp, moov, free, wide) so that continuation segments start with a moof.
    iOS already has the init segment from the first response; re-sending it at
    a non-zero byte offset would confuse its MP4 parser.
    """
    SKIP_TYPES = {b'ftyp', b'moov', b'free', b'wide', b'skip'}
    buf = b''
    header_skipped = False
    while True:
        if not header_skipped:
            chunk = proc.stdout.read(65536)
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 8:
                box_size = struct.unpack('>I', buf[:4])[0]
                box_type = buf[4:8]
                if box_size == 1:
                    if len(buf) < 16:
                        break
                    box_size = struct.unpack('>Q', buf[8:16])[0]
                if box_size < 8:
                    header_skipped = True
                    yield buf
                    buf = b''
                    break
                if box_type in SKIP_TYPES:
                    if len(buf) >= box_size:
                        buf = buf[box_size:]
                    else:
                        break
                else:
                    header_skipped = True
                    yield buf
                    buf = b''
                    break
        else:
            chunk = proc.stdout.read(65536)
            if not chunk:
                return
            yield chunk


@app.route('/stream-track/<path:filename>')
def stream_track(filename):
    """
    Stream a file via FFmpeg with a selected audio track.
    Query params:
      audio=<stream_index>  — ffmpeg stream index of the audio track
      t=<seconds>           — start time offset for seeking (default: 0)

    iOS Safari requires 206 Partial Content and byte-range support to play
    video at all.  Desktop browsers (Chrome, Firefox) work fine with a plain
    200 streaming response.  The two paths are kept separate to avoid Chrome's
    byte-range continuation requests interfering with the URL t= seek logic.
    """
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403
    if not candidate.exists() or not candidate.is_file():
        return 'Not Found', 404

    try:
        audio_param = request.args.get('audio', 'auto')
        url_start_time = float(request.args.get('t', 0))
    except ValueError:
        return 'Bad Request', 400

    ua = request.headers.get('User-Agent', '')
    is_ios = 'iPhone' in ua or 'iPad' in ua

    # Parse Range header (used only for iOS path below).
    range_header = request.headers.get('Range', '')
    is_range_request = False
    range_start = 0
    range_end = None
    if range_header:
        m = re.match(r'bytes=(\d+)-(\d*)', range_header)
        if m:
            is_range_request = True
            range_start = int(m.group(1))
            range_end = int(m.group(2)) if m.group(2) else None

    logger.info('stream_track() is_ios=%s Range="%s"', is_ios, range_header)

    # ── iOS path ─────────────────────────────────────────────────────────────
    if is_ios:
        file_size = candidate.stat().st_size

        # Small range probe (e.g. Range: bytes=0-1) — confirm range support.
        is_probe = (
            is_range_request and range_start == 0
            and range_end is not None and range_end < 16
        )
        if is_probe:
            assert isinstance(range_end, int)
            null_bytes = bytes(range_end + 1)
            resp = make_response(null_bytes, 206)
            resp.headers['Content-Type'] = 'video/mp4'
            resp.headers['Accept-Ranges'] = 'bytes'
            resp.headers['Content-Range'] = (
                f'bytes 0-{range_end}/{file_size}'
            )
            resp.headers['Content-Length'] = str(range_end + 1)
            return resp

        # Continuation: iOS buffered up to range_start and needs more.
        # We use _IOS_STREAM_BITRATE_BPS (the same constant bitrate we encode
        # at) for the byte→time conversion so the estimate is accurate.
        is_continuation = range_start > 0
        start_time = url_start_time
        if is_continuation:
            start_time = url_start_time + range_start / _IOS_STREAM_BITRATE_BPS
            logger.info(
                'stream_track() Continuation: bytes=%d t_url=%.2f → t=%.2fs',
                range_start,
                url_start_time,
                start_time,
            )

        # Constant bitrate transcode for iOS so that byte→time stays accurate
        # across the whole stream. zerolatency minimises encoder buffering.
        video_codec = [
            '-c:v', 'libx264',
            '-preset', 'ultrafast',
            '-b:v', '1500k', '-maxrate', '2000k', '-bufsize', '3000k',
            '-tune', 'zerolatency',
        ]

    # ── non-iOS (desktop) path ───────────────────────────────────────────────
    else:
        is_continuation = False
        start_time = url_start_time
        # Copy H.264 at t=0 only — no CPU cost for the initial stream.
        # At t>0 (seeks) we must re-encode: -c:v copy preserves source PTS
        # (e.g. 30 s) while -c:a aac resets to 0, causing 30 s A/V desync.
        src_codec = _get_video_codec(candidate)
        if src_codec == 'h264' and start_time == 0:
            video_codec = ['-c:v', 'copy']
        else:
            video_codec = [
                '-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '23',
            ]

    # 'auto' selects the first audio stream; numeric selects by stream index.
    if audio_param == 'auto':
        audio_map = '0:a:0'
    else:
        try:
            audio_map = f'0:{int(audio_param)}'
        except ValueError:
            return 'Bad Request', 400

    # default_base_moof: moov contains full codec info (H.264 SPS/PPS, AAC
    # AudioSpecificConfig) AND the correct total duration, so the browser
    # sets video.duration correctly and the seekbar shows the full length.
    movflags = 'frag_keyframe+default_base_moof'

    cmd = [
        'ffmpeg',
        '-hide_banner',
        '-loglevel', 'error',
        '-ss', str(start_time),
        '-i', str(candidate),
        '-map', '0:v:0',
        '-map', audio_map,
        *video_codec,
        '-c:a', 'aac',
        '-b:a', '128k' if is_ios else '192k',
        '-f', 'mp4',
        '-movflags', movflags,
        'pipe:1',
    ]

    logger.info('stream_track() Running: %s', ' '.join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.error('stream_track() ffmpeg not found')
        return 'ffmpeg not available', 500

    def generate():
        total_bytes = 0
        try:
            if is_continuation:
                # Strip the ftyp+moov init segment — iOS already has it from
                # the first response; re-sending it at a non-zero byte offset
                # would confuse the MP4 parser.
                for chunk in _skip_mp4_init_boxes(proc):
                    total_bytes += len(chunk)
                    yield chunk
            else:
                while True:
                    assert isinstance(proc.stdout, int)
                    chunk = proc.stdout.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    yield chunk
        finally:
            assert isinstance(proc.stdout, int)
            proc.stdout.close()
            rc = proc.wait()
            logger.info(
                'stream_track() done: bytes=%d rc=%d t=%.2f',
                total_bytes,
                rc,
                start_time,
            )

    stream_headers = {
        'Content-Type': 'video/mp4',
        'X-Accel-Buffering': 'no',
    }
    if is_ios and is_range_request:
        stream_headers['Accept-Ranges'] = 'bytes'
        stream_headers['Content-Range'] = (
            f'bytes {range_start}-{file_size - 1}/{file_size}'
        )
        status = 206
    else:
        status = 200

    return app.response_class(
        generate(),
        status=status,
        headers=stream_headers,
    )


SUBTITLE_CACHE_DIR = DOWNLOADS_PATH / '.cache' / 'subtitle_cache'
SUBTITLE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

HLS_CACHE_DIR = DOWNLOADS_PATH / '.cache' / 'hls_cache'
HLS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Image-based subtitle codecs that cannot be converted to WebVTT.
_IMAGE_SUBTITLE_CODECS = frozenset({
    'hdmv_pgs_subtitle', 'dvd_subtitle', 'dvdsub',
    'dvb_subtitle', 'xsub',
})

# Per-file locks that serialize subtitle extraction so only one ffmpeg
# pass runs per file at a time.  35 simultaneous requests → only one
# ffmpeg process → all others wait on the lock then hit the cache.
_subtitle_locks: dict = {}
_subtitle_locks_mu = Lock()


def _subtitle_lock_for(key: str) -> Lock:
    with _subtitle_locks_mu:
        if key not in _subtitle_locks:
            _subtitle_locks[key] = Lock()
        return _subtitle_locks[key]


def _extract_all_subtitles(candidate: Path, safe_name: str) -> None:
    """Extract all text-based subtitle tracks in a single ffmpeg pass.

    Writes each track as a .vtt file in SUBTITLE_CACHE_DIR.  Must be
    called with the per-file subtitle lock already held.
    """
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'quiet',
                '-print_format', 'json',
                '-show_streams',
                str(candidate),
            ],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(result.stdout)
    except Exception as exc:
        logger.error('_extract_all_subtitles() ffprobe failed: %s', exc)
        return

    to_extract = {
        s['index']: SUBTITLE_CACHE_DIR / f'{safe_name}.{s["index"]}.vtt'
        for s in data.get('streams', [])
        if s.get('codec_type') == 'subtitle'
        and s.get('codec_name', '') not in _IMAGE_SUBTITLE_CODECS
        and not (
            SUBTITLE_CACHE_DIR / f'{safe_name}.{s.get("index", 0)}.vtt'
        ).exists()
    }
    if not to_extract:
        return

    cmd = [
        'ffmpeg', '-hide_banner', '-loglevel', 'error',
        '-i', str(candidate),
    ]
    for idx, out_path in to_extract.items():
        cmd += ['-map', f'0:{idx}', '-f', 'webvtt', str(out_path)]

    logger.info(
        '_extract_all_subtitles() extracting %d tracks from %s',
        len(to_extract), candidate.name,
    )
    try:
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        _, stderr_bytes = proc.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        logger.error(
            '_extract_all_subtitles() timed out for %s', candidate.name,
        )
        return
    except Exception as exc:
        logger.error('_extract_all_subtitles() error: %s', exc)
        return

    if proc.returncode != 0:
        logger.error(
            '_extract_all_subtitles() ffmpeg rc=%d for %s: %s',
            proc.returncode, candidate.name,
            stderr_bytes.decode(errors='replace')[:500],
        )
        return

    for idx, out_path in to_extract.items():
        if out_path.exists():
            logger.info(
                '_extract_all_subtitles() cached track %d (%d bytes)',
                idx, out_path.stat().st_size,
            )
        else:
            logger.warning(
                '_extract_all_subtitles() missing output for track %d', idx,
            )


# Track in-progress HLS generation to prevent duplicate workers.
# Maps (str(candidate), audio_idx) → subprocess.Popen object.
_hls_procs: dict = {}
_hls_lock = Lock()


def _hls_dir(candidate: Path, audio_idx: int) -> Path:
    """Return the HLS cache directory for a given file + audio track index."""
    h = hashlib.sha256(str(candidate).encode()).hexdigest()[:16]
    return HLS_CACHE_DIR / h / str(audio_idx)


def _hls_root(candidate: Path) -> Path:
    """Return the HLS cache root for a file (parent of audio-track dirs)."""
    h = hashlib.sha256(str(candidate).encode()).hexdigest()[:16]
    return HLS_CACHE_DIR / h


def _clear_file_caches(candidate: Path) -> None:
    """Delete HLS and subtitle caches for a given source file."""
    hls_root = _hls_root(candidate)
    if hls_root.exists():
        shutil.rmtree(hls_root, ignore_errors=True)
        logger.info('_clear_file_caches() HLS cache removed: %s', hls_root)

    try:
        rel = str(candidate.relative_to(DOWNLOADS_PATH.resolve()))
    except ValueError:
        rel = str(candidate)
    safe_name = rel.replace(os.sep, '_')
    for vtt in SUBTITLE_CACHE_DIR.glob(f'{safe_name}.*.vtt'):
        vtt.unlink(missing_ok=True)
        logger.info('_clear_file_caches() subtitle cache removed: %s', vtt)


_HLS_MIN_SEGMENTS = 3  # segments before we let the player start


def _hls_ready(candidate: Path, audio_idx: int) -> bool:
    """Return True if enough HLS segments exist to start playback.

    Returns True as soon as _HLS_MIN_SEGMENTS .ts files are on disk so the
    player can start immediately while ffmpeg continues generating the rest.
    Also returns True once the .done marker exists (fully generated).

    Segments that exist without either .done or .generating are stale (a
    previous generation run was killed).  We return False in that case so
    hls_status() will wipe and restart generation.
    """
    hls_d = _hls_dir(candidate, audio_idx)
    done_f = hls_d / '.done'
    if done_f.exists():
        # Sanity check: playlist must also exist.  If it doesn't, the cache
        # is corrupt (segments deleted externally, interrupted write, etc.).
        # Remove .done so hls_status() can restart generation cleanly.
        if not (hls_d / 'playlist.m3u8').exists():
            logger.warning(
                '_hls_ready() corrupt cache (no playlist), clearing .done:'
                ' %s audio=%d',
                candidate.name, audio_idx,
            )
            done_f.unlink(missing_ok=True)
            return False
        return True
    key = (str(candidate), audio_idx)
    with _hls_lock:
        active = key in _hls_procs and _hls_procs[key].poll() is None
    if active or (hls_d / '.generating').exists():
        return sum(1 for _ in hls_d.glob('seg*.ts')) >= _HLS_MIN_SEGMENTS
    return False


def _latest_seg_num(hls_d: Path) -> int:
    """Return highest seg*.ts number on disk, or -1 if none."""
    segs = list(hls_d.glob('seg*.ts'))
    if not segs:
        return -1
    return max(int(f.stem[3:]) for f in segs)


def _generate_hls_bg(
        candidate: Path,
        audio_idx: int,
        start_seg: int = 0,
) -> None:
    """Generate HLS segments for one audio track in a background thread.

    Uses -c:v copy when source is already H.264 (remux only, near-zero CPU),
    encodes to H.264 otherwise.  Audio always transcoded to AAC.

    When start_seg > 0 (seek restart) any existing ffmpeg proc for this key is
    killed and a new one is started at the requested segment position.
    """
    key = (str(candidate), audio_idx)
    with _hls_lock:
        active = key in _hls_procs and _hls_procs[key].poll() is None
        if start_seg == 0 and active:
            return
        if start_seg > 0:
            # Collapse concurrent seek restarts: if a restart for this key is
            # already in progress (proc is active), bail out.  The first caller
            # wins; subsequent segment-request threads will keep polling.
            if active:
                return
            existing = _hls_procs.get(key)
            if existing is not None and existing.poll() is None:
                existing.terminate()

    hls_d = _hls_dir(candidate, audio_idx)
    hls_d.mkdir(parents=True, exist_ok=True)
    playlist = hls_d / 'playlist.m3u8'
    done = hls_d / '.done'
    generating_marker = hls_d / '.generating'

    if start_seg == 0:
        if done.exists():
            return

        # Cross-worker guard: another worker may already be running ffmpeg.
        if generating_marker.exists():
            return

        # Clean up stale partial run (killed ffmpeg, no .done, no .generating).
        if not generating_marker.exists() and any(hls_d.glob('seg*.ts')):
            logger.warning(
                '_generate_hls_bg() stale cache, cleaning: %s audio=%d',
                candidate.name, audio_idx,
            )
            for f in hls_d.glob('seg*.ts'):
                f.unlink(missing_ok=True)
            for f in (playlist,):
                if f.exists():
                    f.unlink()

    generating_marker.touch()

    if start_seg == 0:
        # Store duration before ffmpeg starts. hls_playlist() uses this to
        # serve a dynamically-built VOD playlist (with #EXT-X-ENDLIST) instead
        # of ffmpeg's live playlist, giving the player a full seekbar from the
        # first request.
        duration = _get_video_duration(candidate)
        if duration:
            (hls_d / 'duration.txt').write_text(str(duration))

    vcodec = _get_video_codec(candidate)
    pix_fmt = _get_video_pix_fmt(candidate)
    # Copy H.264 8-bit to avoid re-encoding (segments appear in seconds).
    # h264_mp4toannexb converts AVCC→Annex B required by MPEG-TS.
    # Non-H.264 or 10-bit sources are encoded to ensure browser compatibility.
    if vcodec == 'h264' and pix_fmt == 'yuv420p':
        video_args = ['-c:v', 'copy', '-bsf:v', 'h264_mp4toannexb']
    else:
        video_args = [
            '-c:v', 'libx264', '-preset', 'veryfast',
            '-crf', '23', '-pix_fmt', 'yuv420p',
        ]

    seek_args = []
    if start_seg > 0:
        seek_args = ['-ss', str(start_seg * _HLS_SEGMENT_TIME)]

    cmd = [
        'ffmpeg', '-hide_banner', '-loglevel', 'error',
        *seek_args,
        '-i', str(candidate),
        '-map', '0:v:0',
        # absolute stream index, same as subtitle_track
        '-map', f'0:{audio_idx}',
        *video_args,
        '-c:a', 'aac', '-b:a', '128k', '-ac', '2',
        '-f', 'hls',
        '-hls_time', str(_HLS_SEGMENT_TIME),
        '-hls_list_size', '0',
        '-hls_flags', 'independent_segments',
        '-start_number', str(start_seg),
        '-hls_segment_filename', str(hls_d / 'seg%05d.ts'),
        str(playlist),
    ]
    logger.info(
        '_generate_hls_bg() start: %s audio=%d start_seg=%d',
        candidate.name, audio_idx, start_seg,
    )
    proc = None
    try:
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        with _hls_lock:
            _hls_procs[key] = proc
        _, stderr_bytes = proc.communicate(timeout=7200)
        if proc.returncode == 0 and start_seg == 0:
            done.touch()
            logger.info(
                '_generate_hls_bg() done: %s audio=%d',
                candidate.name, audio_idx,
            )
        elif proc.returncode not in (0, -15, -9, 255):
            # -15/-9 = killed by signal; 255 = ffmpeg's clean SIGTERM exit
            stderr_text = (
                (stderr_bytes or b'').decode('utf-8', errors='replace').strip()
            )
            logger.error(
                '_generate_hls_bg() rc=%d: %s audio=%d\n%s',
                proc.returncode, candidate.name, audio_idx, stderr_text,
            )
            # Clean up partial segments so _hls_ready won't return True on
            # stale corrupt data (avoids MEDIA_ERR_SRC_NOT_SUPPORTED).
            for f in hls_d.glob('seg*.ts'):
                f.unlink(missing_ok=True)
            playlist.unlink(missing_ok=True)
    except Exception as exc:
        logger.exception('_generate_hls_bg() exception: %s', exc)
    finally:
        generating_marker.unlink(missing_ok=True)
        with _hls_lock:
            if _hls_procs.get(key) is proc:
                del _hls_procs[key]


@app.route('/hls-cancel/<path:filename>', methods=['POST'])
def hls_cancel(filename):
    """Terminate any active HLS generation for a file (all audio tracks).

    Called by the player when the user navigates away so server resources
    are freed immediately instead of continuing to encode unused video.
    """
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()
    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403

    candidate_str = str(candidate)
    killed = 0
    with _hls_lock:
        for key, proc in list(_hls_procs.items()):
            if key[0] == candidate_str and proc.poll() is None:
                proc.terminate()
                del _hls_procs[key]
                # Remove .generating immediately so _hls_ready returns False
                # on the next poll — prevents a reloading page from seeing
                # the dying process as "active" (MEDIA_ERR_SRC_NOT_SUPPORTED).
                _hls_dir(candidate, key[1]).joinpath('.generating').unlink(
                    missing_ok=True,
                )
                killed += 1
                logger.info(
                    'hls_cancel() terminated ffmpeg: %s audio=%d',
                    candidate.name, key[1],
                )

    return jsonify({'status': 'cancelled', 'killed': killed})


@app.route('/hls-status/<path:filename>')
def hls_status(filename):
    """Return HLS generation status; kick off generation if not started."""
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()
    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403
    if not candidate.exists() or not candidate.is_file():
        return 'Not Found', 404

    try:
        audio_idx = int(request.args.get('audio', 0))
    except ValueError:
        return 'Bad Request', 400

    if _hls_ready(candidate, audio_idx):
        return jsonify({'status': 'ready'})

    key = (str(candidate), audio_idx)
    with _hls_lock:
        generating = key in _hls_procs and _hls_procs[key].poll() is None

    if not generating:
        Thread(
            target=_generate_hls_bg,
            args=(candidate, audio_idx),
            daemon=True,
        ).start()

    return jsonify({'status': 'generating'}), 202


@app.route('/hls/<path:filename>/<int:audio_idx>/playlist.m3u8')
def hls_playlist(filename, audio_idx):
    """Serve the HLS m3u8 playlist, triggering generation if needed.

    The playlist is served as soon as _HLS_MIN_SEGMENTS segments exist, even
    while ffmpeg is still running.  Without #EXT-X-ENDLIST hls.js treats it as
    a live stream and re-polls, picking up new segments automatically.  Once
    ffmpeg finishes and writes .done, the playlist gains #EXT-X-ENDLIST and
    hls.js switches to full VOD mode (seekable full-length bar).
    """
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()
    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403
    if not candidate.exists() or not candidate.is_file():
        return 'Not Found', 404

    if not _hls_ready(candidate, audio_idx):
        key = (str(candidate), audio_idx)
        with _hls_lock:
            generating = key in _hls_procs and _hls_procs[key].poll() is None
        if not generating:
            Thread(
                target=_generate_hls_bg,
                args=(candidate, audio_idx),
                daemon=True,
            ).start()
        return jsonify({'status': 'generating'}), 202

    hls_d = _hls_dir(candidate, audio_idx)
    if not (hls_d / 'playlist.m3u8').exists():
        return jsonify({'status': 'generating'}), 202

    done_file = hls_d / '.done'
    dur_file = hls_d / 'duration.txt'

    if done_file.exists():
        # Serve ffmpeg's actual playlist — exact EXTINF for subtitle sync
        response = make_response(
            send_file(
                str(hls_d / 'playlist.m3u8'),
                mimetype='application/vnd.apple.mpegurl',
            ),
        )
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    # Still generating: serve dynamic VOD playlist (full seekbar, ~timings)
    if dur_file.exists():
        try:
            duration = float(dur_file.read_text().strip())
            response = make_response(_build_vod_playlist(duration), 200)
            response.headers['Content-Type'] = 'application/vnd.apple.mpegurl'
            response.headers['Cache-Control'] = 'no-store'
            return response
        except Exception:
            pass

    return jsonify({'status': 'generating'}), 202


@app.route('/hls/<path:filename>/<int:audio_idx>/<segment>')
def hls_segment(filename, audio_idx, segment):
    """Serve an HLS .ts segment, waiting up to 60 s for it to be generated."""
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()
    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403

    hls_d = _hls_dir(candidate, audio_idx)
    target = (hls_d / segment).resolve()
    if not str(target).startswith(str(hls_d.resolve())):
        return 'Forbidden', 403

    # Parse segment number: seg00450.ts → 450
    try:
        seg_num = int(segment[3:segment.index('.')])
    except (ValueError, IndexError):
        return 'Not Found', 404

    deadline = time.time() + 60
    restarted = False
    while not target.exists() and time.time() < deadline:
        time.sleep(0.5)
        if not restarted and time.time() > deadline - 57:  # after ~3s waiting
            latest = _latest_seg_num(hls_d)
            if seg_num > latest + 30:  # more than 30 segments ahead (120s)
                restarted = True
                start_from = max(0, seg_num - 2)
                logger.info(
                    'hls_segment() seek restart: seg=%d latest=%d file=%s',
                    seg_num, latest, candidate.name,
                )
                Thread(
                    target=_generate_hls_bg,
                    args=(candidate, audio_idx, start_from),
                    daemon=True,
                ).start()

    if not target.exists():
        return 'Not Found', 404

    response = make_response(send_file(str(target), mimetype='video/MP2T'))
    # Segments are immutable once written — safe to cache aggressively.
    response.headers['Cache-Control'] = 'public, max-age=86400, immutable'
    return response


@app.route('/subtitle-track/<path:filename>')
def subtitle_track(filename):
    """Extract a subtitle stream as WebVTT for client-side rendering.

    All text-based subtitle tracks are extracted in a single ffmpeg pass
    and cached under SUBTITLE_CACHE_DIR.  Concurrent requests for the same
    file wait on a per-file lock so only one ffmpeg process runs at a time;
    subsequent requests are served directly from cache.
    """
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403
    if not candidate.exists() or not candidate.is_file():
        return 'Not Found', 404

    try:
        stream_index = int(request.args.get('index', 0))
    except ValueError:
        return 'Bad Request', 400

    safe_name = filename.replace(os.sep, '_')
    cache_file = SUBTITLE_CACHE_DIR / f'{safe_name}.{stream_index}.vtt'

    # Fast path: already cached — no lock needed
    if cache_file.exists():
        logger.info(
            'subtitle_track() cache hit index=%d %s', stream_index, filename,
        )
        return app.response_class(
            cache_file.read_bytes(),
            status=200,
            headers={'Content-Type': 'text/vtt; charset=utf-8'},
        )

    # Extract all subtitle tracks in one ffmpeg pass, serialized per file
    lock = _subtitle_lock_for(safe_name)
    with lock:
        # Re-check under lock: another greenlet may have just extracted it
        if cache_file.exists():
            logger.info(
                'subtitle_track() cache hit index=%d %s (post-lock)',
                stream_index, filename,
            )
        else:
            _extract_all_subtitles(candidate, safe_name)

    if not cache_file.exists():
        logger.error(
            'subtitle_track() extraction failed index=%d %s',
            stream_index, filename,
        )
        return 'Subtitle extraction failed', 500

    logger.info(
        'subtitle_track() serving index=%d %s', stream_index, filename,
    )
    return app.response_class(
        cache_file.read_bytes(),
        status=200,
        headers={'Content-Type': 'text/vtt; charset=utf-8'},
    )


if __name__ == '__main__':
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    finally:
        stop_monitor()
