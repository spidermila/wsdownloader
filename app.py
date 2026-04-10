import hashlib
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from threading import Thread
from time import sleep
from typing import Optional
from urllib.parse import urlparse

import gevent.subprocess
import requests
from flask import flash
from flask import Flask
from flask import g
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_socketio import emit
from flask_socketio import SocketIO
from passlib.hash import md5_crypt


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

    def get_file_name(self) -> str:
        try:
            _purl = Path(urlparse(url=self.url).path)
            return _purl.name
        except:  # NOQA: E722
            logger.error('unable to extract file name from url %s', self.url)
            raise

    def get_human_size(self) -> str:
        return _human_size(self.size_bytes)


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
                size_bytes INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                token TEXT DEFAULT '',
                auto_download INTEGER NOT NULL DEFAULT 1,
                user_name TEXT DEFAULT '',
                password_hash TEXT DEFAULT '',
                dark_mode INTEGER NOT NULL DEFAULT 0
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
            conn.execute("""
                ALTER TABLE settings
                ADD COLUMN dark_mode INTEGER NOT NULL DEFAULT 0
            """)

        cursor = conn.execute('PRAGMA table_info(links)')
        columns = [row[1] for row in cursor.fetchall()]
        if 'size_bytes' not in columns:
            conn.execute("""
                ALTER TABLE links
                ADD COLUMN size_bytes INTEGER DEFAULT 0
            """)

        conn.commit()
    finally:
        conn.close()


def get_settings() -> dict:
    db = get_db()
    row = db.execute("""
        SELECT id, token, auto_download, user_name, password_hash, dark_mode
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


def read_links_from_db() -> list[Link]:
    db = get_db()
    rows = db.execute("""
        SELECT id, url, created_at, status, pct_downloaded, size_bytes
        FROM links ORDER by created_at DESC
    """).fetchall()
    links: list[Link] = []
    if len(rows) == 0:
        logger.info('read_links_from_db() No links found in database')
        return links
    for row in rows:
        _link = Link(url=row['url'])
        _link.status = row['status']
        _link.pct_downloaded = row['pct_downloaded']
        _link.size_bytes = row['size_bytes']
        links.append(_link)
    return links


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


def validate_url(url) -> str:
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


def test_url(url: str) -> bool:
    response = requests.head(url)
    if response.status_code == 200:
        logger.info('URL test succeeded: %s', url)
        return True
    logger.info('URL test failed: %s', url)
    return False


def add_link_if_new(link_raw: str) -> tuple[bool, str]:
    url = (link_raw or '').strip()
    if not url:
        return (False, '')

    db = get_db()
    try:
        cur = db.execute(
            'INSERT OR IGNORE INTO links (url) VALUES (?)', (url,),
        )
        db.commit()
        added = cur.rowcount > 0
        if added:
            logger.info('add_link_if_new() Link added: %s', url)
        else:
            logger.warning('add_link_if_new() Link already exists: %s', url)
        return (added, url)
    except sqlite3.Error:
        logger.error('add_link_if_new() Error adding link: %s', url)
        return (False, url)


def _human_size(num_bytes: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(num_bytes)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.0f} {u}" if u == 'B' else f"{size:.1f} {u}"
        size /= 1024
    return '0 B'


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


def list_downloaded_files() -> list[dict]:
    files: list[dict] = []
    try:
        root = DOWNLOADS_PATH.resolve()
        if not root.exists():
            return files
        for p in sorted(root.iterdir(), key=lambda x: x.name.lower()):
            if p.is_file() and p.name[0] != '.':
                stat = p.stat()
                files.append({
                    'name': p.name,
                    'size': _human_size(stat.st_size),
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
            SELECT url, status, pct_downloaded, size_bytes
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
                f"{row['pct_downloaded']}:{row['size_bytes']}"
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
                if f.is_file() and f.name[0] != '.'
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
                    SELECT url, status, pct_downloaded, size_bytes
                    FROM links ORDER BY created_at DESC
                """).fetchall()

                # Also fetch errors
                error_rows = conn.execute("""
                    SELECT id, file_id, file_name, error_type, error_message,
                           created_at, retry_count
                    FROM download_errors ORDER BY created_at DESC
                """).fetchall()
                conn.close()

                links = []
                for row in rows:
                    link = Link(url=row['url'])
                    link.status = row['status']
                    link.pct_downloaded = row['pct_downloaded']
                    link.size_bytes = row['size_bytes']
                    links.append(link_to_dict(link))

                errors = [dict(row) for row in error_rows]
                files = list_downloaded_files()
                fs = get_fs_usage(DOWNLOADS_PATH)

                socketio.emit(
                    'full_update', {
                        'links': links,
                        'files': files,
                        'fs': fs,
                        'errors': errors,
                    },
                )
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


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url_input = request.form.get('link', '')
        val_message = validate_url(url_input)

        if val_message == 'ok' and not test_url(url_input):
            message = 'Link nedostupný'
            logger.error('index() %s, input was: %s', message, url_input)
            flash(message, 'error')
        elif val_message != 'ok':
            logger.error(
                'index() URL validation failed, input was: %s', url_input,
            )
            flash(val_message, 'error')
        else:
            added, value = add_link_if_new(url_input)
            if added:
                logger.info('index() Link added: %s', value)
                flash(f"Přidáno: {value}", 'success')
                socketio.emit('link_added', link_to_dict(Link(value)))
            else:
                logger.info('index() Link already exists: %s', value)
                flash(f"Již existuje: {value}", 'warning')
        return redirect(url_for('index'))

    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    errors = read_download_errors()

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


@app.route('/delete', methods=['POST'])
def delete_link():
    url_to_delete = (request.form.get('url') or '').strip()
    if not url_to_delete:
        logger.error('delete_link() No URL provided')
        flash('Žádná URL poskytnuta.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('DELETE FROM links WHERE url = ?', (url_to_delete,))
    db.commit()

    if cur.rowcount > 0:
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
            logger.info('delete_file() File deleted: %s', candidate)
            flash(f"Odstraněn soubor: {filename}", 'success')
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

    settings = get_settings()
    return render_template('player.html', filename=filename, settings=settings)


@socketio.on('connect')
def handle_connect():
    """Send current state when client connects."""
    logger.info('handle_connect() Client connected via WebSocket')
    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    errors = read_download_errors()
    emit(
        'full_update', {
            'links': [link_to_dict(link) for link in links],
            'files': files,
            'fs': fs,
            'errors': errors,
        },
    )


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
    emit(
        'full_update', {
            'links': [link_to_dict(link) for link in links],
            'files': files,
            'fs': fs,
            'errors': errors,
        },
    )


def link_to_dict(link: Link) -> dict:
    return {
        'url': link.url,
        'file_name': link.get_file_name(),
        'status': link.status,
        'pct_downloaded': link.pct_downloaded,
        'size_bytes': link.size_bytes,
        'human_size': link.get_human_size(),
    }


@app.after_request
def add_no_cache(response):
    if request.endpoint in (
        'stream_file', 'player', 'stream_track', 'subtitle_track',
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
            if codec in ('hdmv_pgs_subtitle', 'dvd_subtitle', 'dvdsub'):
                continue
            subtitle_tracks.append({
                'index': index,
                'label': _track_label(
                    len(subtitle_tracks) + 1, language, title, codec,
                    fallback_prefix='Titulky',
                ),
            })

    return jsonify({
        'audio_tracks': audio_tracks,
        'subtitle_tracks': subtitle_tracks,
    })


@app.route('/stream-track/<path:filename>')
def stream_track(filename):
    """
    Stream a file via FFmpeg with a selected audio track.
    Query params:
      audio=<stream_index>  — ffmpeg stream index of the audio track
      t=<seconds>           — start time offset for seeking (default: 0)
    """
    root = DOWNLOADS_PATH.resolve()
    candidate = (root / filename).resolve()

    if not str(candidate).startswith(str(root) + os.sep):
        return 'Forbidden', 403
    if not candidate.exists() or not candidate.is_file():
        return 'Not Found', 404

    try:
        audio_index = int(request.args.get('audio', 0))
        start_time = float(request.args.get('t', 0))
    except ValueError:
        return 'Bad Request', 400

    # When seeking to a non-zero offset, mixing -c:v copy with -c:a aac causes
    # A/V timestamp desync: video preserves original PTS (~T) while the AAC
    # encoder resets its clock to 0. Re-encoding video fixes the alignment.
    if start_time > 0:
        video_codec = ['-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '23']
    else:
        video_codec = ['-c:v', 'copy']

    cmd = [
        'ffmpeg',
        '-hide_banner',
        '-loglevel', 'error',
        '-ss', str(start_time),
        '-i', str(candidate),
        '-map', '0:v:0',
        '-map', f'0:{audio_index}',
        *video_codec,
        '-c:a', 'aac',
        '-b:a', '192k',
        '-f', 'mp4',
        '-movflags', 'frag_keyframe+empty_moov',
        'pipe:1',
    ]

    logger.info('stream_track() Running: %s', ' '.join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.error('stream_track() ffmpeg not found')
        return 'ffmpeg not available', 500

    def generate():
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.stdout.close()
            proc.wait()

    return app.response_class(
        generate(),
        status=200,
        headers={
            'Content-Type': 'video/mp4',
            'X-Accel-Buffering': 'no',
        },
    )


SUBTITLE_CACHE_DIR = DATA_DIR / 'subtitle_cache'
SUBTITLE_CACHE_DIR.mkdir(parents=True, exist_ok=True)


@app.route('/subtitle-track/<path:filename>')
def subtitle_track(filename):
    """Extract a subtitle stream as WebVTT for client-side rendering.

    Extracted VTT files are cached under DATA_DIR/subtitle_cache so that
    only the first request for a given file+track is slow.
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

    if cache_file.exists():
        logger.info(
            'subtitle_track() Cache hit for index %d from %s',
            stream_index, filename,
        )
        return app.response_class(
            cache_file.read_bytes(),
            status=200,
            headers={'Content-Type': 'text/vtt; charset=utf-8'},
        )

    logger.info(
        'subtitle_track() Extracting index %d from %s', stream_index, filename,
    )

    cmd = [
        'ffmpeg',
        '-hide_banner',
        '-loglevel', 'error',
        '-i', str(candidate),
        '-map', f'0:{stream_index}',
        '-f', 'webvtt',
        'pipe:1',
    ]
    try:
        proc = gevent.subprocess.Popen(
            cmd,
            stdout=gevent.subprocess.PIPE,
            stderr=gevent.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.error('subtitle_track() ffmpeg not found')
        return 'ffmpeg not available', 500

    try:
        vtt_bytes, _ = proc.communicate(timeout=300)
    except gevent.subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        logger.error('subtitle_track() ffmpeg timed out')
        return 'Subtitle extraction timed out', 500
    except Exception as exc:
        proc.kill()
        logger.error('subtitle_track() read error: %s', exc)
        return 'Subtitle extraction failed', 500

    if proc.returncode != 0 or not vtt_bytes:
        logger.error(
            'subtitle_track() ffmpeg failed, rc=%d bytes=%d',
            proc.returncode, len(vtt_bytes),
        )
        return 'Subtitle extraction failed', 500

    cache_file.write_bytes(vtt_bytes)
    logger.info(
        'subtitle_track() done, %d bytes, cached to %s',
        len(vtt_bytes), cache_file.name,
    )
    return app.response_class(
        vtt_bytes,
        status=200,
        headers={'Content-Type': 'text/vtt; charset=utf-8'},
    )


if __name__ == '__main__':
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    finally:
        stop_monitor()
