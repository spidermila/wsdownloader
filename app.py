import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from threading import Thread
from time import sleep
from typing import Optional
from urllib.parse import urlparse

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

from logger import Logger


app = Flask(__name__)

logger = Logger('app.py')

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

socketio = SocketIO(app, cors_allowed_origins='*')

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
            # return self.url.split('/')[-1]
            _purl = Path(urlparse(url=self.url).path)
            return _purl.name
        except:  # NOQA: E722
            message = f'unable to extract file name from url {self.url}='
            logger.log_message(message, 0)
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

        # NEW: settings singleton table (id is forced to be 1)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                token TEXT DEFAULT '',
                auto_download INTEGER NOT NULL DEFAULT 1, -- 0/1 boolean
                user_name TEXT DEFAULT '',
                password_hash TEXT DEFAULT '',
                dark_mode INTEGER NOT NULL DEFAULT 0 -- 0/1 boolean
            )
        """)
        conn.execute('INSERT OR IGNORE INTO settings (id) VALUES (1)')

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
        message = f'Failed to get salt for user {user_name}'
        logger.log_message(message, 0)
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
        message = f'Connection failed {e.strerror=}, {e.errno=}, {e.filename=}'
        logger.log_message(message, 0)
        return ('Connection failed', '<dummy></dummy>')
    rc = response.status_code
    if not rc == 200:
        message = f'Got RC: {rc}, {response.text=}'
        logger.log_message(message, 0)
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
        (settings['user_name'] + ':Webshare:' + settings['password_hash']).encode('utf-8'),  # NOQA: E501
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
            message = 'login OK'
            logger.log_message(message, 2)
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
    _, payload = api_post(url, data=data, headers=headers)
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            message = 'check_token() OK'
            logger.log_message(message, 2)
            return True
    message = 'check_token() failed'
    logger.log_message(message, 0)
    return False


def read_links_from_db() -> list[Link]:
    db = get_db()
    rows = db.execute("""
        SELECT id, url, created_at, status, pct_downloaded, size_bytes
        FROM links ORDER by created_at DESC
    """).fetchall()
    links: list[Link] = []
    if len(rows) == 0:
        message = 'read_links_from_db() No links found in database'
        logger.log_message(message, 2)
        return links
    for row in rows:
        _link = Link(url=row['url'])
        _link.status = row['status']
        _link.pct_downloaded = row['pct_downloaded']
        _link.size_bytes = row['size_bytes']
        links.append(_link)
    return links


def validate_url(url) -> str:
    URL_RE = re.compile(
        r"""
    ^
    (?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://                # scheme://
    (?:(?P<userinfo>[^/\s@]+(?::[^/\s@]*)?)@)?            # optional user:pass@
    (?P<host>
        localhost
    | \[[0-9A-Fa-f:.]+\]                                 # IPv6 in [brackets]
    | \d{1,3}(?:\.\d{1,3}){3}                            # IPv4 (checked further in code)  # NOQA: E501
    | (?:[A-Za-z0-9]                                     # domain
            (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
        )
        (?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+
        \.?
    )
    (?::(?P<port>\d{1,5}))?                                # optional :port
    (?P<path>/[^\s?#]*)?                                   # optional /path
    (?:\?(?P<query>[^\s#]*))?                              # optional ?query
    (?:\#(?P<fragment>[^\s]*))?                            # optional #fragment
    $
    """, re.VERBOSE,
    )

    if not URL_RE.fullmatch(url):
        return 'Neplatný link.'

    p = urlparse(url)
    allowed_schemes = {'http', 'https'}
    # Optionally restrict schemes (recommended when using requests)
    if allowed_schemes is not None and p.scheme.lower() not in allowed_schemes:
        message = f"Invalid URL scheme: {p.scheme}, allowed: {allowed_schemes}"
        logger.log_message(message, 0)
        return 'Neplatný link.'

    if p.port is not None and not (0 <= p.port <= 65535):
        message = f"Invalid URL port: {p.port}"
        logger.log_message(message, 0)
        return 'Neplatný link.'

    # IPv4 range check (regex above only checks the shape)
    host = p.hostname or ''
    if host.count('.') == 3 and all(
        part.isdigit() for part in host.split('.')
    ):
        parts = [int(x) for x in host.split('.')]
        if any(not (0 <= x <= 255) for x in parts):
            message = f"Invalid IPv4 address: {host}"
            logger.log_message(message, 0)
            return 'Neplatný link.'
    message = f"URL validated successfully: {url}"
    logger.log_message(message, 2)
    return 'ok'


def test_url(url: str) -> bool:
    response = requests.head(url)
    if response.status_code == 200:
        message = f"URL test succeeded: {url}"
        logger.log_message(message, 2)
        return True
    message = f"URL test failed: {url}"
    logger.log_message(message, 2)
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
        added = cur.rowcount > 0  # 1 if inserted, 0 if ignored (duplicate)
        message = f"add_link_if_new() Link {'added' if added else 'already exists'}: {url}"  # NOQA: E501
        logger.log_message(message, 2 if added else 1)
        return (added, url)
    except sqlite3.Error:
        # For robustness; in a simple app we just surface a generic failure
        message = f"add_link_if_new() Error adding link: {url}"
        logger.log_message(message, 0)
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
    # Prefer the configured downloads path if none provided
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
        message = f"get_fs_usage() Error getting fs usage for {base_path}: {e}"
        logger.log_message(message, 0)
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
        message = f"list_downloaded_files() Error listing files in {DOWNLOADS_PATH}: {e}"  # NOQA: E501
        logger.log_message(message, 0)
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
        conn.close()

        # Include links state
        state_parts = []
        for row in rows:
            state_parts.append(
                f"{row['url']}:{row['status']}:{row['pct_downloaded']}:{row['size_bytes']}",  # NOQA: E501
            )

        # Include files state
        if DOWNLOADS_PATH.exists():
            files = sorted([
                f.name for f in DOWNLOADS_PATH.iterdir()
                if f.is_file() and f.name[0] != '.'
            ])
            state_parts.extend(files)

        state_str = '|'.join(state_parts)
        return hashlib.md5(state_str.encode()).hexdigest()
    except Exception as e:
        message = f"get_db_state_hash() Error computing state hash: {e}"
        logger.log_message(message, 0)
        return ''


def monitor_database_changes():
    """Background thread that monitors for database/filesystem changes."""
    global _last_db_hash

    message = 'monitor_database_changes() Thread started'
    logger.log_message(message, 2)

    # Initialize with current state
    _last_db_hash = get_db_state_hash()

    while _monitor_running:
        try:
            sleep(5)

            current_hash = get_db_state_hash()

            if current_hash and current_hash != _last_db_hash:
                # print(f"Change detected - old: {_last_db_hash[:8]}, new: {current_hash[:8]}")  # NOQA: E501
                _last_db_hash = current_hash

                # Get fresh data
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""
                    SELECT url, status, pct_downloaded, size_bytes
                    FROM links ORDER BY created_at DESC
                """).fetchall()
                conn.close()

                links = []
                for row in rows:
                    link = Link(url=row['url'])
                    link.status = row['status']
                    link.pct_downloaded = row['pct_downloaded']
                    link.size_bytes = row['size_bytes']
                    links.append(link_to_dict(link))

                files = list_downloaded_files()
                fs = get_fs_usage(DOWNLOADS_PATH)

                # Emit to all connected clients
                socketio.emit(
                    'full_update', {
                        'links': links,
                        'files': files,
                        'fs': fs,
                    },
                )
                message = f"monitor_database_changes() Emitted update: {len(links)} links, {len(files)} files"  # NOQA: E501
                logger.log_message(message, 2)

        except Exception as e:
            message = f"monitor_database_changes() Error in monitor thread: {e}"  # NOQA: E501
            logger.log_message(message, 0)
            import traceback
            traceback.print_exc()

    message = 'monitor_database_changes() Thread stopped'
    logger.log_message(message, 2)


def start_monitor():
    """Start the background monitoring thread."""
    global _monitor_thread, _monitor_running

    if _monitor_thread is None or not _monitor_thread.is_alive():
        _monitor_running = True
        _monitor_thread = Thread(target=monitor_database_changes, daemon=True)
        _monitor_thread.start()
        message = 'start_monitor() Monitor thread started'
        logger.log_message(message, 2)


def stop_monitor():
    """Stop the background monitoring thread."""
    global _monitor_running
    _monitor_running = False
    message = 'stop_monitor() Monitor thread stopping...'
    logger.log_message(message, 2)


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
        message = validate_url(url_input)

        if message == 'ok' and not test_url(url_input):
            message = 'Link nedostupný'
            logger.log_message(f"index() {message}, input was: {url_input}", 0)
            flash(message, 'error')
        elif message != 'ok':
            message = f"index() URL validation failed, input was: {url_input}"
            logger.log_message(message, 0)
            flash(message, 'error')
        else:
            added, value = add_link_if_new(url_input)
            if added:
                message = f"index() Link added: {value}"
                logger.log_message(message, 2)
                flash(f"Přidáno: {value}", 'success')
                socketio.emit('link_added', link_to_dict(Link(value)))
            else:
                message = f"index() Link already exists: {value}"
                logger.log_message(message, 2)
                flash(f"Již existuje: {value}", 'warning')
        return redirect(url_for('index'))

    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)

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
        message = 'save_login() Missing username or password'
        logger.log_message(message, 0)
        flash('Je třeba vyplnit uživatelské jméno i heslo.', 'error')
        return redirect(url_for('index'))

    if not save_credentials(user_name, password):
        message = f'save_login() Failed to save credentials for user {user_name}'  # NOQA: E501
        logger.log_message(message, 0)
        flash('Přihlášení selhalo', 'error')
        return redirect(url_for('index'))
    token = login_and_get_token()
    if not token:
        message = f'save_login() Failed to obtain token for user {user_name}'
        logger.log_message(message, 0)
        flash('Přihlášení selhalo', 'error')
        return redirect(url_for('index'))
    save_token_value(token)
    message = f'save_login() User {user_name} logged in successfully'
    logger.log_message(message, 2)
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
    message = 'logout() User logged out successfully'
    logger.log_message(message, 2)
    flash('Odhlášení proběhlo úspěšně', 'success')
    return redirect(url_for('index'))


@app.route('/delete', methods=['POST'])
def delete_link():
    url_to_delete = (request.form.get('url') or '').strip()
    if not url_to_delete:
        message = 'delete_link() No URL provided'
        logger.log_message(message, 0)
        flash('Žádná URL poskytnuta.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cur = db.execute('DELETE FROM links WHERE url = ?', (url_to_delete,))
    db.commit()

    if cur.rowcount > 0:
        message = f'delete_link() Link deleted: {url_to_delete}'
        logger.log_message(message, 2)
        flash(f"Odstraněno: {url_to_delete}", 'success')
        socketio.emit('link_deleted', {'url': url_to_delete})
    else:
        message = f'delete_link() Link not found: {url_to_delete}'
        logger.log_message(message, 1)
        flash(f"Nenalezeno: {url_to_delete}", 'error')
    return redirect(url_for('index'))


@app.route('/delete-file', methods=['POST'])
def delete_file():
    filename = (request.form.get('filename') or '').strip()
    if not filename:
        message = 'delete_file() No filename provided'
        logger.log_message(message, 0)
        flash('Zadán název souboru.', 'error')
        return redirect(url_for('index'))

    try:
        root = DOWNLOADS_PATH.resolve()
        candidate = (root / filename).resolve()

        if not str(candidate).startswith(str(root) + os.sep):
            message = f"delete_file() Invalid file path: {candidate} is outside of {root}"  # NOQA: E501
            logger.log_message(message, 0)
            flash('Neplatná cesta k souboru.', 'error')
            return redirect(url_for('index'))

        if candidate.exists() and candidate.is_file():
            candidate.unlink()
            message = f'delete_file() File deleted: {candidate}'
            logger.log_message(message, 2)
            flash(f"Odstraněn soubor: {filename}", 'success')
            socketio.emit('file_deleted', {'filename': filename})
        else:
            message = f'delete_file() File not found: {candidate}'
            logger.log_message(message, 1)
            flash(f"Soubor nenalezen: {filename}", 'error')
    except Exception as e:
        message = f"delete_file() Error deleting file {filename}: {e}"
        logger.log_message(message, 0)
        flash(f"Chyba při odstraňování souboru: {filename}", 'error')

    return redirect(url_for('index'))


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
    message = f'update_auto_download() Auto-download {"enabled" if enabled else "disabled"}'  # NOQA: E501
    logger.log_message(message, 2)
    msg = f'Automatické stahování {"zapnuto" if enabled else "vypnuto"}.'
    flash(msg, 'success')
    return redirect(url_for('index'))


@app.post('/settings/dark-mode')
def update_dark_mode():
    dark_mode = 1 if request.form.get('dark_mode') else 0
    db = get_db()
    db.execute('UPDATE settings SET dark_mode = ? WHERE id = 1', (dark_mode,))
    db.commit()
    message = f'update_dark_mode() Dark mode {"enabled" if dark_mode else "disabled"}'  # NOQA: E501
    logger.log_message(message, 2)
    return redirect(url_for('index'))


@app.route('/help', methods=['GET'])
def help_page():
    settings = get_settings()
    return render_template('help.html', settings=settings)


@socketio.on('connect')
def handle_connect():
    """Send current state when client connects."""
    message = 'handle_connect() Client connected via WebSocket'
    logger.log_message(message, 2)
    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    emit(
        'full_update', {
            'links': [link_to_dict(link) for link in links],
            'files': files,
            'fs': fs,
        },
    )


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    message = 'handle_disconnect() Client disconnected from WebSocket'
    logger.log_message(message, 2)


@socketio.on('request_update')
def handle_request_update():
    links = read_links_from_db()
    files = list_downloaded_files()
    fs = get_fs_usage(DOWNLOADS_PATH)
    emit(
        'full_update', {
            'links': [link_to_dict(link) for link in links],
            'files': files,
            'fs': fs,
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
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'  # NOQA: E501
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    finally:
        stop_monitor()
