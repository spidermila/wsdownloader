import logging
import os
import shutil
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from time import sleep
from time import time
from typing import Optional
from typing import TypedDict

import requests
from requests import HTTPError
from requests import RequestException


def configure_logging() -> logging.Logger:
    level = os.getenv('LOG_LEVEL', 'INFO').upper()

    logging.basicConfig(
        level=level,
        format='[%(asctime)s.%(msecs)03d] %(levelname)s downloader: %(message)s',  # NOQA: E501
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout,
        force=True,
    )
    logging.captureWarnings(True)
    return logging.getLogger(__name__)


logger = configure_logging()

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


def _parse_total_size_from_content_range(content_range: str) -> int | None:
    """
    Example Content-Range: 'bytes 100-999/12345'
    Returns total size (12345) or None if not parseable.
    """
    try:
        _, range_part = content_range.split(' ', 1)
        _, total = range_part.split('/', 1)
        return int(total) if total.isdigit() else None
    except Exception:
        return None


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
    except sqlite3.DatabaseError:
        logger.error('Failed to set journal_mode to WAL for %s', DB_PATH)
    return conn


def fetch_oldest() -> Optional[sqlite3.Row]:
    db = get_db()
    return db.execute("""
        SELECT id, url, created_at, status, pct_downloaded, size_bytes
         FROM links
         WHERE status NOT IN ('connection_failed', 'failed', 'space_waiting')
         ORDER BY created_at ASC LIMIT 1
    """).fetchone()


def delete_by_id(row_id: int) -> int:
    db = get_db()
    try:
        cur = db.execute('DELETE FROM links WHERE id = ?', (row_id,))
        db.commit()
        db.close()
        logger.info(
            'delete_by_id() Deleted row with id %d: %s',
            row_id, 'Success' if cur.rowcount > 0 else 'Row not found',
        )
    except sqlite3.Error as e:
        logger.error('delete_by_id() Database error: %s', e)
        return 0
    return cur.rowcount


def set_pct_downloaded_by_id(row_id: int, new_pct: int) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            'UPDATE links SET pct_downloaded = ? WHERE id = ?',
            (new_pct, row_id),
        )
        db.commit()
        updated = cur.rowcount > 0
        db.close()
        return updated
    except sqlite3.Error as e:
        logger.error('set_pct_downloaded_by_id() Database error: %s', e)
        return False


def set_speed_bps_by_id(row_id: int, speed_bps: int) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            'UPDATE links SET speed_bps = ? WHERE id = ?',
            (int(speed_bps), row_id),
        )
        db.commit()
        updated = cur.rowcount > 0
        db.close()
        return updated
    except sqlite3.Error as e:
        logger.error('set_speed_bps_by_id() Database error: %s', e)
        return False


def set_file_size_by_id(row_id: int, size_bytes: int) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            'UPDATE links SET size_bytes = ? WHERE id = ?',
            (size_bytes, row_id),
        )
        db.commit()
        updated = cur.rowcount > 0
        db.close()
        logger.info(
            'set_file_size_by_id() Updated row %d with size_bytes=%d: %s',
            row_id, size_bytes, 'Success' if updated else 'Row not found',
        )
        return updated
    except sqlite3.Error as e:
        logger.error('set_file_size_by_id() Database error: %s', e)
        return False


def _store_queue_file_size(row_id: int, file: dict) -> None:
    """
    Store the file size reported by the Webshare queue API (the 'size'
    field, in bytes) for a newly added link, so the queue size is known
    without waiting for the file to start downloading.
    """
    size_raw = file.get('size')
    if not size_raw:
        return
    try:
        size_bytes = int(size_raw)
    except (TypeError, ValueError):
        logger.warning(
            '_store_queue_file_size() Unparseable size %r for row_id=%d',
            size_raw, row_id,
        )
        return
    validated_size_bytes = _validate_size_bytes(size_bytes)
    if validated_size_bytes is None:
        return
    set_file_size_by_id(row_id, validated_size_bytes)


def set_status_downloaded_by_id(row_id: int, new_status: str) -> bool:
    db = get_db()
    try:
        cur = db.execute(
            'UPDATE links SET status = ? WHERE id = ?',
            (new_status, row_id),
        )
        db.commit()
        updated = cur.rowcount > 0
        db.close()
        logger.info(
            'set_status_downloaded_by_id() Updated row '
            "%d with status='%s': %s",
            row_id, new_status, 'Success' if updated else 'Row not found',
        )
        return updated
    except sqlite3.Error as e:
        logger.error('set_status_downloaded_by_id() Database error: %s', e)
        return False


def get_settings() -> dict:
    db = get_db()
    row = db.execute("""
        SELECT id, token, auto_download, user_name, password_hash
        FROM settings WHERE id = 1
    """).fetchone()
    if not row:
        return {
            'id': 1,
            'token': '',
            'auto_download': 0,
            'user_name': '',
            'password_hash': '',
        }
    return dict(row)


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
            'percent_free': round(percent_free, 1),
        }
    except Exception as e:
        logger.error(
            'get_fs_usage() Error getting filesystem usage for %s: %s',
            base_path, e,
        )
        return {
            'total': 0,
            'used': 0,
            'free': 0,
            'percent_free': 0.0,
            'mount_display': str(base_path),
        }


def api_post(url: str | bytes, data: dict, headers: dict) -> tuple[str, str]:
    try:
        response = requests.post(url, data=data, headers=headers)
    except RequestException as e:
        logger.error('api_post() Connection failed: %s', e)
        return ('Connection failed', '<dummy></dummy>')

    rc = response.status_code
    if rc != 200:
        logger.error(
            'api_post() Got RC: %d, response.text=%r', rc, response.text,
        )
        return ('Connection failed', '<dummy></dummy>')

    if isinstance(url, bytes):
        url = url.decode('utf-8', errors='replace')

    logger.info('api_post() Successful POST to %s, RC: %d', url, rc)
    return ('OK', response.text)


def download_file(url: str, row_id: int) -> None:
    chunk_size = 1024 * 1024
    fs_usage = get_fs_usage()
    if fs_usage['percent_free'] < 5:
        set_status_downloaded_by_id(
            row_id=row_id,
            new_status='space_waiting',
        )
        return

    local_filename = url.split('/')[-1]
    temp_filepath = DOWNLOADS_PATH / f'.{local_filename}'
    final_filepath = DOWNLOADS_PATH / local_filename

    existing_bytes = (
        temp_filepath.stat().st_size if temp_filepath.exists() else 0
    )

    total_size = None
    last_modified = None

    try:
        head = requests.head(url, allow_redirects=True, timeout=30)
        head.raise_for_status()
        head_headers = head.headers
        if 'Content-Length' in head_headers:
            total_size = int(head_headers['Content-Length'])
        last_modified = head_headers.get('Last-Modified')
    except RequestException:
        pass

    if (
        total_size is not None and
        existing_bytes == total_size and
        existing_bytes > 0
    ):
        if temp_filepath.exists() and not final_filepath.exists():
            temp_filepath.replace(final_filepath)
        delete_by_id(row_id)
        return

    headers = {}
    if existing_bytes > 0:
        headers['Range'] = f'bytes={existing_bytes}-'
        if last_modified:
            headers['If-Range'] = last_modified

    logger.info(
        'download_file() Starting download of %s to %s (resume from %d bytes)',
        url, temp_filepath, existing_bytes,
    )
    set_status_downloaded_by_id(row_id=row_id, new_status='downloading')

    bytes_downloaded = existing_bytes
    last_update_time = time()
    last_bytes_at_update = bytes_downloaded
    update_interval = 2

    try:
        with requests.get(
            url,
            headers=headers,
            stream=True,
            allow_redirects=True,
            timeout=30,
        ) as r:
            r.raise_for_status()

            if 'Range' in headers and r.status_code == 200:
                logger.warning(
                    'download_file() Server did not honor Range request; '
                    'restarting full download.',
                )
                existing_bytes = 0
                bytes_downloaded = 0

            if r.status_code == 206:
                cr = r.headers.get('Content-Range')
                total_from_cr = (
                    _parse_total_size_from_content_range(cr)
                    if cr else None
                )
                if total_from_cr is not None:
                    total_size = total_from_cr
            elif total_size is None and r.headers.get('Content-Length'):
                total_size = int(r.headers['Content-Length'])

            mode = (
                'ab' if (existing_bytes > 0 and r.status_code == 206)
                else 'wb'
            )
            with open(temp_filepath, mode) as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    f.write(chunk)
                    bytes_downloaded += len(chunk)

                    current_time = time()
                    elapsed = current_time - last_update_time
                    if elapsed >= update_interval:
                        if total_size:
                            pct = int(bytes_downloaded / total_size * 100)
                            pct = max(0, min(pct, 100))
                            set_pct_downloaded_by_id(
                                row_id=row_id,
                                new_pct=pct,
                            )
                        speed = int(
                            (bytes_downloaded - last_bytes_at_update)
                            / elapsed,
                        )
                        set_speed_bps_by_id(row_id, max(0, speed))
                        last_update_time = current_time
                        last_bytes_at_update = bytes_downloaded

    except HTTPError:
        logger.error(
            'download_file() HTTP error while downloading %s to %s',
            url, temp_filepath,
        )
        set_speed_bps_by_id(row_id, 0)
        set_status_downloaded_by_id(
            row_id=row_id,
            new_status='connection_failed',
        )
        return
    except RequestException:
        logger.error(
            'download_file() Connection error while downloading %s to %s',
            url, temp_filepath,
        )
        set_speed_bps_by_id(row_id, 0)
        set_status_downloaded_by_id(
            row_id=row_id,
            new_status='connection_failed',
        )
        return
    except OSError as e:
        logger.error(
            'download_file() File I/O error while writing %s: %s',
            temp_filepath, e,
        )
        set_speed_bps_by_id(row_id, 0)
        set_status_downloaded_by_id(row_id=row_id, new_status='failed')
        return

    set_speed_bps_by_id(row_id, 0)

    final_size = temp_filepath.stat().st_size
    if total_size is None:
        logger.warning(
            'download_file() Download finished (unknown expected size) '
            'for %s to %s', url, temp_filepath,
        )
        temp_filepath.replace(final_filepath)
        delete_by_id(row_id)
        return

    if final_size == total_size:
        logger.warning(
            'download_file() Download successful for %s to %s',
            url, temp_filepath,
        )
        temp_filepath.replace(final_filepath)
        delete_by_id(row_id)
    else:
        logger.error(
            "download_file() Sizes don't match for %s. Expected %d, got %d.",
            url, total_size, final_size,
        )
        set_status_downloaded_by_id(row_id=row_id, new_status='failed')


def check_token(token: str) -> bool:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'user_data/'
    data = {
        'wst': token,
    }
    if len(token) < 1:
        logger.info('No token is set - user is not logged in.')
        return False
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        logger.error('check_token() Connection failed')
        return False

    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element) and status.text == 'OK':
        logger.info('check_token() Token is valid: %s', token)
        return True

    logger.warning('check_token() Token is invalid: %s', token)
    return False


def get_queue(token: str) -> tuple[str, list[dict] | None]:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'queue/'
    data = {
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        logger.error('get_queue() Connection failed')
        return ('Connection failed', None)

    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element) and status.text == 'OK':

        class ResponseDict(TypedDict):
            status: str | None
            total: str | None
            files: list[dict]

        response_dict: ResponseDict = {
            'status': root.findtext('status'),
            'total': root.findtext('total'),
            'files': [],
        }

        for file_elem in root.findall('file'):
            file_info: dict[str, str | None] = {
                child.tag: child.text for child in file_elem
            }
            response_dict['files'].append(file_info)

        logger.info(
            'get_queue() Retrieved queue with %d files',
            len(response_dict['files']),
        )
        return ('OK', response_dict['files'])

    logger.warning('get_queue() Failed to retrieve queue')
    return ('Not found', None)


def get_download_link(token: str, file_id: str) -> tuple[str, str | None]:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'file_link/'
    data = {
        'ident': file_id,
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        logger.error(
            'get_download_link() Connection failed for file_id=%s', file_id,
        )
        return ('Connection failed', None)

    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            logger.info(
                'get_download_link() Retrieved download link for file_id=%s',
                file_id,
            )
            link = root.find('link')
            if isinstance(link, ET.Element):
                return ('OK', link.text)

        if status.text == 'FATAL':
            logger.error(
                'get_download_link() Fatal error for file_id=%s', file_id,
            )
            message_elem = root.find('message')
            error_msg = ''
            if isinstance(message_elem, ET.Element) and message_elem.text:
                error_msg = message_elem.text
                if message_elem.text == 'File temporarily unavailable.':
                    logger.info(
                        'get_download_link() File temporarily unavailable '
                        'for file_id=%s, raw payload: %s', file_id, payload,
                    )
                    return ('Temporary unavailable', None)
            # Return error message as second element for Fatal errors
            return ('Fatal error', error_msg if error_msg else None)

    logger.warning(
        'get_download_link() Failed to retrieve download link for file_id=%s',
        file_id,
    )
    return ('Not found', None)


def dequeue_file(token: str, file_id) -> str | None:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'dequeue_file/'
    data = {
        'ident': file_id,
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        logger.error(
            'dequeue_file() Connection failed for file_id=%s', file_id,
        )
        return None

    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element) and status.text == 'OK':
        logger.info('dequeue_file() Successfully dequeued file_id=%s', file_id)
        return status.text

    return None


def add_link_if_new(link_raw: str) -> tuple[bool, str, Optional[int]]:
    url = (link_raw or '').strip()
    if not url:
        logger.warning('add_link_if_new() Invalid URL: %s', link_raw)
        return (False, '', None)

    db = get_db()
    try:
        cur = db.execute(
            'INSERT OR IGNORE INTO links (url) VALUES (?)',
            (url,),
        )
        db.commit()
        added = cur.rowcount > 0
        row_id = cur.lastrowid if added else None
        if added:
            logger.info('add_link_if_new() Added new link to DB: %s', url)
        else:
            logger.info(
                'add_link_if_new() Link already exists in DB, not added: %s',
                url,
            )
        return (added, url, row_id)
    except sqlite3.Error:
        logger.error(
            'add_link_if_new() Database error while adding link: %s', url,
        )
        return (False, url, None)


def log_download_error(
    file_id: str,
    file_name: str,
    error_type: str,
    error_message: str = '',
) -> bool:
    """Log a download error to the database for user notification."""
    db = get_db()
    try:
        cur = db.execute(
            """
            INSERT INTO download_errors
                (file_id, file_name, error_type, error_message)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                error_type = excluded.error_type,
                error_message = excluded.error_message,
                created_at = CURRENT_TIMESTAMP
            """,
            (file_id, file_name, error_type, error_message),
        )
        db.commit()
        db.close()
        logger.info(
            f'log_download_error() Logged error for file_id={file_id}, '
            f'error_type={error_type}',
        )
        return cur.rowcount > 0
    except sqlite3.Error as e:
        logger.error(f'log_download_error() Database error: {e}')
        return False


def main_loop() -> None:
    settings = get_settings()
    if settings['auto_download'] == 1:
        token = settings['token']
        if check_token(token):
            _, queue = get_queue(token)
            if queue:
                for file in queue:
                    file_id = file['ident']
                    file_name = file['name']
                    result, link = get_download_link(token, file_id)
                    if link:
                        logger.info(
                            'main_loop() Retrieved download link for '
                            'file_id=%s, file_name=%s and adding it to '
                            'the local queue', file_id, file_name,
                        )
                        add_status, _, row_id = add_link_if_new(link)
                        if add_status:
                            dequeue_file(token, file_id)
                            if row_id is not None:
                                _store_queue_file_size(row_id, file)
                    else:
                        logger.warning(
                            'main_loop() Failed to retrieve download link '
                            'for file_id=%s, file_name=%s', file_id, file_name,
                        )
            else:
                logger.info('main_loop() No files in WS queue')

    row = fetch_oldest()
    if not row:
        logger.info('main_loop() No links to process. DB is empty.')
        sleep(10)
        return

    row_id = row['id']
    url = row['url']

    try:
        response = requests.head(url, allow_redirects=True, timeout=30)
    except RequestException as e:
        logger.warning(
            'main_loop() HEAD request failed for row_id=%d, url=%s: %s',
            row_id, url, e,
        )
        set_status_downloaded_by_id(row_id, 'connection_failed')
        sleep(10)
        return

    content_length = response.headers.get('Content-Length')
    content_type = response.headers.get('Content-Type', '')
    if (
        response.status_code == 200
        and content_length is not None
        and not content_type.startswith('text/html')
    ):
        logger.info(
            'main_loop() Valid link found for row_id=%d, url=%s', row_id, url,
        )
        set_file_size_by_id(row_id, int(content_length))
        download_file(url, row_id)
    else:
        logger.warning(
            'main_loop() Invalid link or connection not working for '
            'row_id=%d, url=%s (status=%d, content_type=%s, '
            'content_length=%s)',
            row_id, url, response.status_code, content_type, content_length,
        )
        set_status_downloaded_by_id(row_id, 'connection_failed')
        sleep(10)


def main():
    while True:
        main_loop()


if __name__ == '__main__':
    raise SystemExit(main())
