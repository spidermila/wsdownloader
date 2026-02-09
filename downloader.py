import os
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from time import sleep
from typing import Optional
from typing import TypedDict

import requests
from requests import HTTPError


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


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
    except sqlite3.DatabaseError:
        pass
    return conn


def fetch_oldest() -> Optional[sqlite3.Row]:
    db = get_db()
    return db.execute("""
        SELECT id, url, created_at, status, pct_downloaded, size_bytes
         FROM links ORDER BY created_at ASC LIMIT 1
    """).fetchone()


def delete_by_id(row_id: int) -> int:
    db = get_db()
    cur = db.execute('DELETE FROM links WHERE id = ?', (row_id,))
    db.commit()
    db.close()
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
        print(f"Database error: {e}")
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
        return updated
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False


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
        return updated
    except sqlite3.Error as e:
        print(f"Database error: {e}")
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
            'percent_free': round(percent_free, 1),
        }
    except Exception as e:
        print(f"Error getting fs usage for {base_path}: {e}")
        return {
            'total': 0, 'used': 0, 'free': 0,
            'percent_free': 0.0,
            'mount_display': str(base_path),
        }


def api_post(url: str | bytes, data: dict, headers: dict) -> tuple[str, str]:
    try:
        response = requests.post(url, data=data, headers=headers)
    except ConnectionError as e:
        print('Connection failed')
        print(e.strerror)
        return ('Connection failed', '<dummy></dummy>')
    rc = response.status_code
    if not rc == 200:
        print(f'Got RC: {rc}')
        print(response.text)
        return ('Connection failed', '<dummy></dummy>')
    return ('OK', response.text)


def download_file(url: str, row_id: int) -> None:
    fs_usage = get_fs_usage()
    if fs_usage['percent_free'] < 5:
        set_status_downloaded_by_id(
            row_id=row_id,
            new_status='space_waiting',
        )
        return
    local_filename = url.split('/')[-1]
    temp_filepath = Path(os.path.join(DOWNLOADS_PATH, '.' + local_filename))
    response = requests.head(url)
    file_size = int(response.headers['Content-Length'])
    bytes_downloaded = 0
    print(f'downloading: {temp_filepath}')
    with requests.get(url, stream=True) as r:
        try:
            r.raise_for_status()
            with open(temp_filepath, 'wb') as f:
                set_status_downloaded_by_id(
                    row_id=row_id,
                    new_status='downloading',
                )
                chunk_size = 8192
                for chunk in r.iter_content(chunk_size=chunk_size):
                    f.write(chunk)
                    bytes_downloaded += chunk_size
                    pct_downloaded = int(bytes_downloaded / file_size * 100)
                    set_pct_downloaded_by_id(
                        row_id=row_id,
                        new_pct=pct_downloaded,
                    )
        except HTTPError:
            print('Connection error')
            set_status_downloaded_by_id(
                row_id=row_id,
                new_status='connection_failed',
            )
            return
    stat = temp_filepath.stat()
    final_size = stat.st_size
    if file_size == final_size:
        print('Download successful')
        os.rename(temp_filepath, os.path.join(DOWNLOADS_PATH, local_filename))
        delete_by_id(row_id)
    else:
        print('Sizes dont match')
        set_status_downloaded_by_id(
            row_id=row_id,
            new_status='failed',
        )


def check_token(token: str) -> bool:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'user_data/'
    data = {
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        return False
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            return True
    return False


def get_queue(token: str) -> tuple[str, list[dict] | None]:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'queue/'
    data = {
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        return ('Connection failed', None)
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':

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
                file_info: dict[str, str | None] = {child.tag: child.text for child in file_elem}  # Noqa: E501
                response_dict['files'].append(file_info)
            return ('OK', response_dict['files'])
    return ('Not found', None)
    # Example entry:
    #     {'downloaded': '0',
    #   'ident': 'KkYrWqGcFl',
    #   'img': 'https://img.webshare.cz/static/xxx.jpg',
    #   'name': 'xxxxxxx.mkv',
    #   'password': '0',
    #   'size': '1155405256',
    #   'stripe': 'https://img.webshare.cz/static/xxx.jpg',
    #   'stripe_count': '10'}


def get_download_link(token: str, file_id: str) -> tuple[str, str | None]:
    headers = {'Accept': 'text/xml; charset=UTF-8'}
    url = BASE_URL + 'file_link/'
    data = {
        'ident': file_id,
        'wst': token,
    }
    result, payload = api_post(url, data=data, headers=headers)
    if result == 'Connection failed':
        return ('Connection failed', None)
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            link = root.find('link')
            if isinstance(link, ET.Element):
                return ('OK', link.text)
        elif status.text == 'FATAL':
            message = root.find('link')
            if isinstance(message, ET.Element):
                if message.text == 'File temporarily unavailable.':
                    return ('Temporary unavailable', None)
            # TODO: make better handling for:
            # <response><status>FATAL</status><code>FILE_LINK_FATAL_4</code><message>File temporarily unavailable.</message><app_version>30</app_version></response>  # Noqa: E501
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
        return None
    root = ET.fromstring(payload)
    status = root.find('status')
    if isinstance(status, ET.Element):
        if status.text == 'OK':
            return status.text
    return None


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
        return (added, url)
    except sqlite3.Error:
        # For robustness; in a simple app we just surface a generic failure
        return (False, url)


def main_loop() -> None:
    # check the WS download list
    settings = get_settings()
    if settings['auto_download'] == 1:
        token = settings['token']
        if check_token(token):
            _, queue = get_queue(token)
            if queue:
                for file in queue:
                    file_id = file['ident']
                    file_name = file['name']
                    _, link = get_download_link(token, file_id)
                    if link:
                        print(f'Adding {file_name} from WS to local queue')
                        add_status, url = add_link_if_new(link)
                        if add_status:
                            dequeue_file(token, file_id)
                    else:
                        # TODO: some smarter behavior when link is not found?
                        pass
            else:
                # print('Nothing in queue')
                pass

    # process links from DB
    row = fetch_oldest()
    if not row:
        # print("No links to process. DB is empty.")
        sleep(10)
        return

    row_id = row['id']
    url = row['url']

    response = requests.head(url)
    if response.status_code == 200:
        file_size = int(response.headers['Content-Length'])
        set_file_size_by_id(row_id, file_size)
        download_file(url, row_id)
    else:
        print('invalid link or connection not working')
        sleep(10)


def main():
    while True:
        main_loop()


if __name__ == '__main__':
    raise SystemExit(main())
