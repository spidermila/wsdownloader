"""Opt-in Playwright tests: RUN_E2E=1 pytest tests/e2e -s --no-cov

Starts the real gunicorn + gevent-websocket stack against temp dirs.
Needs network for the Bootstrap / socket.io CDN scripts (skips otherwise).
"""
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

if not os.environ.get('RUN_E2E'):
    pytest.skip(
        'set RUN_E2E=1 to run Playwright e2e tests', allow_module_level=True,
    )
sync_api = pytest.importorskip('playwright.sync_api')

REPO_ROOT = Path(__file__).resolve().parents[2]
LONG_FILE = 'a' * 250 + '.mkv'
SPACED_FILE = ' '.join(['slovo'] * 20) + '.mp4'
DIACRITIC_FILE = 'Příliš žluťoučký kůň úpěl ďábelské ódy.mkv'
XSS_FILE = '<img src=x onerror=alert(1)>.mkv'
QUOTE_FILE = 'he said "hi" & <b>x<b>.txt'
DIR_NAME = 'složka'
LONG_URL = 'https://example.com/' + 'b' * 250 + '.mkv'
SHORT_URL = 'https://example.com/short.mp4'
BUSY_URL = 'https://example.com/busy.mp4'
MAGNET = 'magnet:?xt=urn:btih:' + 'c' * 40 + '&dn=Torrent%20jm%C3%A9no'
VIEWPORTS = {
    '360x640': {'width': 360, 'height': 640},
    '390x844': {'width': 390, 'height': 844},
    '1280x800': {'width': 1280, 'height': 800},
}
MOBILE = VIEWPORTS['360x640']


class Server:
    def __init__(self, url: str, downloads: Path, db: Path, shots: Path):
        self.url = url
        self.downloads = downloads
        self.db = db
        self.shots = shots

    def seed(self) -> None:
        for p in self.downloads.iterdir():
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
        for name in (LONG_FILE, SPACED_FILE, DIACRITIC_FILE, QUOTE_FILE):
            (self.downloads / name).write_text('x')
        (self.downloads / DIR_NAME).mkdir()
        (self.downloads / DIR_NAME / 'in.txt').write_text('x')
        con = sqlite3.connect(self.db)
        con.execute('DELETE FROM links')
        rows = [
            (LONG_URL, 'http', 'new'),
            (SHORT_URL, 'http', 'new'),
            (BUSY_URL, 'http', 'downloading'),
            (MAGNET, 'magnet', 'paused'),
        ]
        con.executemany(
            'INSERT INTO links (url, kind, status) VALUES (?, ?, ?)', rows,
        )
        con.commit()
        con.close()

    def link_urls(self) -> set[str]:
        con = sqlite3.connect(self.db)
        try:
            return {r[0] for r in con.execute('SELECT url FROM links')}
        finally:
            con.close()


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    base = tmp_path_factory.mktemp('e2e')
    (base / 'data').mkdir()
    (base / 'downloads').mkdir()
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('COV_')}
    env.update(
        DATA_DIR=str(base / 'data'),
        DOWNLOADS_DIR=str(base / 'downloads'),
        DB_PATH=str(base / 'data' / 'downloader.db'),
        FLASK_SECRET_KEY='e2e',
        APP_VERSION='9.9.9',
    )
    log = base / 'server.log'
    with log.open('w') as logf:
        proc = subprocess.Popen(
            [
                sys.executable, '-m', 'gunicorn', 'app:app',
                '--bind', f'127.0.0.1:{port}',
                '--worker-class',
                'geventwebsocket.gunicorn.workers.GeventWebSocketWorker',
                '--workers', '1',
            ],
            cwd=REPO_ROOT, env=env, stdout=logf, stderr=logf,
        )
        try:
            deadline = time.time() + 20
            while True:
                try:
                    urllib.request.urlopen(
                        f'http://127.0.0.1:{port}/health', timeout=2,
                    )
                    break
                except OSError:
                    if time.time() > deadline or proc.poll() is not None:
                        pytest.fail(
                            'server did not start:\n' +
                            log.read_text()[-2000:],
                        )
                    time.sleep(0.3)
            shots = base / 'shots'
            shots.mkdir()
            yield Server(
                f'http://127.0.0.1:{port}', base / 'downloads',
                base / 'data' / 'downloader.db', shots,
            )
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture(scope='module')
def browser():
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f'chromium unavailable: {exc}')
        yield b
        b.close()


def _shots(server):
    return Path(os.environ.get('SHOTS_DIR') or server.shots)


def _open(browser, server, kw, extra=(), accept=None):
    server.seed()
    for n in extra:
        (server.downloads / n).write_text('x')
    ctx = browser.new_context(**kw)
    page = ctx.new_page()
    errors: list = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    if accept is not None:
        def on_dialog(d):
            errors.append('dialog ' + d.message)
            d.accept() if accept else d.dismiss()
        page.on('dialog', on_dialog)
    page.goto(server.url)
    if page.evaluate('typeof io') == 'undefined':
        ctx.close()
        pytest.skip('CDN unreachable')
    page.wait_for_function('socket.connected')
    # first full_update replaces the Jinja markup; wait for it
    page.wait_for_selector('#files-tbody tr')
    return ctx, page, errors


@pytest.fixture()
def mobile(browser, server):
    ctx, page, errors = _open(browser, server, {'viewport': MOBILE})
    yield page
    ctx.close()
    assert errors == []


def _file_row(page, name):
    return page.locator('#files-tbody tr').filter(
        has=page.locator(
            'input.row-select[value="'
            f'{name.replace(chr(34), chr(92) + chr(34))}"]',
        ),
    )


def _link_row(page, url):
    return page.locator(f'#links-tbody tr[data-url="{url}"]')


def _count(page, kind):
    return int(
        page.locator(
            f'.bulk-bar[data-bulk="{kind}"] .bulk-count',
        ).inner_text(),
    )


def _tick_file(page, name):
    _file_row(page, name).locator('input.row-select').check()


def _tick_link(page, url):
    _link_row(page, url).locator('input.row-select').check()


def _force_update(page):
    page.evaluate("socket.emit('request_update')")


def _update_roundtrip(page):
    page.evaluate(
        "new Promise(r => { socket.once('full_update', () => setTimeout(r)); "
        "socket.emit('request_update'); })",
    )


@pytest.mark.parametrize('vp', list(VIEWPORTS))
def test_layout(browser, server, vp):
    ctx, page, errors = _open(browser, server, {'viewport': VIEWPORTS[vp]})
    try:
        width = VIEWPORTS[vp]['width']
        page.screenshot(
            path=_shots(server) / f'layout-{vp}-light.png', full_page=True,
        )
        page.evaluate("document.documentElement.dataset.bsTheme = 'dark'")
        page.screenshot(
            path=_shots(server) / f'layout-{vp}-dark.png', full_page=True,
        )
        page.evaluate("document.documentElement.dataset.bsTheme = 'light'")
        link = page.locator('footer a')
        assert link.get_attribute('href') == (
            'https://github.com/spidermila/wsdownloader'
        )
        assert link.get_attribute('target') == '_blank'
        assert 'noopener' in link.get_attribute('rel')
        assert link.inner_text() == 'v9.9.9'

        assert page.evaluate(
            'document.documentElement.scrollWidth',
        ) <= width
        wide = page.evaluate(
            "[...document.querySelectorAll('.table-responsive')]"
            '.filter(e => e.scrollWidth > e.clientWidth + 1)'
            '.map(e => [e.parentElement.id, e.scrollWidth, e.clientWidth])',
        )
        assert wide == []

        rows = [
            _file_row(page, LONG_FILE),
            _link_row(page, LONG_URL),
        ]
        for row in rows:
            targets = row.locator('input.row-select, button, a')
            for i in range(targets.count()):
                el = targets.nth(i)
                if not el.is_visible():
                    continue
                box = el.bounding_box()
                assert box['x'] >= 0
                assert box['x'] + box['width'] <= width
                el.click(trial=True)
        for kind in ('files', 'links'):
            bar = page.locator(f'.bulk-bar[data-bulk="{kind}"]')
            assert bar.is_visible()
            box = bar.bounding_box()
            assert box['x'] + box['width'] <= width
            bar.locator('.bulk-delete').scroll_into_view_if_needed()

        long_cell = _file_row(page, LONG_FILE).locator('.col-filename')
        short_cell = _file_row(page, DIACRITIC_FILE).locator('.col-filename')
        if width < 600:
            assert (
                long_cell.bounding_box()['height']
                > short_cell.bounding_box()['height']
            )
        assert page.locator('footer').is_visible()

        print(f'screenshots: {_shots(server)}')
    finally:
        ctx.close()
    assert errors == []


def test_select_all_and_count(mobile):
    page = mobile
    bar = page.locator('.bulk-bar[data-bulk="files"]')
    assert page.locator('#files-tbody input.row-select').count() == 5
    assert _count(page, 'files') == 0
    assert bar.locator('.bulk-delete').is_disabled()

    _tick_file(page, SPACED_FILE)
    assert _count(page, 'files') == 1
    assert bar.locator('.bulk-delete').is_enabled()
    select_all = page.locator('#files-container input.select-all')
    assert select_all.evaluate('e => e.indeterminate')

    select_all.check()
    assert _count(page, 'files') == 5
    assert _count(page, 'links') == 0
    select_all.uncheck()
    assert _count(page, 'files') == 0

    for name in (LONG_FILE, SPACED_FILE, DIACRITIC_FILE, QUOTE_FILE, DIR_NAME):
        _tick_file(page, name)
    assert select_all.is_checked()
    _file_row(page, DIR_NAME).locator('input.row-select').uncheck()
    assert not select_all.is_checked()
    assert select_all.evaluate('e => e.indeterminate')


def test_selection_survives_update(mobile, server):
    page = mobile
    _tick_file(page, LONG_FILE)
    _tick_file(page, DIACRITIC_FILE)
    _tick_link(page, LONG_URL)
    (server.downloads / 'new.txt').write_text('x')
    _force_update(page)
    page.wait_for_selector('#files-tbody tr[data-filename="new.txt"]')
    assert _count(page, 'files') == 2
    assert _count(page, 'links') == 1
    assert _file_row(page, LONG_FILE).locator('input.row-select').is_checked()
    assert not _file_row(page, 'new.txt').locator(
        'input.row-select',
    ).is_checked()


def test_external_delete_prunes_selection(mobile, server):
    page = mobile
    _tick_file(page, LONG_FILE)
    _tick_file(page, SPACED_FILE)
    (server.downloads / SPACED_FILE).unlink()
    _force_update(page)
    page.wait_for_function(
        "document.querySelectorAll('#files-tbody tr').length === 4",
    )
    assert _count(page, 'files') == 1


def test_rename_keeps_selection(mobile):
    page = mobile
    _tick_file(page, LONG_FILE)
    _file_row(page, SPACED_FILE).get_by_text('Přejmenovat').click()
    _update_roundtrip(page)
    assert page.locator('.rename-input').count() == 1
    assert _count(page, 'files') == 1
    page.locator('.rename-cancel-btn').click()
    assert _count(page, 'files') == 1
    assert _file_row(page, LONG_FILE).locator('input.row-select').is_checked()


def test_bulk_delete_files(mobile, server):
    page = mobile
    _tick_file(page, LONG_FILE)
    _tick_file(page, QUOTE_FILE)
    delete_btn = page.locator('.bulk-bar[data-bulk="files"] .bulk-delete')

    page.once('dialog', lambda d: d.dismiss())
    delete_btn.click()
    assert (server.downloads / LONG_FILE).exists()
    assert (server.downloads / QUOTE_FILE).exists()

    page.once('dialog', lambda d: d.accept())
    with page.expect_navigation():
        delete_btn.click()
    assert not (server.downloads / LONG_FILE).exists()
    assert not (server.downloads / QUOTE_FILE).exists()
    assert (server.downloads / SPACED_FILE).exists()
    assert 'Odstraněno: 2' in page.locator('.alert').first.inner_text()
    page.wait_for_selector('#files-tbody tr')
    assert _count(page, 'files') == 0
    page.screenshot(
        path=_shots(server) / 'bulk-delete-360.png', full_page=True,
    )

    _tick_file(page, DIR_NAME)
    page.once('dialog', lambda d: d.accept())
    with page.expect_navigation():
        delete_btn.click()
    assert not (server.downloads / DIR_NAME).exists()


def test_bulk_delete_queue(mobile, server):
    page = mobile
    assert _link_row(page, BUSY_URL).locator('input.row-select').count() == 0
    _tick_link(page, LONG_URL)
    _tick_link(page, MAGNET)
    page.once('dialog', lambda d: d.accept())
    with page.expect_navigation():
        page.locator('.bulk-bar[data-bulk="links"] .bulk-delete').click()
    assert server.link_urls() == {SHORT_URL, BUSY_URL}


def test_row_buttons_regression(mobile, server):
    page = mobile
    _file_row(page, SPACED_FILE).get_by_text('Přejmenovat').click()
    assert page.locator('.rename-input').count() == 1
    page.locator('.rename-cancel-btn').click()
    with page.expect_navigation():
        _file_row(page, DIACRITIC_FILE).locator('.btn-danger').click()
    assert not (server.downloads / DIACRITIC_FILE).exists()


def test_rename_cancel_escapes_filename(browser, server):
    ctx, page, errors = _open(browser, server, {'viewport': MOBILE})
    try:
        (server.downloads / XSS_FILE).write_text('x')
        _force_update(page)
        page.wait_for_selector('#files-tbody tr[data-filename^="<img"]')
        dialogs: list = []
        page.on('dialog', lambda d: (dialogs.append(d.message), d.dismiss()))
        row = page.locator('#files-tbody tr[data-filename^="<img"]')
        row.get_by_text('Přejmenovat').click()
        assert row.locator('.rename-input').input_value() == XSS_FILE
        row.locator('.rename-cancel-btn').click()
        sync_api.expect(
            row.locator('.filename-display'),
        ).to_have_text(XSS_FILE)
        assert row.locator('.col-filename img').count() == 0
        assert dialogs == []
    finally:
        ctx.close()
    assert errors == []


def test_select_all_clears_during_rename(mobile):
    page = mobile
    _tick_file(page, LONG_FILE)
    _tick_file(page, SPACED_FILE)
    _file_row(page, SPACED_FILE).get_by_text('Přejmenovat').click()
    assert _count(page, 'files') == 1
    select_all = page.locator('#files-container input.select-all')
    select_all.check()
    assert _count(page, 'files') == 4
    select_all.uncheck()
    assert _count(page, 'files') == 0
    assert not select_all.evaluate('e => e.indeterminate')
    page.locator('.rename-cancel-btn').click()
    assert _count(page, 'files') == 0


def test_phone_shows_queue_progress(mobile):
    row = _link_row(mobile, BUSY_URL)
    text = row.locator('.progress-mobile').inner_text()
    assert '%' in text
    assert row.locator('.progress-mobile').is_visible()


PHONES = {
    '320x568': dict(viewport={'width': 320, 'height': 568}),
    '360x640': dict(viewport={'width': 360, 'height': 640}),
    '390x844t': dict(
        viewport={'width': 390, 'height': 844}, has_touch=True, is_mobile=True,
    ),
    '640x360t': dict(
        viewport={'width': 640, 'height': 360}, has_touch=True, is_mobile=True,
    ),
}
UNI255 = ('š' * 127) + 'x'
MIN_NAME_WIDTH = {'360x640': 100, '390x844t': 100, '640x360t': 100}


@pytest.mark.parametrize('name', list(PHONES))
def test_phone_matrix(browser, server, name):
    ctx, page, errs = _open(browser, server, PHONES[name], (UNI255, XSS_FILE))
    try:
        _force_update(page)
        page.wait_for_selector(f'input.row-select[value="{UNI255}"]')
        m = page.evaluate("""() => ({
          sw: document.documentElement.scrollWidth, w: innerWidth,
          wide: [...document.querySelectorAll('.table-responsive')]
            .filter(e => e.scrollWidth > e.clientWidth + 1).length,
          nameW: document.querySelector('#links-tbody .col-filename')
            .getBoundingClientRect().width})""")
        print(name, 'queue name column width', round(m['nameW']))
        assert m['sw'] <= m['w']
        assert m['wide'] == 0
        assert page.locator('#files-tbody img').count() == 0
        busy = _link_row(page, BUSY_URL)
        assert '%' in busy.inner_text()
        if m['w'] < 768:
            assert busy.locator('.progress-mobile').is_visible()
        page.screenshot(
            path=_shots(server) / f'i3-{name}.png', full_page=True,
        )
        if name in MIN_NAME_WIDTH:
            assert m['nameW'] >= MIN_NAME_WIDTH[name]
        link = page.locator('footer a')
        assert link.get_attribute('href') == (
            'https://github.com/spidermila/wsdownloader'
        )
        assert '9.9.9' in page.locator('footer').inner_text()
        for row in (_link_row(page, SHORT_URL), _link_row(page, BUSY_URL)):
            for el in row.locator('input.row-select, button, a').all():
                if el.is_visible():
                    el.click(trial=True)
    finally:
        ctx.close()
    assert errs == []


def test_error_row_escaped(browser, server):
    ctx, page, errs = _open(browser, server, PHONES['360x640'])
    try:
        con = sqlite3.connect(server.db)
        con.execute('DELETE FROM download_errors')
        con.execute(
            'INSERT INTO download_errors (file_id, file_name, error_type, '
            'error_message) VALUES (?, ?, ?, ?)',
            (
                '"><img src=x onerror=alert(2)>', XSS_FILE, 'Fatal error',
                '<img src=x onerror=alert(3)>',
            ),
        )
        con.commit()
        con.close()
        _force_update(page)
        cell = page.locator('#errors-container tbody td').first
        sync_api.expect(cell).to_have_text(XSS_FILE)
        sync_api.expect(
            page.locator('#errors-container tbody td').nth(1),
        ).to_contain_text(
            '<img src=x onerror=alert(3)>',
        )
        _update_roundtrip(page)
        _update_roundtrip(page)
        assert page.locator('#errors-container img').count() == 0
        assert page.locator('#errors-container form input').get_attribute(
            'value',
        ) == '"><img src=x onerror=alert(2)>'
    finally:
        con = sqlite3.connect(server.db)
        con.execute('DELETE FROM download_errors')
        con.commit()
        con.close()
        ctx.close()
    assert errs == []


def test_trailing_space_bulk_delete(browser, server):
    ctx, page, errs = _open(
        browser, server, PHONES['390x844t'], ('a.mkv ', 'a.mkv'), accept=True,
    )
    try:
        _force_update(page)
        page.wait_for_selector('input.row-select[value="a.mkv "]')
        page.locator('input.row-select[value="a.mkv "]').check()
        assert _count(page, 'files') == 1
        with page.expect_navigation():
            page.locator('.bulk-bar[data-bulk="files"] .bulk-delete').click()
        assert not (server.downloads / 'a.mkv ').exists()
        assert (server.downloads / 'a.mkv').exists()
    finally:
        ctx.close()
    assert errs == ['dialog Opravdu smazat vybrané položky? Počet: 1']


def test_dark_mode(browser, server):
    ctx, page, errs = _open(browser, server, PHONES['360x640'], (UNI255,))
    try:
        _force_update(page)
        page.wait_for_selector(f'input.row-select[value="{UNI255}"]')
        page.evaluate("document.documentElement.dataset.bsTheme = 'dark'")
        page.locator('#files-container input.select-all').check()
        box = page.locator('#files-tbody input.row-select').first
        sync_api.expect(box).to_be_checked()
        bg = page.evaluate('getComputedStyle(document.body).backgroundColor')
        assert bg != 'rgb(255, 255, 255)'
        assert page.locator('footer a').is_visible()
        page.screenshot(path=_shots(server) / 'i3-dark.png', full_page=True)
    finally:
        ctx.close()
    assert errs == []


def test_bulk_bars_hidden_when_empty(browser, server):
    ctx, page, errors = _open(browser, server, {'viewport': MOBILE})
    try:
        for kind in ('files', 'links'):
            assert page.locator(
                f'.bulk-bar[data-bulk="{kind}"]',
            ).is_visible()
        con = sqlite3.connect(server.db)
        con.execute('DELETE FROM links')
        con.commit()
        con.close()
        for p in server.downloads.iterdir():
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
        _force_update(page)
        for kind in ('files', 'links'):
            sync_api.expect(
                page.locator(f'.bulk-bar[data-bulk="{kind}"]'),
            ).to_be_hidden()
    finally:
        ctx.close()
    assert errors == []
