# Torrent download support — implementation assessment (issue #39)

## Current shape of the app (relevant to torrents)

- `downloader.py`: single background worker. `main_loop()` pulls oldest row from
  `links`, does `requests.head/get` streaming to `/downloads`, updates
  `pct_downloaded`, `size_bytes`, `status`.
- `app.py`: Flask + SocketIO UI. Single "add link" input in
  `templates/index.html:198` (`<input type="url">`). URL validation in
  `validate_url()` only accepts `http`/`https`.
- SQLite `links(id, url, status, pct_downloaded, size_bytes, ...)`.
- Docker base = `python:3.13-slim`, apt already installs
  `tini curl procps ffmpeg`.

Everything assumes HTTP(S) semantics: HEAD request for Content-Length, resume
via `Range`, one file per row. Torrents violate all of that (peer swarm,
multi-file, seeding phase, listening ports).

---

## CLI / embedded torrent options

### 1. `aria2c` (RPC daemon) — best "simple" fit

- Single C++ binary, in Debian repos (`apt install aria2`).
- Supports HTTP(S), FTP, magnet, `.torrent`, metalink — could even replace
  parts of your current downloader long-term.
- JSON-RPC over HTTP on `localhost:6800`. Auth via `--rpc-secret=<token>`.
- Minimal config to launch:
  ```
  aria2c --enable-rpc --rpc-listen-all=false --rpc-secret=$TOKEN \
         --dir=/downloads --continue=true \
         --enable-dht=true --bt-enable-lpd=true \
         --listen-port=6881-6889 --seed-time=0
  ```
- Python client: plain `requests` POST to `/jsonrpc` (or `aria2p` package).
  No new heavy dep.
- Docker: add `aria2` to `apt-get install`. Expose UDP/TCP `6881-6889`
  only if user wants incoming peers.
- **Pros:** one tool covers both link types; tiny footprint; can shut it down
  if feature disabled.
- **Cons:** another moving process to supervise (needs to run alongside
  `downloader.py` and `gunicorn` — extend `entrypoint.sh` or use tini as
  PID 1 with a supervisor like `s6-overlay`/`supervisord`, or just background
  it from entrypoint).

### 2. `transmission-daemon` + `transmission-rpc` (PyPI)

- Real BT client, mature, `apt install transmission-daemon`.
- JSON-RPC on `:9091`. Config in `settings.json` (auto-generated on first
  run; you set `download-dir`, `rpc-authentication-required`, credentials,
  `peer-port`).
- Python: `transmission-rpc` gives a clean object model
  (`client.add_torrent(magnet)`, `.get_torrents()`).
- **Pros:** best BT feature set (ratio limits, peer stats, per-torrent
  controls).
- **Cons:** heavier; opinionated about its own state dir; separate auth
  config; more surface area than the app needs for a "simple" feature.

### 3. `libtorrent` (python3-libtorrent, in-process)

- No separate daemon — imported directly in `downloader.py`.
- `apt install python3-libtorrent` (system package; not pip-installable
  with hashes, so breaks your `--require-hashes` install).
- You manage a `lt.session`, poll alerts, persist resume data yourself.
- **Pros:** no extra process; tightest UX integration.
- **Cons:** more code to write and maintain; can't be optionally disabled at
  runtime as cleanly (import may fail); complicates the hashed-pip flow.

### 4. `qbittorrent-nox` — full web UI itself; overkill and duplicates yours. Skip.

### 5. `rtorrent` — powerful but XMLRPC + scgi setup is fiddly. Skip for "simple".

**Recommendation:** aria2c. It's the smallest addition and slots naturally
next to the existing HTTP download flow. Transmission is a fine second choice
if you value BT-specific UX (ratios, trackers view).

---

## Data-model changes (small)

Either:

- **Option A — extend `links`:** add `kind TEXT DEFAULT 'http'`
  (`http` / `magnet` / `torrent`) and `external_id TEXT` (aria2 GID or
  transmission hash). Reuse `status` / `pct_downloaded` / `size_bytes`.
- **Option B — new table `torrents`:** cleaner separation, but doubles all
  list/render/socket paths in `app.py` and `index.html`.

Option A wins for "simple" — the UI already has one queue view; you just
render a small badge (🧲) when `kind != 'http'`.

---

## User-friendliness — how to make it non-disturbing

Three layers you can combine:

### Layer 1: feature flag (must-have)

- `TORRENT_ENABLED=false` env var (default off).
- When off:
  - Torrent daemon is not started (nothing extra runs in the container).
  - `validate_url()` keeps rejecting magnets/torrent URLs with a helpful
    message: *"Torrent support disabled. Set TORRENT_ENABLED=1 to enable."*
  - No UI changes visible (input placeholder stays `https://...`).
- When on:
  - `validate_url()` also accepts `magnet:?xt=urn:btih:...` and URLs ending
    in `.torrent`.
  - Input placeholder becomes `https:// or magnet:...`.
  - Small "🧲 Torrent" chip appears in the header/help so users know it works.

This means users who don't care see zero change.

### Layer 2: auto-detect on the existing input

Don't add a second form. In `index()` (`app.py:713`):

```python
if url_input.startswith('magnet:') or url_input.lower().endswith('.torrent'):
    if not TORRENT_ENABLED:
        flash('Torrenty nejsou povoleny.', 'error'); return redirect(...)
    add_torrent(url_input)   # inserts row with kind='magnet'/'torrent'
else:
    # existing HTTP path
```

One box, one workflow. Users who paste a magnet link "just work."

### Layer 3: dedicated Docker image variant (optional, cleanest)

Two tags on Docker Hub:

- `spidermila/wsdownloader:X.Y.Z` — no torrent tooling installed (current
  behavior).
- `spidermila/wsdownloader:X.Y.Z-torrent` — same image + `aria2` apt package
  + torrent code path.

The Python code checks for `aria2c` on `PATH` at startup; if missing, force
`TORRENT_ENABLED=0` regardless of env. Users who don't need it don't get the
extra binary or the exposed ports.

This is the friendliest, but the added CI complexity (matrix build) may not be
worth it. A single image with a runtime toggle is probably enough.

---

## Concrete "simple aria2c" plan (sketch)

1. Dockerfile: `apt-get install ... aria2`.
2. `entrypoint.sh`: if `TORRENT_ENABLED=1`,
   `aria2c --enable-rpc --rpc-secret=$ARIA2_SECRET --dir=$DOWNLOADS_DIR --continue=true --daemon=true ...`.
3. New module `torrent.py` (~80 lines):
   - `add(uri) -> gid` (POST `aria2.addUri` or `aria2.addTorrent`).
   - `status(gid) -> {status, completed, total}` (POST `aria2.tellStatus`).
   - `remove(gid)`.
4. Schema migration in `init_db()`:
   `ALTER TABLE links ADD COLUMN kind TEXT DEFAULT 'http';`
   `ALTER TABLE links ADD COLUMN external_id TEXT;`
5. `downloader.main_loop()`: for `kind='http'` rows keep current logic; for
   others, poll aria2 and update `pct_downloaded`/`size_bytes`; when
   `status=complete`, move file(s) into `DOWNLOADS_PATH` (aria2 already
   writes there) and `delete_by_id`.
6. `validate_url()`: allow `magnet:` and `.torrent` when `TORRENT_ENABLED`.
7. `templates/index.html`: only cosmetic — placeholder text + a badge in
   rows where `kind != 'http'`.

Total diff: probably ~250 lines of Python + 10 lines Dockerfile/entrypoint +
a few template tweaks. No new required Python deps if you talk to aria2 with
plain `requests`.

---

## Things to warn users about (put in README)

- Torrents may open incoming ports (`-p 6881:6881/tcp -p 6881:6881/udp`
  needed for good peer connectivity; works without, just slower).
- Seeding: default `--seed-time=0` disables it; add UI toggle later if you
  want to be a good citizen.
- Legal responsibility disclaimer.
- Disk fills faster; existing `get_fs_usage()` warning already covers this.

---

## TL;DR

- Simplest: **aria2c with JSON-RPC**, feature-flagged via `TORRENT_ENABLED`
  env, auto-detected from a magnet paste in the existing input, `kind`
  column on `links` table.
- If you want a "real" BT client experience: **transmission-daemon** +
  `transmission-rpc`.
- Skip in-process `libtorrent` unless you're willing to abandon
  `--require-hashes` pip installs.
- For zero disturbance to non-torrent users: default the flag off, hide UI
  copy, or ship a `-torrent` image tag.
