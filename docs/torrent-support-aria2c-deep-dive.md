# aria2c torrent integration — deep dive (issue #39)

Companion to `docs/torrent-support-assessment.md`. This document focuses only
on the aria2c option, with concrete version pins, integration touch-points in
the current code, a GUI-first UX design, and a scoped seeding story.

---

## 1. Components and versions

### 1.1 aria2 (the daemon)

- Upstream: `aria2/aria2` on GitHub — **latest release `1.37.0`** (2023-11-15).
  No newer stable release; the project is in low-maintenance mode but still
  packaged everywhere.
- Debian packages available for our base image (`python:3.13-slim` → Debian
  **trixie**):
  - trixie: `aria2 1.37.0+debian-3` ✅ (matches upstream)
  - forky/sid: `1.37.0+debian-4`
  - bookworm: `1.36.0-1` (fallback if we ever downgrade base)
- Runtime footprint: single static-ish C++ binary, ~4 MB installed, plus
  a handful of shared libs (libc-ares, libssh2, libxml2, libssl) already
  present or tiny. Adds ~8 MB to the image; no Python deps.
- License: GPL-2.0-or-later — compatible with our current Apache-2.0/MIT-
  friendly stack for distribution as a Docker image (we're not linking Python
  code against it; we talk to it over JSON-RPC).

### 1.2 Python client — build vs. buy

Two realistic choices for the Python side:

| Option | Pros | Cons |
|---|---|---|
| `aria2p==0.12.1` (PyPI, requires Python ≥3.9) | Nice object model (`api.add_magnet`, `download.progress`), CLI included, actively released 2024. | Extra dep with its own transitive tail (`loguru`, `requests`, `typing-extensions`); needs `--generate-hashes` regeneration; brings a CLI we don't need. |
| **In-house ~120-line `torrent.py`** using `requests` (already pinned) to hit `/jsonrpc` | Zero new deps → no `prod.in` / `prod.txt` churn, no new hashes; we only need 5 methods (`addUri`, `addTorrent`, `tellStatus`, `remove`, `pause`); trivial to test with responses fixtures. | We own the small wrapper. |

**Recommendation: in-house wrapper.** The RPC surface we need is ~5 methods;
`aria2p` earns its keep only if we build a general BT client. Keeps
`requirements/prod.in` untouched and dodges the `--require-hashes` regen.

If we change our mind later, dropping in `aria2p` is a one-line swap.

### 1.3 Base image impact

Current Dockerfile installs `tini curl procps ffmpeg`. Add `aria2` in the
same `apt-get install` line — no new layer, no size regression beyond the
package itself.

Optional: split into a two-stage tag matrix (`:X.Y.Z` vs `:X.Y.Z-torrent`).
Assessment: **not worth the CI complexity for v1**. A single image with the
feature disabled by default and the ~8 MB aria2 binary lying dormant is
cleaner than maintaining two Dockerfiles + two publish jobs. Revisit if
someone actually complains about image size.

---

## 2. Integration surface in the current app

The app is a dual-process design: `gunicorn` (Flask + SocketIO) and
`downloader.py` (worker) share a SQLite DB (`app.py:130` `init_db`). Both
processes will need to know that some rows in `links` are torrents so they
route accordingly.

### 2.1 New process to supervise: `aria2c --enable-rpc`

- Launch from `entrypoint.sh`, backgrounded like `gunicorn` and
  `downloader.py`. Extend the existing monitor loop (`entrypoint.sh:38-56`)
  to include `ARIA_PID` — same pattern.
- Command line (tuned for a private container with the UI as the only
  client):
  ```bash
  aria2c \
    --enable-rpc=true --rpc-listen-all=false --rpc-listen-port=6800 \
    --rpc-secret="${ARIA2_RPC_SECRET}" \
    --dir="${DOWNLOADS_DIR}" \
    --continue=true --auto-file-renaming=false \
    --save-session=/data/aria2.session --save-session-interval=30 \
    --input-file=/data/aria2.session \
    --seed-time="${ARIA2_SEED_TIME:-0}" \
    --seed-ratio="${ARIA2_SEED_RATIO:-0.0}" \
    --enable-dht=true --enable-peer-exchange=true --bt-enable-lpd=true \
    --listen-port=51413 --dht-listen-port=51413 \
    --max-connection-per-server=8 --split=8 \
    --daemon=false
  ```
  Key choices explained:
  - `--rpc-listen-all=false` → binds `127.0.0.1:6800`, only reachable
    from other processes in the container. Web UI never proxies the RPC
    port outward.
  - `--rpc-secret` → shared secret; we generate a random one at container
    start if `ARIA2_RPC_SECRET` isn't set, and pass it to `downloader.py`
    and `app.py` via env. Same trick we already do implicitly with
    `FLASK_SECRET_KEY`.
  - `--save-session` + `--input-file` pointing at the same file →
    torrents survive container restarts (state lives in `/data`, which is
    already a bind-mount).
  - `--seed-time=0` (default) → download-only; user can bump it via a UI
    setting (see §4).
  - `--auto-file-renaming=false` → we want deterministic filenames so the
    "downloaded files" list stays sane.
  - `--daemon=false` → we want it in the foreground so entrypoint can
    monitor its PID like the other processes.

### 2.2 DB schema — extend `links`

Current columns (`app.py:130` in `init_db`): `id, url, created_at, status,
pct_downloaded, size_bytes, speed_bps`. Add two nullable columns via idempotent
`ALTER TABLE ... ADD COLUMN` (the app already uses this migration pattern for
`speed_bps`):

```sql
ALTER TABLE links ADD COLUMN kind TEXT NOT NULL DEFAULT 'http';
    -- 'http' | 'magnet' | 'torrent'
ALTER TABLE links ADD COLUMN external_id TEXT;
    -- aria2 GID (16 hex chars) for kind != 'http', NULL otherwise
```

New status values reuse the existing lifecycle vocabulary as much as
possible: `new`, `downloading`, `space_waiting`, `failed`,
`connection_failed`. We add one more:

- `seeding` — download complete but aria2 is still seeding. Row not
  deleted while in this state.

No new tables. The queue view already knows how to render each status
label (`templates/index.html:250-500`); we only add one more.

### 2.3 `validate_url()` — accept magnet and .torrent

`app.py:415` is where the regex + scheme allow-list lives. Two changes:

1. Recognize `magnet:?xt=urn:btih:<40-hex-or-32-base32>` as a valid
   input independent of the URL_RE regex (magnet links don't fit
   RFC 3986 the same way).
2. Keep the http/https allow-list, but if the path ends with `.torrent`
   (case-insensitive) treat it as a torrent input.
3. Both #1 and #2 are gated on the runtime toggle (`settings.torrent_enabled`,
   see §3). When the toggle is off, they hit the same "Neplatný link"
   response as today with a helpful hint.

Pseudo-code:

```python
def validate_url(url: str) -> str:
    if url.startswith('magnet:?'):
        if not settings_get('torrent_enabled'):
            return 'Torrenty nejsou povoleny. Zapněte je v nastavení.'
        if not MAGNET_RE.fullmatch(url):
            return 'Neplatný magnet link.'
        return 'ok'
    # existing http/https path...
    if url.lower().rsplit('?', 1)[0].endswith('.torrent'):
        if not settings_get('torrent_enabled'):
            return 'Torrenty nejsou povoleny. Zapněte je v nastavení.'
    return 'ok'
```

`MAGNET_RE` = `^magnet:\?(?:[a-z0-9._%+-]+=[^&\s]+&?)+$` with a required
`xt=urn:btih:` parameter.

### 2.4 `index()` POST handler (`app.py:750`) — routing

Today: validate → `test_url()` (HEAD probe) → `add_link_if_new()`. New flow:

```python
kind = classify(url)  # 'http' | 'magnet' | 'torrent'

if kind == 'http':
    reachable, size = test_url(url)   # unchanged
    add_link_if_new(url, kind='http', size_bytes=size)

elif kind == 'torrent':
    # .torrent → fetch the file into /data/torrents/, hand path to aria2 later
    add_link_if_new(url, kind='torrent')

elif kind == 'magnet':
    # No HEAD probe possible; size will come from aria2 after metadata fetch
    add_link_if_new(url, kind='magnet')
```

`add_link_if_new()` (`app.py:488`) grows two optional kwargs (`kind`,
`external_id`). Default values keep every existing test green.

### 2.5 `downloader.py` — parallel path

`main_loop()` at `downloader.py:652` currently: sync WS queue → fetch oldest
non-failed link → HEAD-validate → `download_file()`. Introduce a branch:

```python
row = fetch_oldest()
if row.kind == 'http':
    # existing path unchanged
elif row.kind in ('magnet', 'torrent'):
    torrent_step(row)
```

`torrent_step()` responsibilities:

1. **Enqueue** (idempotent): if `external_id` is NULL, call
   `aria2.addUri([row.url])` (magnet) or `aria2.addTorrent(<b64>)` (file),
   store the returned GID as `external_id`, set status to `downloading`.
2. **Poll** aria2 for known GID via `aria2.tellStatus(gid,
   ['status','totalLength','completedLength','downloadSpeed','files',
   'errorCode','errorMessage'])`.
3. **Reflect** into the same columns UI already reads:
   - `size_bytes` ← `totalLength`
   - `pct_downloaded` ← `100 * completedLength / totalLength`
   - `speed_bps` ← `downloadSpeed`
   - `status` mapping:
     - aria2 `active` → `downloading`
     - aria2 `waiting`/`paused` → `new` (keeps existing UI copy)
     - aria2 `complete` and `--seed-time=0` → `downloaded`, then
       call `aria2.removeDownloadResult(gid)` and, in the current model,
       `delete_by_id()` (row disappears; file is on disk under
       `DOWNLOADS_DIR`, gets picked up by `list_downloaded_files()`)
     - aria2 `complete` with seeding enabled → new `seeding` status until
       `--seed-ratio` / `--seed-time` hits
     - aria2 `error` → `failed`, plus write to `download_errors` (already
       exists in schema, `app.py:145-180`) with `errorMessage`
4. **Sleep** the same 2 s the HTTP path uses, then loop.

Important detail: torrents produce **multiple files** (a directory tree under
`DOWNLOADS_DIR/<torrent-name>/`). `list_downloaded_files()` (`app.py:587`)
currently walks `DOWNLOADS_PATH` non-recursively and skips dotfiles. We have
two options:

- **A. Show only the top-level directory as a single "file"**: match the
  UI's existing one-row-per-item mental model. Requires `os.scandir` to
  keep dirs, and a "download whole folder as .zip" endpoint for the "Play"
  column. Cleaner UI, more backend work.
- **B. Flatten and walk the tree recursively**: torrents dump N rows into
  the downloaded-files list. Simpler code, uglier UI for a 40-file
  season pack.

Recommendation: **A**. The list is already the app's headline view; we
shouldn't detonate it with 200 rows per torrent.

### 2.6 Concurrency

Today the worker downloads one HTTP file at a time (single-threaded
`main_loop`). aria2 downloads many torrents in parallel by default.

For v1 the safe thing is: **only one torrent active at a time**, gate it in
`torrent_step` by calling `aria2.tellActive()` and skipping enqueue if any
active. This matches user expectations from the HTTP path ("one at a time")
and keeps disk usage predictable. A future setting can raise the cap.

---

## 3. Environment / configuration

Add these env vars (all optional; sensible defaults):

| Var | Default | Purpose |
|---|---|---|
| `ARIA2_RPC_SECRET` | randomly generated at container start (written to `/data/.aria2-secret` so downloader can read it) | RPC auth |
| `ARIA2_LISTEN_PORT` | `51413` | BT peer port (TCP+UDP); must be published in `docker run -p` for good connectivity, works without |
| `ARIA2_MAX_ACTIVE` | `1` | how many torrents can download simultaneously |
| `ARIA2_SEED_TIME` | `0` | minutes to seed after completion (0 = off) |
| `ARIA2_SEED_RATIO` | `0.0` | share ratio target (0 = off) |
| `ARIA2_ENABLE_DHT` | `true` | needed for magnet links to bootstrap without trackers |

No env var to enable/disable the feature — that lives in `settings` (§4)
so the user can flip it from the GUI at runtime without a container restart.
If aria2c is not on `PATH` (someone built the image without the apt package),
`app.py` and `downloader.py` force the setting off regardless of DB state and
gray out the toggle.

---

## 4. GUI design — the user-friendly bit

Guiding principle from the previous doc: **users who don't want torrents
should see zero change.** Torrent affordances only appear once the user
opts in.

### 4.1 One new "Nastavení / Torrenty" section

New collapsed panel in `templates/index.html`, sibling to the existing
`auto_download` and `dark_mode` toggle rows near line 48 / 65. Follows the
same POST-form-to-`/settings/...` pattern already used by
`update_auto_download()` (`app.py:1017`) and `update_dark_mode()` (`app.py:1039`).

Contents:

```
┌─ 🧲 Torrenty ─────────────────────────────────────────┐
│ [x] Povolit stahování torrentů                        │
│                                                        │
│ (rest visible only when checkbox is on)               │
│ Sdílení (seeding):                                    │
│   ( ) Vypnuto (výchozí)                               │
│   ( ) Sdílet do poměru: [1.0 ▾]                       │
│   ( ) Sdílet po dobu: [60 minut ▾]                    │
│                                                        │
│ Peer port: 51413  (upravit v proměnných prostředí)    │
│ Status daemona: ● běží / ○ nedostupný                 │
└────────────────────────────────────────────────────────┘
```

Backing changes:

- New settings columns: `torrent_enabled INTEGER DEFAULT 0`,
  `torrent_seed_mode TEXT DEFAULT 'off'` (`off|ratio|time`),
  `torrent_seed_value REAL DEFAULT 0`.
- New route `/settings/torrent` POST handler mirroring
  `update_auto_download`.
- Toggling the checkbox on calls `aria2.saveSession()`, updates the DB, and
  emits a full SocketIO refresh so the input placeholder and help text
  update everywhere.
- Toggling off does **not** stop the daemon (it may still be finishing
  a torrent); it stops *accepting new* torrent inputs and greys out any
  torrent-related UI. A separate "Stop all torrents" button in this panel
  handles the abort case with a confirm dialog.

### 4.2 The add-link input — auto-detect, no second form

`templates/index.html` line ~198 has a single `<input type="url" name="link">`.
Change to `type="text"` (URL input rejects `magnet:` even with a scheme regex)
and update the placeholder based on the setting:

- Torrents off (default): `https://…` (unchanged)
- Torrents on: `https://…, magnet:… nebo .torrent`

The POST handler auto-routes based on `classify(url)`. Users paste a magnet,
it just works. No mental overhead.

### 4.3 Queue row rendering

Each row in the queue table (`templates/index.html:250-500`) gets one visual
addition when `link.kind != 'http'`: a small chip before the filename:

- `🧲 magnet` (magnet URI)
- `📦 torrent` (.torrent file)
- `🌱 seeding` (only in the seeding state; replaces the progress bar with
  "sdílíme 45 min / 60 min" or "poměr 0.7 / 1.0")

We already render Czech status strings per row; add corresponding strings
for the new `seeding` status and the "waiting for metadata" case (aria2
`status=active` but `totalLength=0` right after a magnet is added).

### 4.4 Cancel / remove

The existing `/delete` POST (`app.py`, delete_by_id) is already wired to
each row's delete button. For torrent rows, extend the handler to also
call `aria2.remove(gid)` + `aria2.removeDownloadResult(gid)` and delete
partial files under `DOWNLOADS_DIR/<torrent-name>/`. No new button in the UI.

### 4.5 Errors

Torrent errors (bad magnet, tracker unreachable, metadata timeout) already
have a home: the `download_errors` table + the errors panel rendered in
`templates/index.html:200-400`. Map aria2 `errorCode` + `errorMessage` into
`error_type` / `error_message` columns. No new UI needed.

---

## 5. Seeding — scoped for v1

Not a must per the request, but easy given aria2 already does it. The
minimum useful surface:

- Two aria2 flags in the daemon command line: `--seed-time`,
  `--seed-ratio` (already in §2.1).
- Three-state radio in the settings panel (off / ratio / time) that writes
  back to `settings.torrent_seed_mode` + `torrent_seed_value`.
- When either is non-default, the daemon is restarted with the new flags
  (or, cheaper, we set per-download via `aria2.changeOption(gid, ...)` at
  enqueue time). The per-download approach means users can change the
  setting without restarting the daemon; strongly preferred.
- New `seeding` status shown in the queue view; row not deleted while
  seeding. A "Stop seeding" button on those rows calls `aria2.remove(gid)`
  and reclassifies to `downloaded`.

If any of this feels like scope creep, ship v1 with `--seed-time=0` and no
UI; add the setting in v1.1. The daemon and DB schema decisions in §2 don't
change.

---

## 6. Security, ports, and privacy notes

- **RPC:** bound to `127.0.0.1`, secret-authenticated. No exposure risk.
- **Peer port (51413):** *must not* be exposed by default in
  `docker-compose.yml` / README examples. Users who want incoming peers
  add `-p 51413:51413 -p 51413:51413/udp` themselves. The app works without
  it, just slower.
- **DHT:** enabled by default (needed for magnet metadata) — make this
  explicit in the README so users on privacy-sensitive networks can turn
  it off via `ARIA2_ENABLE_DHT=false`.
- **Legal:** short disclaimer in README + a one-line notice under the
  torrent settings panel ("Za obsah stahovaných torrentů zodpovídá
  uživatel.").

---

## 7. Testing

The existing test suite (`tests/conftest.py`, `tests/test_app_basic.py`,
`tests/test_downloader_queue_size.py`) uses monkeypatched env vars and
reimports the modules. Torrent tests need one more fixture:

- `fake_aria2_rpc` — a `responses` / `pytest-httpserver` mock that
  answers `/jsonrpc` POSTs deterministically. No real aria2 process needed
  in CI.

New tests to write:

1. `classify()` recognizes magnet, `.torrent`, http correctly.
2. `validate_url()` rejects magnet when `torrent_enabled=0`, accepts
   when `=1`.
3. `torrent_step()` transitions row status through
   `new → downloading → downloaded` given canned RPC responses.
4. `/settings/torrent` POST persists new columns and emits SocketIO
   update.
5. Delete route calls aria2 `remove` + `removeDownloadResult` for a
   torrent row.

No changes to CI runners or test infra needed.

---

## 8. Migration and rollout

Because everything is gated behind `settings.torrent_enabled=0` (default 0),
the upgrade path for an existing install is:

1. `docker pull` new image → apt now installs aria2, but the daemon does
   not start (entrypoint checks the setting) and the UI shows no torrent
   affordances.
2. User opens Settings, ticks "Povolit torrenty" → server-side handler
   spawns the aria2 daemon (or unpauses if we chose to always run it) and
   flips the UI copy.
3. First torrent add works.

No DB migration danger — `ALTER TABLE ... ADD COLUMN` with defaults is
idempotent and safe on the existing `links` and `settings` tables (the app
already does this for `speed_bps` and `dark_mode`).

---

## 9. Effort estimate

| Chunk | Est. LOC | Notes |
|---|---|---|
| Dockerfile: add `aria2` | +1 | apt list |
| `entrypoint.sh`: launch daemon + monitor | +30 | mirror existing pattern |
| `torrent.py` (RPC wrapper) | ~120 | 5 methods, secret injection, retries |
| `app.py`: `validate_url`, `classify`, `add_link_if_new` kwargs, new settings route, delete-route branch | ~150 | |
| `downloader.py`: `torrent_step`, status mapping | ~120 | |
| `init_db` migrations | +15 | ALTER TABLE ADD COLUMN × 5 |
| `templates/index.html`: settings panel, placeholder, badges, seeding row | ~80 | |
| Tests (unit + fake RPC) | ~200 | |
| README + CHANGELOG | ~40 | |
| **Total** | **~750 LOC** | (previous rough estimate of 250 was HTTP-side only) |

Two focused PRs would work well:

- **PR 1:** wiring + downloader + backend (no UI changes, feature flag hard-coded off, but tests + RPC mock in place). Reviewable independently.
- **PR 2:** settings UI, placeholder, badges, seeding controls.

---

## 10. Open questions to confirm before implementing

1. **Do we want to keep torrent state in the app DB or delegate to aria2's
   `--save-session`?** Current draft does both (DB is the source of truth,
   session file is a warm-start cache). Alternative: DB stores only the
   external_id and we treat aria2 as authoritative. Cleaner separation,
   but complicates the queue view (which currently reads only DB).
2. **Do torrents count against the WS "auto-download" queue logic?** They
   shouldn't — the WS integration is HTTP-only. `main_loop()` will need to
   route WS-sourced rows exclusively through the HTTP path.
3. **File placement for multi-file torrents (§2.5): option A or B?** Deep-
   dive assumes A (folder as one row).
4. **Seeding shipped in v1 or v1.1?** Keeping in v1 costs ~1 day extra; UI
   already sketched here.
5. **Optional `-torrent` image tag?** Recommendation: no. One image, runtime
   toggle. Revisit if image size becomes a real complaint.

---

## 11. TL;DR (deeper)

- aria2 1.37.0 is in Debian trixie → **`apt install aria2`** in the existing
  Dockerfile is the whole "install" story. No PyPI dep (drop `aria2p`).
- **In-container topology:** third supervised process alongside gunicorn and
  downloader, listening only on `127.0.0.1:6800` with a random RPC secret
  in `/data/.aria2-secret`.
- **Schema:** two new columns on `links` (`kind`, `external_id`) + three on
  `settings` (`torrent_enabled`, `torrent_seed_mode`, `torrent_seed_value`).
  All ALTER TABLE ADD COLUMN, idempotent.
- **UX:** one settings panel (mirrors `auto_download` toggle pattern), same
  add-link input auto-routes magnet/`.torrent` when the toggle is on, small
  chip on torrent rows in the queue, folder-as-row in the downloaded files
  list.
- **Seeding:** doable in v1 with per-download `aria2.changeOption`; a
  radio-button "off / ratio / time" in the settings panel; new `seeding`
  status keeps completed torrent rows visible until the target is hit.
- **Effort:** ~750 LOC across two PRs, no new required PyPI deps, no CI
  changes.

---

## 12. Maintenance status and CVE risk assessment

The cadence looks stale at first glance; the reality is "slow-maintenance,
not dead." Numbers below were pulled live from GitHub, PyPI, NVD, and the
Debian security tracker.

### 12.1 Python 3.14 support

aria2 is a C++ binary — the host Python version is irrelevant for the daemon
itself. It's driven purely over JSON-RPC.

The optional Python client `aria2p` 0.12.1 declares support for Python 3.9
through **3.14** (PyPI classifiers include `Programming Language :: Python
:: 3.14`). Our current base is `python:3.13-slim`; nothing forces us to move
to 3.14, but nothing blocks it either. Our plan uses an in-house wrapper
over `requests`, so this is a non-issue for us.

### 12.2 Upstream project health

- Repo `aria2/aria2`: **not archived**, 41,819 stars, 1,175 open issues.
- Last tagged release: **1.37.0 (2023-11-15)** — 2+ years, looks bad.
- **But**: `master` branch is still receiving commits. Recent activity:
  - 2026-06-25: dependabot bumps merged
  - **2026-05-15: security commit "gnutls: Perform ExtendedKeyUsage
    validation"** (upstream fix for CVE-2026-8367, below)
  - 2026-03-10: docker build-push-action bump
- Read as: maintainers merge patches but haven't cut a release. Distro
  packages track the 1.37.0 tarball, so upstream post-release fixes are
  **not** in the trixie binary.

### 12.3 Known CVEs against 1.37.0

NVD keyword search returned 7 CVEs across the project's history; only two
are open against the current version.

| CVE | Date | Description | Debian trixie status |
|---|---|---|---|
| CVE-2026-71832 | 2026-08-24 | Divide-by-zero in `src/bittorrent_helper.cc` → remote DoS via crafted torrent (v1.37.0 and earlier) | **vulnerable, no DSA, marked unimportant** |
| CVE-2026-8367 | 2026-05-13 | Accepts server certificate with wrong Extended Key Usage; TLS validation weakness | **vulnerable, no DSA, postponed** (fixed in upstream git 2026-05-15) |
| CVE-2026-50574 | 2026-06-23 | yt-dlp downloader integration issue (yt-dlp side, not aria2) | n/a for us |
| CVE-2019-3500 | 2019-01-02 | `--log` leaks HTTP Basic Auth creds to file | resolved |
| CVE-2010-1512, CVE-2009-3617, CVE-2009-3575 | 2009–2010 | old parser/traversal bugs | resolved |

Debian classifies the two open 2026 CVEs as "unimportant" — typical for a
local DoS in a client-side tool + a TLS edge case. That's why no DSA and no
trixie backport.

### 12.4 Practical risk for this deployment

Our topology mitigates most of the surface:

- **RPC:** bound to `127.0.0.1` with a random secret → external attackers
  can't touch it.
- **CVE-2026-8367 (TLS EKU):** only affects outbound HTTPS traffic
  originating from aria2 itself — i.e., fetching a `.torrent` file over
  HTTPS from a URL where an attacker controls a mis-issued cert. Users who
  paste only magnet links: not exposed. Users who paste `.torrent` URLs: a
  compromised CA could serve a bad `.torrent`; the worst outcome is aria2
  starts downloading attacker-chosen content. Low-medium relevance.
- **CVE-2026-71832 (BT parser DoS):** a malicious peer sends a crafted
  message → aria2 divides by zero → aria2 crashes. Our entrypoint monitor
  already restarts crashed processes; `--continue=true` + `--save-session`
  resume the download. Blast radius: seconds of downtime per torrent.
  No RCE, no data loss, no privilege escalation.
- **Peer port not exposed by default** in our docker-compose examples →
  inbound BT connections require the user to opt in.
- **Container isolation:** aria2 runs as the same non-root user as the
  rest of the app, no extra capabilities.

Net: the two open CVEs are real but low-impact in the way we deploy.
A determined operator on a hostile network should not enable the feature;
a typical home-lab user is not meaningfully at risk.

### 12.5 Alternatives if the stagnant upstream is a dealbreaker

- **transmission-daemon** (Debian trixie ships 4.0.5-1, upstream actively
  releases in the 4.0.x line, no open CVEs). Slightly heavier integration
  cost (settings.json auto-generated on first run, separate RPC auth flow),
  but the maintenance story is unambiguous. Everything in §2–§11 above maps
  1:1 to a transmission-rpc backend; only the wrapper module changes.
- **Build aria2 from git** in a Dockerfile stage → picks up the 2026 EKU
  fix, but we take on rebuild responsibility for future patches. Not
  recommended for a hobby project.
- **Defer the feature** until aria2 cuts 1.38.0 or transmission-rpc
  integration gets prioritized.

### 12.6 Recommendation

Proceed with aria2 for v1. The two open CVEs are:

1. Documented in the README ("known issues" section) so users can make an
   informed choice.
2. Materially reduced by our localhost-only RPC and auto-restart supervision.
3. Trackable — if either escalates to a DSA, we bump the base image or
   switch to transmission with the same schema and UI already in place.

If that trade-off doesn't sit right, transmission is a drop-in swap at
the wrapper layer; the rest of the design (settings panel, chip badges,
`kind`/`external_id` columns, seeding UX) is backend-agnostic.
