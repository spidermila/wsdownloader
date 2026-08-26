# Aria2 vs. wsdownloader UI — Feature Gap & UX Improvements

_Assessment date: 2026-08-26 · branch: `feat/torrent-aria2c`_

## Comparison matrix

| Area | Aria2 capability | Current wsdownloader | Gap |
|---|---|---|---|
| **Speed limits** | `max-overall-download-limit`, `max-overall-upload-limit`, per-download `max-download-limit` / `max-upload-limit`, `bt-request-peer-speed-limit` | None exposed | Big — no throttling, torrents can saturate the link |
| **Concurrency** | `max-concurrent-downloads` (global), `max-connection-per-server`, `split`, `bt-max-peers` | Hardcoded 8/8 in `entrypoint.sh:85` | No UI, no per-torrent tuning |
| **File selection (multi-file torrents)** | `select-file=1,3,5`, `change_option` after add | Torrents download every file; `torrent_details.html` shows file list read-only | Big — can't skip unwanted files |
| **File priority** | Aria2 supports via `select-file` reorder | None | Minor |
| **Queue management** | `changePosition`, `getGlobalStat`, `tellWaiting`, `tellStopped`, pause-all/unpause-all | Only per-row pause/resume via `app.py:1302-1338` | No reorder, no bulk actions |
| **Trackers** | Included in `tellStatus` (`bittorrent.announceList`); can add via `change_option` (`bt-tracker`) | Not surfaced | Users can't see why a torrent stalls |
| **Peers view** | `getPeers` (already wrapped `torrent.py:134`) | Shown in details page | ✓ present, but no auto-refresh, no ban/prefer |
| **Global stats** | `getGlobalStat` (total up/down speed, active/waiting/stopped counts) | Not called | Missing header dashboard |
| **Magnet → metadata persistence** | `bt-save-metadata=true` writes .torrent when metadata resolved | Disabled (`entrypoint.sh`) | If aria2 restarts mid-magnet, metadata is lost |
| **Session survival** | `--save-session` + `--input-file` (already used) but combined with `bt-save-metadata=false` breaks magnet resume | Partial | Restart of container loses in-flight magnets |
| **Force vs. graceful removal** | `remove` (graceful — announces stop to tracker) vs. `forceRemove` | Uses `forceRemove` (`torrent.py:124`) | Bad tracker etiquette; private trackers may penalise |
| **HTTP downloads via aria2** | Aria2 handles HTTP with multi-connection, resume, pause | wsdownloader uses its own downloader for HTTP | Two code paths; HTTP has no pause/resume/multi-connection |
| **ETA** | Computable from `totalLength`/`completedLength`/`downloadSpeed` | Not shown | Small win |
| **Verification** | `bt-hash-check-seed`, integrity re-check | None | Advanced |
| **Encryption / private trackers** | `bt-min-crypto-level`, `bt-require-crypto`, `bt-force-encryption` | Defaults only | Some trackers require it |
| **Notifications** | Aria2 RPC notifications (WebSocket) for start/pause/stop/complete/error | 3-s DB polling (`downloader.py:978`) | Higher latency, more DB churn |
| **DHT/PEX/LPD toggles** | Runtime configurable | Hardcoded on | Fine, minor |
| **Proxy / auth** | HTTP/SOCKS proxy, cookies, HTTP auth headers | Not exposed | Missing for gated hosters |
| **Metalink / mirror URLs** | Native | Not supported | Niche |
| **RSS auto-add** | Not native (external) | N/A | Out of scope |
| **Details page live refresh** | `tellStatus` polling | Renders once; user must reload | UX papercut |
| **Waiting/queued state** | Aria2 has `waiting` status | `map_status` (`torrent.py:175`) collapses waiting → downloading? | Verify — users can't see "queued" |

## Recommended improvements — prioritized

### High impact / low effort
1. **Global speed limit controls** — add `torrent_max_dl_bps` / `torrent_max_ul_bps` to settings, apply via `aria2.changeGlobalOption` on save + on aria2 startup. UI: two number inputs in the torrent panel (`templates/index.html:130-167`). One-hour job.
2. **Global stats header** — wrap `aria2.getGlobalStat`, render "↓ 2.4 MB/s · ↑ 800 KB/s · 3 active · 1 waiting" on the index page. Uses one extra RPC call per page load.
3. **Show ETA + upload ratio per row** — compute `(totalLength-completedLength)/downloadSpeed` and `uploadedBytes/totalLength` in `link_to_dict` (`app.py:1567`). Pure display change.
4. **Auto-refresh details page** — add a small JS `setInterval` hitting a JSON endpoint (`/torrent/details.json?gid=…`) every 3-5 s. Peers/speeds update without reload.
5. **Graceful `remove` instead of `forceRemove`** — `torrent.py:124`. Change default; keep force as fallback if graceful times out. Better citizen on private trackers.
6. **Enable `bt-save-metadata=true`** — `entrypoint.sh:31`. Combined with existing `save-session`, magnets survive container restarts. Cost: a few extra KB in `DATA_DIR`.
7. **Bulk actions** — "Pause all torrents" / "Resume all" buttons. Iterate DB rows or call `aria2.pauseAll`/`unpauseAll` (also unwrapped — add to `Aria2Client`).

### Medium impact
8. **File selection UI for multi-file torrents** — after magnet metadata resolves, show file list with checkboxes on details page; call `aria2.changeOption(gid, {"select-file": "1,3,5"})`. Requires small state machine (wait for metadata → prompt user → apply).
9. **Per-torrent speed limit** — inline "⚙" button on row → modal with dl/ul caps → `change_option`. Useful when one torrent hogs bandwidth.
10. **Max concurrent downloads** setting → `aria2.changeGlobalOption` `max-concurrent-downloads`. Surfaces "waiting" state naturally.
11. **Expose "waiting/queued" status distinctly** — check `map_status` (`torrent.py:175`); add badge + Czech label ("ve frontě"). Users currently can't tell why a torrent shows 0 %.
12. **Tracker list on details page** — parse `bittorrent.announceList` from `tellStatus`; show tracker + last announce status. Add an "Add tracker" input calling `change_option` `bt-tracker`.
13. **Switch to RPC WebSocket notifications** — aria2 pushes events; drop the DB write on every 3 s tick to only writing on state change. Reduces I/O and improves latency of UI.

### Lower priority / polish
14. **Route HTTP downloads through aria2** — consolidate on one engine; get free pause/resume + multi-connection HTTP. Bigger refactor; call it out but defer.
15. **Encryption toggle** (`bt-min-crypto-level=arc4`, `bt-require-crypto=true`) for users on ISPs that throttle BT.
16. **Force re-verify** button — `change_option` `bt-hash-check-seed=true` + restart, or use `aria2.saveSession` + external. Niche.
17. **Proxy / basic-auth support** for HTTP torrents behind auth (add `http-user`, `http-passwd`, `all-proxy` per-download options).
18. **Peers view actions** — show country/client/flags (already in `getPeers` response: `ip`, `port`, `bitfield`, `amChoking`, `peerChoking`, `downloadSpeed`, `uploadSpeed`, `seeder`). Currently rendered flat; sort by speed, highlight seeders.
19. **Download session sparkline** — cache last N `getGlobalStat` samples in memory, render tiny chart. Purely cosmetic but users love it.
20. **RPC secret rotation UI** — button that regenerates `.aria2-secret` and restarts aria2. Ops nicety.

## Implementation status

- [x] #1 Global speed limits — implemented
- [x] #5 Graceful remove — implemented
- [x] #6 `bt-save-metadata=true` — implemented
- [x] #7 Bulk pause/resume — implemented
- [x] #8 File selection UI — implemented
- [ ] Others — deferred
