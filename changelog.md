# Changelog

Docker image changelog:

## 0.7.1
(released 21-Oct-2026)
- Magnet links no longer disappear from the list once their metadata is fetched; the row follows the actual download
- Torrents recover after aria2 restarts: interrupted downloads resume and finished ones are verified against the files on disk instead of failing or downloading again
- Seeding status is now shown correctly while a torrent is seeding
- Paused torrents can be resumed after an aria2 restart, and "Pause all" also pauses torrents that have not started yet
- Stopping seeding also removes the stored `.torrent` file; the torrent details page handles torrents aria2 no longer knows about
- Invalid or unreachable links no longer cause a server error, and a Webshare outage no longer logs you out
- Network requests to Webshare and to added links now time out after 30 seconds instead of hanging

## 0.7.0
(released 21-Oct-2026)
- Torrent support (opt-in in settings): paste a `magnet:` link or `.torrent` URL into the same input as regular links; downloads run through a bundled aria2c
- Optional seeding after a torrent finishes, by ratio or by time; only torrent downloads are ever shared, never HTTP/Webshare ones
- Torrent rows show download and upload speed, active connections and ratio; torrents can be paused, resumed, or stopped from seeding
- Per-torrent details page with files, peers and raw aria2 status, plus a choice of which files inside a torrent to download
- Global torrent download/upload speed limits and pause-all / resume-all actions
- `.torrent` files are kept under the data directory and cleaned up automatically, so they no longer appear among your downloads
- Fixed HTTP downloads waiting for free disk space never resuming after space was freed
- Torrent peers listen on port 51413 (override with `ARIA2_LISTEN_PORT`); publish it with `-p 51413:51413/tcp -p 51413:51413/udp` for incoming connections
- Base image moved to Python 3.14 and all dependencies updated to their latest versions, including security fixes in certifi, urllib3 and Werkzeug

## 0.6.0
(released 15-Aug-2026)
- Show current download speed (KB/s or MB/s, unit chosen automatically) next to the progress percentage while a file is downloading
- Fixed queue getting permanently blocked when the oldest link had an expired or otherwise broken URL; the downloader now skips failed rows and moves on to the next valid link
- Expired Webshare download links that redirect to an HTML error page are now correctly detected as invalid instead of being retried in a tight loop
- More robust handling of unusual HTTP responses when validating a link (malformed `Content-Length`, unexpected content types, request timeouts)
- CI/CD moved from a self-hosted runner to GitHub-hosted runners; no functional impact on the image

## 0.5.0
(released 4-Aug-2026)
- Show file sizes for files waiting in the download queue, plus a total queue size, so you know how much space to free up
- File sizes are now captured as soon as a link is added to the queue (for both Webshare and manually added links), instead of only once the download starts

## 0.4.0
(released 18-Apr-2026)
- Added a player to the web app. Now you can play the video files in your browser.
- Some minor optimizations

## 0.3.0
(released 30-Mar-2026)
- Changed to native Python logging
- Improved console logging format
- When app fails to fetch a download link from WS, user is notified in the web UI and can delete the item from queue
- Added rename file feature to web UI

## 0.2.0
(released 10-Feb-2026)
- Improved formatting of web UI
- Improved console logging
- Development environment change - now using private github actions runner for building the docker image

## 0.1.0
(released 9-Feb-2026)
- Initial release
