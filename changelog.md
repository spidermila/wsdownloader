# Changelog

Docker image changelog:

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
