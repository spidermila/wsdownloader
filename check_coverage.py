"""Coverage gate for the torrent code path (reads coverage.json).

Run after pytest:  python check_coverage.py [BASE_REF]

1. Every torrent-related function (and all of torrent.py) must have no
   missing lines and no missing branches.
2. Every line changed versus BASE_REF (default: $COV_BASE or origin/main)
   in app.py, downloader.py and torrent.py must be covered.
"""
import json
import os
import re
import subprocess
import sys

from coverage.python import PythonParser

COVERAGE_JSON = 'coverage.json'
SOURCE_FILES = ('app.py', 'downloader.py', 'torrent.py')
FULL_FILES = ('torrent.py',)
FUNCTIONS = {
    'downloader.py': (
        'fetch_active_torrents', 'set_external_id_by_id',
        'set_connections_by_id', 'set_upload_stats_by_id', 'get_settings',
        '_seeding_enabled', '_fetch_torrent_bytes', '_torrent_file_path',
        '_load_or_fetch_torrent_bytes', '_delete_torrent_file',
        '_enqueue_torrent', '_try_remove_result', '_discard_orphan',
        '_apply_torrent_status', 'torrent_loop', 'torrent_worker', 'main',
    ),
    'app.py': (
        'Link.__init__', '_magnet_display_name', 'init_db', 'get_settings',
        '_row_to_link', '_torrents_enabled', '_magnet_has_valid_btih',
        'validate_url', 'add_link_if_new', '_handle_torrent_add', 'index',
        '_remove_from_aria2', '_delete_staged_torrent_file',
        '_torrent_row_by_url', '_set_row_status', 'delete_link',
        'torrent_details', 'pause_torrent', 'resume_torrent',
        'stop_seeding_torrent', '_parse_speed_limit_kib',
        '_push_global_limits', 'update_torrent_settings',
        '_bulk_torrent_action', 'pause_all_torrents', 'resume_all_torrents',
        'torrent_global_stats', '_torrent_status_files',
        'select_torrent_files', 'link_to_dict',
    ),
}
FILE_RE = re.compile(r'^\+\+\+ b/(.+)$')
HUNK_RE = re.compile(r'^@@ -\S+ \+(\d+)(?:,(\d+))? @@')


def changed_lines(diff_text: str) -> dict[str, set[int]]:
    """Parse `git diff -U0` output into {file: {added line numbers}}."""
    result: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        file_match = FILE_RE.match(line)
        if file_match:
            current = file_match.group(1)
            continue
        hunk = HUNK_RE.match(line)
        if hunk and current:
            start = int(hunk.group(1))
            count = int(hunk.group(2) if hunk.group(2) is not None else 1)
            result.setdefault(current, set()).update(
                range(start, start + count),
            )
    return result


def to_statement_starts(changed: dict[str, set[int]]) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    for name, lines in changed.items():
        if name not in SOURCE_FILES:
            result[name] = lines
            continue
        parser = PythonParser(filename=name)
        parser.parse_source()
        result[name] = {parser.first_line(line) for line in lines}
    return result


def function_failures(cov: dict) -> list[str]:
    failures = []
    files = cov['files']
    for name in FULL_FILES:
        data = files[name]
        if data['missing_lines'] or data['missing_branches']:
            failures.append(
                f'{name}: missing lines {data["missing_lines"]} '
                f'branches {data["missing_branches"]}',
            )
    for name, funcs in FUNCTIONS.items():
        known = files[name]['functions']
        for func in funcs:
            if func not in known:
                failures.append(f'{name}:{func} not found in coverage data')
                continue
            data = known[func]
            if data['missing_lines'] or data['missing_branches']:
                failures.append(
                    f'{name}:{func} missing lines {data["missing_lines"]} '
                    f'branches {data["missing_branches"]}',
                )
    return failures


def diff_failures(cov: dict, changed: dict[str, set[int]]) -> list[str]:
    failures: list[str] = []
    for name, lines in sorted(changed.items()):
        data = cov['files'].get(name)
        if data is None:
            continue
        uncovered = set(data['missing_lines'])
        uncovered.update(src for src, _dst in data['missing_branches'])
        failures.extend(
            f'{name}:{line} changed but not covered'
            for line in sorted(lines & uncovered)
        )
    return failures


def main(argv: list[str]) -> int:
    base = (
        argv[1] if len(argv) > 1
        else os.environ.get('COV_BASE', 'origin/main')
    )
    with open(COVERAGE_JSON) as fh:
        cov = json.load(fh)
    proc = subprocess.run(
        [
            'git', 'diff', '-U0', '--no-ext-diff', '--no-textconv', '--text',
            '--no-color',
            '--src-prefix=a/', '--dst-prefix=b/', '--merge-base', base,
            '--', *SOURCE_FILES,
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f'git diff against {base} failed: {proc.stderr.strip()}')
        return 1
    failures = function_failures(cov) + diff_failures(
        cov, to_statement_starts(changed_lines(proc.stdout)),
    )
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print('Coverage gate passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
