"""Tests for the coverage gate script (check_coverage.py)."""
import json
import shutil
import subprocess

import pytest

import check_coverage

DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,0 +11,2 @@ def x():
+a
+b
@@ -30 +32 @@ def y():
-c
+d
@@ -40,2 +41,0 @@ def z():
-gone
-gone
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-x
+y
"""


def _file(missing_lines=(), missing_branches=(), functions=None):
    return {
        'missing_lines': list(missing_lines),
        'missing_branches': [list(b) for b in missing_branches],
        'functions': functions or {},
    }


def _cov(**files):
    base = {name: _file() for name in check_coverage.SOURCE_FILES}
    for name in check_coverage.FUNCTIONS:
        base[name]['functions'] = {
            f: _file() for f in check_coverage.FUNCTIONS[name]
        }
    base.update(files)
    return {'files': base}


def test_changed_lines_parses_hunks():
    changed = check_coverage.changed_lines(DIFF)
    assert changed['app.py'] == {11, 12, 32}
    assert changed['README.md'] == {1}


def test_diff_failures_flags_uncovered_changed_line():
    cov = _cov(**{'app.py': _file(missing_lines=[12])})
    assert check_coverage.diff_failures(cov, {'app.py': {11, 12}}) == [
        'app.py:12 changed but not covered',
    ]


def test_diff_failures_flags_partial_branch_source_line():
    cov = _cov(**{'app.py': _file(missing_branches=[(11, 14)])})
    assert check_coverage.diff_failures(cov, {'app.py': {11}}) == [
        'app.py:11 changed but not covered',
    ]


def test_diff_failures_passes_for_covered_or_untracked():
    cov = _cov(**{'app.py': _file(missing_lines=[99])})
    assert check_coverage.diff_failures(
        cov, {'app.py': {11}, 'README.md': {1}},
    ) == []


def test_function_failures_clean():
    assert check_coverage.function_failures(_cov()) == []


def test_function_failures_reports_function_file_and_missing_name():
    cov = _cov()
    cov['files']['torrent.py']['missing_lines'] = [3]
    cov['files']['app.py']['functions']['index']['missing_branches'] = [
        [1, 2],
    ]
    del cov['files']['downloader.py']['functions']['torrent_loop']
    out = check_coverage.function_failures(cov)
    assert len(out) == 3
    assert any(f.startswith('torrent.py:') for f in out)
    assert any(f.startswith('app.py:index') for f in out)
    assert 'downloader.py:torrent_loop not found in coverage data' in out


@pytest.fixture()
def cov_file(tmp_path, monkeypatch):
    path = tmp_path / 'coverage.json'
    monkeypatch.setattr(check_coverage, 'COVERAGE_JSON', str(path))
    return path


def _git_result(returncode, stdout='', stderr=''):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_main_passes(cov_file, monkeypatch, capsys):
    cov_file.write_text(json.dumps(_cov()))
    monkeypatch.setattr(
        check_coverage.subprocess, 'run',
        lambda *a, **kw: _git_result(0, DIFF),
    )
    assert check_coverage.main(['x', 'main']) == 0
    assert 'passed' in capsys.readouterr().out


def test_main_fails_on_uncovered_changed_line(
    cov_file, monkeypatch, capsys,
):
    cov_file.write_text(
        json.dumps(_cov(**{'app.py': _file(missing_lines=[11])})),
    )
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return _git_result(0, DIFF)

    monkeypatch.setattr(check_coverage.subprocess, 'run', fake_run)
    monkeypatch.setenv('COV_BASE', 'env-base')
    assert check_coverage.main(['x']) == 1
    assert 'env-base' in seen[0]
    assert 'app.py:11 changed but not covered' in capsys.readouterr().out


def test_main_fails_when_git_diff_fails(cov_file, monkeypatch, capsys):
    cov_file.write_text(json.dumps(_cov()))
    monkeypatch.setattr(
        check_coverage.subprocess, 'run',
        lambda *a, **kw: _git_result(128, stderr='bad ref'),
    )
    assert check_coverage.main(['x', 'nope']) == 1
    assert 'bad ref' in capsys.readouterr().out


SRC = """\
x = 1
value = call(
    1,
    2,
)
if x and (
    x > 0
):
    y = 2
    # comment
"""


def test_to_statement_starts_matches_coverage_parser(tmp_path, monkeypatch):
    (tmp_path / 'app.py').write_text(
        'x = 1\ntry:\n    pass\nexcept (\n    ValueError\n):\n    pass\n',
    )
    monkeypatch.chdir(tmp_path)
    result = check_coverage.to_statement_starts({'app.py': {1, 5, 6}})
    assert result == {'app.py': {1, 4}}


def test_continuation_line_change_fails_gate(tmp_path, monkeypatch):
    (tmp_path / 'app.py').write_text(SRC)
    monkeypatch.chdir(tmp_path)
    changed = check_coverage.to_statement_starts({'app.py': {3}})
    assert changed == {'app.py': {2}}
    cov = _cov(**{'app.py': _file(missing_lines=[2])})
    assert check_coverage.diff_failures(cov, changed) == [
        'app.py:2 changed but not covered',
    ]


needs_git = pytest.mark.skipif(
    shutil.which('git') is None, reason='git not installed',
)


def _git(cwd, *args):
    subprocess.run(
        ['git', *args], cwd=cwd, check=True, capture_output=True,
        env={
            'GIT_CONFIG_GLOBAL': '/dev/null', 'PATH': '/usr/bin:/bin',
            'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t',
            'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t',
        },
    )


@needs_git
@pytest.mark.parametrize(
    'prefix_cfg', [
        'diff.noprefix=true', 'diff.mnemonicPrefix=true',
    ],
)
def test_main_ignores_user_diff_prefix_config(
    tmp_path, monkeypatch, capsys, prefix_cfg,
):
    (tmp_path / 'app.py').write_text('a = 1\n')
    _git(tmp_path, 'init', '-q', '-b', 'main')
    _git(tmp_path, 'add', '.')
    _git(tmp_path, 'commit', '-qm', 'base')
    (tmp_path / 'app.py').write_text('a = 1\nb = 2\n')
    (tmp_path / 'coverage.json').write_text(
        json.dumps(_cov(**{'app.py': _file(missing_lines=[2])})),
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', prefix_cfg.split('=')[0])
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', prefix_cfg.split('=')[1])
    assert check_coverage.main(['x', 'main']) == 1
    assert 'app.py:2 changed but not covered' in capsys.readouterr().out


@needs_git
def test_main_fails_when_base_ref_missing(tmp_path, monkeypatch, capsys):
    _git(tmp_path, 'init', '-q', '-b', 'main')
    (tmp_path / 'coverage.json').write_text(json.dumps(_cov()))
    monkeypatch.chdir(tmp_path)
    assert check_coverage.main(['x', 'origin/main']) == 1
    assert 'failed' in capsys.readouterr().out


@needs_git
def test_main_ignores_diff_attributes(tmp_path, monkeypatch, capsys):
    (tmp_path / 'app.py').write_text('a = 1\n')
    (tmp_path / '.gitattributes').write_text('app.py -diff\n')
    _git(tmp_path, 'init', '-q', '-b', 'main')
    _git(tmp_path, 'add', '.')
    _git(tmp_path, 'commit', '-qm', 'base')
    (tmp_path / 'app.py').write_text('a = 1\nb = 2\n')
    (tmp_path / 'coverage.json').write_text(
        json.dumps(_cov(**{'app.py': _file(missing_lines=[2])})),
    )
    monkeypatch.chdir(tmp_path)
    assert check_coverage.main(['x', 'main']) == 1
    assert 'app.py:2 changed but not covered' in capsys.readouterr().out


def test_git_diff_command_disables_textconv_and_binary_guess(
    cov_file, monkeypatch,
):
    cov_file.write_text(json.dumps(_cov()))
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return _git_result(0, stdout='')

    monkeypatch.setattr(check_coverage.subprocess, 'run', fake_run)
    assert check_coverage.main(['x', 'main']) == 0
    assert '--no-textconv' in seen[0] and '--text' in seen[0]
