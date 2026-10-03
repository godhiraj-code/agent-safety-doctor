import os
import stat
from types import SimpleNamespace
from pathlib import Path

from agent_safety_doctor.config import ScannerConfig
from agent_safety_doctor.scanner import iter_candidate_files, safe_read


def test_read_rechecks_limit_if_file_grows_after_stat(tmp_path, monkeypatch):
    path = tmp_path / "growing.log"
    path.write_bytes(b"x" * 101)
    original_stat = Path.stat

    def stale_stat(self, *args, **kwargs):
        if self == path:
            return SimpleNamespace(st_size=1, st_mode=stat.S_IFREG)
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stale_stat)
    assert safe_read(path, 100) is None


def test_ignored_directory_globs_prune_walk(tmp_path, monkeypatch):
    ignored = tmp_path / "generated-assets"
    (ignored / "nested").mkdir(parents=True)
    (ignored / "nested" / "secret.env").write_text("TOKEN=synthetic-private-value")
    (tmp_path / "safe.py").write_text("print('ok')")
    visited = []
    original_scandir = os.scandir

    def scan(path):
        visited.append(Path(path))
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", scan)
    config = ScannerConfig(ignore_globs=("generated-*",))
    metadata = SimpleNamespace(files_skipped=0)
    files = list(iter_candidate_files(tmp_path, config, metadata))
    assert files == [tmp_path / "safe.py"]
    assert ignored not in visited
