from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".vercel",
    ".mypy_cache",
    ".ruff_cache",
}

DEFAULT_IGNORE_GLOBS = [
    "*.pyc",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.webp",
    "*.gif",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.sqlite",
    "*.db",
    "*safety-report.md",
    "*agent-safety-report.md",
]


@dataclass(frozen=True)
class ScannerConfig:
    ignore_dirs: tuple[str, ...] = tuple(sorted(DEFAULT_IGNORES))
    ignore_globs: tuple[str, ...] = tuple(DEFAULT_IGNORE_GLOBS)
    allow_secret_file_globs: tuple[str, ...] = ("*.example", ".env.example", "example.env")
    max_file_bytes: int = 300_000
    scan_tests: bool = False
    config_path: Path | None = None

    def should_ignore_relpath(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/")
        return any(fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(Path(normalized).name, pattern) for pattern in self.ignore_globs)

    def is_allowed_secret_file(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/")
        return any(fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(Path(normalized).name, pattern) for pattern in self.allow_secret_file_globs)


def load_config(root: Path, explicit_path: Path | None = None) -> ScannerConfig:
    config_path = explicit_path or discover_config(root)
    if not config_path:
        return ScannerConfig()
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Config file does not exist: {config_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML config {config_path}: {exc}") from exc

    scanner = raw.get("scanner", {})
    if not isinstance(scanner, dict):
        raise ValueError("Config [scanner] section must be a table")

    return ScannerConfig(
        ignore_dirs=tuple(sorted(_merged_list(scanner, "ignore_dirs", sorted(DEFAULT_IGNORES)))),
        ignore_globs=tuple(_merged_list(scanner, "ignore_globs", DEFAULT_IGNORE_GLOBS)),
        allow_secret_file_globs=tuple(_merged_list(scanner, "allow_secret_file_globs", ["*.example", ".env.example", "example.env"])),
        max_file_bytes=int(scanner.get("max_file_bytes", 300_000)),
        scan_tests=bool(scanner.get("scan_tests", False)),
        config_path=config_path,
    )


def discover_config(root: Path) -> Path | None:
    candidate = root / ".agent-safety-doctor.toml"
    return candidate if candidate.exists() else None


def _merged_list(raw: dict[str, object], key: str, default: list[str]) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Config scanner.{key} must be a list of strings")
    merged = list(default)
    for item in value:
        if item not in merged:
            merged.append(item)
    return merged
