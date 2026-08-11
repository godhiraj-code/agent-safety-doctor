from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

from .config import ScannerConfig, load_config
from .models import Finding, ScanMetadata, ScanResult, SEVERITY_RANK

SECRET_NAME_RE = re.compile(r"(^|[._-])(env|secret|secrets|credential|credentials|token|tokens|key|keys)([._-]|$)", re.I)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<name>\b[A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|DATABASE[_-]?URL|AUTH[_-]?HEADER)[A-Z0-9_]*\b)\s*[:=]\s*(?:(?P<quote>['\"])(?P<quoted_value>[^'\"\r\n]{8,})(?P=quote)|(?P<bare_value>[^\s'\"#;,]{8,}))",
    re.I,
)
PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)
BEARER_TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})")
INLINE_SECRET_FLAG_RE = re.compile(r"(?i)(--(?:token|api-key|apikey|password|secret|access-key|auth)\s+)(\S{8,})")
URL_CREDENTIAL_RE = re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<creds>[^/@\s:]+:[^/@\s]+)@", re.I)
LONG_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|sk-[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_=-]{32,})\b")
RISKY_COMMAND_RE = re.compile(
    r"\b(rm\s+-rf|sudo\s+rm|git\s+reset\s+--hard|git\s+clean\s+-fd|git\s+push\s+[^\n;&|]*--force(?:-with-lease)?|chmod\s+777|docker\s+system\s+prune|docker\s+rm\s+-f|helm\s+uninstall|drop\s+database|truncate\s+table|volumeDelete|deleteVolume|railway\s+[^\n;&|]*delete|kubectl\s+delete|terraform\s+destroy|aws\s+s3\s+(?:rm|rb)\s+[^\n;&|]*(?:--recursive|--force)|gcloud\s+[^\n;&|]*\sdelete\b|az\s+[^\n;&|]*\sdelete\b)\b",
    re.I,
)
MCP_HINT_RE = re.compile(r"\b(mcpServers|modelcontextprotocol|model context protocol|mcp-server|@modelcontextprotocol|mcp\.json)\b", re.I)
MCP_RISK_TERM_RE = re.compile(r"\b(admin|full_access|write|delete|destroy|execute|shell|filesystem|fs|database|db|kubectl|terraform|docker|aws)\b|\*", re.I)
APPROVAL_HINT_RE = re.compile(r"\b(approval|approved by|requires? human|human[- ]in[- ]the[- ]loop|confirmation|required before|manual review)\b", re.I)
BACKUP_HINT_RE = re.compile(r"\b(backup|rollback|restore|snapshot|point[- ]in[- ]time|pit backup|disaster recovery|revert)\b", re.I)
TEXT_EXTS = {
    ".md",
    ".txt",
    ".json",
    ".jsonc",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".env",
    ".pem",
    ".key",
    "",
}


def scan_workspace(root: Path, config: ScannerConfig | None = None, display_root: str | None = None) -> ScanResult:
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Workspace path must be an existing directory: {root}")
    config = config or load_config(root)
    metadata_config_path = config.config_path
    if metadata_config_path:
        try:
            metadata_config_path = metadata_config_path.resolve().relative_to(root)
        except (OSError, ValueError):
            if display_root:
                metadata_config_path = Path(metadata_config_path.name)
    metadata = ScanMetadata.start(Path(display_root) if display_root else root, metadata_config_path)
    findings: list[Finding] = []
    saw_approval_policy = False
    saw_backup_policy = False
    saw_mcp = False

    for path in iter_candidate_files(root, config, metadata):
        r = rel(path, root)
        text = safe_read(path, config.max_file_bytes)
        if text is None:
            metadata.files_skipped += 1
            continue
        metadata.files_scanned += 1
        metadata.bytes_scanned += min(path.stat().st_size, config.max_file_bytes)

        findings.extend(secret_file_findings(path, root, config))
        if not is_low_signal_file(path, root, config):
            findings.extend(secret_assignment_findings(path, root, text))
        findings.extend(risky_command_findings(path, root, text, config))

        mcp_findings, mcp_seen = mcp_surface_findings(path, root, text, config)
        findings.extend(mcp_findings)
        saw_mcp = saw_mcp or mcp_seen

        if has_positive_policy_evidence(text, APPROVAL_HINT_RE):
            saw_approval_policy = True
        if has_positive_policy_evidence(text, BACKUP_HINT_RE):
            saw_backup_policy = True

    if saw_mcp:
        findings.append(
            Finding(
                "info",
                "mcp_detected",
                ".",
                "MCP/tooling references detected; runtime permissions should be explicitly reviewed.",
                "Create a tool inventory with owner, scope, credential source, allowed actions, and approval requirement.",
                rule_id="mcp.detected",
            )
        )

    if not saw_approval_policy:
        findings.append(
            Finding(
                "medium",
                "missing_policy",
                ".",
                "No approval/human-in-the-loop policy language found.",
                "Add AGENT_SAFETY.md defining which actions require explicit human approval.",
                rule_id="policy.approval_missing",
            )
        )

    if not saw_backup_policy:
        findings.append(
            Finding(
                "medium",
                "missing_rollback",
                ".",
                "No backup/rollback/restore policy language found.",
                "Document restore steps and verify backups before allowing agents near production data or infra.",
                rule_id="policy.rollback_missing",
            )
        )

    findings.extend(git_findings(root))
    return ScanResult(metadata=metadata.finish(), findings=sort_dedupe(findings))


def iter_candidate_files(root: Path, config: ScannerConfig, metadata) -> Iterable[Path]:
    for base, dirs, files in os.walk(root):
        base_path = Path(base)
        dirs[:] = [d for d in dirs if d not in set(config.ignore_dirs)]
        if should_skip(base_path, root, config):
            metadata.files_skipped += len(files)
            continue
        for name in files:
            path = base_path / name
            if path.is_symlink() or not is_within_root(path, root):
                metadata.files_skipped += 1
                continue
            if should_skip(path, root, config) or not looks_text_candidate(path):
                metadata.files_skipped += 1
                continue
            yield path


def should_skip(path: Path, root: Path, config: ScannerConfig) -> bool:
    try:
        rel_path = path.relative_to(root).as_posix()
    except ValueError:
        return True
    parts = Path(rel_path).parts
    if any(part in set(config.ignore_dirs) for part in parts):
        return True
    if config.should_ignore_relpath(rel_path):
        return True
    return False


def is_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def looks_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name.lower().startswith(".env")


def safe_read(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def is_low_signal_file(path: Path, root: Path, config: ScannerConfig) -> bool:
    if config.scan_tests:
        return False
    parts = set(path.relative_to(root).parts)
    return "tests" in parts or "agent_safety_doctor" in parts or path.name.startswith("test_") or path.name.endswith("_test.py")


def secret_file_findings(path: Path, root: Path, config: ScannerConfig) -> list[Finding]:
    r = rel(path, root)
    if SECRET_NAME_RE.search(path.name) and not config.is_allowed_secret_file(r):
        return [
            Finding(
                "high",
                "secrets_exposure",
                r,
                "Secret/credential-looking file is present inside an agent-accessible workspace.",
                "Move real secrets outside the agent workspace; commit only .env.example-style placeholders; scope tokens to least privilege.",
                rule_id="secrets.filename",
            )
        ]
    return []


def secret_assignment_findings(path: Path, root: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    r = rel(path, root)
    for line_no, line in enumerate(text.splitlines(), start=1):
        if PRIVATE_KEY_BLOCK_RE.search(line):
            findings.append(
                Finding(
                    "high",
                    "secret_value_pattern",
                    r,
                    "Private key block found. Value is redacted.",
                    "Move private keys outside the repo/workspace; rotate if this was a live key.",
                    line=line_no,
                    evidence="-----BEGIN [REDACTED] PRIVATE KEY-----",
                    rule_id="secrets.private_key",
                )
            )
            continue
        match = SECRET_ASSIGNMENT_RE.search(line)
        if not match:
            continue
        name = match.group("name")
        value = match.group("quoted_value") or match.group("bare_value")
        if is_non_secret_identifier(name) or is_placeholder_secret(value):
            continue
        findings.append(
            Finding(
                "high",
                "secret_value_pattern",
                r,
                f"Potential secret assignment `{name}` found. Value is redacted.",
                "Move the value to a secret manager or untracked local environment file; rotate it if this was a real credential.",
                line=line_no,
                evidence=f"{name}=[REDACTED]",
                rule_id="secrets.assignment",
            )
        )
    return findings


def is_non_secret_identifier(name: str) -> bool:
    """Filter scanner/config constants that mention secret-like words but are not credentials."""
    lowered = name.lower()
    return lowered.endswith("_re") or any(token in lowered for token in ["glob", "regex", "regexp", "pattern", "hint", "rule", "schema"])


def is_placeholder_secret(value: str) -> bool:
    stripped = value.strip()
    if stripped.startswith(("(", "[", "{")):
        return True
    lowered = stripped.lower()
    if lowered.startswith(("${", "{{", "<")):
        return True
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    tokens = set(normalized.split("_"))
    return bool(tokens & {"example", "placeholder", "dummy", "fake", "test", "changeme", "redacted"}) or normalized.endswith("do_not_use")


def risky_command_findings(path: Path, root: Path, text: str, config: ScannerConfig) -> list[Finding]:
    if is_low_signal_file(path, root, config):
        return []
    findings: list[Finding] = []
    r = rel(path, root)
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in RISKY_COMMAND_RE.finditer(line):
            findings.append(
                Finding(
                    "high",
                    "destructive_action",
                    r,
                    f"Risky command/API pattern found: `{match.group(0)}`.",
                    "Require explicit approval before destructive commands; add dry-run defaults and backup verification before execution.",
                    line=line_no,
                    evidence=redact_line(line),
                    rule_id="commands.destructive",
                )
            )
    return findings


def mcp_surface_findings(path: Path, root: Path, text: str, config: ScannerConfig) -> tuple[list[Finding], bool]:
    r = rel(path, root)
    saw_mcp = bool(MCP_HINT_RE.search(text) or "mcp" in path.name.lower())
    if not saw_mcp or is_low_signal_file(path, root, config):
        return [], saw_mcp
    findings: list[Finding] = []
    if MCP_RISK_TERM_RE.search(text):
        findings.append(
            Finding(
                "medium",
                "mcp_tool_surface",
                r,
                "MCP/tooling config appears to expose broad or write-capable tools.",
                "Inventory each MCP tool, separate read/write scopes, and add policy checks before write/delete/admin tools run.",
                rule_id="mcp.broad_tool_surface",
            )
        )
    findings.extend(mcp_json_findings(path, root, text))
    return findings, saw_mcp


def mcp_json_findings(path: Path, root: Path, text: str) -> list[Finding]:
    if path.suffix.lower() != ".json":
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    servers = parsed.get("mcpServers") if isinstance(parsed, dict) else None
    if not isinstance(servers, dict):
        return []
    findings: list[Finding] = []
    for server_name, server in servers.items():
        blob = json.dumps(server).lower() if isinstance(server, (dict, list)) else str(server).lower()
        if MCP_RISK_TERM_RE.search(blob):
            findings.append(
                Finding(
                    "medium",
                    "mcp_server_risk",
                    rel(path, root),
                    f"MCP server `{server_name}` appears to expose write/admin/destructive capabilities.",
                    "Split this MCP server into read-only and write-capable profiles; require approval for write/delete/admin tools.",
                    evidence=f"server={server_name}",
                    rule_id="mcp.server_risk",
                )
            )
    return findings


def git_findings(root: Path) -> list[Finding]:
    git_dir = root / ".git"
    if not git_dir.exists():
        return [
            Finding(
                "medium",
                "missing_version_control",
                ".",
                "Workspace is not a Git repository.",
                "Use version control before allowing coding agents to mutate files; require clean diff review before apply/deploy.",
                rule_id="git.missing",
            )
        ]
    try:
        proc = subprocess.run(
            ["git", "status", "--short"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except Exception as exc:  # pragma: no cover
        return [Finding("info", "git_status_unknown", ".", f"Could not inspect git status: {exc}", "Run git status manually before agent work.", rule_id="git.status_unknown")]

    if proc.stdout.strip():
        return [
            Finding(
                "medium",
                "dirty_workspace",
                ".",
                "Git working tree has uncommitted changes.",
                "Snapshot or commit before agent runs so unintended changes are easy to review and revert.",
                rule_id="git.dirty",
            )
        ]
    return []


def redact_line(line: str) -> str:
    redacted = line.strip()
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group('name')}=[REDACTED]", redacted)
    redacted = BEARER_TOKEN_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
    redacted = INLINE_SECRET_FLAG_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
    redacted = URL_CREDENTIAL_RE.sub(lambda m: f"{m.group('scheme')}[REDACTED]@", redacted)
    redacted = LONG_TOKEN_RE.sub("[REDACTED]", redacted)
    return redacted[:240]


def has_positive_policy_evidence(text: str, pattern: re.Pattern[str]) -> bool:
    negation_re = re.compile(r"\b(no|not|without|missing|absent|lacks?|none)\b", re.I)
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        stripped = line.strip()
        if stripped.endswith("?"):
            continue
        window = line[: match.start()]
        if negation_re.search(window[-80:]):
            continue
        return True
    return False


def sort_dedupe(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.category, finding.path, finding.line, finding.evidence or finding.detail)
        deduped[key] = finding
    return sorted(deduped.values(), key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.category, f.path, f.line or 0, f.detail))
